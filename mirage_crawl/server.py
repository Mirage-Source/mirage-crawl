"""The sensor.

Serves a plausible documentation site plus every policy surface a crawler
might consult, and records what each client does with them.

Three things are measured that a plain access log cannot give you:

  Who read which policy file.  Each file carries a beacon: a path that appears
  in that file and nowhere else. Fetching it proves the file was read.

  Whether the reader and the crawler are the same machine.  The beacon encodes
  a hash of the address it was served to, so a hit from a different address is
  proof of a distributed fleet sharing one policy read.

  Whether repeat fetches are wasteful.  Content is deterministic, so ETag and
  Last-Modified never change unless the content does. A client refetching an
  unchanged page without a conditional header is choosing to.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import secrets
import socket
import stat
import time
from html import escape
from pathlib import Path
from urllib.parse import urlsplit

from aiohttp import web

from . import beacons, capture, credentials, eventlog, hunt, personas, policies
from .config import Config
from .fingerprint import build as build_fingerprint
from .identity import RangeTable, VerifierCache
from .sitegen import Site

STYLE = """:root{color-scheme:light dark}
body{margin:0;font:16px/1.6 system-ui,sans-serif;max-width:52rem;padding:2rem}
nav a{margin-right:1rem}
.hidden{display:none}
.mark{background-image:url("{css_beacon}")}
"""

SCRIPT = """(function(){
  try { fetch("{js_beacon}", {cache:"no-store"}); } catch (e) {}
})();
"""


LISTENER_PUBLIC = "public"
LISTENER_FRONT = "front"
LISTENER_PROXY = "proxy"
LISTENER_ADMIN = "admin"

# The two faces served on the general-purpose listeners (public/front/proxy).
# Per-service persona ports are a third kind of face, named for the persona.
FACE_DOCS = "docs"
FACE_ATTACK = "attack"

# Listener roles that are plumbing, not a persona.
_BASE_ROLES = {LISTENER_PUBLIC, LISTENER_FRONT, LISTENER_PROXY, LISTENER_ADMIN}


def _strip_port(host: str) -> str:
    """The hostname from a Host header, without the port.

    IPv6 literals are bracketed ("[::1]:80"); an unbracketed colon is a port.
    """
    host = host.strip().lower()
    if host.startswith("["):
        return host[1 : host.find("]")] if "]" in host else host
    return host.split(":", 1)[0] if ":" in host else host


def choose_face(host_header: str, docs_hosts: frozenset[str] | set[str]) -> str:
    """docs if the client asked for the site by its name, else attack.

    Crawlers arrive via DNS and links, so they send the real hostname.
    Scanners sweep address space and send the bare IP, a wrong name, or no
    Host at all. That split is the face: the documentation site answers to
    its name; everything else meets the attack face.
    """
    return FACE_DOCS if _strip_port(host_header) in docs_hosts else FACE_ATTACK


def _sock_key(sockname) -> tuple | None:
    """Normalise a socket name so a connection can be matched to its listener."""
    if isinstance(sockname, (str, bytes)):
        return ("unix", os.path.abspath(os.fsdecode(sockname)))
    if isinstance(sockname, tuple) and len(sockname) >= 2:
        return ("tcp", sockname[0], sockname[1])
    return None


def _without_first(names: list[str], drop: set[str]) -> list[str]:
    """Remove the first occurrence of each name in `drop` (case-insensitive).

    The TLS front inserts its headers right after the request line, having
    stripped any client copies, so the first occurrence is always ours.
    Removing it restores the client's own header order.
    """
    pending = set(drop)
    kept = []
    for name in names:
        lowered = name.lower()
        if lowered in pending:
            pending.discard(lowered)
            continue
        kept.append(name)
    return kept


def _canary_footer(token: str) -> str:
    """Plant a canary as what looks like an ordinary content-revision marker.

    Visible text (so it survives HTML-to-text extraction into a corpus) that
    reads as a static-site build hash rather than a flag.
    """
    return f'<hr><footer><small>Document revision {token}</small></footer>'


def _page_shell(title: str, body: str, head: str = "") -> str:
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        f"<title>{escape(title)}</title>"
        "<link rel=\"stylesheet\" href=\"/assets/style.css\">"
        f"{head}</head><body>{body}"
        "<script src=\"/assets/app.js\"></script></body></html>"
    )


class Sensor:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.secret = config.load_secret()
        self.site = Site(
            config.site_seed,
            projects=config.projects,
            pages_per_project=config.pages_per_project,
            fork_every=config.fork_every,
        )
        self.log = eventlog.EventLog(config.log_dir, config.sensor_id)

        self.ranges = RangeTable()
        loaded = self.ranges.load_file(config.ranges_file)
        self.verifier = VerifierCache(self.ranges, ttl=config.identity_ttl)
        self._ranges_loaded = loaded

        self._beacon_cache: dict[tuple[str, str, str], tuple[str, float]] = {}
        self._identity_sem = asyncio.Semaphore(16)
        self._seen_identities: set[tuple[str, str]] = set()
        self.started_at = time.time()

        # Filled in by start_sites(): socket name -> listener role.
        self.listeners: dict[tuple, str] = {}
        self.public_address: tuple | None = None
        # URLs pointing at ourselves are never indicators.
        self._own_host = urlsplit(config.origin).hostname
        self.proxy_address: tuple | None = None
        self.persona_addresses: dict[str, tuple] = {}
        # Key for deriving decoy identifiers (job/container ids). Separate
        # domain from the beacon MAC so a leaked decoy id reveals nothing
        # about the signing key.
        self._decoy_key = hashlib.blake2b(self.secret, person=b"decoy-id", digest_size=32).digest()

        # Hostnames that get the docs face: the origin's host plus any extras.
        hosts = {h.strip().lower() for h in config.site_hosts.split(",") if h.strip()}
        if self._own_host:
            hosts.add(self._own_host.lower())
        self.docs_hosts = frozenset(hosts)

    # -- helpers -----------------------------------------------------------

    def listener_of(self, request: web.Request) -> str:
        """Which listener a request arrived on. Unknown means public."""
        transport = request.transport
        sockname = transport.get_extra_info("sockname") if transport is not None else None
        key = _sock_key(sockname)
        return self.listeners.get(key, LISTENER_PUBLIC) if key else LISTENER_PUBLIC

    def face_of(self, request: web.Request, listener: str) -> str:
        """Which face serves this request: a persona port names its persona;
        otherwise the Host header decides docs vs attack."""
        if listener not in _BASE_ROLES:
            return listener  # a persona port is its own face
        return choose_face(request.headers.get("Host", ""), self.docs_hosts)

    def client_identity(self, request: web.Request, listener: str) -> tuple[str, str | None]:
        """(client ip, ja4) as far as this listener is entitled to say."""
        ip = request.remote or "127.0.0.1"
        if listener == LISTENER_FRONT:
            forwarded = request.headers.get("X-Forwarded-For", "")
            if forwarded:
                ip = forwarded.split(",")[0].strip()
            return ip, request.headers.get(self.config.ja4_header) or None
        if listener == LISTENER_PROXY and self.config.trust_proxy_header:
            value = request.headers.get(self.config.trust_proxy_header, "")
            if value:
                ip = value.split(",")[0].strip()
        # A plain proxy terminated TLS itself, so it cannot know the client's
        # JA4. Any JA4 header here is client-supplied.
        return ip, None

    def mint(self, standard: str, ip: str, ua: str) -> str:
        """Mint a beacon, reusing one for the same client within the window."""
        window = self.config.beacon_reuse_seconds
        if window <= 0:
            return beacons.mint(self.secret, standard, ip, ua)

        key = (standard, ip, ua)
        now = time.time()
        hit = self._beacon_cache.get(key)
        if hit and now - hit[1] < window:
            return hit[0]

        token = beacons.mint(self.secret, standard, ip, ua, now=now)
        if len(self._beacon_cache) > 20_000:
            cutoff = now - window
            self._beacon_cache = {
                k: v for k, v in self._beacon_cache.items() if v[1] >= cutoff
            }
        self._beacon_cache[key] = (token, now)
        return token

    def emit(self, request: web.Request, kind: str, **fields) -> None:
        """Log an event tied to this request: all of a request's events share
        its rid and face, so per-face analysis needs no join."""
        fields.setdefault("face", request.get("face"))
        self.log.emit(kind, rid=request.get("rid"), **fields)

    def trap(self, standard: str, ip: str, ua: str) -> str:
        return policies.trap_path(standard, self.mint(standard, ip, ua))

    def _schedule_identity(self, ip: str, fp) -> None:
        if not self.config.verify_identity:
            return
        key = (ip, fp.claimed_crawler or "-")
        if key in self._seen_identities:
            return
        self._seen_identities.add(key)
        if len(self._seen_identities) > 100_000:
            self._seen_identities.clear()
        asyncio.create_task(self._verify_identity(ip, fp))

    async def _verify_identity(self, ip: str, fp) -> None:
        async with self._identity_sem:
            try:
                verdict = await self.verifier.get(
                    ip, fp.claimed_crawler, fp.operator, fp.verify_method
                )
            except Exception as exc:
                self.log.emit(
                    eventlog.EVENT_IDENTITY,
                    ip=ip,
                    claimed=fp.claimed_crawler,
                    verdict="error",
                    detail=str(exc)[:200],
                )
                return

        self.log.emit(
            eventlog.EVENT_IDENTITY,
            ip=ip,
            claimed=fp.claimed_crawler,
            operator=fp.operator,
            method=verdict.method,
            verdict=verdict.verdict,
            detail=verdict.detail,
            rdns=verdict.rdns_name,
            matched_range=verdict.matched_range,
            ua=fp.user_agent[:400],
        )

    # -- middleware --------------------------------------------------------

    @web.middleware
    async def record(self, request: web.Request, handler):
        start = time.perf_counter()
        listener = self.listener_of(request)
        if listener == LISTENER_ADMIN:
            # Operator traffic: served only /healthz, and never logged as a client.
            request["listener"] = listener
            if request.path == "/healthz":
                return await self.health(request)
            return web.Response(status=404, text="not found")
        ip, ja4 = self.client_identity(request, listener)
        ua = request.headers.get("User-Agent", "")

        injected = (
            {"x-forwarded-for", self.config.ja4_header.lower()}
            if listener == LISTENER_FRONT else set()
        )
        raw_names = _without_first(
            [name.decode("latin-1") for name, _ in request.raw_headers], injected
        )
        headers, headers_truncated = capture.header_pairs(request.raw_headers, injected)
        raw_path, raw_query = capture.split_raw(request.raw_path)
        request["rid"] = secrets.token_hex(8)
        request["body"] = await capture.read_body(request, self.config.body_bytes)
        findings, indicator_locations = capture.scan_request(
            raw_path, raw_query, headers, request["body"], self._own_host
        )
        request["findings"] = findings
        version = f"{request.version.major}.{request.version.minor}"
        fp = build_fingerprint(user_agent=ua, raw_header_names=raw_names, http_version=version)
        request["fp"] = fp
        request["ip"] = ip
        request["ja4"] = ja4
        request["listener"] = listener
        request["face"] = self.face_of(request, listener)
        persona = personas.get(listener)

        try:
            # A persona port never uses the shared docs router: on :11434 the
            # request is for Ollama, not for /robots.txt.
            if persona is not None:
                response = await self.persona_dispatch(request, persona)
            else:
                response = await handler(request)
        except web.HTTPException as exc:
            response = exc
        except Exception:
            response = web.Response(status=500, text="internal error")

        # Replace aiohttp's stack-revealing Server header on every response.
        # A persona sets its own via request["server_header"].
        response.headers["Server"] = request.get("server_header") or self.config.server_header
        for name, value in request.get("extra_headers", ()):
            response.headers[name] = value

        duration_us = int((time.perf_counter() - start) * 1_000_000)

        self.emit(
            request,
            eventlog.EVENT_REQUEST,
            ip=ip,
            method=request.method,
            path=request.path,
            query=request.query_string or None,
            raw_path=raw_path,
            raw_query=raw_query,
            headers=headers,
            headers_truncated=headers_truncated,
            host=request.headers.get("Host"),
            http_version=version,
            ua=ua[:400],
            status=response.status,
            bytes=int(response.content_length or 0),
            duration_us=duration_us,
            header_order=list(fp.header_order),
            header_order_hash=fp.header_order_hash,
            header_count=fp.header_count,
            claimed_crawler=fp.claimed_crawler,
            operator=fp.operator,
            claims_browser=fp.claims_browser,
            browser_header_score=fp.browser_header_score,
            conditional=fp.conditional,
            accept_encoding=fp.accepts_encoding,
            accept_language=fp.sends_accept_language,
            referer=request.headers.get("Referer"),
            signals=list(fp.signals),
            ja4=ja4,
            listener=listener,
            face=request["face"],
            resource=request.get("resource_kind"),
            content_hash=request.get("content_hash"),
            fork_of=request.get("fork_of"),
            indicators=findings.as_dict() if findings.any() else None,
            indicator_locations=indicator_locations or None,
            **capture.body_fields(request["body"], self.config.body_log_bytes),
        )

        # Which face the credential was tried against. A hunt probe's family
        # until per-port personas exist; "site" for the documentation site.
        probe = hunt.match(request.path)
        persona = request.get("persona") or (probe.family if probe else "site")
        for cred in credentials.extract(headers, raw_query, request["body"]):
            self.emit(
                request,
                eventlog.EVENT_CREDENTIAL,
                ip=ip,
                path=raw_path,
                method=request.method,
                persona=persona,
                ua=ua[:400],
                **cred.as_dict(),
            )

        self._schedule_identity(ip, fp)
        return response

    # -- responses ---------------------------------------------------------

    def _conditional(self, request: web.Request, etag: str, last_modified: str):
        """Return a 304 when the client proved it already has this content."""
        if request.headers.get("If-None-Match", "").strip() == etag:
            return web.Response(status=304, headers={"ETag": etag, "Last-Modified": last_modified})
        if request.headers.get("If-Modified-Since", "").strip() == last_modified:
            return web.Response(status=304, headers={"ETag": etag, "Last-Modified": last_modified})
        return None

    async def policy_file(self, request: web.Request) -> web.Response:
        policy = policies.BY_PATH[request.path]
        ip, fp = request["ip"], request["fp"]
        body, tokens = policies.render_with(
            policy, lambda std: self.mint(std, ip, fp.user_agent), self.config.origin
        )
        token = tokens.pop(policy.standard)

        request["resource_kind"] = "policy"
        self.emit(
            request,
            eventlog.EVENT_POLICY_READ,
            ip=ip,
            standard=policy.standard,
            path=policy.path,
            token=token,
            extra_tokens=tokens or None,
            ua=fp.user_agent[:400],
            claimed_crawler=fp.claimed_crawler,
        )
        return web.Response(
            text=body,
            content_type=policy.content_type.split(";")[0],
            charset="utf-8",
            headers={"Cache-Control": "no-store", "X-Robots-Tag": "noai, noimageai"},
        )

    async def index(self, request: web.Request) -> web.Response:
        ip, fp = request["ip"], request["fp"]
        hidden = self.trap("hidden_link", ip, fp.user_agent)
        nofollow = self.trap("nofollow", ip, fp.user_agent)

        links = "".join(
            f'<li><a href="{p.path}">{escape(p.name)}</a>'
            + (f" <em>fork of {p.fork_of}</em>" if p.fork_of else "")
            + "</li>"
            for p in self.site.projects[:12]
        )
        body = (
            "<h1>Example documentation</h1>"
            "<nav><a href=\"/docs/\">All projects</a>"
            "<a href=\"/public/\">Public notices</a>"
            f'<a href="{nofollow}" rel="nofollow">Changelog archive</a></nav>'
            f"<ul>{links}</ul>"
            f'<div class="hidden"><a href="{hidden}">internal index</a></div>'
            + _canary_footer(escape(self.site.canary('/')))
        )
        request["resource_kind"] = "index"
        return web.Response(text=_page_shell("Example documentation", body), content_type="text/html")

    async def docs_index(self, request: web.Request) -> web.Response:
        links = "".join(
            f'<li><a href="{p.path}">{escape(p.name)}</a>'
            + (f" <em>fork of {p.fork_of}</em>" if p.fork_of else "")
            + "</li>"
            for p in self.site.projects
        )
        body = (
            "<h1>Projects</h1>"
            f"<ul>{links}</ul>"
            f'<p><a href="{policies.STABLE_DISALLOW_LINKED}">Restricted appendix</a> '
            "(disallowed in robots.txt)</p>"
        )
        request["resource_kind"] = "docs_index"
        return web.Response(text=_page_shell("Projects", body), content_type="text/html")

    async def project(self, request: web.Request) -> web.Response:
        pid = request.match_info["pid"]
        proj = self.site.project(pid)
        if proj is None:
            raise web.HTTPNotFound(text="not found")
        links = "".join(
            f'<li><a href="/docs/{pid}/{i:02d}.html">Page {i:02d}</a></li>'
            for i in range(proj.page_count)
        )
        note = f"<p>Fork of <a href=\"/docs/{proj.fork_of}/\">{proj.fork_of}</a>.</p>" if proj.fork_of else ""
        body = f"<h1>{escape(proj.name)}</h1>{note}<ul>{links}</ul>"
        request["resource_kind"] = "project_index"
        request["fork_of"] = proj.fork_of
        return web.Response(text=_page_shell(proj.name, body), content_type="text/html")

    async def page(self, request: web.Request) -> web.Response:
        pid = request.match_info["pid"]
        try:
            index = int(request.match_info["idx"])
        except ValueError:
            raise web.HTTPNotFound(text="not found")

        page = self.site.page(pid, index)
        if page is None:
            raise web.HTTPNotFound(text="not found")

        request["resource_kind"] = "page"
        request["content_hash"] = page.content_hash
        request["fork_of"] = page.fork_of

        cached = self._conditional(request, page.etag, page.last_modified)
        if cached is not None:
            return cached

        paragraphs = "".join(f"<p>{escape(p)}</p>" for p in page.body)
        nav = ""
        if index + 1 < self.site.pages_per_project:
            nav = f'<a href="/docs/{pid}/{index + 1:02d}.html">Next</a>'
        body = (
            f"<h1>{escape(page.title)}</h1>{paragraphs}"
            f"<nav>{nav}</nav>"
            f"{_canary_footer(escape(page.canary))}"
        )
        return web.Response(
            text=_page_shell(page.title, body),
            content_type="text/html",
            headers={
                "ETag": page.etag,
                "Last-Modified": page.last_modified,
                "Cache-Control": "public, max-age=3600",
            },
        )

    async def restricted_index(self, request: web.Request) -> web.Response:
        """Linked from /docs/ and disallowed in robots.txt.

        Fetching this means the client either never read robots.txt or read it
        and proceeded anyway. Which of the two is decided by whether we also
        logged a policy read for the same client.
        """
        ip, fp = request["ip"], request["fp"]
        child = self.trap("meta_noai", ip, fp.user_agent)
        body = (
            "<h1>Restricted appendix</h1>"
            "<p>Not licensed for training use.</p>"
            f'<p><a href="{child}">Appendix A</a></p>'
        )
        request["resource_kind"] = "restricted"
        return web.Response(
            text=_page_shell(
                "Restricted appendix",
                body,
                head='<meta name="robots" content="noai, noimageai, noindex">',
            ),
            content_type="text/html",
            headers={"X-Robots-Tag": "noai, noimageai, noindex"},
        )

    async def public_index(self, request: web.Request) -> web.Response:
        request["resource_kind"] = "public"
        return web.Response(
            text=_page_shell("Public notices", "<h1>Public notices</h1><p>Freely crawlable.</p>"),
            content_type="text/html",
        )

    async def stylesheet(self, request: web.Request) -> web.Response:
        ip, fp = request["ip"], request["fp"]
        request["resource_kind"] = "asset_css"
        return web.Response(
            text=STYLE.replace("{css_beacon}", self.trap("css_beacon", ip, fp.user_agent)),
            content_type="text/css",
        )

    async def script(self, request: web.Request) -> web.Response:
        ip, fp = request["ip"], request["fp"]
        request["resource_kind"] = "asset_js"
        return web.Response(
            text=SCRIPT.replace("{js_beacon}", self.trap("js_beacon", ip, fp.user_agent)),
            content_type="application/javascript",
        )

    async def catch_all(self, request: web.Request) -> web.Response:
        """Anything unrouted. This is where trap hits land."""
        ip, fp = request["ip"], request["fp"]
        path = request.path

        beacon = beacons.find_in_path(self.secret, path)
        if beacon is not None:
            same_ip = beacon.matches_ip(ip)
            self.emit(
                request,
                eventlog.EVENT_TRAP_HIT,
                ip=ip,
                path=path,
                token=beacon.token,
                standard=beacon.standard,
                minted_at=beacon.minted_at,
                delay_seconds=round(beacon.age_seconds(), 3),
                same_ip=same_ip,
                same_ua=beacon.matches_ua(fp.user_agent),
                split_fleet=not same_ip,
                ua=fp.user_agent[:400],
                claimed_crawler=fp.claimed_crawler,
                disallowed=policies.disallowed(path, fp.user_agent),
            )
            request["resource_kind"] = f"trap:{beacon.standard}"
            body = (
                "<h1>Internal</h1>"
                "<p>This document is not licensed for training use.</p>"
                + _canary_footer(escape(self.site.canary(path)))
            )
            return web.Response(
                text=_page_shell("Internal", body),
                content_type="text/html",
                headers={"X-Robots-Tag": "noai, noindex"},
            )

        probe = hunt.match(path)
        if probe is not None:
            return await self.hunt_probe(request, probe)

        if path in (
            policies.STABLE_DISALLOW_UNLINKED,
            policies.STABLE_ALLOW_UNLINKED,
        ):
            kind = (
                "stable_disallow_unlinked"
                if path == policies.STABLE_DISALLOW_UNLINKED
                else "stable_allow_unlinked"
            )
            self.emit(
                request,
                eventlog.EVENT_TRAP_HIT,
                ip=ip,
                path=path,
                token=None,
                standard=kind,
                same_ip=None,
                split_fleet=None,
                ua=fp.user_agent[:400],
                claimed_crawler=fp.claimed_crawler,
                disallowed=policies.disallowed(path, fp.user_agent),
            )
            request["resource_kind"] = kind
            return web.Response(
                text=_page_shell("Notice", _canary_footer(escape(self.site.canary(path)))),
                content_type="text/html",
            )

        request["resource_kind"] = "not_found"
        raise web.HTTPNotFound(text="not found")

    async def hunt_probe(self, request: web.Request, probe: hunt.Probe) -> web.Response:
        """A recognised compute-hijack probe.

        The body is where the value is. A bot that believes it found an exposed
        Ray dashboard or YARN cluster sends configuration next, and that
        configuration carries wallet addresses, pool hostnames and the URL the
        miner binary comes from — hard indicators that cluster campaigns across
        unrelated source addresses far better than behaviour does.
        """
        ip, fp = request["ip"], request["fp"]
        request["resource_kind"] = f"hunt:{probe.family}"

        captured: capture.Body | None = request["body"]
        body = captured.text() if captured is not None else ""

        findings: hunt.PayloadFindings = request["findings"]

        self.emit(
            request,
            eventlog.EVENT_HUNT,
            ip=ip,
            method=request.method,
            path=request.path,
            query=request.query_string or None,
            family=probe.family,
            target=probe.target,
            category=probe.category,
            intent=probe.intent,
            mitre=list(probe.mitre),
            ua=fp.user_agent[:400],
            claimed_crawler=fp.claimed_crawler,
            ja4=request["ja4"],
            # The body itself is on the request event (same rid); not duplicated here.
            body_bytes=len(captured.data) if captured is not None else 0,
            body_sha256=capture.body_fields(captured, 0).get("body_sha256"),
            indicators=findings.as_dict() if findings.any() else None,
            decoy_served=bool(probe.decoy is not None and self.config.hunt_decoys),
        )

        if probe.decoy is not None and self.config.hunt_decoys:
            return web.Response(
                text=probe.decoy,
                content_type=probe.content_type,
                headers={"Cache-Control": "no-store"},
            )
        raise web.HTTPNotFound(text="not found")

    async def persona_dispatch(self, request: web.Request, persona: personas.Persona) -> web.Response:
        """Serve one request on a persona port.

        Matching is scoped to the persona's own service families, so the port
        decides the product and path collisions vanish. An unrecognised path
        on a live service port gets the persona's default reply, because a real
        service answers something on its own port rather than going silent.
        """
        request["server_header"] = persona.server_header
        if persona.extra_headers:
            request["extra_headers"] = persona.extra_headers
        fp = request["fp"]

        # A web-app face answers every path itself (traversal, SQLi, CMS and
        # webshell shapes get inert decoy pages). It owns the whole port, so it
        # comes before the stage and probe handlers.
        if persona.respond is not None:
            body = request["body"]
            reply = persona.respond(
                request.method, request.path, request.query_string or "",
                request.headers.get("Content-Type", ""),
                body.text() if body is not None else "",
                self._decoy_key,
            )
            request["resource_kind"] = f"webapp:{reply.kind}"
            self.emit(
                request, eventlog.EVENT_HUNT, ip=request["ip"], method=request.method,
                path=request.path, query=request.query_string or None,
                family=persona.name, target="PHP web application",
                category=personas.webapp.CATEGORY_WEBAPP, intent=reply.intent,
                web_attack=reply.kind, mitre=list(reply.mitre),
                ua=fp.user_agent[:400], claimed_crawler=fp.claimed_crawler, ja4=request["ja4"],
                body_sha256=capture.body_fields(body, 0).get("body_sha256") if body is not None else None,
                indicators=(request["findings"].as_dict() if request["findings"].any() else None),
                decoy_served=self.config.hunt_decoys,
            )
            return web.Response(
                status=reply.status, text=reply.body,
                content_type=reply.content_type, charset="utf-8",
                headers={"Cache-Control": "no-store"},
            )

        # A multi-stage workflow step wins over the static probe decoy, so the
        # attacker gets a consistent world (submit -> poll, create -> inspect).
        if persona.stage is not None:
            stage = persona.stage(request.method, request.path, request["ip"], self._decoy_key)
            if stage is not None and self.config.hunt_decoys:
                request["resource_kind"] = f"hunt:{stage.family}"
                self.emit(
                    request, eventlog.EVENT_HUNT, ip=request["ip"], method=request.method,
                    path=request.path, query=request.query_string or None,
                    family=stage.family, target=stage.target, category=stage.category,
                    intent=stage.intent, mitre=["T1610", "T1496"],
                    ua=fp.user_agent[:400], claimed_crawler=fp.claimed_crawler, ja4=request["ja4"],
                    body_sha256=capture.body_fields(request["body"], 0).get("body_sha256"),
                    indicators=(request["findings"].as_dict() if request["findings"].any() else None),
                    decoy_served=True, stage=True,
                )
                return web.Response(
                    status=stage.status, body=stage.body.encode(),
                    content_type=stage.content_type, headers={"Cache-Control": "no-store"},
                )

        probe = persona.match(request.path)
        if probe is not None:
            return await self.hunt_probe(request, probe)

        request["resource_kind"] = f"persona:{persona.name}"
        served = persona.default_decoy is not None and self.config.hunt_decoys
        self.emit(
            request,
            eventlog.EVENT_HUNT,
            ip=request["ip"],
            method=request.method,
            path=request.path,
            query=request.query_string or None,
            family=persona.name,
            target=persona.name,
            category="recon",
            intent="probe a known service port on an unmapped path",
            mitre=["T1046"],
            ua=fp.user_agent[:400],
            claimed_crawler=fp.claimed_crawler,
            ja4=request["ja4"],
            indicators=(request["findings"].as_dict() if request["findings"].any() else None),
            decoy_served=served,
        )
        if served:
            # A service-shaped 404 body, not aiohttp's: a real service returns
            # its own not-found JSON for an unknown route on its own port.
            return web.Response(
                status=404,
                text=persona.default_decoy,
                content_type=persona.default_content_type,
                headers={"Cache-Control": "no-store"},
            )
        raise web.HTTPNotFound(text="not found")

    async def health(self, request: web.Request) -> web.Response:
        # Sensor internals (decoys on, probe counts) are the clearest possible
        # "this is a honeypot" tell. Anywhere but the admin socket, /healthz
        # is just another unrouted path.
        if request.get("listener") != LISTENER_ADMIN:
            return await self.catch_all(request)
        return web.json_response(
            {
                "ok": True,
                "sensor": self.config.sensor_id,
                "uptime_s": round(time.time() - self.started_at, 1),
                "events_written": self.log.written,
                "events_dropped": self.log.dropped,
                "range_operators": self.ranges.operators,
                "ranges_loaded": self._ranges_loaded,
                "pages": len(self.site.all_page_paths()),
                "policy_surfaces": len(policies.POLICY_FILES),
                "hunt_probes": len(hunt.PROBES),
                "hunt_categories": hunt.categories(),
                "hunt_decoys": self.config.hunt_decoys,
            }
        )


def build_app(config: Config) -> web.Application:
    sensor = Sensor(config)
    app = web.Application(middlewares=[sensor.record])
    app["sensor"] = sensor

    for policy in policies.POLICY_FILES:
        app.router.add_get(policy.path, sensor.policy_file)

    app.router.add_get("/", sensor.index)
    app.router.add_get("/healthz", sensor.health)
    app.router.add_get("/docs/", sensor.docs_index)
    app.router.add_get(policies.STABLE_DISALLOW_LINKED, sensor.restricted_index)
    app.router.add_get("/public/", sensor.public_index)
    app.router.add_get("/assets/style.css", sensor.stylesheet)
    app.router.add_get("/assets/app.js", sensor.script)
    app.router.add_get(r"/docs/{pid:p\d+}/", sensor.project)
    app.router.add_get(r"/docs/{pid:p\d+}/{idx:\d+}.html", sensor.page)
    app.router.add_route("*", "/{tail:.*}", sensor.catch_all)

    async def _on_start(_app: web.Application) -> None:
        await sensor.log.start()
        sensor.log.emit(
            eventlog.EVENT_SENSOR,
            event="start",
            origin=config.origin,
            pages=len(sensor.site.all_page_paths()),
            policy_surfaces=len(policies.POLICY_FILES),
            range_operators=sensor.ranges.operators,
        )

    async def _on_stop(_app: web.Application) -> None:
        sensor.log.emit(eventlog.EVENT_SENSOR, event="stop")
        await sensor.log.stop()

    app.on_startup.append(_on_start)
    app.on_cleanup.append(_on_stop)
    return app


def _tcp_socket(host: str, port: int) -> socket.socket:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    return socket.create_server((host, port), family=family, backlog=512, reuse_port=False)


def _unix_socket(path: Path) -> socket.socket:
    path = Path(os.path.abspath(path))
    if len(os.fsencode(path)) >= 104:  # sun_path is 104-108 bytes depending on OS
        raise RuntimeError(f"socket path too long for AF_UNIX ({len(str(path))} chars): {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        # Only ever replace a stale socket, never some other file.
        if not stat.S_ISSOCK(path.lstat().st_mode):
            raise RuntimeError(f"{path} exists and is not a socket; refusing to replace it")
        path.unlink()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old_umask = os.umask(0o177)  # socket file is created 0600: owner only
    try:
        sock.bind(str(path))
    finally:
        os.umask(old_umask)
    sock.listen(512)
    return sock


async def start_sites(app: web.Application, config: Config) -> web.AppRunner:
    """Start every listener and record which socket plays which role.

    Trust is decided by listener: whatever arrives on the public port is
    taken at face value from the socket, and only the front socket (and a
    proxy listener, if configured) may supply a client address.
    """
    if config.trust_proxy_header and not config.proxy_listen:
        raise ValueError(
            "CRAWL_TRUST_PROXY_HEADER is set but CRAWL_PROXY_LISTEN is not. The header is "
            "only trusted on a dedicated proxy listener; trusting it on the public port "
            "would let any client forge its address."
        )

    sensor: Sensor = app["sensor"]
    unix_paths = [
        Path(os.path.abspath(path))
        for path in (config.front_socket, config.admin_socket)
        if path is not None
    ]

    async def _unlink(_app: web.Application) -> None:
        for path in unix_paths:
            try:
                path.unlink()
            except OSError:
                pass

    app.on_cleanup.append(_unlink)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()

    async def add(sock: socket.socket, role: str) -> tuple:
        await web.SockSite(runner, sock).start()
        name = sock.getsockname()
        sensor.listeners[_sock_key(name)] = role
        return name

    sensor.public_address = await add(_tcp_socket(config.host, config.port), LISTENER_PUBLIC)

    for path, role in ((config.front_socket, LISTENER_FRONT), (config.admin_socket, LISTENER_ADMIN)):
        if path is not None:
            await add(_unix_socket(path), role)

    if config.proxy_listen:
        host, _, port = config.proxy_listen.rpartition(":")
        sensor.proxy_address = await add(_tcp_socket(host or "127.0.0.1", int(port)), LISTENER_PROXY)

    for name, port in personas.parse_ports(config.persona_ports):
        address = await add(_tcp_socket(config.host, port), name)
        sensor.persona_addresses[name] = address
    return runner

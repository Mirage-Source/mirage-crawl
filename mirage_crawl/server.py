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
import time
from html import escape

from aiohttp import web

from . import beacons, eventlog, hunt, policies
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

    # -- helpers -----------------------------------------------------------

    def client_ip(self, request: web.Request) -> str:
        header = self.config.trust_proxy_header
        if header:
            value = request.headers.get(header, "")
            if value:
                return value.split(",")[0].strip()
        return request.remote or "0.0.0.0"

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
        ip = self.client_ip(request)
        ua = request.headers.get("User-Agent", "")

        raw_names = [name.decode("latin-1") for name, _ in request.raw_headers]
        version = f"{request.version.major}.{request.version.minor}"
        fp = build_fingerprint(user_agent=ua, raw_header_names=raw_names, http_version=version)
        request["fp"] = fp
        request["ip"] = ip

        try:
            response = await handler(request)
        except web.HTTPException as exc:
            response = exc
        except Exception:
            response = web.Response(status=500, text="internal error")

        duration_us = int((time.perf_counter() - start) * 1_000_000)

        self.log.emit(
            eventlog.EVENT_REQUEST,
            ip=ip,
            method=request.method,
            path=request.path,
            query=request.query_string or None,
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
            ja4=request.headers.get(self.config.ja4_header),
            resource=request.get("resource_kind"),
            content_hash=request.get("content_hash"),
            fork_of=request.get("fork_of"),
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
        token = self.mint(policy.standard, ip, fp.user_agent)
        body = policy.render(policies.trap_path(policy.standard, token), self.config.origin)

        request["resource_kind"] = "policy"
        self.log.emit(
            eventlog.EVENT_POLICY_READ,
            ip=ip,
            standard=policy.standard,
            path=policy.path,
            token=token,
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
            f"<p>{escape(self.site.canary('/'))}</p>"
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
            f"<p><small>{escape(page.canary)}</small></p>"
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
            self.log.emit(
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
                disallowed=policies.disallowed(path),
            )
            request["resource_kind"] = f"trap:{beacon.standard}"
            body = (
                f"<h1>Internal</h1><p>{escape(self.site.canary(path))}</p>"
                "<p>This document is not licensed for training use.</p>"
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
            self.log.emit(
                eventlog.EVENT_TRAP_HIT,
                ip=ip,
                path=path,
                token=None,
                standard=kind,
                same_ip=None,
                split_fleet=None,
                ua=fp.user_agent[:400],
                claimed_crawler=fp.claimed_crawler,
                disallowed=policies.disallowed(path),
            )
            request["resource_kind"] = kind
            return web.Response(
                text=_page_shell("Notice", f"<p>{escape(self.site.canary(path))}</p>"),
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

        body = ""
        if request.method in ("POST", "PUT", "PATCH"):
            try:
                raw = await request.content.read(self.config.hunt_body_bytes)
                body = raw.decode("utf-8", "replace")
            except Exception:
                body = ""

        surface = f"{request.path}?{request.query_string}\n{body}"
        findings = hunt.scan_payload(surface)

        self.log.emit(
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
            ja4=request.headers.get(self.config.ja4_header),
            body_bytes=len(body),
            body=body[:4000] if body else None,
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

    async def health(self, request: web.Request) -> web.Response:
        request["resource_kind"] = "health"
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

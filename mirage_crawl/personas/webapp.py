"""A PHP/WordPress-shaped web face that looks exploitable but never is.

Compute-hijack scanners are not the only traffic worth capturing. The louder
flood is commodity web exploitation: traversal, SQLi, CMS probes, and the
upload-a-webshell chains that follow a freshly disclosed PHP bug. A host that
404s all of it teaches the operator nothing. A host that *looks* like an
unpatched PHP site draws the full follow-up and lets the sensor record it.

The ceiling (see the project CLAUDE.md) is absolute and this module keeps it:

  * Nothing is ever executed. There is no process-execution import anywhere
    near here, and no request body is ever run, interpreted, or stored to a
    path that anything could run.
  * The vulnerability is never emulated. A traversal does not read a real
    file; it gets a *generated, obviously synthetic* passwd-style page. A SQLi
    gets a generic database-error page, not a real query result. An upload
    gets an ordinary PHP-looking page, never confirmation that a shell landed.
  * Everything is deterministic and seed-derived, so the fake site is stable
    across restarts (an attacker who revisits sees the same world) and no
    outbound packet is ever sent.

So the responses here are deception content, not exploit code: they classify
the *shape* of an incoming request and hand back a plausible, inert page. Full
capture of the request (headers, body, indicators) happens upstream in the
middleware; this module only decides what the decoy says back, and tags the
attempt so the event log names it.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass

from .. import decode

# Category for the event log, alongside hunt.py's CATEGORY_* set.
CATEGORY_WEBAPP = "web_app"


@dataclass(frozen=True)
class Reply:
    status: int
    content_type: str
    body: str
    kind: str          # short tag: what shape of request this was
    intent: str        # human sentence for the event log
    mitre: tuple[str, ...]


def _derive(key: bytes, *parts: str, length: int = 8) -> str:
    """A stable synthetic token from the seed, so fake content never changes."""
    msg = "\x00".join(parts).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()[:length]


# -- request-shape detection ------------------------------------------------
#
# Deliberately small and standard. This is enough to pick which decoy page to
# serve; it is not a full attack classifier (that is Phase 2's attacks.py).
# Every pattern is matched against the percent-decoded forms so a doubly
# encoded "%252e%252e" is seen the same as "..".

_TRAVERSAL = re.compile(
    r"(?:\.\.[\\/]){2,}"                       # repeated ../ or ..\
    r"|/etc/(?:passwd|shadow)\b"               # canonical unix targets
    r"|[\\/]win(?:dows[\\/]win)?\.ini\b"       # canonical windows targets
    r"|/proc/self/(?:environ|cmdline)\b",
    re.I,
)
_SQLI = re.compile(
    r"union\s+select"
    r"|\bor\s+1\s*=\s*1\b"
    r"|'\s*or\s*'1'\s*=\s*'1"
    r"|\b(?:sleep|benchmark|pg_sleep)\s*\("
    r"|information_schema\b"
    r"|\bextractvalue\s*\(",
    re.I,
)
_PHPINFO = re.compile(r"phpinfo|\?=php[0-9a-f]{8}", re.I)
_CMS = re.compile(
    r"wp-login\.php|wp-admin|wp-includes|wp-content|xmlrpc\.php|/administrator\b",
    re.I,
)
# The "unpatched PHP" follow-up shape: a webshell/body that carries PHP source,
# or the include/wrapper knobs recent PHP RCE chains toggle. We recognise the
# shape to tag and answer it; we never act on it.
_PHP_BODY = re.compile(r"<\?php\b|<\?=|eval\s*\(|assert\s*\(", re.I)
_PHP_WRAPPER = re.compile(
    r"php://(?:filter|input)|data://|phar://|auto_prepend_file|allow_url_include",
    re.I,
)
_PHP_PATH = re.compile(r"\.php($|[/?])", re.I)


def _peeled(*texts: str) -> str:
    """One haystack: every text, plus its percent-decoded and log4j-collapsed
    forms, joined so a single regex pass sees every layer."""
    out: list[str] = []
    for text in texts:
        if not text:
            continue
        for layer in decode.url_layers(text):
            out.append(layer)
            collapsed = decode.deobfuscate_log4j(layer)
            if collapsed != layer:
                out.append(collapsed)
    return "\n".join(out)


# -- inert decoy content ----------------------------------------------------

def _fake_passwd(key: bytes) -> str:
    """A synthetic passwd-style file. The system accounts are the distro
    defaults everyone already knows (not secrets); the two app accounts are
    seed-derived names. Every shell is nologin: nothing here is real, and
    nothing here is usable."""
    app = _derive(key, "passwd-user", length=6)
    svc = _derive(key, "passwd-svc", length=6)
    lines = [
        "root:x:0:0:root:/root:/usr/sbin/nologin",
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
        f"app_{app}:x:1000:1000:app:/var/www/app:/usr/sbin/nologin",
        f"svc_{svc}:x:1001:1001:service:/nonexistent:/usr/sbin/nologin",
    ]
    return "\n".join(lines) + "\n"


def _db_error(key: bytes) -> str:
    """A generic database-error page. It hints the parameter was interpolated
    (which is what draws the follow-up) without ever running a query."""
    code = _derive(key, "sql-errno", length=4)
    return (
        "<!doctype html><html><head><title>Database Error</title></head><body>"
        "<h1>Database Error</h1>"
        "<p>Error establishing a database result.</p>"
        f"<pre>SQLSTATE[42000]: Syntax error or access violation: 1064 ({code})</pre>"
        "</body></html>"
    )


def _phpinfo(key: bytes) -> str:
    ver = "8.1." + str(int(_derive(key, "php-patch", length=2), 16) % 30)
    return (
        "<!doctype html><html><head><title>phpinfo()</title></head><body>"
        f"<h1>PHP Version {ver}</h1>"
        "<table><tr><td>System</td><td>Linux web01 5.15.0</td></tr>"
        "<tr><td>Server API</td><td>FPM/FastCGI</td></tr>"
        "<tr><td>Loaded Configuration File</td><td>/etc/php/8.1/fpm/php.ini</td></tr>"
        "</table></body></html>"
    )


def _wp_login() -> str:
    return (
        "<!doctype html><html><head><title>Log In &lsaquo; Blog &#8212; WordPress</title>"
        "</head><body class=\"login\"><div id=\"login\"><form name=\"loginform\" "
        "action=\"/wp-login.php\" method=\"post\">"
        "<label>Username or Email Address<input type=\"text\" name=\"log\"></label>"
        "<label>Password<input type=\"password\" name=\"pwd\"></label>"
        "<input type=\"submit\" value=\"Log In\"></form></div></body></html>"
    )


def _landing(key: bytes) -> str:
    rev = _derive(key, "wp-rev", length=6)
    return (
        "<!doctype html><html><head><title>Home</title>"
        "<meta name=\"generator\" content=\"WordPress 6.4.2\">"
        "</head><body><h1>Welcome</h1><p>Just another WordPress site.</p>"
        f"<!-- rev {rev} --></body></html>"
    )


def _not_found() -> str:
    return (
        "<!doctype html><html><head><title>404 Not Found</title></head><body>"
        "<h1>Not Found</h1><p>The requested URL was not found on this server.</p>"
        "</body></html>"
    )


# -- the responder ----------------------------------------------------------

def respond(
    method: str,
    path: str,
    query: str,
    content_type: str,
    body_text: str,
    key: bytes,
) -> Reply:
    """Pick the inert page for one request to the PHP face.

    Order matters: the most specific, highest-signal shapes first, so a
    traversal that also looks like a .php request is tagged as the traversal.
    Nothing here reads a real file, runs a query, or executes a body.
    """
    pq = _peeled(path, query)
    body = _peeled(body_text) if body_text else ""

    if _TRAVERSAL.search(pq):
        return Reply(
            200, "text/plain", _fake_passwd(key),
            "path_traversal",
            "read a sensitive file through path traversal (served a synthetic one)",
            ("T1083", "T1006"),
        )

    if _SQLI.search(pq) or (body and _SQLI.search(body)):
        return Reply(
            500, "text/html", _db_error(key),
            "sqli",
            "inject SQL through a request parameter (served a generic DB error)",
            ("T1190",),
        )

    # An unpatched-PHP follow-up: PHP source in the body, a dangerous wrapper,
    # or an upload aimed at a .php endpoint. Captured in full upstream; here it
    # gets an ordinary page, never confirmation that a shell was planted.
    is_upload = method == "POST" and "multipart/form-data" in content_type.lower()
    if (
        (body and _PHP_BODY.search(body))
        or _PHP_WRAPPER.search(pq)
        or (body and _PHP_WRAPPER.search(body))
        or (is_upload and _PHP_PATH.search(path))
    ):
        return Reply(
            200, "text/html", _landing(key),
            "php_rce_attempt",
            "deliver or trigger PHP code (webshell/wrapper shape; nothing executed)",
            ("T1190", "T1505.003"),
        )

    if _PHPINFO.search(pq):
        return Reply(
            200, "text/html", _phpinfo(key),
            "info_disclosure",
            "read environment through a phpinfo page (served a fake one)",
            ("T1082",),
        )

    if _CMS.search(pq):
        return Reply(
            200, "text/html", _wp_login(),
            "cms_probe",
            "probe a WordPress install for a way in",
            ("T1190", "T1133"),
        )

    # Not an attack shape we recognise: behave like an ordinary PHP site so a
    # browse or an unknown path still looks alive.
    if path in ("/", "/index.php", "/index.html"):
        return Reply(200, "text/html", _landing(key), "browse",
                     "fetch the site root", ())
    return Reply(404, "text/html", _not_found(), "browse",
                 "fetch an unmapped path", ())

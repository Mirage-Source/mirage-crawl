"""End-to-end test of the TLS front.

Generates a throwaway certificate, boots the sensor and the front, connects a
real TLS client through it, and checks that the JA4 fingerprint computed from
the ClientHello reaches the sensor's event log.
"""

from __future__ import annotations

import asyncio
import shutil
import ssl
import subprocess
import sys
import tempfile
from pathlib import Path

import aiohttp

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mirage_crawl import eventlog, ja4 as ja4mod  # noqa: E402
from mirage_crawl.config import Config  # noqa: E402
from mirage_crawl.server import build_app, start_sites  # noqa: E402
from mirage_crawl.tlsfront import Front, inject_headers  # noqa: E402

failures: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    print(f"  {'PASS' if condition else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not condition else ""))
    if not condition:
        failures.append(name)


def make_cert(directory: Path) -> tuple[str, str]:
    cert, key = directory / "cert.pem", directory / "key.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "1",
            "-subj", "/CN=docs.test.invalid",
            "-addext", "subjectAltName=DNS:docs.test.invalid",
        ],
        check=True, capture_output=True,
    )
    return str(cert), str(key)


def test_header_injection() -> None:
    print("\nheader injection")
    head = b"GET /robots.txt HTTP/1.1\r\nHost: x.test\r\nUser-Agent: bot"
    out = inject_headers(head, "t13d1516h2_aaaa_bbbb", "203.0.113.9", "X-Mirage-JA4")
    check("request line stays first", out.split(b"\r\n")[0] == b"GET /robots.txt HTTP/1.1")
    check("ja4 injected", b"X-Mirage-JA4: t13d1516h2_aaaa_bbbb" in out)
    check("xff injected", b"X-Forwarded-For: 203.0.113.9" in out)
    check("original headers kept", b"Host: x.test" in out and b"User-Agent: bot" in out)

    spoofed = (
        b"GET / HTTP/1.1\r\nHost: x.test\r\n"
        b"X-Mirage-JA4: forged\r\nX-Forwarded-For: 1.2.3.4\r\nx-real-ip: 9.9.9.9"
    )
    out2 = inject_headers(spoofed, "real_ja4", "203.0.113.9", "X-Mirage-JA4")
    check("client-supplied ja4 stripped", b"forged" not in out2)
    check("client-supplied xff stripped", b"1.2.3.4" not in out2)
    check("client-supplied x-real-ip stripped", b"9.9.9.9" not in out2)
    check("our values survive", b"real_ja4" in out2 and b"203.0.113.9" in out2)

    check("no ja4 still injects xff",
          b"X-Forwarded-For: 8.8.8.8" in inject_headers(head, None, "8.8.8.8", "X-Mirage-JA4"))


async def test_front_limits(cert: str, key: str, tmp: Path) -> None:
    print("\ntls front limits")
    log = eventlog.EventLog(tmp / "limits", "t", prefix="tls-")
    await log.start()
    front = Front(cert=cert, key=key, backend_socket=str(tmp / "nowhere.sock"), log=log,
                  hello_timeout=0.3, handshake_timeout=0.3, idle_timeout=0.3, max_connections=1)
    server = await asyncio.start_server(front.handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    loop = asyncio.get_running_loop()
    silent_r, silent_w = await asyncio.open_connection("127.0.0.1", port)
    await asyncio.sleep(0.05)
    # Over the cap: closed straight away rather than queued.
    extra_r, extra_w = await asyncio.open_connection("127.0.0.1", port)
    started = loop.time()
    extra = await asyncio.wait_for(extra_r.read(), timeout=2)
    check("connection over the cap is refused immediately", extra == b"" and loop.time() - started < 0.25)

    started = loop.time()
    silent = await asyncio.wait_for(silent_r.read(), timeout=3)
    waited = loop.time() - started
    check("silent client dropped at the hello timeout", silent == b"" and waited < 1.0, f"{waited:.2f}s")

    # A half-sent ClientHello: header promises more than ever arrives.
    slow_r, slow_w = await asyncio.open_connection("127.0.0.1", port)
    slow_w.write(b"\x16\x03\x01\x02\x00\x01")
    await slow_w.drain()
    check("slowloris hello dropped", await asyncio.wait_for(slow_r.read(), timeout=3) == b"")
    for w in (silent_w, extra_w, slow_w):
        w.close()

    server.close()
    await log.stop()
    events = list(eventlog.read_events(tmp / "limits"))
    reasons = sorted({e.get("error") for e in events})
    check("timeouts are logged with a reason", "hello_timeout" in reasons, str(reasons))
    check("refusals are logged", "over_capacity" in reasons, str(reasons))


async def run() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="mirage-tls-"))
    try:
        test_header_injection()

        cert, key = make_cert(tmp)
        cfg = Config(
            host="127.0.0.1", port=0, sensor_id="tls-test", origin="https://docs.test.invalid",
            log_dir=tmp / "events", secret_file=tmp / "secret",
            ranges_file=Path("config/crawler_ranges.json"),
            projects=4, pages_per_project=3,
            verify_identity=False, beacon_reuse_seconds=0,
            front_socket=tmp / "front.sock", admin_socket=tmp / "admin.sock",
        )
        app = build_app(cfg)
        runner = await start_sites(app, cfg)

        seen: list[tuple] = []
        tls_log = eventlog.EventLog(cfg.log_dir, "tls-test", prefix="tls-")
        await tls_log.start()
        front = Front(
            cert=cert, key=key,
            backend_socket=str(cfg.front_socket),
            log=tls_log,
            on_hello=lambda ip, fp, hello: seen.append((ip, fp, hello)),
        )
        server = await asyncio.start_server(front.handle, "127.0.0.1", 0)
        front_port = server.sockets[0].getsockname()[1]

        client_ctx = ssl.create_default_context()
        client_ctx.check_hostname = False
        client_ctx.verify_mode = ssl.CERT_NONE
        client_ctx.set_alpn_protocols(["http/1.1"])

        print("\ntls handshake through the front")
        async with aiohttp.ClientSession() as session:
            connector_url = f"https://127.0.0.1:{front_port}/robots.txt"
            async with session.get(
                connector_url, ssl=client_ctx,
                headers={"User-Agent": "Mozilla/5.0 (compatible; GPTBot/1.2)",
                         "X-Mirage-JA4": "forged-by-client"},
            ) as resp:
                status = resp.status
                body = await resp.text()

            async with session.get(
                f"https://127.0.0.1:{front_port}/api/tags", ssl=client_ctx,
                headers={"User-Agent": "python-requests/2.31.0"},
            ) as resp2:
                hunt_status = resp2.status
                hunt_body = await resp2.text()

        # A scanner that speaks plain HTTP to :443 never completes a handshake
        # and never reaches the sensor. It must still leave a record.
        reader, writer = await asyncio.open_connection("127.0.0.1", front_port)
        writer.write(b"GET / HTTP/1.0\r\n\r\n")
        await writer.drain()
        await asyncio.wait_for(reader.read(), timeout=5)
        writer.close()
        await asyncio.sleep(0.2)

        server.close()
        try:
            await asyncio.wait_for(server.wait_closed(), timeout=5)
        except asyncio.TimeoutError:
            pass
        await runner.cleanup()
        await tls_log.stop()
        await asyncio.sleep(0.3)

        check("request succeeded over TLS", status == 200, f"status {status}")
        check("robots.txt content came through", "User-agent:" in body)
        check("ClientHello was captured", len(seen) >= 1)

        fingerprints = [fp for _, fp, _ in seen if fp]
        check("ja4 computed", bool(fingerprints), str(seen[:1]))
        if fingerprints:
            fp = fingerprints[0]
            parts = fp.split("_")
            check("ja4 has three parts", len(parts) == 3, fp)
            check("ja4 part a is 10 chars", len(parts[0]) == 10, fp)
            check("ja4 alpn code is h1", parts[0].endswith("h1"), fp)

        events = list(eventlog.read_events(cfg.log_dir))
        requests = [e for e in events if e["kind"] == eventlog.EVENT_REQUEST]
        hunts = [e for e in events if e["kind"] == eventlog.EVENT_HUNT]

        with_ja4 = [r for r in requests if r.get("ja4")]
        check("ja4 reached the event log", bool(with_ja4), f"{len(requests)} requests logged")
        if with_ja4 and fingerprints:
            check("logged ja4 matches the handshake", with_ja4[0]["ja4"] == fingerprints[0],
                  f"{with_ja4[0]['ja4']} vs {fingerprints[0]}")
            check("forged client ja4 was not trusted",
                  with_ja4[0]["ja4"] != "forged-by-client")

        check("real client ip forwarded",
              bool(requests) and requests[0]["ip"] == "127.0.0.1", str(requests[:1]))

        print("\ntls event log")
        tls_files = sorted(p.name for p in Path(cfg.log_dir).glob("tls-*.jsonl"))
        check("front writes its own tls-YYYY-MM-DD.jsonl", len(tls_files) == 1, str(tls_files))
        tls_events = [e for e in events if e["kind"] == eventlog.EVENT_TLS]
        # one keep-alive TLS connection (both HTTPS requests) + the plain-HTTP attempt
        check("read_events picks up the tls file", len(tls_events) == 2, f"{len(tls_events)} tls events")
        ok = [e for e in tls_events if e.get("handshake_ok")]
        check("completed handshakes logged with ja4", bool(ok) and ok[0]["ja4"] == fingerprints[0] if fingerprints else False)
        check("tls event carries alpn and versions", bool(ok) and ok[0]["alpn"] == ["http/1.1"]
              and ok[0]["versions"], str(ok[:1]))
        plain = [e for e in tls_events if not e.get("handshake_ok")]
        check("non-TLS bytes on :443 still logged", bool(plain) and plain[0]["ja4"] is None, str(plain[:1]))
        check("non-TLS attempt records what was sent",
              bool(plain) and plain[0].get("first_bytes", "").startswith("GET / HTTP/1.0"), str(plain[:1]))

        await test_front_limits(cert, key, tmp)

        print("\nhunt probe over TLS")
        check("ollama probe served a decoy", hunt_status == 200, f"status {hunt_status}")
        check("decoy looks like a model list", "llama3" in hunt_body, hunt_body[:80])
        check("hunt event logged", len(hunts) == 1, f"{len(hunts)} hunt events")
        if hunts:
            check("hunt event carries ja4", bool(hunts[0].get("ja4")))
            check("hunt family is ollama", hunts[0]["family"] == "ollama")
            check("hunt category is llm_inference", hunts[0]["category"] == "llm_inference")

        return 1 if failures else 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    code = asyncio.run(run())
    print("\nFAILURES: " + ", ".join(failures) if failures else "\nall TLS checks passed")
    sys.exit(code)

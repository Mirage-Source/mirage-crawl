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
from aiohttp import web

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mirage_crawl import eventlog, ja4 as ja4mod  # noqa: E402
from mirage_crawl.config import Config  # noqa: E402
from mirage_crawl.server import build_app  # noqa: E402
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
            trust_proxy_header="X-Forwarded-For",
        )
        app = build_app(cfg)
        runner = web.AppRunner(app)
        await runner.setup()
        await web.TCPSite(runner, "127.0.0.1", 0).start()
        backend_port = runner.addresses[0][1]

        seen: list[tuple] = []
        front = Front(
            cert=cert, key=key,
            backend_host="127.0.0.1", backend_port=backend_port,
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

        server.close()
        try:
            await asyncio.wait_for(server.wait_closed(), timeout=5)
        except asyncio.TimeoutError:
            pass
        await runner.cleanup()
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

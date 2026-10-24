"""End-to-end: run the sensor and drive real crawler personas at it.

Each persona exercises one behaviour the instrument is supposed to be able to
tell apart, and the assertions check that the event log actually distinguishes
them. Distinct source addresses are simulated by talking to the sensor over its
front socket with X-Forwarded-For set, which is exactly what the TLS front does.
Header trust is never switched on globally: a separate block checks that the
same headers sent to the public port are ignored.
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

import aiohttp
from aiohttp import web

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mirage_crawl import eventlog, policies  # noqa: E402
from mirage_crawl.config import Config  # noqa: E402
from mirage_crawl.server import build_app, start_sites  # noqa: E402

TOKEN_RE = re.compile(r"/([A-Za-z0-9_-]{26})/")

UA_POLITE = "Mozilla/5.0 (compatible; PoliteBot/1.0; +http://example.invalid/bot)"
UA_IGNORANT = "Scrapy/2.11 (+https://scrapy.org)"
UA_DEFIANT = "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)"
UA_MINER = "Mozilla/5.0 (compatible; ClaudeBot/1.0)"
UA_READER = "Mozilla/5.0 (compatible; FleetReader/1.0)"
UA_FETCHER = "Mozilla/5.0 (compatible; FleetFetcher/1.0)"
UA_FORGER = "ForgerBot/1.0"
UA_PROXIED = "ProxiedBot/1.0"
UA_LIAR = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"


async def get(session, url, ip, ua, **kw):
    headers = {"User-Agent": ua, "X-Forwarded-For": ip}
    headers.update(kw.pop("headers", {}))
    async with session.get(url, headers=headers, **kw) as resp:
        # Keep the CIMultiDict: converting to a plain dict loses aiohttp's
        # case-insensitive lookup and 'ETag' is stored as 'Etag'.
        return resp.status, resp.headers, await resp.text()


def trap_from(body: str) -> str | None:
    match = TOKEN_RE.search(body)
    return match.group(0) if match else None


async def run() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="mirage-crawl-test-"))
    failures: list[str] = []

    try:
        cfg = Config(
            host="127.0.0.1",
            port=0,
            sensor_id="test-sensor",
            origin="http://test.invalid",
            log_dir=tmp / "events",
            secret_file=tmp / "beacon.secret",
            ranges_file=Path("config/crawler_ranges.json"),
            projects=8,
            pages_per_project=4,
            verify_identity=False,
            beacon_reuse_seconds=0,
            front_socket=tmp / "front.sock",
            admin_socket=tmp / "admin.sock",
            trust_proxy_header="X-Real-IP",
            proxy_listen="127.0.0.1:0",
        )
        app = build_app(cfg)
        runner = await start_sites(app, cfg)
        sensor = app["sensor"]
        public = f"http://127.0.0.1:{sensor.public_address[1]}"
        proxy = f"http://127.0.0.1:{sensor.proxy_address[1]}"
        base = "http://docs.test.invalid"

        # Header trust comes from the listener, never from the header itself.
        async with aiohttp.ClientSession() as pub:
            await get(pub, f"{public}/robots.txt", "6.6.6.6", UA_FORGER,
                      headers={"X-Mirage-JA4": "forged-ja4", "X-Real-IP": "6.6.6.7"})
            await get(pub, f"{proxy}/robots.txt", "6.6.6.8", UA_PROXIED,
                      headers={"X-Real-IP": "7.7.7.7", "X-Mirage-JA4": "forged-ja4"})

        front = aiohttp.UnixConnector(path=str(cfg.front_socket))
        async with aiohttp.ClientSession(connector=front) as s:
            await get(s, f"{base}/humans.txt", "10.0.0.20", UA_POLITE,
                      headers={"X-Mirage-JA4": "t13d0000h1_front_ja4"})

            # 1. Polite: reads robots.txt, crawls only allowed content.
            status, _, robots = await get(s, f"{base}/robots.txt", "10.0.0.1", UA_POLITE)
            assert status == 200, "robots.txt should serve"
            await get(s, f"{base}/docs/", "10.0.0.1", UA_POLITE)
            await get(s, f"{base}/docs/p000/00.html", "10.0.0.1", UA_POLITE)

            # 2. Ignorant: never reads robots.txt, follows the linked
            #    disallowed path anyway.
            await get(s, f"{base}/docs/", "10.0.0.2", UA_IGNORANT)
            await get(s, f"{base}{policies.STABLE_DISALLOW_LINKED}", "10.0.0.2", UA_IGNORANT)

            # 3. Defiant: reads robots.txt, then fetches a disallowed path that
            #    is reachable from a link.
            await get(s, f"{base}/robots.txt", "10.0.0.3", UA_DEFIANT)
            await get(s, f"{base}{policies.STABLE_DISALLOW_LINKED}", "10.0.0.3", UA_DEFIANT)

            # 4. Miner: reads robots.txt and fetches the unlinked beacon path,
            #    which is only knowable from that file.
            _, _, robots_miner = await get(s, f"{base}/robots.txt", "10.0.0.4", UA_MINER)
            trap = trap_from(robots_miner)
            assert trap, "robots.txt must embed a beacon path"
            miner_trap = [ln for ln in robots_miner.splitlines() if trap in ln][0]
            miner_path = miner_trap.split(":", 1)[1].strip()
            await get(s, f"{base}{miner_path}", "10.0.0.4", UA_MINER)

            # 5. Split fleet: one address reads llms.txt, a different address
            #    fetches the path it leaked.
            _, _, llms = await get(s, f"{base}/llms.txt", "10.0.0.5", UA_READER)
            match = re.search(r"http://test\.invalid(/private/llms/[A-Za-z0-9_-]{26}/context\.html)", llms)
            assert match, "llms.txt must embed a beacon path"
            await get(s, f"{base}{match.group(1)}", "10.9.9.9", UA_FETCHER)

            # 6. Conditional requests: a well-behaved refetch, and a wasteful one.
            _, headers, _ = await get(s, f"{base}/docs/p001/00.html", "10.0.0.6", UA_POLITE)
            etag = headers.get("ETag")
            assert etag, "pages must carry an ETag"
            status_304, _, _ = await get(
                s, f"{base}/docs/p001/00.html", "10.0.0.6", UA_POLITE,
                headers={"If-None-Match": etag},
            )
            status_200, _, _ = await get(s, f"{base}/docs/p001/00.html", "10.0.0.7", UA_IGNORANT)

            # 7. Liar: claims Chrome but sends almost no browser headers and
            #    never fetches the stylesheet or script.
            _, liar_headers, liar_body = await get(s, f"{base}/", "10.0.0.8", UA_LIAR)
            _, _, a_page = await get(s, f"{base}/docs/p000/00.html", "10.0.0.12", UA_LIAR)

            # 8. Every other policy surface responds.
            surface_status = {}
            for policy in policies.POLICY_FILES:
                st, _, _ = await get(s, f"{base}{policy.path}", "10.0.0.9", UA_POLITE)
                surface_status[policy.path] = st

            # 9. Unknown paths 404 without minting anything.
            st_404, _, _ = await get(s, f"{base}/no/such/page", "10.0.0.10", UA_POLITE)

            # 10. /healthz is not on the face the internet sees.
            st_health_front, _, health_front_body = await get(s, f"{base}/healthz", "10.0.0.11", UA_POLITE)
            st_unrouted, _, unrouted_body = await get(s, f"{base}/healthz-nope", "10.0.0.11", UA_POLITE)

        async with aiohttp.ClientSession() as pub:
            st_health_public, _, _ = await get(pub, f"{public}/healthz", "6.6.6.6", UA_FORGER)

        admin = aiohttp.UnixConnector(path=str(cfg.admin_socket))
        async with aiohttp.ClientSession(connector=admin) as adm:
            st_health, _, health_body = await get(adm, "http://admin/healthz", "-", "ops")
            st_admin_other, _, _ = await get(adm, "http://admin/robots.txt", "-", "ops")

        await runner.cleanup()

        # -- assertions over the event log --------------------------------
        events = list(eventlog.read_events(cfg.log_dir))
        requests = [e for e in events if e["kind"] == eventlog.EVENT_REQUEST]
        reads = [e for e in events if e["kind"] == eventlog.EVENT_POLICY_READ]
        hits = [e for e in events if e["kind"] == eventlog.EVENT_TRAP_HIT]

        def check(name: str, condition: bool, detail: str = "") -> None:
            print(f"  {'PASS' if condition else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not condition else ""))
            if not condition:
                failures.append(name)

        print("\nlistener trust")
        forged = [r for r in requests if r["ua"] == UA_FORGER]
        check("forged XFF on the public port ignored", bool(forged) and forged[0]["ip"] == "127.0.0.1",
              str(forged[:1]))
        check("forged JA4 on the public port ignored", bool(forged) and forged[0]["ja4"] is None)
        check("public requests are labelled public", bool(forged) and forged[0]["listener"] == "public")
        check("public request header order keeps the client's own XFF",
              bool(forged) and "x-forwarded-for" in forged[0]["header_order"])
        proxied = [r for r in requests if r["ua"] == UA_PROXIED]
        check("proxy header honoured on the proxy listener",
              bool(proxied) and proxied[0]["ip"] == "7.7.7.7", str(proxied[:1]))
        check("JA4 never trusted from a plain proxy", bool(proxied) and proxied[0]["ja4"] is None)
        check("proxied requests are labelled proxy", bool(proxied) and proxied[0]["listener"] == "proxy")
        via_front = [r for r in requests if r["ip"] == "10.0.0.20"]
        check("XFF kept through the front socket", len(via_front) == 1)
        check("JA4 kept through the front socket",
              bool(via_front) and via_front[0]["ja4"] == "t13d0000h1_front_ja4")
        check("front-injected headers dropped from the header order",
              bool(via_front) and "x-forwarded-for" not in via_front[0]["header_order"]
              and "x-mirage-ja4" not in via_front[0]["header_order"], str(via_front[:1]))

        print("\nevent log")
        check("requests logged", len(requests) >= 25, f"got {len(requests)}")
        check("policy reads logged", len(reads) >= 20, f"got {len(reads)}")
        check("all 18 surfaces served 200", all(v == 200 for v in surface_status.values()),
              str({k: v for k, v in surface_status.items() if v != 200}))

        print("\npolicy-read attribution")
        by_std = {r["standard"] for r in reads}
        check("robots read recorded", "robots" in by_std)
        check("llms read recorded", "llms" in by_std)
        check("tdm read recorded", "tdm_wellknown" in by_std)
        check("reads carry the minted token", all(r.get("token") for r in reads))

        print("\ntrap hits")
        miner_hits = [h for h in hits if h["ip"] == "10.0.0.4" and h["standard"] == "robots"]
        check("miner hit attributed to robots.txt", len(miner_hits) == 1)
        check("miner hit marked disallowed", bool(miner_hits and miner_hits[0]["disallowed"]))
        check("miner hit same_ip", bool(miner_hits and miner_hits[0]["same_ip"] is True))
        check("miner delay recorded", bool(miner_hits and miner_hits[0]["delay_seconds"] >= 0))

        split = [h for h in hits if h["standard"] == "llms"]
        check("split-fleet hit attributed to llms.txt", len(split) == 1)
        check("split-fleet flagged", bool(split and split[0]["split_fleet"] is True))
        check("split-fleet fetcher differs from reader",
              bool(split and split[0]["ip"] == "10.9.9.9"))

        print("\nlinked-disallowed separation")
        ignorant_reads = [r for r in reads if r["ip"] == "10.0.0.2"]
        defiant_reads = [r for r in reads if r["ip"] == "10.0.0.3"]
        restricted = [
            r for r in requests
            if r["path"] == policies.STABLE_DISALLOW_LINKED and r["status"] == 200
        ]
        check("ignorant never read a policy file", len(ignorant_reads) == 0)
        check("defiant did read robots.txt", any(r["standard"] == "robots" for r in defiant_reads))
        check("both reached the restricted page", len(restricted) == 2)

        print("\nconditional requests")
        check("conditional refetch returns 304", status_304 == 304, f"got {status_304}")
        check("unconditional refetch returns 200", status_200 == 200, f"got {status_200}")
        cond_flags = [r["conditional"] for r in requests if r["path"] == "/docs/p001/00.html"]
        check("conditional flag recorded", cond_flags.count(True) == 1 and cond_flags.count(False) == 2,
              str(cond_flags))

        print("\nfingerprinting")
        liar = [r for r in requests if r["ip"] == "10.0.0.8"]
        check("liar logged", len(liar) == 1)
        check("liar flagged as claiming browser", bool(liar and liar[0]["claims_browser"]))
        check("liar caught by thin headers",
              bool(liar and "browser_claim_thin_headers" in liar[0]["signals"]),
              str(liar[0]["signals"]) if liar else "")
        gptbot = [r for r in requests if r.get("claimed_crawler") == "GPTBot"]
        check("GPTBot recognised from UA", len(gptbot) >= 1)
        check("header order captured", bool(liar and len(liar[0]["header_order"]) >= 2))
        check("header order hashed", bool(liar and liar[0]["header_order_hash"]))

        print("\nfingerprint resistance")
        check("Server header is not the aiohttp default",
              liar_headers.get("Server") == "nginx", liar_headers.get("Server"))
        giveaways = ("mirage", "MIRAGE-CANARY", "honeypot", "decoy")
        leaked = [w for w in giveaways if w.lower() in (liar_body + a_page).lower()]
        check("no honeypot tell in served page bodies", not leaked, str(leaked))
        check("canary still present as a revision string",
              "Document revision" in a_page and "Document revision" in liar_body)

        print("\nmisc")
        check("unknown path 404s", st_404 == 404, f"got {st_404}")
        check("no trap minted for unknown path",
              not any(h["path"] == "/no/such/page" for h in hits))
        check("health ok on the admin socket", st_health == 200 and json.loads(health_body)["ok"] is True)
        check("no events dropped", json.loads(health_body)["events_dropped"] == 0)
        check("/healthz 404s on the public port", st_health_public == 404, str(st_health_public))
        check("/healthz 404s through the front", st_health_front == 404, str(st_health_front))
        check("that 404 is indistinguishable from any unrouted path",
              st_unrouted == 404 and health_front_body == unrouted_body)
        check("admin socket serves nothing but /healthz", st_admin_other == 404)
        check("admin requests are not logged as client traffic",
              not any(r.get("ua") == "ops" for r in requests))

        print(f"\n{len(events)} events across {len(list(Path(cfg.log_dir).glob('*.jsonl')))} file(s)")
        return 1 if failures else 0

    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    code = asyncio.run(run())
    print("\nFAILURES" if code else "\nall checks passed")
    sys.exit(code)

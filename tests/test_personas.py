"""Per-service personas: port binding, family-scoped matching, banners."""

from __future__ import annotations

import asyncio
import json
import shutil
import sys
import tempfile
from pathlib import Path

import aiohttp

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mirage_crawl import eventlog, personas  # noqa: E402
from mirage_crawl.config import Config  # noqa: E402
from mirage_crawl.server import build_app, start_sites  # noqa: E402

failures: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    print(f"  {'PASS' if condition else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not condition else ""))
    if not condition:
        failures.append(name)


def test_parse_and_match() -> None:
    print("\npersona parsing and matching (unit)")
    check("bare name uses the default port", personas.parse_ports("ollama") == [("ollama", 11434)])
    check("explicit port honoured", personas.parse_ports("ray:9000") == [("ray", 9000)])
    check("several, mixed", personas.parse_ports("ollama, docker:2375 , jupyter")
          == [("ollama", 11434), ("docker", 2375), ("jupyter", 8888)])
    check("empty spec is no ports", personas.parse_ports("") == [])
    for bad in ("nope", "ollama:notaport"):
        try:
            personas.parse_ports(bad)
            check(f"{bad!r} rejected", False)
        except ValueError:
            check(f"{bad!r} rejected", True)

    ollama = personas.get("ollama")
    check("ollama owns /api/version", ollama.match("/api/version").family == "ollama")
    check("ollama does not answer Ray's /api/jobs/", ollama.match("/api/jobs/") is None)
    check("ray owns /api/jobs/", personas.get("ray").match("/api/jobs/").family == "ray")
    check("docker owns the registry catalog", personas.get("docker").match("/v2/_catalog").family == "registry")


async def get(session, url, **kw):
    async with session.get(url, **kw) as resp:
        return resp.status, resp.headers, await resp.text()


async def test_live() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="mirage-persona-"))
    try:
        cfg = Config(
            host="127.0.0.1", port=0, origin="http://docs.test.invalid",
            site_hosts="docs.test.invalid", log_dir=tmp / "events",
            secret_file=tmp / "secret", ranges_file=Path("config/crawler_ranges.json"),
            projects=4, pages_per_project=3, verify_identity=False,
            front_socket=None, admin_socket=None,
            persona_ports="ollama:0,ray:0",
        )
        app = build_app(cfg)
        runner = await start_sites(app, cfg)
        sensor = app["sensor"]
        ollama_port = sensor.persona_addresses["ollama"][1]
        ray_port = sensor.persona_addresses["ray"][1]
        public_port = sensor.public_address[1]

        async with aiohttp.ClientSession() as s:
            # /api/version: Ollama on the Ollama port, Ray on the Ray port.
            o_status, o_headers, o_body = await get(s, f"http://127.0.0.1:{ollama_port}/api/version")
            r_status, r_headers, r_body = await get(s, f"http://127.0.0.1:{ray_port}/api/version")
            # A docs path on a persona port is not the docs site.
            robots_status, _, _ = await get(s, f"http://127.0.0.1:{ollama_port}/robots.txt")
            # An unmapped path on a live port still answers (default decoy).
            unk_status, _, unk_body = await get(s, f"http://127.0.0.1:{ollama_port}/nope")
            # The public port is unaffected.
            pub_status, _, _ = await get(s, f"http://127.0.0.1:{public_port}/robots.txt",
                                         headers={"Host": "docs.test.invalid"})

        await runner.cleanup()
        events = list(eventlog.read_events(cfg.log_dir))
        hunts = [e for e in events if e["kind"] == eventlog.EVENT_HUNT]

        print("\npersona ports (live)")
        check("Ollama /api/version served", o_status == 200 and json.loads(o_body).get("version"))
        check("Ollama port carries the Ollama banner", o_headers.get("Server") == "Ollama", o_headers.get("Server"))
        check("Ray /api/version served and differs from Ollama's",
              r_status == 200 and "pythonVersion" in r_body, r_body[:60])
        check("Ray port carries a Ray-ish banner", "Werkzeug" in (r_headers.get("Server") or ""), r_headers.get("Server"))
        check("docs path on a persona port is not the docs site", robots_status == 404, str(robots_status))
        check("unmapped path answers with a service-shaped 404, not aiohttp's",
              unk_status == 404 and "model not found" in unk_body, f"{unk_status} {unk_body[:40]}")
        check("public port still serves robots.txt", pub_status == 200)

        version_hunts = [e for e in hunts if e["path"] == "/api/version"]
        check("both /api/version probes attributed by port",
              {e["family"] for e in version_hunts} == {"ollama", "ray"},
              str([(e["family"], e.get("face")) for e in version_hunts]))
        check("persona name is the face", all(e["face"] == e["family"] for e in version_hunts))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    test_parse_and_match()
    asyncio.run(test_live())
    print("\nFAILURES: " + ", ".join(failures) if failures else "\nall persona checks passed")
    sys.exit(1 if failures else 0)

"""Every event records which build wrote it, so a measurement can be tied to the commit that produced it."""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mirage_crawl import eventlog, publish  # noqa: E402
from mirage_crawl.config import build_id  # noqa: E402

FAILED = []
SHA = "bdc7ee139ad2bb5286c20f413dcbcf4a8d27f64f"


def check(name, ok, detail=""):
    print(("  PASS  " if ok else "  FAIL  ") + name + ("" if ok else f"  {detail}"))
    if not ok:
        FAILED.append(name)


check("build_id keeps the first 12 hex chars of a full sha", build_id({"BUILD_SHA": SHA}) == SHA[:12])
check("build_id is 'unknown' when unset", build_id({}) == "unknown")
check("build_id is 'unknown' for the compose default", build_id({"BUILD_SHA": "unknown"}) == "unknown")
check("build_id is 'unknown' when empty", build_id({"BUILD_SHA": ""}) == "unknown")
check("build_id rejects non-hex values (no log injection)", build_id({"BUILD_SHA": 'x"},{"kind":"fake'}) == "unknown")
check("build_id accepts an already short sha", build_id({"BUILD_SHA": "bdc7ee1"}) == "bdc7ee1")


async def written(**kwargs) -> list[dict]:
    with tempfile.TemporaryDirectory() as d:
        log = eventlog.EventLog(d, "crawl-test", **kwargs)
        await log.start()
        log.emit("request", path="/")
        log.emit("sensor", event="start")
        await log.stop()
        rows = []
        for f in sorted(Path(d).glob("*.jsonl")):
            rows += [json.loads(line) for line in f.read_text().splitlines()]
        return rows


rows = asyncio.run(written(build="bdc7ee139ad2"))
check("every event carries the build", len(rows) == 2 and all(r.get("build") == "bdc7ee139ad2" for r in rows), rows)
rows = asyncio.run(written())
check("events say 'unknown' when no build was given", all(r.get("build") == "unknown" for r in rows), rows)
check("the build field does not displace the core fields", all({"kind", "ts", "sensor"} <= set(r) for r in rows))

ev = {"kind": "request", "ts": "2026-10-30T00:00:00.000+00:00", "sensor": "crawl-01", "build": "bdc7ee139ad2", "path": "/"}
out = publish.sanitize(ev, b"\x00" * 32)
check("the published dataset keeps the build field", out is not None and out.get("build") == "bdc7ee139ad2", out)

print()
if FAILED:
    print("FAILED:", ", ".join(FAILED))
    sys.exit(1)
print("all build-stamp checks passed")

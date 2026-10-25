"""Tests for scripts/export_r2.py: which days get published, and what lands.

    python tests/test_export_r2.py
"""

from __future__ import annotations

import gzip
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from mirage_crawl import beacons, policies  # noqa: E402
import export_r2  # noqa: E402

failures: list[str] = []
SECRET = b"t" * 32
SALT = "test-salt"


def check(name: str, condition: bool, detail: str = "") -> None:
    print(f"  {'PASS' if condition else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not condition else ""))
    if not condition:
        failures.append(name)


def ts(day: str, hh: int = 0) -> float:
    return datetime.fromisoformat(f"{day}T{hh:02d}:00:00+00:00").timestamp()


def write(path: Path, events: list, gz: bool = False, junk: str | None = None) -> None:
    lines = [json.dumps(e) for e in events] + ([junk] if junk else [])
    data = ("\n".join(lines) + "\n").encode()
    if gz:
        path = path.with_name(path.name + ".gz")
        path.write_bytes(gzip.compress(data))
    else:
        path.write_bytes(data)


def published(bucket: Path, key: str) -> list[dict]:
    with gzip.open(bucket / key, "rt", encoding="utf-8") as f:
        return [json.loads(line) for line in f]


beacon = beacons.mint(SECRET, "robots", "198.51.100.7", "Bot")
trap = policies.trap_path("robots", beacon)

with tempfile.TemporaryDirectory() as d:
    events, bucket = Path(d) / "events", Path(d) / "bucket"
    events.mkdir()
    write(events / "2026-10-24.jsonl", [
        {"kind": "trap_hit", "ts": "2026-10-24T10:00:00+00:00", "path": trap, "token": beacon, "split_fleet": True,
         "ip": "198.51.100.7"},
        {"kind": "request", "ts": "2026-10-24T10:00:01+00:00", "rid": "a", "path": "/", "ip": "198.51.100.7",
         "headers": [["Cookie", "sid=visitor"]], "body": None},
        # A credential from the same non-attack request must be redacted too.
        {"kind": "credential", "ts": "2026-10-24T10:00:01+00:00", "rid": "a", "ip": "198.51.100.7",
         "scheme": "form", "user": "alice", "password": "pw"},
    ], junk="{not json")
    write(events / "tls-2026-10-24.jsonl", [{"kind": "tls", "ts": "2026-10-24T10:00:00+00:00", "ja4": "t13d",
                                             "ip": "198.51.100.7"}], gz=True)
    # Unfinished day: must wait.
    write(events / "2026-10-25.jsonl", [{"kind": "request", "ts": "2026-10-25T00:10:00+00:00"}])
    # A rotation that crashed after writing the .gz but before deleting the
    # original leaves both; the plain file is the complete one.
    write(events / "2026-10-23.jsonl", [{"kind": "request", "ts": "2026-10-23T09:00:00+00:00", "n": 1},
                                        {"kind": "request", "ts": "2026-10-23T09:00:01+00:00", "n": 2}])
    write(events / "2026-10-23.jsonl", [{"kind": "request", "ts": "2026-10-23T09:00:00+00:00", "n": 1}], gz=True)
    (events / "beacon.secret").write_bytes(b"not a log")

    store = export_r2.LocalStore(bucket)
    summary = export_r2.run(events, store, SECRET, SALT, now=ts("2026-10-25", 2), lag_s=3600)

    print("which days")
    check("complete days published, unfinished day skipped",
          summary["published"] == [("events", "2026-10-23"), ("events", "2026-10-24"), ("tls", "2026-10-24")],
          summary["published"])
    check("plain file preferred over a duplicate .gz",
          [e["n"] for e in published(bucket, "crawl/events/day=2026-10-23.jsonl.gz")] == [1, 2])

    print("what lands")
    out = published(bucket, "crawl/events/day=2026-10-24.jsonl.gz")
    check("events sanitized", beacon not in json.dumps(out) and out[0]["split_fleet"] is True)
    check("gzip-rotated input read", published(bucket, "crawl/tls/day=2026-10-24.jsonl.gz")[0]["ja4"] == "t13d")
    manifest = json.loads((bucket / "crawl/manifest.json").read_text())
    entry = next(f for f in manifest["files"] if f["day"] == "2026-10-24" and f["stream"] == "events")
    check("manifest counts rows, dropped and malformed",
          (entry["rows"], entry["dropped"], entry["malformed"]) == (3, 0, 1), entry)
    published_text = json.dumps(out) + json.dumps(published(bucket, "crawl/tls/day=2026-10-24.jsonl.gz"))
    check("no raw source ip in any published stream", "198.51.100.7" not in published_text)
    check("visitor cookie and credential redacted",
          "sid=visitor" not in published_text and "alice" not in published_text)
    check("manifest has checksum and size", len(entry["sha256"]) == 64 and entry["bytes"] > 0)
    reqs = [e for e in out if e["kind"] == "request"]
    check("every published request has the classifier fields, even from before the classifier",
          all({"attacks", "tools", "oast"} <= set(e) for e in reqs), [sorted(e) for e in reqs])
    old = [e for e in published(bucket, "crawl/events/day=2026-10-23.jsonl.gz")]
    check("a legacy request gets the classifier fields too", all("attacks" in e for e in old))

    print("idempotence")
    again = export_r2.run(events, store, SECRET, SALT, now=ts("2026-10-25", 3), lag_s=3600)
    check("second run publishes nothing", again["published"] == [], again["published"])
    later = export_r2.run(events, store, SECRET, SALT, now=ts("2026-10-26", 2), lag_s=3600)
    check("next day's run publishes the newly finished day", later["published"] == [("events", "2026-10-25")])

print("secret loading")
with tempfile.TemporaryDirectory() as d:
    missing = Path(d) / "beacon.secret"
    try:
        export_r2.read_secret(missing)
        check("missing key file is an error, never a new key", False)
    except FileNotFoundError:
        check("missing key file is an error, never a new key", not missing.exists())
    missing.write_text(SECRET.hex())
    check("hex key file read", export_r2.read_secret(missing) == SECRET)

print()
if failures:
    print(f"{len(failures)} FAILED: {', '.join(failures)}")
    sys.exit(1)
print("all export checks passed")

"""Log rotation planning and that analysis still reads gzip-rotated files."""

from __future__ import annotations

import gzip
import json
import sys
import tempfile
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from mirage_crawl import eventlog  # noqa: E402
import rotate_logs  # noqa: E402

failures: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    print(f"  {'PASS' if condition else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not condition else ""))
    if not condition:
        failures.append(name)


def test_plan() -> None:
    print("\nrotation planning")
    with tempfile.TemporaryDirectory() as t:
        d = Path(t)
        for name in ("2026-10-24.jsonl", "2026-10-22.jsonl", "2026-07-01.jsonl",
                     "tls-2026-10-22.jsonl", "2026-10-23.jsonl.gz", "notes.txt"):
            (d / name).write_text("{}\n")
        today = date(2026, 10, 24)
        to_compress, to_delete = rotate_logs.plan(d, compress_after=2, delete_after=90, today=today)
        cnames = {p.name for p in to_compress}
        dnames = {p.name for p in to_delete}

        check("today is never compressed", "2026-10-24.jsonl" not in cnames)
        check("a 2-day-old file is compressed", "2026-10-22.jsonl" in cnames)
        check("prefixed (tls) files rotate too", "tls-2026-10-22.jsonl" in cnames)
        check("already-gz is not re-compressed", "2026-10-23.jsonl.gz" not in cnames)
        check("non-log file ignored", "notes.txt" not in cnames and "notes.txt" not in dnames)
        check("old file past delete window is deleted", "2026-07-01.jsonl" in dnames)
        check("deleted files are not also compressed", dnames.isdisjoint(cnames))

        # delete_after=-1 disables deletion
        _, none_deleted = rotate_logs.plan(d, compress_after=2, delete_after=-1, today=today)
        check("delete disabled by -1", none_deleted == [])


def test_gzip_roundtrip_read() -> None:
    print("\ngzip-rotated logs still read")
    with tempfile.TemporaryDirectory() as t:
        d = Path(t)
        plain = {"kind": "request", "ts": "2026-10-24T10:00:00Z", "actor": "A", "path": "/a"}
        rolled = {"kind": "request", "ts": "2026-10-23T10:00:00Z", "actor": "B", "path": "/b"}
        (d / "2026-10-24.jsonl").write_text(json.dumps(plain) + "\n")
        with gzip.open(d / "2026-10-23.jsonl.gz", "wt") as fh:
            fh.write(json.dumps(rolled) + "\n")

        events = list(eventlog.read_events(d))
        check("both plain and gz events are read", len(events) == 2, str(len(events)))
        # Oldest day first: the gz'd 10-23 must precede the plain 10-24.
        check("ordering by day survives rotation",
              [e["actor"] for e in events] == ["B", "A"], str([e.get("actor") for e in events]))


if __name__ == "__main__":
    test_plan()
    test_gzip_roundtrip_read()
    print("\nFAILURES: " + ", ".join(failures) if failures else "\nall rotation checks passed")
    sys.exit(1 if failures else 0)

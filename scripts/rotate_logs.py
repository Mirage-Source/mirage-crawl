#!/usr/bin/env python3
"""Compress and expire old event-log files.

The sensor already rolls one file per UTC day and never rewrites it, so there
is nothing to rotate in the hot path -- this is pure housekeeping run from a
timer. It gzips days older than --compress-after (a day is closed once a newer
day exists, so today is never touched) and deletes days older than --delete-
after. Keeping it out of the sensor preserves the "no external dependency in
the request path" property: if this never runs, the only cost is disk.

    python3 scripts/rotate_logs.py data/events --compress-after 2 --delete-after 90

Both windows count whole UTC days from today. The TLS front's prefixed files
(tls-YYYY-MM-DD.jsonl) are handled the same way.
"""

from __future__ import annotations

import argparse
import gzip
import re
import shutil
import sys
from datetime import date, datetime, timezone
from pathlib import Path

# A log file is <optional-prefix>YYYY-MM-DD.jsonl (optionally already .gz).
_DAY_RE = re.compile(r"(\d{4})-(\d{2})-(\d{2})\.jsonl(\.gz)?$")


def _file_day(path: Path) -> date | None:
    m = _DAY_RE.search(path.name)
    if not m:
        return None
    try:
        return date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return None


def plan(directory: Path, compress_after: int, delete_after: int, today: date):
    """Return (to_compress, to_delete) lists without touching disk.

    Separated from the action so the behaviour is unit-testable and
    --dry-run is exact.
    """
    to_compress: list[Path] = []
    to_delete: list[Path] = []
    for path in sorted(directory.glob("*.jsonl*")):
        day = _file_day(path)
        if day is None:
            continue
        age = (today - day).days
        if delete_after >= 0 and age > delete_after:
            to_delete.append(path)
        elif compress_after >= 0 and age >= compress_after and path.suffix != ".gz":
            to_compress.append(path)
    return to_compress, to_delete


def _compress(path: Path) -> Path:
    gz = path.with_suffix(path.suffix + ".gz")
    with open(path, "rb") as src, gzip.open(gz, "wb") as dst:
        shutil.copyfileobj(src, dst)
    path.unlink()
    return gz


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mirage-crawl-rotate-logs")
    parser.add_argument("log_dir", nargs="?", default="data/events")
    parser.add_argument("--compress-after", type=int, default=2,
                        help="gzip files older than this many days (-1 disables)")
    parser.add_argument("--delete-after", type=int, default=-1,
                        help="delete files older than this many days (-1 disables, the default)")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    directory = Path(args.log_dir)
    if not directory.is_dir():
        print(f"no such directory: {directory}", file=sys.stderr)
        return 1

    today = datetime.now(timezone.utc).date()
    to_compress, to_delete = plan(directory, args.compress_after, args.delete_after, today)

    for path in to_delete:
        print(f"{'would delete' if args.dry_run else 'delete'}  {path.name}")
        if not args.dry_run:
            path.unlink()
    for path in to_compress:
        print(f"{'would compress' if args.dry_run else 'compress'}  {path.name}")
        if not args.dry_run:
            _compress(path)
    if not to_compress and not to_delete:
        print("nothing to do")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

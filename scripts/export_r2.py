"""Publish finished days of the event log, sanitized, to Cloudflare R2.

Each run uploads every complete UTC day not yet in crawl/manifest.json:

    crawl/events/day=2026-10-24.jsonl.gz    sensor events (request, policy_read, ...)
    crawl/tls/day=2026-10-24.jsonl.gz       TLS-front events (JA4)
    crawl/manifest.json

Every event goes through mirage_crawl.publish.sanitize first: beacon tokens and
honeytokens never leave the box, and an event that can't be cleaned is dropped
and counted in the manifest. Output stays JSON lines rather than Parquet
because event kinds differ in shape and the instrument is still changing;
DuckDB and pandas read gzipped JSON lines directly.

Reads the log volume and the beacon key; writes nothing on the box. The key is
only ever read: this must never call Config.load_secret, which creates a new
key when the file is missing and would orphan every token already served.

    python scripts/export_r2.py --events /app/data/events --secret-file /app/data/beacon.secret
    python scripts/export_r2.py ... --out-dir /tmp/bucket      # local, no R2
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mirage_crawl.config import _parse_secret  # noqa: E402
from mirage_crawl.publish import anonymize, attacked, sanitize  # noqa: E402

PREFIX = "crawl"
MANIFEST = f"{PREFIX}/manifest.json"
DAY_S = 86400
_FILE_RE = re.compile(r"^(tls-)?(\d{4}-\d{2}-\d{2})\.jsonl(\.gz)?$")


class LocalStore:
    def __init__(self, root: Path):
        self.root = Path(root)

    def get(self, key: str) -> bytes | None:
        p = self.root / key
        return p.read_bytes() if p.exists() else None

    def put(self, key: str, local: Path, content_type: str, immutable: bool) -> None:
        dest = self.root / key
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(local, dest)


class R2Store:
    def __init__(self, account_id: str, access_key_id: str, secret_access_key: str, bucket: str):
        import boto3

        self.bucket = bucket
        self.s3 = boto3.client(
            "s3", endpoint_url=f"https://{account_id}.r2.cloudflarestorage.com",
            aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key, region_name="auto",
        )

    def get(self, key: str) -> bytes | None:
        try:
            return self.s3.get_object(Bucket=self.bucket, Key=key)["Body"].read()
        except self.s3.exceptions.NoSuchKey:
            return None

    def put(self, key: str, local: Path, content_type: str, immutable: bool) -> None:
        cache = "public, max-age=31536000, immutable" if immutable else "public, max-age=300"
        self.s3.upload_file(str(local), self.bucket, key,
                            ExtraArgs={"ContentType": content_type, "CacheControl": cache})


def read_secret(path: Path) -> bytes:
    """The beacon key, read-only. A missing file is an error, never a new key."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"{path} not found; refusing to run without the sensor's own key")
    return _parse_secret(path.read_bytes(), path)


def day_files(events_dir: Path) -> dict[tuple[str, str], Path]:
    """(stream, day) -> file. A plain .jsonl wins over a .gz of the same day: a
    rotation that died between writing the .gz and deleting the original
    leaves the plain file as the complete copy."""
    found: dict[tuple[str, str], Path] = {}
    for path in sorted(Path(events_dir).iterdir()):
        m = _FILE_RE.match(path.name)
        if not m:
            continue
        key = ("tls" if m.group(1) else "events", m.group(2))
        if key not in found or not m.group(3):
            found[key] = path
    return found


def _lines(path: Path):
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as f:
        yield from f


def _events(path: Path):
    for line in _lines(path):
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            yield None


def export_day(path: Path, secret: bytes, salt: str, out: Path) -> dict:
    # First pass: which requests are attacks, so a credential event can follow
    # its request's verdict (it carries the rid, not the attack labels).
    attack_rids = {e["rid"] for e in _events(path)
                   if isinstance(e, dict) and e.get("kind") == "request" and e.get("rid") and attacked(e)}
    rows = dropped = malformed = 0
    with gzip.GzipFile(out, "wb", mtime=0) as gz:
        for event in _events(path):
            if event is None:
                malformed += 1
                continue
            clean = sanitize(event, secret) if isinstance(event, dict) else None
            if clean is None:
                dropped += 1
                continue
            clean = anonymize(clean, salt, attack_rids)
            gz.write((json.dumps(clean, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8"))
            rows += 1
    return {"rows": rows, "dropped": dropped, "malformed": malformed}


def run(events_dir: Path, store, secret: bytes, salt: str, now: float, lag_s: float) -> dict:
    raw = store.get(MANIFEST)
    manifest = json.loads(raw) if raw else {"format": 1, "files": []}
    done = {(f["stream"], f["day"]) for f in manifest["files"]}
    summary = {"published": []}

    for (stream, day), path in sorted(day_files(events_dir).items(), key=lambda kv: (kv[0][1], kv[0][0])):
        day_end = datetime.fromisoformat(day).replace(tzinfo=timezone.utc).timestamp() + DAY_S
        if (stream, day) in done or day_end + lag_s > now:
            continue
        key = f"{PREFIX}/{stream}/day={day}.jsonl.gz"
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "day.jsonl.gz"
            counts = export_day(path, secret, salt, out)
            data = out.read_bytes()
            # Data first, then the manifest that lists it.
            store.put(key, out, "application/gzip", immutable=True)
            manifest["files"] = [f for f in manifest["files"] if f["path"] != key] + [{
                "stream": stream, "day": day, "path": key, **counts,
                "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                "exported_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }]
            manifest["files"].sort(key=lambda f: (f["stream"], f["day"]))
            manifest["updated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            mpath = Path(tmp) / "manifest.json"
            mpath.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
            store.put(MANIFEST, mpath, "application/json", immutable=False)
        summary["published"].append((stream, day))
        print(f"{stream} {day}: {counts['rows']} events, {counts['dropped']} dropped, "
              f"{counts['malformed']} malformed, {len(data)} bytes", file=sys.stderr, flush=True)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--events", required=True, type=Path)
    parser.add_argument("--secret-file", required=True, type=Path)
    parser.add_argument("--out-dir", type=Path, help="write here instead of R2")
    parser.add_argument("--lag-minutes", type=float, default=60,
                        help="wait this long after midnight UTC before a day counts as finished")
    args = parser.parse_args()

    # Never publish raw addresses: no salt, no export. Same salt as mirage-core
    # so the two datasets join on hashed IP.
    salt = os.environ.get("IP_SALT")
    if not salt:
        parser.error("IP_SALT must be set to anonymize IPs")

    if args.out_dir:
        store = LocalStore(args.out_dir)
    else:
        missing = [k for k in ("R2_ACCOUNT_ID", "R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY", "R2_BUCKET")
                   if not os.environ.get(k)]
        if missing:
            parser.error(f"set {', '.join(missing)} or pass --out-dir")
        store = R2Store(os.environ["R2_ACCOUNT_ID"], os.environ["R2_ACCESS_KEY_ID"],
                        os.environ["R2_SECRET_ACCESS_KEY"], os.environ["R2_BUCKET"])

    summary = run(args.events, store, read_secret(args.secret_file), salt, time.time(), args.lag_minutes * 60)
    print(f"done: published {len(summary['published'])} day files", file=sys.stderr)


if __name__ == "__main__":
    main()

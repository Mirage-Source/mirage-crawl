"""Crawl digest: windowing, aggregation, follow-up list, report rendering."""

from __future__ import annotations

import json
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import digest  # noqa: E402

failures: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    print(f"  {'PASS' if condition else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not condition else ""))
    if not condition:
        failures.append(name)


def _ts(days_ago: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write(tmp: Path, events: list[dict]) -> Path:
    d = tmp / "events"
    d.mkdir()
    with open(d / "2026-10-24.jsonl", "w") as fh:
        for e in events:
            fh.write(json.dumps(e) + "\n")
    return d


def test_digest() -> None:
    print("\ncrawl digest")
    events = [
        # Recent attacker (1 day ago) that reached payload.
        {"kind": "hunt", "ts": _ts(1), "actor": "RECENT", "actor_basis": "header_order",
         "ip": "2.2.2.2", "face": "php", "family": "php", "web_attack": "sqli",
         "mitre": ["T1190"], "path": "/x.php",
         "indicators": {"wallets": {"monero": ["48abc"]}, "urls": ["http://evil/x"], "miners": ["xmrig"]}},
        {"kind": "request", "ts": _ts(1), "actor": "RECENT", "actor_basis": "header_order",
         "ip": "2.2.2.2", "face": "php", "path": "/x.php"},
        # Recent benign crawler.
        {"kind": "policy_read", "ts": _ts(0.5), "actor": "CRAWLER", "actor_basis": "ja4",
         "ip": "1.1.1.1", "face": "docs", "standard": "robots"},
        {"kind": "request", "ts": _ts(0.5), "actor": "CRAWLER", "actor_basis": "ja4",
         "ip": "1.1.1.1", "face": "docs", "path": "/robots.txt"},
        # OLD attacker (10 days ago) — must be excluded from a 3-day window.
        {"kind": "hunt", "ts": _ts(10), "actor": "OLD", "actor_basis": "header_order",
         "ip": "9.9.9.9", "face": "ray", "family": "ray", "decoy_served": True, "path": "/api/jobs/"},
    ]
    with tempfile.TemporaryDirectory() as t:
        log = _write(Path(t), events)
        d = digest.build_digest(log, days=3)

        check("old session excluded from window", d["totals"]["actor_sessions"] == 2,
              str(d["totals"]["actor_sessions"]))
        check("payload stage counted", d["by_stage"].get("payload") == 1, str(d["by_stage"]))
        check("wallet aggregated", d["indicators"]["wallets"].get("monero") == ["48abc"])
        check("miner aggregated", d["indicators"]["miners"] == ["xmrig"])
        check("sqli tagged", d["web_attacks"].get("sqli") == 1)
        check("follow-up lists the payload actor only",
              [f["actor"] for f in d["follow_up"]] == ["RECENT"], str([f["actor"] for f in d["follow_up"]]))
        check("follow-up flags PAYLOAD", d["follow_up"][0]["indicators"] is True)

        report = digest.render_report(d)
        check("report has a Follow up section", "## Follow up on" in report)
        check("report names the payload actor", "RECENT"[:12] in report)
        check("report is non-trivial markdown", report.startswith("# mirage-crawl digest"))


if __name__ == "__main__":
    test_digest()
    print("\nFAILURES: " + ", ".join(failures) if failures else "\nall digest checks passed")
    sys.exit(1 if failures else 0)

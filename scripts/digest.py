#!/usr/bin/env python3
"""Compact, publishable digest of the HTTP sensor over a recent window.

This is the crawl-side equivalent of mirage-core's published dataset: it turns
the raw event log into a small summary.json + REPORT.md that can be committed
to gh-pages and read by the periodic cross-sensor digest. It is cheap by
construction -- crawl's log is flat JSONL, no database -- and it ships only
aggregates plus a bounded "follow up on" list, never the raw traffic.

    python3 scripts/digest.py data/events --days 3 --out-dir out/

Windowing is by event timestamp: only sessions last seen within --days are
summarised, so a digest run every few days reports that slice.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mirage_crawl import sessions as sess  # noqa: E402

# How many items to keep in any "top N" / follow-up list in the published
# summary. Keeps the artifact small and the report skimmable.
TOP = 15


def _within(last_seen: str | None, cutoff: str) -> bool:
    return bool(last_seen) and last_seen >= cutoff


def build_digest(log_dir: str | Path, days: int) -> dict:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    alls = sess.build_sessions(log_dir)
    windowed = [s for s in alls.values() if _within(s.last_seen, cutoff)]

    stage_counts = Counter(s.stage_reached for s in windowed)
    face_counts: Counter = Counter()
    family_counts: Counter = Counter()
    attack_counts: Counter = Counter()
    wallets: dict[str, set[str]] = {}
    pools: set[str] = set()
    urls: set[str] = set()
    miners: set[str] = set()
    mitre: set[str] = set()
    creds = 0
    for s in windowed:
        face_counts.update(s.faces)
        family_counts.update(s.families)
        attack_counts.update(s.web_attacks)
        for cur, addrs in s.wallets.items():
            wallets.setdefault(cur, set()).update(addrs)
        pools |= s.pools; urls |= s.payload_urls; miners |= s.miners; mitre |= s.mitre
        creds += s.credential_attempts

    # The follow-up list: anything that got past pure recon, most-advanced first.
    rank = sess._STAGE_RANK
    notable = sorted(
        (s for s in windowed if rank[s.stage_reached] >= rank["decoy_served"]),
        key=lambda s: (rank[s.stage_reached], s.event_count), reverse=True,
    )[:TOP]

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "window_days": days,
        "since": cutoff,
        "sensor": "mirage-crawl (HTTP)",
        "totals": {
            "actor_sessions": len(windowed),
            "events": sum(s.event_count for s in windowed),
            "requests": sum(s.request_count for s in windowed),
            "credential_attempts": creds,
        },
        "by_stage": dict(stage_counts),
        "by_face": dict(face_counts.most_common()),
        "hunt_families": dict(family_counts.most_common(TOP)),
        "web_attacks": dict(attack_counts.most_common()),
        "indicators": {
            "wallets": {k: sorted(v) for k, v in wallets.items()},
            "pools": sorted(pools),
            "payload_urls": sorted(urls)[:TOP],
            "miners": sorted(miners),
            "mitre": sorted(mitre),
        },
        "follow_up": [
            {
                "actor": s.actor, "stage": s.stage_reached, "basis": s.actor_basis,
                "ips": sorted(s.ips), "families": sorted(s.families),
                "web_attacks": sorted(s.web_attacks),
                "indicators": bool(s.wallets or s.pools or s.payload_urls or s.miners),
                "credential_attempts": s.credential_attempts,
                "first_seen": s.first_seen, "last_seen": s.last_seen,
                "user_agents": sorted(s.user_agents)[:3],
            }
            for s in notable
        ],
    }


def render_report(d: dict) -> str:
    t = d["totals"]
    out: list[str] = []
    out.append(f"# mirage-crawl digest — last {d['window_days']} days")
    out.append("")
    out.append(f"_Generated {d['generated_at']} · window since {d['since']}_")
    out.append("")
    out.append(f"**{t['actor_sessions']} actor sessions**, {t['events']} events, "
               f"{t['requests']} requests, {t['credential_attempts']} credential attempts.")
    out.append("")
    out.append("## By stage")
    for stage in sess.STAGES:
        if d["by_stage"].get(stage):
            out.append(f"- `{stage}`: {d['by_stage'][stage]}")
    out.append("")
    if d["by_face"]:
        out.append("## By face / persona")
        for face, n in d["by_face"].items():
            out.append(f"- {face}: {n}")
        out.append("")
    if d["hunt_families"]:
        out.append("## Compute-hijack probes (families)")
        for fam, n in d["hunt_families"].items():
            out.append(f"- {fam}: {n}")
        out.append("")
    ind = d["indicators"]
    if any(ind.values()):
        out.append("## Extracted indicators")
        if ind["wallets"]:
            out.append(f"- wallets: {ind['wallets']}")
        if ind["pools"]:
            out.append(f"- mining pools: {', '.join(ind['pools'])}")
        if ind["miners"]:
            out.append(f"- miner binaries: {', '.join(ind['miners'])}")
        if ind["payload_urls"]:
            out.append("- payload URLs:")
            out.extend(f"  - `{u}`" for u in ind["payload_urls"])
        if d["web_attacks"]:
            out.append(f"- web-attack shapes: {d['web_attacks']}")
        if ind["mitre"]:
            out.append(f"- MITRE: {', '.join(ind['mitre'])}")
        out.append("")
    out.append("## Follow up on")
    if not d["follow_up"]:
        out.append("_Nothing past recon this window._")
    for f in d["follow_up"]:
        bits = [f"**{f['stage']}**", f"ips={f['ips']}"]
        if f["families"]:
            bits.append(f"families={f['families']}")
        if f["web_attacks"]:
            bits.append(f"attacks={f['web_attacks']}")
        if f["indicators"]:
            bits.append("PAYLOAD")
        if f["credential_attempts"]:
            bits.append(f"creds×{f['credential_attempts']}")
        out.append(f"- `{f['actor'][:12]}` — " + ", ".join(bits))
    out.append("")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="mirage-crawl-digest")
    ap.add_argument("log_dir", nargs="?", default="data/events")
    ap.add_argument("--days", type=int, default=3)
    ap.add_argument("--out-dir", default="")
    args = ap.parse_args(argv)

    d = build_digest(args.log_dir, args.days)
    report = render_report(d)

    if args.out_dir:
        out = Path(args.out_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "summary.json").write_text(json.dumps(d, indent=2))
        (out / "REPORT.md").write_text(report)
        print(f"wrote {out/'summary.json'} and {out/'REPORT.md'}")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

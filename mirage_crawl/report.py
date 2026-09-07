"""Command-line report over a captured event log.

    python -m mirage_crawl.report data/events
    python -m mirage_crawl.report data/events --json > profiles.json
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from . import eventlog
from .classify import build_profiles, standard_matrix

STATE_ORDER = ("miner", "defiant", "ignorant", "compliant", "indeterminate")


def _bar(value: int, total: int, width: int = 22) -> str:
    if total <= 0:
        return " " * width
    filled = round(width * value / total)
    return "#" * filled + "." * (width - filled)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mirage-crawl-report")
    parser.add_argument("log_dir", nargs="?", default="data/events")
    parser.add_argument("--json", action="store_true", help="emit profiles as JSON")
    parser.add_argument("--min-requests", type=int, default=1)
    args = parser.parse_args(argv)

    log_dir = Path(args.log_dir)
    if not log_dir.exists():
        print(f"no event log at {log_dir}")
        return 1

    profiles = {
        k: v for k, v in build_profiles(log_dir).items() if v.requests >= args.min_requests
    }

    if args.json:
        print(json.dumps([p.as_dict() for p in profiles.values()], indent=2))
        return 0

    events = list(eventlog.read_events(log_dir))
    kinds = Counter(e.get("kind") for e in events)
    reads = [e for e in events if e.get("kind") == eventlog.EVENT_POLICY_READ]
    hits = [e for e in events if e.get("kind") == eventlog.EVENT_TRAP_HIT]

    print("=" * 74)
    print("MIRAGE CRAWL SENSOR")
    print("=" * 74)
    print(f"events        {len(events)}  ({', '.join(f'{k}={v}' for k, v in kinds.most_common())})")
    print(f"clients       {len(profiles)}")
    print(f"policy reads  {len(reads)}")
    print(f"trap hits     {len(hits)}")

    print("\n" + "-" * 74)
    print("COMPLIANCE")
    print("-" * 74)
    states = Counter(p.state for p in profiles.values())
    total = sum(states.values()) or 1
    for state in STATE_ORDER:
        count = states.get(state, 0)
        print(f"  {state:14s} {count:5d}  {_bar(count, total)}  {count / total:5.1%}")

    print("\n" + "-" * 74)
    print("WHICH STANDARD DID EACH CLIENT READ")
    print("-" * 74)
    matrix = standard_matrix(profiles)
    all_standards = sorted({s for row in matrix.values() for s in row})
    if not all_standards:
        print("  no policy reads recorded yet")
    else:
        header = "  " + "client".ljust(26) + "".join(s[:11].ljust(12) for s in all_standards)
        print(header)
        for client in sorted(matrix, key=lambda c: -sum(matrix[c].values())):
            row = matrix[client]
            cells = "".join(("yes" if row.get(s) else "-").ljust(12) for s in all_standards)
            print("  " + client[:25].ljust(26) + cells)

    print("\n" + "-" * 74)
    print("IDENTITY")
    print("-" * 74)
    verdicts = Counter(p.identity_verdict or "unchecked" for p in profiles.values())
    for verdict, count in verdicts.most_common():
        print(f"  {verdict:16s} {count}")
    liars = [p for p in profiles.values() if p.identity_verdict == "impersonating"]
    for p in liars:
        print(f"    ! {p.claimed_crawler} from {sorted(p.addresses)[:3]} — {p.identity_detail}")

    print("\n" + "-" * 74)
    print("SPLIT FLEETS  (policy read by one address, trap fetched by another)")
    print("-" * 74)
    split = [p for p in profiles.values() if p.split_fleet_hits]
    if not split:
        print("  none observed")
    for p in sorted(split, key=lambda x: -x.split_fleet_hits):
        print(f"  {(p.claimed_crawler or p.user_agent)[:44]:46s} hits={p.split_fleet_hits:4d} fleet={len(p.addresses)}")

    print("\n" + "-" * 74)
    print("WASTE  (repeat fetches with no conditional header)")
    print("-" * 74)
    wasteful = [p for p in profiles.values() if p.repeat_fetches]
    if not wasteful:
        print("  no repeat fetches observed yet")
    for p in sorted(wasteful, key=lambda x: -x.wasteful_refetches)[:15]:
        print(
            f"  {(p.claimed_crawler or p.user_agent)[:40]:42s} "
            f"repeat={p.repeat_fetches:5d} wasteful={p.wasteful_refetches:5d} "
            f"({p.waste_ratio:.0%})  dup-content={p.duplicate_content_fetches}"
        )

    print("\n" + "-" * 74)
    print("CAPABILITY  (does the client do what its user agent implies?)")
    print("-" * 74)
    print("  " + "client".ljust(42) + "js    css   hidden nofollow noai")
    for p in sorted(profiles.values(), key=lambda x: -x.requests)[:20]:
        flag = lambda b: ("yes" if b else "-").ljust(6)  # noqa: E731
        print(
            "  " + (p.claimed_crawler or p.user_agent)[:40].ljust(42)
            + flag(p.executes_js) + flag(p.loads_css) + flag(p.follows_hidden)
            + flag(p.follows_nofollow) + flag(p.ignores_meta_noai)
        )

    print("\n" + "-" * 74)
    print("COMPUTE-HIJACK RECONNAISSANCE")
    print("-" * 74)
    hunters = [p for p in profiles.values() if p.is_hunter]
    hunt_events = [e for e in events if e.get("kind") == eventlog.EVENT_HUNT]
    if not hunters:
        print("  no probes for exposed compute observed")
    else:
        print(f"  {len(hunters)} client(s), {len(hunt_events)} probes")
        by_category = Counter(c for p in hunters for c in p.hunt_categories)
        for category, count in by_category.most_common():
            print(f"    {category:18s} {count} client(s)")

        print("\n  most probed targets")
        for family, count in Counter(e.get("family") for e in hunt_events).most_common(10):
            print(f"    {family:18s} {count}")

        print("\n  clients")
        for p in sorted(hunters, key=lambda x: -x.hunt_probes)[:12]:
            print(
                f"    {(p.claimed_crawler or p.user_agent)[:32]:34s} "
                f"probes={p.hunt_probes:4d}  {','.join(sorted(p.hunt_categories))[:36]}"
            )

    indicators = [
        p for p in profiles.values() if p.wallets or p.pools or p.miners or p.payload_urls
    ]
    if indicators:
        print("\n  HARD INDICATORS EXTRACTED FROM PAYLOADS")
        for p in indicators:
            print(f"    {(p.claimed_crawler or p.user_agent)[:44]}")
            for currency, addresses in sorted(p.wallets.items()):
                for address in sorted(addresses):
                    print(f"      wallet {currency:9s} {address}")
            for pool in sorted(p.pools):
                print(f"      pool             {pool}")
            for miner in sorted(p.miners):
                print(f"      miner            {miner}")
            for url in sorted(p.payload_urls)[:5]:
                print(f"      url              {url}")
        techniques = sorted({t for p in indicators for t in p.mitre})
        if techniques:
            print(f"\n    MITRE: {', '.join(techniques)}")

    ja4s = Counter(j for p in profiles.values() for j in p.ja4)
    if ja4s:
        print("\n" + "-" * 74)
        print("TLS FINGERPRINTS  (JA4)")
        print("-" * 74)
        for fingerprint, count in ja4s.most_common(12):
            claimants = sorted(
                {
                    (p.claimed_crawler or p.user_agent)[:30]
                    for p in profiles.values()
                    if fingerprint in p.ja4
                }
            )
            note = "   <- one TLS stack, several claimed identities" if len(claimants) > 1 else ""
            print(f"  {fingerprint:42s} {count}{note}")
            if len(claimants) > 1:
                for claimant in claimants[:6]:
                    print(f"      {claimant}")

    print("\n" + "-" * 74)
    print("TOP CLIENTS")
    print("-" * 74)
    for p in sorted(profiles.values(), key=lambda x: -x.requests)[:15]:
        mark = " [hunter]" if p.is_hunter else ""
        print(
            f"  {p.requests:6d}  {p.state:13s} fleet={len(p.addresses):3d}  "
            f"{(p.claimed_crawler or p.user_agent)[:36]}{mark}"
        )
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

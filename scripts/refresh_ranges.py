"""Refresh published crawler IP ranges into config/crawler_ranges.json.

    python scripts/refresh_ranges.py

Reads the `sources` map from the config file, fetches each published list, and
writes the merged CIDR blocks back into `operators`. Operators whose fetch
fails keep whatever blocks were already on disk, because an empty list is
worse than a stale one: absent ranges give `unverifiable`, but a partial list
gives false `impersonating` verdicts for the addresses it omits.

Every published list seen so far uses the same shape as Google's:

    {"prefixes": [{"ipv4Prefix": "..."}, {"ipv6Prefix": "..."}]}

Anything else is skipped with a warning rather than guessed at.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

CONFIG = Path(__file__).resolve().parents[1] / "config" / "crawler_ranges.json"
TIMEOUT = 20
UA = "mirage-crawl range refresher (research sensor)"


def extract(payload: dict) -> list[str]:
    out: list[str] = []
    prefixes = payload.get("prefixes")
    if isinstance(prefixes, list):
        for entry in prefixes:
            if not isinstance(entry, dict):
                continue
            for key in ("ipv4Prefix", "ipv6Prefix", "ipv4prefix", "ipv6prefix", "prefix"):
                value = entry.get(key)
                if isinstance(value, str):
                    out.append(value)
    return out


def fetch(url: str) -> list[str]:
    request = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return extract(json.loads(response.read().decode("utf-8")))


def main() -> int:
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    sources = config.get("sources", {})
    operators = dict(config.get("operators", {}))

    changed = 0
    for operator, urls in sources.items():
        collected: list[str] = []
        for url in urls:
            try:
                found = fetch(url)
            except (urllib.error.URLError, json.JSONDecodeError, OSError) as exc:
                print(f"  {operator:12s} {url}  FAILED ({exc.__class__.__name__})")
                continue
            if not found:
                print(f"  {operator:12s} {url}  no prefixes found (unexpected shape)")
                continue
            print(f"  {operator:12s} {url}  {len(found)} prefixes")
            collected.extend(found)

        if collected:
            merged = sorted(set(collected))
            if operators.get(operator) != merged:
                changed += 1
            operators[operator] = merged
        elif operator in operators:
            print(f"  {operator:12s} keeping {len(operators[operator])} existing prefixes")

    config["operators"] = operators
    CONFIG.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")

    total = sum(len(v) for v in operators.values())
    print(f"\n{len(operators)} operators, {total} prefixes, {changed} updated -> {CONFIG}")
    if not operators:
        print("\nNo ranges loaded. Every cidr-verified crawler will report `unverifiable`.")
        print("Check the source URLs in the config file — operators move them.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

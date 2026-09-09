"""Turn the raw event log into per-client compliance profiles.

The central judgement is a four-way split, and the reason it needs beacons
rather than an access log is that two of the four are indistinguishable
otherwise:

    compliant  read a policy file, fetched nothing disallowed
    ignorant   never read a policy file, fetched disallowed content
    defiant    read a policy file, then fetched disallowed content anyway
    miner      read a policy file and used it as a source of URLs, fetching a
               path that appears in that file and nowhere else

Without a beacon you cannot separate *ignorant* from *defiant* — both look
like "fetched a disallowed path" — and you cannot see *miner* at all, because
a miner's requests are indistinguishable from ordinary crawling unless you
planted the URL yourself.

Clients are keyed by (user agent, claimed crawler) rather than by address, so
an operator rotating through a fleet aggregates into one profile. The set of
addresses is kept on the profile so fleet size is visible.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from . import eventlog

STATE_COMPLIANT = "compliant"
STATE_IGNORANT = "ignorant"
STATE_DEFIANT = "defiant"
STATE_MINER = "miner"
STATE_INDETERMINATE = "indeterminate"

# Beacons that prove capability rather than policy reading.
CAPABILITY_STANDARDS = {"js_beacon", "css_beacon", "hidden_link", "nofollow", "meta_noai"}


@dataclass
class Profile:
    user_agent: str
    claimed_crawler: str | None
    operator: str | None = None

    addresses: set[str] = field(default_factory=set)
    requests: int = 0
    bytes_served: int = 0

    standards_read: set[str] = field(default_factory=set)
    standards_mined: set[str] = field(default_factory=set)
    disallowed_paths: set[str] = field(default_factory=set)

    executes_js: bool = False
    loads_css: bool = False
    follows_hidden: bool = False
    follows_nofollow: bool = False
    ignores_meta_noai: bool = False

    split_fleet_hits: int = 0
    max_read_to_fetch_delay: float = 0.0

    conditional_requests: int = 0
    repeat_fetches: int = 0
    wasteful_refetches: int = 0
    duplicate_content_fetches: int = 0

    identity_verdict: str | None = None
    identity_detail: str | None = None
    signals: set[str] = field(default_factory=set)

    ja4: set[str] = field(default_factory=set)

    hunt_probes: int = 0
    hunt_families: set[str] = field(default_factory=set)
    hunt_categories: set[str] = field(default_factory=set)
    wallets: dict[str, set[str]] = field(default_factory=dict)
    pools: set[str] = field(default_factory=set)
    payload_urls: set[str] = field(default_factory=set)
    miners: set[str] = field(default_factory=set)
    mitre: set[str] = field(default_factory=set)

    _paths_seen: dict[str, int] = field(default_factory=lambda: defaultdict(int), repr=False)
    _hashes_seen: dict[str, int] = field(default_factory=lambda: defaultdict(int), repr=False)

    @property
    def state(self) -> str:
        if self.standards_mined:
            return STATE_MINER
        if self.disallowed_paths and self.standards_read:
            return STATE_DEFIANT
        if self.disallowed_paths and not self.standards_read:
            return STATE_IGNORANT
        if self.standards_read:
            return STATE_COMPLIANT
        return STATE_INDETERMINATE

    @property
    def is_hunter(self) -> bool:
        """Probed for exposed compute rather than crawling content."""
        return self.hunt_probes > 0

    @property
    def waste_ratio(self) -> float:
        """Share of repeat fetches that carried no conditional header."""
        if self.repeat_fetches == 0:
            return 0.0
        return self.wasteful_refetches / self.repeat_fetches

    def as_dict(self) -> dict:
        return {
            "user_agent": self.user_agent,
            "claimed_crawler": self.claimed_crawler,
            "operator": self.operator,
            "state": self.state,
            "addresses": sorted(self.addresses),
            "fleet_size": len(self.addresses),
            "requests": self.requests,
            "standards_read": sorted(self.standards_read),
            "standards_mined": sorted(self.standards_mined),
            "disallowed_fetched": sorted(self.disallowed_paths),
            "split_fleet_hits": self.split_fleet_hits,
            "max_read_to_fetch_delay_s": round(self.max_read_to_fetch_delay, 1),
            "executes_js": self.executes_js,
            "loads_css": self.loads_css,
            "follows_hidden_link": self.follows_hidden,
            "follows_nofollow": self.follows_nofollow,
            "ignores_meta_noai": self.ignores_meta_noai,
            "repeat_fetches": self.repeat_fetches,
            "wasteful_refetches": self.wasteful_refetches,
            "waste_ratio": round(self.waste_ratio, 3),
            "duplicate_content_fetches": self.duplicate_content_fetches,
            "identity_verdict": self.identity_verdict,
            "identity_detail": self.identity_detail,
            "signals": sorted(self.signals),
            "ja4": sorted(self.ja4),
            "hunt_probes": self.hunt_probes,
            "hunt_families": sorted(self.hunt_families),
            "hunt_categories": sorted(self.hunt_categories),
            "wallets": {k: sorted(v) for k, v in self.wallets.items()},
            "pools": sorted(self.pools),
            "payload_urls": sorted(self.payload_urls),
            "miners": sorted(self.miners),
            "mitre": sorted(self.mitre),
        }


def _key(ua: str, claimed: str | None) -> tuple[str, str]:
    return (ua or "-", claimed or "-")


def build_profiles(log_dir: str | Path) -> dict[tuple[str, str], Profile]:
    profiles: dict[tuple[str, str], Profile] = {}

    def profile_for(ua: str, claimed: str | None) -> Profile:
        key = _key(ua, claimed)
        if key not in profiles:
            profiles[key] = Profile(user_agent=ua or "-", claimed_crawler=claimed)
        return profiles[key]

    for event in eventlog.read_events(log_dir):
        kind = event.get("kind")
        ua = event.get("ua", "") or ""
        claimed = event.get("claimed_crawler")

        if kind == eventlog.EVENT_REQUEST:
            p = profile_for(ua, claimed)
            p.addresses.add(event.get("ip", "-"))
            p.requests += 1
            p.bytes_served += int(event.get("bytes") or 0)
            p.operator = p.operator or event.get("operator")
            for sig in event.get("signals") or ():
                p.signals.add(sig)
            if event.get("ja4"):
                p.ja4.add(event["ja4"])

            resource = event.get("resource")
            path = event.get("path", "")
            status = event.get("status")
            if status in (200, 304) and resource in ("page", "index", "docs_index", "project_index"):
                seen_before = p._paths_seen[path]
                p._paths_seen[path] += 1
                if seen_before:
                    p.repeat_fetches += 1
                    if not event.get("conditional"):
                        p.wasteful_refetches += 1
                if event.get("conditional"):
                    p.conditional_requests += 1

            content_hash = event.get("content_hash")
            if content_hash:
                if p._hashes_seen[content_hash]:
                    p.duplicate_content_fetches += 1
                p._hashes_seen[content_hash] += 1

        elif kind == eventlog.EVENT_POLICY_READ:
            p = profile_for(ua, claimed)
            p.standards_read.add(event["standard"])
            p.addresses.add(event.get("ip", "-"))

        elif kind == eventlog.EVENT_TRAP_HIT:
            p = profile_for(ua, claimed)
            p.addresses.add(event.get("ip", "-"))
            standard = event.get("standard", "")

            if standard == "js_beacon":
                p.executes_js = True
            elif standard == "css_beacon":
                p.loads_css = True
            elif standard == "hidden_link":
                p.follows_hidden = True
            elif standard == "nofollow":
                p.follows_nofollow = True
            elif standard == "meta_noai":
                p.ignores_meta_noai = True
            elif standard not in ("stable_disallow_unlinked", "stable_allow_unlinked"):
                # A policy-file beacon: proof the file was read AND mined.
                p.standards_mined.add(standard)
                p.standards_read.add(standard)

            if event.get("disallowed"):
                p.disallowed_paths.add(event.get("path", ""))
            if event.get("split_fleet"):
                p.split_fleet_hits += 1
            delay = event.get("delay_seconds")
            if isinstance(delay, (int, float)):
                p.max_read_to_fetch_delay = max(p.max_read_to_fetch_delay, float(delay))

        elif kind == eventlog.EVENT_HUNT:
            p = profile_for(ua, claimed)
            p.addresses.add(event.get("ip", "-"))
            p.hunt_probes += 1
            p.hunt_families.add(event.get("family", "?"))
            p.hunt_categories.add(event.get("category", "?"))
            for technique in event.get("mitre") or ():
                p.mitre.add(technique)
            if event.get("ja4"):
                p.ja4.add(event["ja4"])

            indicators = event.get("indicators") or {}
            for currency, addresses in (indicators.get("wallets") or {}).items():
                p.wallets.setdefault(currency, set()).update(addresses)
            p.pools.update(indicators.get("pools") or ())
            p.payload_urls.update(indicators.get("urls") or ())
            p.miners.update(indicators.get("miners") or ())

        elif kind == eventlog.EVENT_IDENTITY:
            p = profile_for(ua, event.get("claimed"))
            p.identity_verdict = event.get("verdict")
            p.identity_detail = event.get("detail")
            p.operator = p.operator or event.get("operator")

    # A disallowed fetch reached through an ordinary link is recorded on the
    # request stream rather than as a trap hit, so fold those in too.
    for event in eventlog.read_events(log_dir, kinds={eventlog.EVENT_REQUEST}):
        if event.get("resource") == "restricted" and event.get("status") == 200:
            p = profile_for(event.get("ua", ""), event.get("claimed_crawler"))
            p.disallowed_paths.add(event.get("path", ""))

    return profiles


def standard_matrix(profiles: dict) -> dict[str, dict[str, int]]:
    """crawler -> {standard -> read count}, the adoption matrix."""
    matrix: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for profile in profiles.values():
        name = profile.claimed_crawler or profile.user_agent[:40] or "-"
        for standard in profile.standards_read:
            if standard not in CAPABILITY_STANDARDS:
                matrix[name][standard] += 1
    return {k: dict(v) for k, v in matrix.items()}

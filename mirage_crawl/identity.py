"""Independent verification of who a client claims to be.

Two mechanisms, both external to the client, so neither can be spoofed by
setting a header:

  Forward-confirmed reverse DNS (FCrDNS)
      Reverse-resolve the IP to a hostname, then forward-resolve that hostname
      and require the original IP to come back. Google, Bing, Yandex and Ahrefs
      document this as the way to verify their crawlers. An impersonator
      controls neither the reverse zone for the IP nor the forward record for
      the claimed domain, so passing this is strong evidence.

  Published address ranges
      OpenAI, Anthropic, Apple, Amazon and others publish the CIDR blocks their
      crawlers use. Membership is a straight containment check.

The verdicts are deliberately coarse, and `unverifiable` is kept distinct from
`impersonating`. A crawler with no published verification mechanism cannot be
confirmed *or* refuted, and recording that as a failure would fabricate a
finding. Only a claim that is contradicted by a mechanism the operator
themselves publishes counts as impersonation.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import time
from dataclasses import dataclass
from pathlib import Path

VERDICT_VERIFIED = "verified"
VERDICT_IMPERSONATING = "impersonating"
VERDICT_UNVERIFIABLE = "unverifiable"
VERDICT_UNDECLARED = "undeclared"

# Hostname suffixes each operator's crawlers reverse-resolve to.
RDNS_SUFFIXES: dict[str, tuple[str, ...]] = {
    "Google": (".googlebot.com", ".google.com", ".googleusercontent.com"),
    "Microsoft": (".search.msn.com",),
    "Yandex": (".yandex.ru", ".yandex.net", ".yandex.com"),
    "Ahrefs": (".ahrefs.com", ".ahrefs.net"),
    "DuckDuckGo": (".duckduckgo.com",),
    "Apple": (".applebot.apple.com",),
}


@dataclass(frozen=True)
class Verdict:
    verdict: str
    method: str
    detail: str
    rdns_name: str | None = None
    matched_range: str | None = None


class RangeTable:
    """Published CIDR blocks, loaded from a config file.

    Ranges live in config rather than code because the publication URLs and the
    blocks themselves change. A stale bundled list would silently produce
    `impersonating` verdicts for legitimate crawlers, which is the most
    damaging error this module could make -- so a miss is always reported as
    `unverifiable`, never as impersonation, unless the operator has ranges
    loaded AND the address falls outside all of them.
    """

    def __init__(self) -> None:
        self._by_operator: dict[str, list[ipaddress._BaseNetwork]] = {}
        self.loaded_at: float | None = None
        self.source: str | None = None

    def load_file(self, path: str | Path) -> int:
        path = Path(path)
        if not path.exists():
            return 0
        data = json.loads(path.read_text(encoding="utf-8"))
        return self.load_mapping(data.get("operators", {}), source=str(path))

    def load_mapping(self, mapping: dict[str, list[str]], source: str = "inline") -> int:
        total = 0
        table: dict[str, list[ipaddress._BaseNetwork]] = {}
        for operator, cidrs in mapping.items():
            nets = []
            for cidr in cidrs:
                try:
                    nets.append(ipaddress.ip_network(cidr, strict=False))
                except ValueError:
                    continue
            if nets:
                table[operator] = nets
                total += len(nets)
        self._by_operator = table
        self.loaded_at = time.time()
        self.source = source
        return total

    def has(self, operator: str) -> bool:
        return operator in self._by_operator

    def contains(self, operator: str, ip: str) -> str | None:
        nets = self._by_operator.get(operator)
        if not nets:
            return None
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for net in nets:
            if addr in net:
                return str(net)
        return None

    @property
    def operators(self) -> list[str]:
        return sorted(self._by_operator)


async def reverse_confirm(ip: str, timeout: float = 3.0) -> tuple[str | None, bool]:
    """Forward-confirmed reverse DNS. Returns (hostname, confirmed)."""
    loop = asyncio.get_running_loop()

    def _lookup() -> tuple[str | None, bool]:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
        except (OSError, socket.herror, socket.gaierror):
            return None, False
        try:
            infos = socket.getaddrinfo(hostname, None)
        except (OSError, socket.gaierror):
            return hostname, False
        addresses = {info[4][0] for info in infos}
        return hostname, ip in addresses

    try:
        return await asyncio.wait_for(loop.run_in_executor(None, _lookup), timeout)
    except (asyncio.TimeoutError, Exception):
        return None, False


async def verify(
    ip: str,
    claimed_crawler: str | None,
    operator: str | None,
    method: str | None,
    ranges: RangeTable,
    timeout: float = 3.0,
) -> Verdict:
    """Decide whether a claimed crawler identity holds up."""
    if claimed_crawler is None or operator is None:
        return Verdict(VERDICT_UNDECLARED, "none", "no declared crawler in user agent")

    if operator == "library":
        # A library UA is honest about being automation; there is nothing to
        # impersonate, so it is simply undeclared as a crawler identity.
        return Verdict(VERDICT_UNDECLARED, "none", "generic HTTP library")

    if method == "cidr":
        if not ranges.has(operator):
            return Verdict(
                VERDICT_UNVERIFIABLE,
                "cidr",
                f"no published ranges loaded for {operator}",
            )
        matched = ranges.contains(operator, ip)
        if matched:
            return Verdict(VERDICT_VERIFIED, "cidr", f"in {operator} range", matched_range=matched)
        return Verdict(
            VERDICT_IMPERSONATING,
            "cidr",
            f"claims {claimed_crawler} but address is outside all published {operator} ranges",
        )

    if method == "rdns":
        hostname, confirmed = await reverse_confirm(ip, timeout=timeout)
        suffixes = RDNS_SUFFIXES.get(operator, ())
        if hostname is None:
            return Verdict(VERDICT_UNVERIFIABLE, "rdns", "no PTR record", rdns_name=None)
        if not confirmed:
            return Verdict(
                VERDICT_IMPERSONATING,
                "rdns",
                "PTR does not forward-confirm to the same address",
                rdns_name=hostname,
            )
        if suffixes and not hostname.lower().rstrip(".").endswith(suffixes):
            return Verdict(
                VERDICT_IMPERSONATING,
                "rdns",
                f"forward-confirmed as {hostname}, not a {operator} domain",
                rdns_name=hostname,
            )
        return Verdict(VERDICT_VERIFIED, "rdns", f"forward-confirmed {hostname}", rdns_name=hostname)

    return Verdict(
        VERDICT_UNVERIFIABLE,
        "none",
        f"{operator} publishes no verification mechanism",
    )


class VerifierCache:
    """Caches verdicts per (ip, claimed crawler) so DNS is not on the hot path."""

    def __init__(self, ranges: RangeTable, ttl: float = 3600.0, max_entries: int = 50_000) -> None:
        self.ranges = ranges
        self.ttl = ttl
        self.max_entries = max_entries
        self._cache: dict[tuple[str, str], tuple[float, Verdict]] = {}

    async def get(
        self, ip: str, claimed: str | None, operator: str | None, method: str | None
    ) -> Verdict:
        key = (ip, claimed or "-")
        now = time.time()
        hit = self._cache.get(key)
        if hit and now - hit[0] < self.ttl:
            return hit[1]

        verdict = await verify(ip, claimed, operator, method, self.ranges)

        if len(self._cache) >= self.max_entries:
            oldest = sorted(self._cache.items(), key=lambda kv: kv[1][0])[: self.max_entries // 4]
            for k, _ in oldest:
                self._cache.pop(k, None)

        self._cache[key] = (now, verdict)
        return verdict

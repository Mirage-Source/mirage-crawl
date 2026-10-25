"""Export sessions as mirage.actor/1 records: the shape every Mirage sensor emits.

One record per (sensor, actor). The record is a read-side export, not what a
sensor pushes to mirage-fleet: fleet keeps each sensor's own payload as-is
("the shared surface is the HTTP contract, not a shared schema"). This is the
layer above that, where a correlator merges sensors into entities. See
docs/ACTOR-SCHEMA.md for the contract and the reasoning.

Actor ids are sensor-local (each sensor keys its own HMAC), so two records are
never joined on `actor`. They are joined on indicators, and only on the strong
ones: a shared source IP or a commodity credential pair links unrelated
actors, and a false merge is worse than a missed join.

    python -m mirage_crawl.actors data/events > actors.jsonl
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

from . import sessions as sessions_mod

SCHEMA = "mirage.actor/1"
SENSOR_TYPE = "http"

# Closed vocabulary. Adding a type is a minor (additive) change; changing what
# an existing type's value means is a new schema version.
STRENGTH: dict[str, str] = {
    "ip": "weak",          # source address: CGNAT, cloud, proxies, Tor exits
    "credential": "weak",  # [user, password]: commodity lists collide constantly
    "miner": "weak",       # binary name: everyone runs xmrig
    "cve": "weak",         # which exploit: thousands of actors share one
    "tool": "weak",        # which scanner or kit
    "infra_ip": "strong",  # an address the payload points at (stage 2, C2)
    "domain": "strong",    # a hostname the payload points at, OAST callbacks
    "url": "strong",       # a stage-2 or payload URL
    "wallet": "strong",    # "<chain>:<address>"
    "pool": "strong",      # stratum URL or pool host
    "sha256": "strong",    # exploit body or uploaded file
    "honeytoken": "strong",  # a credential we planted, seen coming back
}

CORE_KEYS = (
    "schema", "sensor", "actor", "actor_basis", "first_seen", "last_seen", "events",
    "reached_payload", "fingerprints", "indicators", "mitre", "detail",
)

_CHAINS = ("monero", "bitcoin", "ethereum")
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DEFAULT_PORT = {"http": 80, "https": 443}


def _ip(raw: str) -> str | None:
    try:
        addr = ipaddress.ip_address(str(raw).strip().strip("[]"))
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return str(addr)


def _domain(raw: str) -> str | None:
    host = str(raw).strip().rstrip(".").lower()
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = host.split(".")
    if len(labels) < 2 or not all(_LABEL.match(label) for label in labels):
        return None
    return host


def _url(raw: str) -> str | None:
    try:
        parts = urlsplit(str(raw).strip())
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORT or not parts.hostname:
        return None
    host = _ip(parts.hostname) or _domain(parts.hostname)
    if host is None:
        return None
    if ":" in host:
        host = f"[{host}]"
    netloc = host if port in (None, _DEFAULT_PORT[scheme]) else f"{host}:{port}"
    # Path and query are kept byte-for-byte: they are payload, not identity.
    return urlunsplit((scheme, netloc, parts.path, parts.query, ""))


def _wallet(raw: str) -> str | None:
    chain, sep, address = str(raw).partition(":")
    chain = chain.lower()
    if not sep or chain not in _CHAINS or not address:
        return None
    if chain == "ethereum" or address.lower().startswith("bc1"):
        address = address.lower()  # EIP-55 / bech32 case carries no identity
    return f"{chain}:{address}"


def normalize(kind: str, raw) -> str | None:
    """The canonical string for one indicator, or None if it is not valid.

    Both sensors must produce byte-identical output for the same indicator;
    docs/actor-schema/vectors.json pins that down.
    """
    if raw is None:
        return None
    if kind in ("ip", "infra_ip"):
        return _ip(raw)
    if kind == "domain":
        return _domain(raw)
    if kind == "url":
        return _url(raw)
    if kind == "wallet":
        return _wallet(raw)
    if kind == "pool":
        value = str(raw).strip().lower()
        return value or None
    if kind == "sha256":
        value = str(raw).strip().lower()
        return value if _SHA256.match(value) else None
    if kind == "honeytoken":
        value = str(raw).strip()
        return value or None
    if kind == "credential":
        user, password = raw
        return json.dumps([user, password], separators=(",", ":"), ensure_ascii=False)
    if kind in ("miner", "tool"):
        value = str(raw).strip().lower()
        return value or None
    if kind == "cve":
        value = str(raw).strip().upper()
        return value if _CVE.match(value) else None
    raise ValueError(f"unknown indicator type: {kind!r}")


def _ts(value: str | None) -> str | None:
    if not value:
        return None
    try:
        t = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _indicators(s: sessions_mod.Session) -> list[dict]:
    raw: list[tuple[str, object]] = []
    raw += [("ip", ip) for ip in s.ips]
    for url in s.payload_urls:
        raw.append(("url", url))
        # The host a payload URL points at is infrastructure: a strong key,
        # unlike the source address the request came from.
        host = (urlsplit(url).hostname or "") if "://" in url else ""
        raw.append(("infra_ip", host) if _ip(host) else ("domain", host))
    raw += [("domain", d) for d in s.oast]
    raw += [("wallet", f"{chain}:{a}") for chain, addrs in s.wallets.items() for a in addrs]
    raw += [("pool", p) for p in s.pools]
    raw += [("sha256", h) for h in s.attack_body_hashes]
    raw += [("honeytoken", t) for t in s.honeytoken_tokens]
    raw += [("credential", pair) for pair in s.credential_pairs]
    raw += [("miner", m) for m in s.miners]
    raw += [("cve", c) for c in s.cves]
    raw += [("tool", t) for t in s.tools]

    seen: set[tuple[str, str]] = set()
    for kind, value in raw:
        norm = normalize(kind, value)
        if norm is not None:
            seen.add((kind, norm))
    return [{"type": k, "value": v, "strength": STRENGTH[k]} for k, v in sorted(seen)]


def record(s: sessions_mod.Session) -> dict:
    """One mirage.actor/1 record. Shared core keys only at the top level;
    everything HTTP-specific lives under `detail`."""
    fingerprints = sorted(
        [{"type": "ja4", "value": j} for j in s.ja4s]
        + [{"type": "header_order", "value": h} for h in s.header_orders],
        key=lambda f: (f["type"], f["value"]),
    )
    return {
        "schema": SCHEMA,
        "sensor": {"type": SENSOR_TYPE, "id": min(s.sensors) if s.sensors else "unknown"},
        "actor": s.actor,
        "actor_basis": s.actor_basis,
        "first_seen": _ts(s.first_seen),
        "last_seen": _ts(s.last_seen),
        "events": s.event_count,
        "reached_payload": s.has_payload,
        "fingerprints": fingerprints,
        "indicators": _indicators(s),
        "mitre": sorted(s.mitre),
        "detail": {
            "stage": s.stage_reached,
            "faces": sorted(s.faces),
            "user_agents": sorted(s.user_agents)[:10],
            "families": sorted(s.families),
            "attack_classes": dict(sorted(s.attack_classes.items())),
            "honeytokens_issued": sorted(s.honeytokens_issued),
            "honeytokens_used": sorted(s.honeytokens_used),
            "credential_attempts": s.credential_attempts,
            "requests": s.request_count,
        },
    }


def export(sessions: dict[str, sessions_mod.Session]) -> list[dict]:
    return [record(sessions[a]) for a in sorted(sessions)]


def join_keys(rec: dict) -> set[tuple[str, str]]:
    """The (type, value) pairs a correlator may join two records on."""
    return {(i["type"], i["value"]) for i in rec["indicators"] if i["strength"] == "strong"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mirage-crawl-actors", description=__doc__.splitlines()[0])
    parser.add_argument("log_dir")
    parser.add_argument("--payload-only", action="store_true", help="only actors that reached payload")
    args = parser.parse_args(argv)
    for rec in export(sessions_mod.build_sessions(args.log_dir)):
        if args.payload_only and not rec["reached_payload"]:
            continue
        sys.stdout.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

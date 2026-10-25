"""Session analysis: reconstruct an actor's activity from the event log.

The sensor keeps no session state -- a "session" is a read-time grouping of
events that share an `actor` (the stateless HMAC of ip + ja4/header-order the
server stamps on every event). This module does that grouping once, so research
on "the concerned sessions" is a supported query rather than a roll-your-own
jq exercise: for each actor it builds one record with the identity, an ordered
timeline, the attacker-progression stage it reached, and the hard indicators it
emitted (wallets, pools, miners, payload URLs, credentials, exploits, MITRE).

It is pure read-side tooling over the append-only log; it never touches the
running sensor. Run it:

    python -m mirage_crawl.sessions data/events                 # summary table
    python -m mirage_crawl.sessions data/events --has-payload   # only the ones that paid off
    python -m mirage_crawl.sessions data/events --actor <id>    # one session's full timeline
    python -m mirage_crawl.sessions data/events --json > sessions.json
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from . import eventlog

# Attacker-progression ladder, lowest to highest. The whole decoy design rests
# on moving an actor down this list: a decoy that never pulls a follow-up or a
# payload is not earning its keep, and that is measurable here.
STAGES = ("seen", "probed", "decoy_served", "followup", "payload")
_STAGE_RANK = {s: i for i, s in enumerate(STAGES)}

# web_attack tags that mean an actual exploitation attempt, not just recon.
_PAYLOAD_ATTACKS = {"sqli", "php_rce_attempt"}


def _parse_ts(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


@dataclass
class Session:
    actor: str
    actor_basis: str | None = None

    ips: set[str] = field(default_factory=set)
    ja4s: set[str] = field(default_factory=set)
    user_agents: set[str] = field(default_factory=set)
    operators: set[str] = field(default_factory=set)
    claimed_crawlers: set[str] = field(default_factory=set)

    first_seen: str | None = None
    last_seen: str | None = None
    request_count: int = 0
    event_count: int = 0

    faces: set[str] = field(default_factory=set)
    families: set[str] = field(default_factory=set)
    hunt_categories: set[str] = field(default_factory=set)

    standards_read: set[str] = field(default_factory=set)
    standards_mined: set[str] = field(default_factory=set)

    decoy_served: bool = False
    walked_multistage: bool = False

    web_attacks: set[str] = field(default_factory=set)
    # From the attack classifier on request events: class -> request count.
    attack_classes: dict[str, int] = field(default_factory=dict)
    cves: set[str] = field(default_factory=set)
    tools: set[str] = field(default_factory=set)
    oast: set[str] = field(default_factory=set)
    exploits: set[str] = field(default_factory=set)
    # Honeytoken kinds issued to / replayed by this actor. A replay is a
    # payload by definition: someone acted on a credential we planted.
    honeytokens_issued: set[str] = field(default_factory=set)
    honeytokens_used: set[str] = field(default_factory=set)
    mitre: set[str] = field(default_factory=set)

    wallets: dict[str, set[str]] = field(default_factory=dict)
    pools: set[str] = field(default_factory=set)
    payload_urls: set[str] = field(default_factory=set)
    miners: set[str] = field(default_factory=set)
    credential_attempts: int = 0

    timeline: list[dict] = field(default_factory=list)

    @property
    def duration_s(self) -> float:
        a, b = _parse_ts(self.first_seen), _parse_ts(self.last_seen)
        return (b - a).total_seconds() if a and b else 0.0

    @property
    def has_payload(self) -> bool:
        return bool(
            self.wallets or self.pools or self.payload_urls or self.miners
            or self.credential_attempts
            or self.attack_classes
            or self.honeytokens_used
            or (self.web_attacks & _PAYLOAD_ATTACKS)
        )

    @property
    def stage_reached(self) -> str:
        if self.has_payload:
            return "payload"
        if self.walked_multistage:
            return "followup"
        if self.decoy_served:
            return "decoy_served"
        if self.families or self.web_attacks:
            return "probed"
        return "seen"

    def _absorb_indicators(self, ind: dict | None) -> None:
        if not ind:
            return
        for currency, addrs in (ind.get("wallets") or {}).items():
            self.wallets.setdefault(currency, set()).update(addrs)
        self.pools.update(ind.get("pools") or ())
        self.payload_urls.update(ind.get("urls") or ())
        self.miners.update(ind.get("miners") or ())
        if ind.get("jndi"):
            self.exploits.add("log4shell")
        if ind.get("shellshock"):
            self.exploits.add("shellshock")
        if ind.get("metadata_ssrf"):
            self.exploits.add("metadata_ssrf")

    def _observe(self, e: dict) -> None:
        self.event_count += 1
        ts = e.get("ts")
        if ts:
            if self.first_seen is None or ts < self.first_seen:
                self.first_seen = ts
            if self.last_seen is None or ts > self.last_seen:
                self.last_seen = ts
        if e.get("ip"):
            self.ips.add(e["ip"])
        if e.get("ja4"):
            self.ja4s.add(e["ja4"])
        if e.get("ua"):
            self.user_agents.add(e["ua"])
        if e.get("operator"):
            self.operators.add(e["operator"])
        if e.get("claimed_crawler"):
            self.claimed_crawlers.add(e["claimed_crawler"])
        if e.get("face"):
            self.faces.add(e["face"])
        if self.actor_basis is None:
            self.actor_basis = e.get("actor_basis")

        kind = e.get("kind")
        if kind == eventlog.EVENT_REQUEST:
            self.request_count += 1
            self._absorb_indicators(e.get("indicators"))
            # An attack is a payload by definition (recon stays in hunt events),
            # so it counts toward the stage even with no hard indicator.
            for cls in {a["cls"] for a in e.get("attacks") or ()}:
                self.attack_classes[cls] = self.attack_classes.get(cls, 0) + 1
            self.cves.update(a["cve"] for a in e.get("attacks") or () if a.get("cve"))
            self.tools.update(t["name"] for t in e.get("tools") or ())
            self.oast.update(e.get("oast") or ())
            self.honeytokens_used.update(h["kind"] for h in e.get("honeytokens") or ())
        elif kind == eventlog.EVENT_POLICY_READ:
            if e.get("standard"):
                self.standards_read.add(e["standard"])
        elif kind == eventlog.EVENT_TRAP_HIT:
            # A trap hit on a disallowed path is the mined-after-reading signal.
            if e.get("standard") and e.get("disallowed"):
                self.standards_mined.add(e["standard"])
        elif kind == eventlog.EVENT_HUNT:
            if e.get("family"):
                self.families.add(e["family"])
            if e.get("category"):
                self.hunt_categories.add(e["category"])
            if e.get("web_attack"):
                self.web_attacks.add(e["web_attack"])
            if e.get("decoy_served"):
                self.decoy_served = True
            self.honeytokens_issued.update(h["kind"] for h in e.get("honeytokens_issued") or ())
            if e.get("stage"):
                self.walked_multistage = True
            self._absorb_indicators(e.get("indicators"))
        elif kind == eventlog.EVENT_CREDENTIAL:
            self.credential_attempts += 1

        self.mitre.update(e.get("mitre") or ())

        # One compact timeline step per event, in log order.
        tag = (
            e.get("web_attack") or e.get("standard") or e.get("family")
            or e.get("resource") or e.get("scheme")
        )
        self.timeline.append({
            "ts": ts, "kind": kind, "face": e.get("face"),
            "method": e.get("method"), "path": e.get("path"), "tag": tag,
        })

    def as_dict(self) -> dict:
        return {
            "actor": self.actor,
            "actor_basis": self.actor_basis,
            "stage_reached": self.stage_reached,
            "ips": sorted(self.ips),
            "ja4s": sorted(self.ja4s),
            "user_agents": sorted(self.user_agents),
            "operators": sorted(self.operators),
            "claimed_crawlers": sorted(self.claimed_crawlers),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration_s": round(self.duration_s, 1),
            "request_count": self.request_count,
            "event_count": self.event_count,
            "faces": sorted(self.faces),
            "families": sorted(self.families),
            "hunt_categories": sorted(self.hunt_categories),
            "standards_read": sorted(self.standards_read),
            "standards_mined": sorted(self.standards_mined),
            "decoy_served": self.decoy_served,
            "walked_multistage": self.walked_multistage,
            "web_attacks": sorted(self.web_attacks),
            "attack_classes": dict(sorted(self.attack_classes.items())),
            "cves": sorted(self.cves),
            "tools": sorted(self.tools),
            "oast": sorted(self.oast),
            "exploits": sorted(self.exploits),
            "honeytokens_issued": sorted(self.honeytokens_issued),
            "honeytokens_used": sorted(self.honeytokens_used),
            "mitre": sorted(self.mitre),
            "wallets": {k: sorted(v) for k, v in self.wallets.items()},
            "pools": sorted(self.pools),
            "payload_urls": sorted(self.payload_urls),
            "miners": sorted(self.miners),
            "credential_attempts": self.credential_attempts,
            "timeline": self.timeline,
        }


def build_sessions(log_dir: str | Path) -> dict[str, Session]:
    """Group every actor-stamped event into one Session per actor.

    Events with no actor (async identity verdicts, the TLS front's connection
    log) are skipped: they are not request activity and would otherwise fold
    into a single bogus "None" session.
    """
    out: dict[str, Session] = {}
    for event in eventlog.read_events(log_dir):
        actor = event.get("actor")
        if not actor:
            continue
        sess = out.get(actor)
        if sess is None:
            sess = out[actor] = Session(actor=actor)
        sess._observe(event)
    return out


def filter_sessions(
    sessions: dict[str, Session],
    *,
    actor: str | None = None,
    has_payload: bool = False,
    min_stage: str | None = None,
    since: str | None = None,
) -> dict[str, Session]:
    def keep(s: Session) -> bool:
        if actor is not None and s.actor != actor:
            return False
        if has_payload and not s.has_payload:
            return False
        if min_stage is not None and _STAGE_RANK[s.stage_reached] < _STAGE_RANK[min_stage]:
            return False
        if since is not None and (s.last_seen or "") < since:
            return False
        return True

    return {a: s for a, s in sessions.items() if keep(s)}


# -- CLI --------------------------------------------------------------------

def _print_summary(sessions: dict[str, Session]) -> None:
    order = sorted(
        sessions.values(),
        key=lambda s: (_STAGE_RANK[s.stage_reached], s.event_count),
        reverse=True,
    )
    print(f"{'ACTOR':14}{'BASIS':14}{'STAGE':13}{'EVTS':>5}  {'IPS':>4}  WHAT")
    print("-" * 78)
    for s in order:
        what_bits = []
        if s.families:
            what_bits.append("/".join(sorted(s.families)))
        if s.web_attacks:
            what_bits.append("+".join(sorted(s.web_attacks)))
        if s.attack_classes:
            what_bits.append("+".join(sorted(s.attack_classes)))
        if s.tools:
            what_bits.append("tool:" + ",".join(sorted(s.tools)))
        if s.standards_read:
            what_bits.append("read:" + ",".join(sorted(s.standards_read)))
        if s.wallets or s.miners:
            what_bits.append("MINER")
        if s.credential_attempts:
            what_bits.append(f"creds×{s.credential_attempts}")
        print(f"{s.actor[:13]:14}{(s.actor_basis or '-'):14}{s.stage_reached:13}"
              f"{s.event_count:5d}  {len(s.ips):4d}  {' '.join(what_bits)[:30]}")
    print("-" * 78)
    by_stage = {st: 0 for st in STAGES}
    for s in sessions.values():
        by_stage[s.stage_reached] += 1
    print("sessions by stage: " + "  ".join(f"{k}={v}" for k, v in by_stage.items()))


def _print_one(s: Session) -> None:
    d = s.as_dict()
    print(f"actor {s.actor}  basis={s.actor_basis}  stage={s.stage_reached}")
    print(f"  ips={sorted(s.ips)} ja4s={sorted(s.ja4s)}")
    print(f"  ua={sorted(s.user_agents)}")
    print(f"  window {s.first_seen} -> {s.last_seen} ({round(s.duration_s,1)}s, {s.event_count} events)")
    if s.wallets or s.pools or s.miners or s.payload_urls:
        print(f"  payload: wallets={d['wallets']} pools={d['pools']} miners={d['miners']} urls={d['payload_urls']}")
    if s.exploits or s.web_attacks:
        print(f"  attacks: exploits={sorted(s.exploits)} web={sorted(s.web_attacks)}")
    if s.attack_classes or s.tools or s.oast:
        print(f"  classified: {d['attack_classes']} cves={d['cves']} tools={d['tools']} oast={d['oast']}")
    if s.credential_attempts:
        print(f"  credentials attempted: {s.credential_attempts}")
    if s.mitre:
        print(f"  mitre: {sorted(s.mitre)}")
    print("  timeline:")
    for step in s.timeline:
        tag = f" [{step['tag']}]" if step.get("tag") else ""
        print(f"    {step['ts']}  {step['kind']:11} {step.get('face') or '-':7} "
              f"{step.get('method') or '':4} {step.get('path') or ''}{tag}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mirage-crawl-sessions")
    parser.add_argument("log_dir", nargs="?", default="data/events")
    parser.add_argument("--json", action="store_true", help="emit sessions as JSON")
    parser.add_argument("--actor", help="show one actor's full timeline")
    parser.add_argument("--has-payload", action="store_true", help="only sessions that produced a payload")
    parser.add_argument("--min-stage", choices=STAGES, help="only sessions at or past this stage")
    parser.add_argument("--since", help="only sessions last seen on/after this ISO date")
    args = parser.parse_args(argv)

    sessions = build_sessions(args.log_dir)
    sessions = filter_sessions(
        sessions, actor=args.actor, has_payload=args.has_payload,
        min_stage=args.min_stage, since=args.since,
    )

    if args.json:
        import json
        print(json.dumps([s.as_dict() for s in sessions.values()], indent=2))
        return 0

    if not sessions:
        print("no matching sessions")
        return 0

    if args.actor or len(sessions) == 1:
        for s in sessions.values():
            _print_one(s)
    else:
        _print_summary(sessions)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

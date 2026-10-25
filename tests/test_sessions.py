"""Session analysis: group the event log by actor into researchable sessions."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mirage_crawl import sessions  # noqa: E402

failures: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    print(f"  {'PASS' if condition else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not condition else ""))
    if not condition:
        failures.append(name)


# A synthetic log: one benign crawler (A1, keyed on ja4) and one attacker (A2,
# keyed on header order) who is probed -> served a decoy -> walks a multi-stage
# chain -> drops a miner payload and tries a credential and a SQLi.
EVENTS = [
    {"kind": "request", "ts": "2026-10-24T10:00:00Z", "actor": "A1", "actor_basis": "ja4",
     "ip": "1.1.1.1", "ja4": "J1", "ua": "GoodBot/1.0", "face": "docs",
     "method": "GET", "path": "/robots.txt", "status": 200},
    {"kind": "policy_read", "ts": "2026-10-24T10:00:00Z", "actor": "A1", "actor_basis": "ja4",
     "ip": "1.1.1.1", "face": "docs", "standard": "robots", "token": "tok1"},
    {"kind": "request", "ts": "2026-10-24T10:00:02Z", "actor": "A1", "actor_basis": "ja4",
     "ip": "1.1.1.1", "ja4": "J1", "ua": "GoodBot/1.0", "face": "docs",
     "method": "GET", "path": "/docs/", "status": 200},

    {"kind": "hunt", "ts": "2026-10-24T11:00:00Z", "actor": "A2", "actor_basis": "header_order",
     "ip": "2.2.2.2", "ua": "python-requests/2.31", "face": "ray", "family": "ray",
     "category": "gpu_ml", "mitre": ["T1046"], "method": "GET", "path": "/api/version",
     "decoy_served": True},
    {"kind": "hunt", "ts": "2026-10-24T11:00:05Z", "actor": "A2", "actor_basis": "header_order",
     "ip": "2.2.2.2", "face": "ray", "family": "ray", "category": "gpu_ml",
     "mitre": ["T1610", "T1496"], "method": "POST", "path": "/api/jobs/",
     "decoy_served": True, "stage": True},
    {"kind": "hunt", "ts": "2026-10-24T11:00:10Z", "actor": "A2", "actor_basis": "header_order",
     "ip": "2.2.2.2", "face": "ray", "family": "ray", "category": "gpu_ml",
     "mitre": ["T1496"], "method": "POST", "path": "/api/jobs/", "decoy_served": True, "stage": True,
     "indicators": {"wallets": {"monero": ["48edfHu7"]}, "pools": ["supportxmr"],
                    "urls": ["http://evil.example/xmrig"], "miners": ["xmrig"],
                    "jndi": True}},
    {"kind": "credential", "ts": "2026-10-24T11:00:12Z", "actor": "A2", "actor_basis": "header_order",
     "ip": "2.2.2.2", "face": "php", "method": "POST", "path": "/wp-login.php",
     "scheme": "form", "username": "admin"},
    {"kind": "hunt", "ts": "2026-10-24T11:00:15Z", "actor": "A2", "actor_basis": "header_order",
     "ip": "2.2.2.3", "face": "php", "family": "php", "category": "web_app",
     "web_attack": "sqli", "mitre": ["T1190"], "method": "GET", "path": "/item.php"},

    # A3: one request carrying an attack but no hard indicator (the live
    # React2Shell shape), which the stage ladder used to miss entirely.
    {"kind": "request", "ts": "2026-10-24T12:00:00Z", "actor": "A3", "actor_basis": "ja4",
     "ip": "3.3.3.3", "ja4": "J3", "ua": "Mozilla/5.0", "face": "attack", "method": "POST", "path": "/",
     "status": 200,
     "attacks": [{"cls": "deserialization", "location": "body:0", "evidence": "$1:__proto__:then",
                  "decoded": False, "sig": "react2shell", "cve": "CVE-2025-55182"}],
     "tools": [{"name": "bissa", "kind": "exploit_kit"}], "oast": ["c0ffee.oast.fun"]},
    # A4: a scanner that names itself but sends no payload stays below 'payload'.
    {"kind": "request", "ts": "2026-10-24T12:00:05Z", "actor": "A4", "actor_basis": "header_order",
     "ip": "4.4.4.4", "ua": "Mozilla/5.0 zgrab/0.x", "face": "attack", "method": "GET", "path": "/",
     "status": 200, "attacks": None, "tools": [{"name": "zgrab", "kind": "scanner"}], "oast": None},

    # An identity event has no actor; it must not crash the grouping or create
    # a bogus session.
    {"kind": "identity", "ts": "2026-10-24T11:00:20Z", "ip": "2.2.2.2",
     "claimed": None, "verdict": "unverifiable"},
]


def _write_log(tmp: Path) -> Path:
    d = tmp / "events"
    d.mkdir()
    with open(d / "2026-10-24.jsonl", "w") as fh:
        for e in EVENTS:
            fh.write(json.dumps(e) + "\n")
    return d


def test_grouping() -> None:
    print("\nsession grouping")
    with tempfile.TemporaryDirectory() as t:
        log = _write_log(Path(t))
        sess = sessions.build_sessions(log)

        check("one session per actor, no bogus session from actorless events",
              set(sess) == {"A1", "A2", "A3", "A4"}, str(sorted(sess)))
        a3, a4 = sess["A3"], sess["A4"]
        check("A3 attack class absorbed", a3.attack_classes == {"deserialization": 1}, str(a3.attack_classes))
        check("A3 cve absorbed", a3.cves == {"CVE-2025-55182"}, str(a3.cves))
        check("A3 tool and oast absorbed", a3.tools == {"bissa"} and a3.oast == {"c0ffee.oast.fun"})
        check("A3 attack alone reaches 'payload'", a3.stage_reached == "payload", a3.stage_reached)
        check("A4 tool without attack is not 'payload'", a4.stage_reached == "seen", a4.stage_reached)
        a1, a2 = sess["A1"], sess["A2"]

        check("A1 basis is ja4", a1.actor_basis == "ja4")
        check("A1 keeps its ja4 and ua", a1.ja4s == {"J1"} and "GoodBot/1.0" in a1.user_agents)
        check("A1 read robots", a1.standards_read == {"robots"})
        check("A1 request count", a1.request_count == 2, str(a1.request_count))
        check("A1 only the docs face", a1.faces == {"docs"})
        check("A1 reached only 'seen'", a1.stage_reached == "seen", a1.stage_reached)

        check("A2 basis is header_order", a2.actor_basis == "header_order")
        check("A2 gathers both its addresses", a2.ips == {"2.2.2.2", "2.2.2.3"}, str(a2.ips))
        check("A2 touched ray and php", a2.families == {"ray", "php"}, str(a2.families))
        check("A2 decoy was served", a2.decoy_served is True)
        check("A2 walked the multi-stage chain", a2.walked_multistage is True)
        check("A2 wallet extracted", a2.wallets.get("monero") == {"48edfHu7"})
        check("A2 pool/miner/url extracted",
              a2.pools == {"supportxmr"} and a2.miners == {"xmrig"} and a2.payload_urls == {"http://evil.example/xmrig"})
        check("A2 exploit from indicators", "log4shell" in a2.exploits)
        check("A2 web_attack tag", a2.web_attacks == {"sqli"})
        check("A2 credential attempt counted", a2.credential_attempts == 1, str(a2.credential_attempts))
        check("A2 mitre union", {"T1046", "T1610", "T1496", "T1190"} <= a2.mitre, str(a2.mitre))
        check("A2 reached 'payload'", a2.stage_reached == "payload", a2.stage_reached)


def test_timeline_and_window() -> None:
    print("\ntimeline and window")
    with tempfile.TemporaryDirectory() as t:
        log = _write_log(Path(t))
        a2 = sessions.build_sessions(log)["A2"]
        check("timeline ordered by ts",
              [s["path"] for s in a2.timeline] == ["/api/version", "/api/jobs/", "/api/jobs/", "/wp-login.php", "/item.php"],
              str([s["path"] for s in a2.timeline]))
        check("timeline carries the attack tag", any(s.get("tag") == "sqli" for s in a2.timeline))
        check("first/last seen set", a2.first_seen == "2026-10-24T11:00:00Z" and a2.last_seen == "2026-10-24T11:00:15Z")
        check("duration computed", round(a2.duration_s) == 15, str(a2.duration_s))


def test_filters_and_json() -> None:
    print("\nfilters and json export")
    with tempfile.TemporaryDirectory() as t:
        log = _write_log(Path(t))
        allsess = sessions.build_sessions(log)
        payload = sessions.filter_sessions(allsess, has_payload=True)
        check("has_payload keeps only the attackers", set(payload) == {"A2", "A3"}, str(set(payload)))
        actor = sessions.filter_sessions(allsess, actor="A1")
        check("actor filter narrows to one", set(actor) == {"A1"})

        d = allsess["A2"].as_dict()
        check("as_dict is json-serialisable", json.loads(json.dumps(d))["actor"] == "A2")
        for key in ("actor", "actor_basis", "ips", "ja4s", "stage_reached", "wallets",
                    "web_attacks", "attack_classes", "cves", "tools", "oast",
                    "mitre", "timeline", "first_seen", "last_seen"):
            check(f"as_dict has {key}", key in d)


if __name__ == "__main__":
    test_grouping()
    test_timeline_and_window()
    test_filters_and_json()
    print("\nFAILURES: " + ", ".join(failures) if failures else "\nall session checks passed")
    sys.exit(1 if failures else 0)

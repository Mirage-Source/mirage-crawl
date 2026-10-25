"""Shared actor schema (mirage.actor/1): normalisation, strength, the record.

docs/actor-schema/vectors.json holds language-neutral normalisation vectors.
mirage-core's exporter, whenever it is written, must pass the same file:
that is what makes "the same indicator" mean the same string on both sides.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mirage_crawl import actors, sessions  # noqa: E402

failures: list[str] = []
VECTORS = Path(__file__).resolve().parents[1] / "docs" / "actor-schema" / "vectors.json"


def check(name: str, condition: bool, detail: str = "") -> None:
    print(f"  {'PASS' if condition else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not condition else ""))
    if not condition:
        failures.append(name)


def test_vectors() -> None:
    print("\nnormalisation vectors (shared with mirage-core)")
    vectors = json.loads(VECTORS.read_text())
    wrong = [(v["type"], v["raw"], actors.normalize(v["type"], v["raw"]), v["normalized"])
             for v in vectors if actors.normalize(v["type"], v["raw"]) != v["normalized"]]
    check(f"all {len(vectors)} vectors normalise as specified", not wrong, str(wrong[:4]))
    check("every indicator type has at least one vector",
          set(actors.STRENGTH) <= {v["type"] for v in vectors},
          str(set(actors.STRENGTH) - {v["type"] for v in vectors}))


def test_strength() -> None:
    print("\njoin-key strength")
    check("source ips and credential pairs are weak (shared NAT, commodity lists)",
          actors.STRENGTH["ip"] == "weak" and actors.STRENGTH["credential"] == "weak")
    check("payload-derived keys are strong",
          all(actors.STRENGTH[t] == "strong"
              for t in ("wallet", "pool", "sha256", "url", "domain", "infra_ip", "honeytoken")))


# A RedTail-shaped actor and a crawler, as the sensor logs them.
EVENTS = [
    {"kind": "request", "ts": "2026-10-24T20:01:00.120+00:00", "sensor": "crawl-01", "actor": "R1",
     "actor_basis": "header_order", "ip": "45.43.36.172", "ua": "libredtail-http", "face": "attack",
     "method": "POST", "path": "/index.php", "header_order_hash": "aa11", "status": 200,
     "body_sha256": "AB" * 32,
     "indicators": {"urls": ["https://217.60.102.5/sh"], "wallets": {"monero": []}, "pools": [],
                    "miners": ["xmrig"]},
     "attacks": [{"cls": "php_code", "location": "query", "evidence": "x", "decoded": False,
                  "sig": None, "cve": "CVE-2024-4577"}],
     "tools": [{"name": "redtail", "kind": "botnet"}], "oast": ["c0ffee.oast.fun"],
     "honeytokens": [{"kind": "db_password", "token": "TOKEN1", "location": "body"}]},
    {"kind": "credential", "ts": "2026-10-24T20:01:02+00:00", "sensor": "crawl-01", "actor": "R1",
     "actor_basis": "header_order", "ip": "45.43.36.172", "scheme": "basic", "user": "root",
     "password": "admin"},
    {"kind": "request", "ts": "2026-10-24T20:05:00+00:00", "sensor": "crawl-01", "actor": "C1",
     "actor_basis": "ja4", "ip": "2600:1F18:0000::0001", "ja4": "t13d_x_y",
     "ua": "Claude-SearchBot/1.0", "face": "docs", "method": "GET", "path": "/robots.txt", "status": 200},
]


def _records() -> dict[str, dict]:
    with tempfile.TemporaryDirectory() as t:
        d = Path(t) / "events"
        d.mkdir()
        (d / "2026-10-24.jsonl").write_text("".join(json.dumps(e) + "\n" for e in EVENTS))
        return {r["actor"]: r for r in actors.export(sessions.build_sessions(d))}


def test_record() -> None:
    print("\nactor record")
    recs = _records()
    r, c = recs["R1"], recs["C1"]
    check("schema id and sensor", r["schema"] == "mirage.actor/1"
          and r["sensor"] == {"type": "http", "id": "crawl-01"}, str(r.get("sensor")))
    check("timestamps are RFC 3339 UTC with Z, second precision",
          r["first_seen"] == "2026-10-24T20:01:00Z" and r["last_seen"] == "2026-10-24T20:01:02Z",
          f"{r['first_seen']} {r['last_seen']}")
    check("reached_payload is the shared stage bit", r["reached_payload"] is True and c["reached_payload"] is False)

    ind = {(i["type"], i["value"]) for i in r["indicators"]}
    want = {
        ("ip", "45.43.36.172"), ("url", "https://217.60.102.5/sh"), ("infra_ip", "217.60.102.5"),
        ("domain", "c0ffee.oast.fun"), ("sha256", "ab" * 32), ("honeytoken", "TOKEN1"),
        ("credential", '["root","admin"]'), ("miner", "xmrig"), ("cve", "CVE-2024-4577"),
        ("tool", "redtail"),
    }
    check("indicators extracted and normalised", want <= ind, str(want - ind))
    check("each indicator carries its strength",
          all(i["strength"] == actors.STRENGTH[i["type"]] for i in r["indicators"]))
    check("empty wallet lists produce no indicator", not any(t == "wallet" for t, _ in ind))
    check("indicators sorted for stable diffs",
          r["indicators"] == sorted(r["indicators"], key=lambda i: (i["type"], i["value"])))

    fps = {(f["type"], f["value"]) for f in c["fingerprints"]}
    check("crawler fingerprints: ja4, protocol-local", ("ja4", "t13d_x_y") in fps, str(fps))
    check("source ipv6 canonicalised", ("ip", "2600:1f18::1") in {(i["type"], i["value"]) for i in c["indicators"]})
    check("sensor-specific facts live under detail, not the shared core",
          "attack_classes" in r["detail"] and "attack_classes" not in r)
    check("record is json and has exactly the shared keys",
          set(r) == set(actors.CORE_KEYS) and json.loads(json.dumps(r)) == r, str(set(r) ^ set(actors.CORE_KEYS)))


def test_join_helper() -> None:
    print("\njoin keys")
    recs = _records()
    keys = actors.join_keys(recs["R1"])
    check("join_keys yields only strong indicators",
          keys and all(actors.STRENGTH[t] == "strong" for t, _ in keys), str(keys))
    check("a shared source ip alone never joins two actors",
          ("ip", "45.43.36.172") not in keys)


if __name__ == "__main__":
    test_vectors()
    test_strength()
    test_record()
    test_join_helper()
    print("\nFAILURES: " + ", ".join(failures) if failures else "\nall actor checks passed")
    sys.exit(1 if failures else 0)

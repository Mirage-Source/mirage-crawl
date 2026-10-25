"""Tests for publish.anonymize: what the public dataset may say about a person.

The sensor logs everything; the published copy must not identify the people
who only browsed the site. Rules:

  * every source IP becomes mirage-core's salted hash (same salt, same HMAC),
    including IPs inside forwarding headers, so the two datasets still join;
  * a request the classifier did not label an attack loses its Cookie and
    Authorization values and its body, and so does a credential event that
    came from such a request;
  * an attack request is kept whole: there the headers and body are the payload;
  * reverse DNS is kept only for a verified crawler (a home ISP's PTR name
    encodes the subscriber's address).

    python tests/test_anonymize.py
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mirage_crawl.publish import REDACTED, anonymize, attacked  # noqa: E402

failures: list[str] = []
SALT = "test-salt"


def check(name: str, condition: bool, detail: str = "") -> None:
    print(f"  {'PASS' if condition else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not condition else ""))
    if not condition:
        failures.append(name)


def core_hash(ip: str) -> str:
    """mirage-core's scripts/anonymize.py, verbatim."""
    return "anon_" + hmac.new(SALT.encode(), ip.encode(), hashlib.sha256).hexdigest()[:16]


VISITOR = "49.36.239.37"
browse = {
    "kind": "request", "rid": "r1", "ip": VISITOR, "face": "docs", "method": "GET", "path": "/docs/",
    "raw_path": "/docs/", "raw_query": None,
    "headers": [["Host", "scannersnoop.com"], ["Cookie", "crumb=abc123"],
                ["Authorization", "Bearer eyJhbGciOi"], ["X-Forwarded-For", "10.0.0.5, 203.0.113.9"],
                ["User-Agent", "Mozilla/5.0"]],
    "body": "hello", "body_encoding": "utf-8", "body_sha256": "ff" * 32, "body_len": 5,
    "attacks": None,
}
exploit = {
    "kind": "request", "rid": "r2", "ip": "45.43.36.172", "face": "attack", "method": "GET", "path": "/",
    "raw_path": "/cgi-bin/status", "raw_query": None,
    "headers": [["Cookie", "() { :; }; /bin/bash -c id"]],
    "body": None, "attacks": [{"cls": "shellshock", "location": "header:Cookie", "evidence": "() {",
                                "decoded": False, "sig": None, "cve": None}],
}

print("source addresses")
out = anonymize(json.loads(json.dumps(browse)), SALT, attack_rids=set())
check("source ip hashed exactly like mirage-core", out["ip"] == core_hash(VISITOR), out["ip"])
xff = dict(out["headers"])["X-Forwarded-For"]
check("every ip inside a forwarding header hashed",
      xff == f"{core_hash('10.0.0.5')}, {core_hash('203.0.113.9')}", xff)
check("no raw visitor address anywhere", VISITOR not in json.dumps(out) and "203.0.113.9" not in json.dumps(out))
for kind in ("tls", "identity", "trap_hit", "policy_read", "hunt"):
    ev = anonymize({"kind": kind, "ip": VISITOR}, SALT, attack_rids=set())
    check(f"{kind} event ip hashed", ev["ip"] == core_hash(VISITOR))

print("\nnon-attack request: private fields dropped")
h = dict(out["headers"])
check("Cookie value redacted, header name kept", h["Cookie"] == REDACTED)
check("Authorization value redacted", h["Authorization"] == REDACTED)
check("ordinary headers untouched", h["User-Agent"] == "Mozilla/5.0" and h["Host"] == "scannersnoop.com")
check("body and its hash dropped, length kept",
      "body" not in out and "body_sha256" not in out and out["body_len"] == 5, str(out.keys()))

print("\nattack request: kept whole")
ex = anonymize(json.loads(json.dumps(exploit)), SALT, attack_rids={"r2"})
check("payload header kept", dict(ex["headers"])["Cookie"] == "() { :; }; /bin/bash -c id")
check("attacker ip still hashed", ex["ip"] == core_hash("45.43.36.172"))

print("\ncredential events follow their request")
cred = {"kind": "credential", "rid": "r1", "ip": VISITOR, "scheme": "basic", "user": "alice", "password": "pw"}
c = anonymize(dict(cred), SALT, attack_rids={"r2"})
check("credential from a non-attack request redacted",
      c["user"] == REDACTED and c["password"] == REDACTED and c["scheme"] == "basic", c)
c2 = anonymize(dict(cred, rid="r2"), SALT, attack_rids={"r2"})
check("credential from an attack request kept", c2["user"] == "alice" and c2["password"] == "pw")

print("\nreverse dns")
ident = {"kind": "identity", "ip": VISITOR, "verdict": "undeclared", "rdns": "49-36-239-37.isp.example"}
check("visitor rdns dropped", anonymize(dict(ident), SALT, attack_rids=set())["rdns"] is None)
bot = dict(ident, verdict="verified", rdns="crawl-66-249-66-1.googlebot.com")
check("verified crawler rdns kept",
      anonymize(bot, SALT, attack_rids=set())["rdns"] == "crawl-66-249-66-1.googlebot.com")

print("\nevents logged before the classifier existed")
legacy = {k: v for k, v in exploit.items() if k != "attacks"}
check("attack status recomputed when the field is absent", attacked(legacy))
legacy_browse = {k: v for k, v in browse.items() if k != "attacks"}
check("plain browse recomputed as not an attack", not attacked(legacy_browse))

print()
if failures:
    print(f"{len(failures)} FAILED: {', '.join(failures)}")
    sys.exit(1)
print("all anonymize checks passed")

"""Tests for mirage_crawl/publish.py: what makes an event safe to publish.

A published beacon token lets anyone fetch the trap it points to and forge a
policy read (or a split-fleet hit) into this dataset; a published honeytoken
lets anyone replay a planted credential. So every token the sensor minted must
be gone from the output, in any encoding the sensor itself would recognise,
and an event that cannot be cleaned must be dropped, not shipped.

Tokens here are minted with a test key by the sensor's own code.

    python tests/test_publish.py
"""

from __future__ import annotations

import base64
import copy
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mirage_crawl import beacons, honeytokens, policies  # noqa: E402
from mirage_crawl.publish import leaks, sanitize  # noqa: E402

failures: list[str] = []
SECRET = b"t" * 32
IP, UA = "198.51.100.7", "ExampleBot/1.0"


def check(name: str, condition: bool, detail: str = "") -> None:
    print(f"  {'PASS' if condition else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not condition else ""))
    if not condition:
        failures.append(name)


def text_of(event) -> str:
    return json.dumps(event)


beacon = beacons.mint(SECRET, "robots", IP, UA)
control = beacons.mint(SECRET, "robots", IP, UA, now=1_800_000_000)
trap = policies.trap_path("robots", beacon)
aws = honeytokens.render(SECRET, "aws_access_key", IP)
ghp = honeytokens.render(SECRET, "git_credentials", IP)
# Shaped like ours but minted with another key: not ours, must be kept.
foreign = beacons.mint(b"x" * 32, "robots", IP, UA)
foreign_aws = honeytokens.render(b"x" * 32, "aws_access_key", IP)

print("token fields")
ev = {"kind": "policy_read", "ip": IP, "standard": "robots", "path": "/robots.txt",
      "token": beacon, "extra_tokens": {"control_allow": control}, "ua": UA}
out = sanitize(ev, SECRET)
check("policy_read keeps what was read", out["standard"] == "robots" and out["path"] == "/robots.txt")
check("policy_read token fields removed", "token" not in out and "extra_tokens" not in out)
check("input event is not modified", ev["token"] == beacon)

print("beacons inside strings")
ev = {"kind": "trap_hit", "path": trap, "token": beacon, "standard": "robots",
      "same_ip": False, "split_fleet": True}
out = sanitize(ev, SECRET)
check("trap path redacted", beacon not in text_of(out) and "[beacon]" in out["path"], out.get("path"))
check("trap verdicts kept", out["split_fleet"] is True and out["standard"] == "robots")

ev = {"kind": "request", "path": trap, "raw_path": trap, "query": None,
      "headers": [["Host", "example.invalid"], ["Referer", "https://example.invalid" + trap]],
      "body": None, "body_encoding": None}
out = sanitize(ev, SECRET)
check("request for a trap URL redacted everywhere", out is not None and beacon not in text_of(out))
check("unrelated header kept", out["headers"][0] == ["Host", "example.invalid"])

ev = {"kind": "request", "path": f"/x/{foreign}/y", "headers": [], "body": None}
out = sanitize(ev, SECRET)
check("token-shaped string from another key kept", out["path"] == f"/x/{foreign}/y")

print("honeytokens")
ev = {"kind": "hunt", "honeytokens_issued": [{"kind": "aws_access_key", "token": aws.value}]}
out = sanitize(ev, SECRET)
check("issued honeytokens keep only their kind", out["honeytokens_issued"] == [{"kind": "aws_access_key"}])

ev = {"kind": "request", "path": "/", "headers": [["X-Api-Key", ghp.value]],
      "body": f"aws_access_key_id={aws.value}\naws_secret_access_key={aws.secret}\n",
      "body_encoding": "utf-8",
      "honeytokens": [{"kind": "aws_access_key", "location": "body", "token": aws.payload, "same_ip": False}]}
out = sanitize(ev, SECRET)
check("replayed honeytokens redacted in headers and body",
      out is not None and ghp.value not in text_of(out) and aws.value not in text_of(out))
check("AWS secret derived from a found key id is redacted too", aws.secret not in text_of(out))
check("replay detection result kept without the token",
      out["honeytokens"] == [{"kind": "aws_access_key", "location": "body", "same_ip": False}])

raw_body = b"\x00\x01" + aws.value.encode() + b"\xff"
ev = {"kind": "request", "path": "/", "headers": [],
      "body": base64.b64encode(raw_body).decode(), "body_encoding": "base64"}
out = sanitize(ev, SECRET)
decoded = base64.b64decode(out["body"])
check("base64 body redacted and re-encoded",
      aws.value.encode() not in decoded and decoded.startswith(b"\x00\x01") and decoded.endswith(b"\xff"))

basic = base64.b64encode(f"admin:{ghp.value}".encode()).decode()
ev = {"kind": "request", "path": "/", "headers": [["Authorization", f"Basic {basic}"]], "body": None}
out = sanitize(ev, SECRET)
auth = out["headers"][0][1]
check("Basic auth credential redacted and re-encoded",
      auth.startswith("Basic ") and ghp.value not in base64.b64decode(auth[6:]).decode())

ev = {"kind": "request", "path": "/", "headers": [["X-Api-Key", foreign_aws.value]], "body": None}
check("honeytoken-shaped value from another key kept",
      sanitize(ev, SECRET)["headers"][0][1] == foreign_aws.value)

print("fail closed")
# Percent-encoding hides the token from the plain-text pass; the sensor's own
# detector still decodes it, so the event must be dropped rather than shipped.
hidden = "".join(f"%{b:02X}" for b in aws.value.encode())
ev = {"kind": "request", "path": "/", "query": f"key={hidden}", "headers": [], "body": None}
check("leak() sees the percent-encoded honeytoken", leaks(ev, SECRET))
check("event that cannot be cleaned is dropped", sanitize(ev, SECRET) is None)
check("clean event has no leaks", not leaks(sanitize(copy.deepcopy({"kind": "tls", "ip": IP, "ja4": "t13d"}), SECRET), SECRET))

print()
if failures:
    print(f"{len(failures)} FAILED: {', '.join(failures)}")
    sys.exit(1)
print("all publish checks passed")

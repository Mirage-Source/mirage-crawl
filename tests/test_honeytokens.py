"""Honeytokens: minting, rendering into credential shapes, and detecting replay."""

from __future__ import annotations

import base64
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mirage_crawl import honeytokens as ht, hunt  # noqa: E402

failures: list[str] = []
SECRET = b"s" * 32
NOW = 1_800_000_000.0


def check(name: str, condition: bool, detail: str = "") -> None:
    print(f"  {'PASS' if condition else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not condition else ""))
    if not condition:
        failures.append(name)


def scan(*, path="/", query=None, headers=(), body=None, ip="9.9.9.9", now=NOW):
    return ht.scan_request(SECRET, path, query, [list(h) for h in headers], body, ip, now=now)


def test_shapes() -> None:
    print("\ncredential shapes")
    pair = ht.render(SECRET, "aws_access_key", "1.2.3.4", now=NOW)
    check("aws key id looks like AKIA + 16 base32", re.fullmatch(r"AKIA[A-Z2-7]{16}", pair.value) is not None, pair.value)
    check("aws secret is 40 base64 chars", re.fullmatch(r"[A-Za-z0-9+/]{40}", pair.secret or "") is not None, str(pair.secret))
    check("aws secret is deterministic for the key id",
          ht.render(SECRET, "aws_access_key", "1.2.3.4", now=NOW).secret == pair.secret)
    check("api key shape", re.fullmatch(r"sk_live_[a-z2-7]{16}[0-9a-f]{8}", ht.render(SECRET, "api_key", "1.2.3.4", now=NOW).value) is not None)
    check("db password shape", re.fullmatch(r"[A-Z2-7]{8}-[A-Z2-7]{8}-\d{2}", ht.render(SECRET, "db_password", "1.2.3.4", now=NOW).value) is not None)
    check("git token shape", re.fullmatch(r"ghp_[a-z2-7]{16}[A-Za-z0-9]{20}", ht.render(SECRET, "git_credentials", "1.2.3.4", now=NOW).value) is not None)
    try:
        ht.render(SECRET, "nope", "1.2.3.4")
        check("unknown kind refused", False)
    except ValueError:
        check("unknown kind refused", True)


def test_detection() -> None:
    print("\ndetection")
    for kind in ht.KINDS:
        cred = ht.render(SECRET, kind, "1.2.3.4", now=NOW)
        hits = scan(query=f"k={cred.value}")
        check(f"{kind} found in a query value", [h["kind"] for h in hits] == [kind], str(hits))
    aws = ht.render(SECRET, "aws_access_key", "1.2.3.4", now=NOW)
    sigv4 = f"AWS4-HMAC-SHA256 Credential={aws.value}/20261025/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=ab"
    hits = scan(headers=[("Authorization", sigv4)])
    check("aws key id found in a SigV4 Authorization header (secret never sent)",
          hits and hits[0]["kind"] == "aws_access_key" and hits[0]["location"] == "header:Authorization", str(hits))
    basic = base64.b64encode(f"admin:{ht.render(SECRET, 'db_password', '1.2.3.4', now=NOW).value}".encode()).decode()
    hits = scan(headers=[("Authorization", f"Basic {basic}")])
    check("password found inside Basic auth", hits and hits[0]["kind"] == "db_password", str(hits))
    hits = scan(query="k=%2541" + aws.value[1:])
    check("percent-encoded key found", hits and hits[0]["kind"] == "aws_access_key", str(hits))
    hits = scan(body=f'{{"aws_access_key_id": "{aws.value}"}}'.encode(), headers=[("Content-Type", "application/json")])
    check("found in a body", hits and hits[0]["location"] == "body", str(hits))


def test_binding() -> None:
    print("\nbinding and forgery")
    aws = ht.render(SECRET, "aws_access_key", "1.2.3.4", now=NOW)
    same = scan(query=f"k={aws.value}", ip="1.2.3.4")[0]
    other = scan(query=f"k={aws.value}", ip="5.6.7.8")[0]
    check("same_ip true for the address it was served to", same["same_ip"] is True, str(same))
    check("same_ip false for another address", other["same_ip"] is False, str(other))
    check("age and mint time recovered", abs(same["minted_at"] - NOW) < 3600 and same["age_s"] >= 0, str(same))
    check("hit has the fixed keys", set(same) == {"kind", "location", "minted_at", "age_s", "same_ip", "token"}, str(same))
    check("wrong secret rejects", ht.scan_request(b"x" * 32, "/", f"k={aws.value}", [], None, "1.2.3.4") == [])
    forged = aws.value[:-1] + ("A" if aws.value[-1] != "A" else "B")
    check("one flipped character is rejected (MAC)", scan(query=f"k={forged}") == [])
    check("random AKIA key is not a hit", scan(query="k=AKIAIOSFODNN7EXAMPLE") == [])
    check("one hit per (kind, location, token)",
          len(scan(query=f"a={aws.value}&b={aws.value}")) == 1)


def test_fill_and_decoys() -> None:
    print("\ndecoy templating")
    text = "ID={{ht:aws_access_key}}\nSECRET={{ht:aws_secret}}\nPW={{ht:db_password}}\nAPI={{ht:api_key}}\nGIT={{ht:git_credentials}}"
    out, issued = ht.fill(SECRET, text, "1.2.3.4", now=NOW)
    check("no placeholder survives", "{{" not in out, out)
    check("issued lists each minted kind once",
          sorted(i["kind"] for i in issued) == sorted(["aws_access_key", "db_password", "api_key", "git_credentials"]), str(issued))
    akid = re.search(r"ID=(\S+)", out).group(1)
    secret = re.search(r"SECRET=(\S+)", out).group(1)
    check("secret belongs to the same key id in the same response",
          secret == ht.render(SECRET, "aws_access_key", "1.2.3.4", now=NOW).secret and akid.startswith("AKIA"))
    hits = scan(body=out.encode(), ip="1.2.3.4")
    check("everything we serve is recognised when replayed", {h["kind"] for h in hits} == {i["kind"] for i in issued}, str(hits))
    out2, _ = ht.fill(SECRET, text, "5.6.7.8", now=NOW)
    check("different requester, different tokens, same layout", out2 != out and out2.count("\n") == out.count("\n"))
    plain, none = ht.fill(SECRET, "nothing here", "1.2.3.4")
    check("text without placeholders is untouched", plain == "nothing here" and none == [])

    for path, family in (("/.env", "dotenv"), ("/.aws/credentials", "aws"),
                         ("/.git-credentials", "git"), ("/.git/config", "git")):
        probe = hunt.match(path)
        check(f"{path} carries a honeytoken decoy",
              probe is not None and probe.family == family and probe.decoy and "{{ht:" in probe.decoy, str(probe))
    check("HEAD is not given a git config body", "{{ht:" not in (hunt.match("/.git/HEAD").decoy or ""))

    # Self-detection only sees a credential used against this host, so the
    # git remote must point here, never at a real third-party service.
    for path in ("/.git-credentials", "/.git/config"):
        decoy = hunt.match(path).decoy
        check(f"{path} remote points at our own host",
              "@{{host}}" in decoy and "github.com" not in decoy, decoy)
    out, _ = ht.fill(SECRET, "https://deploy:{{ht:git_credentials}}@{{host}}/x.git", "1.2.3.4",
                     now=NOW, host="sensor.example.test")
    check("fill substitutes our host", "@sensor.example.test/x.git" in out and "{{" not in out, out)


def test_false_positives() -> None:
    print("\nfalse positives")
    import json
    fixture = json.loads((Path(__file__).resolve().parent / "fixtures" / "benign_requests.json").read_text())
    flagged = [r["raw_path"] for r in fixture if ht.scan_request(SECRET, r["raw_path"], r["raw_query"], r["headers"], None, "1.1.1.1")]
    check(f"0 hits on {len(fixture)} live benign requests", not flagged, str(flagged[:3]))


if __name__ == "__main__":
    test_shapes()
    test_detection()
    test_binding()
    test_fill_and_decoys()
    test_false_positives()
    print("\nFAILURES: " + ", ".join(failures) if failures else "\nall honeytoken checks passed")
    sys.exit(1 if failures else 0)

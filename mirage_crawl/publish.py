"""What makes a logged event safe to publish.

The event log holds two kinds of live secret: beacon tokens (in policy reads,
trap hits, and the path/headers of any request for a trap URL) and the
honeytokens the sensor planted (issued in hunt replies, replayed by attackers
in headers and bodies). Publishing either breaks the instrument: a beacon lets
anyone forge a policy read or a split-fleet hit into the dataset, a honeytoken
lets anyone fake a replay.

So an event is published only after:
  1. token-carrying fields are dropped (the verdicts derived from them stay);
  2. every value the sensor's own key verifies as one of its tokens is
     replaced, wherever it appears -- plain text, a base64 body, a Basic
     Authorization header -- and for an AWS key ID, its derived secret too;
  3. the sensor's own detection, including percent-decoding, finds nothing
     left. If it does, the event is dropped rather than shipped.

Redaction is by verification, never by shape alone: a token-shaped string the
key does not verify (a forgery, someone else's key, random text) is data and
stays.
"""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import hmac
import ipaddress
import re
from typing import Any, Callable

from . import attacks, beacons, decode, honeytokens

BEACON_MARK = "[beacon]"
HONEYTOKEN_MARK = "[honeytoken]"

_TOKEN_FIELDS = ("token", "extra_tokens")
_BEACON_RUN = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{%d}(?![A-Za-z0-9_-])" % beacons.TOKEN_CHARS)


def _ours(secret: bytes, text: str) -> list[honeytokens.Token]:
    found = []
    for shape in honeytokens._SHAPES:
        for m in shape.finditer(text):
            token = honeytokens.parse(secret, "".join(m.groups()))
            if token is not None:
                found.append(token)
    return found


def _has_beacon(secret: bytes, text: str) -> bool:
    return any(beacons.parse(secret, m.group(0)) for m in _BEACON_RUN.finditer(text))


def _basic(value: str) -> str | None:
    """The decoded credentials of a Basic Authorization value, else None."""
    if not value.lower().startswith("basic "):
        return None
    try:
        return base64.b64decode(value[6:].strip(), validate=True).decode("latin-1")
    except (binascii.Error, ValueError):
        return None


def _units(event: Any):
    """Every string in the event, plus the decoded form of encoded ones."""
    if isinstance(event, str):
        yield event
        decoded = _basic(event)
        if decoded is not None:
            yield decoded
    elif isinstance(event, dict):
        if event.get("body_encoding") == "base64" and isinstance(event.get("body"), str):
            try:
                yield base64.b64decode(event["body"]).decode("latin-1")
            except (binascii.Error, ValueError):
                pass
        for value in event.values():
            yield from _units(value)
    elif isinstance(event, (list, tuple)):
        for value in event:
            yield from _units(value)


def leaks(event: Any, secret: bytes) -> bool:
    """True if anything in the event still verifies as one of our tokens,
    including after percent-decoding, as the sensor's own scanner would see it."""
    for text in _units(event):
        for layer in decode.url_layers(text):
            if _has_beacon(secret, layer) or _ours(secret, layer):
                return True
    return False


def _redactor(secret: bytes, aws_secrets: set[str]) -> Callable[[str], str]:
    def beacon(m: re.Match) -> str:
        return BEACON_MARK if beacons.parse(secret, m.group(0)) else m.group(0)

    def honeytoken(m: re.Match) -> str:
        return HONEYTOKEN_MARK if honeytokens.parse(secret, "".join(m.groups())) else m.group(0)

    def redact(text: str) -> str:
        text = _BEACON_RUN.sub(beacon, text)
        for shape in honeytokens._SHAPES:
            text = shape.sub(honeytoken, text)
        for value in aws_secrets:
            text = text.replace(value, HONEYTOKEN_MARK)
        return text

    return redact


def _rewrite(value: Any, redact: Callable[[str], str]) -> Any:
    if isinstance(value, str):
        decoded = _basic(value)
        if decoded is not None:
            cleaned = redact(decoded)
            if cleaned != decoded:
                return "Basic " + base64.b64encode(cleaned.encode("latin-1")).decode("ascii")
            return value
        return redact(value)
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if key == "body" and value.get("body_encoding") == "base64" and isinstance(item, str):
                try:
                    raw = base64.b64decode(item).decode("latin-1")
                except (binascii.Error, ValueError):
                    out[key] = redact(item)
                    continue
                cleaned = redact(raw)
                out[key] = item if cleaned == raw else base64.b64encode(cleaned.encode("latin-1")).decode("ascii")
            else:
                out[key] = _rewrite(item, redact)
        return out
    if isinstance(value, list):
        return [_rewrite(item, redact) for item in value]
    return value


# -- anonymisation: what the public copy may say about a person ---------------

REDACTED = "[redacted]"
_PRIVATE_HEADERS = {"cookie", "authorization", "proxy-authorization"}
_IP_HEADERS = {
    "x-forwarded-for", "x-real-ip", "forwarded", "true-client-ip", "cf-connecting-ip",
    "x-client-ip", "x-originating-ip", "client-ip", "x-cluster-client-ip",
}
_IP_TOKEN = re.compile(r"[0-9A-Fa-f:.]{3,45}")
_BODY_FIELDS = ("body", "body_sha256", "body_encoding")


def anonymize_ip(ip: str, salt: str) -> str:
    """mirage-core's scripts/anonymize.py scheme, so the two datasets join."""
    return "anon_" + hmac.new(salt.encode(), ip.encode(), hashlib.sha256).hexdigest()[:16]


def _hash_ips_in(value: str, salt: str) -> str:
    def sub(m: re.Match) -> str:
        try:
            ipaddress.ip_address(m.group(0))
        except ValueError:
            return m.group(0)
        return anonymize_ip(m.group(0), salt)
    return _IP_TOKEN.sub(sub, value)


def _body_bytes(event: dict) -> bytes | None:
    body = event.get("body")
    if not isinstance(body, str):
        return None
    try:
        return base64.b64decode(body) if event.get("body_encoding") == "base64" else body.encode("utf-8")
    except (binascii.Error, ValueError):
        return body.encode("utf-8", "replace")


def backfill_classifier(event: dict) -> dict:
    """Give a request logged before the classifier existed the same `attacks`,
    `tools` and `oast` fields a live one has, so every published day has one
    schema and a query over several days does not fail on a missing column.
    Run on the raw event, before anything is redacted."""
    if event.get("kind") == "request" and "attacks" not in event:
        event.update(attacks.analyze(
            event.get("raw_path") or event.get("path") or "", event.get("raw_query"),
            event.get("headers") or [], _body_bytes(event),
        ).event_fields())
    return event


def attacked(event: dict) -> bool:
    """Whether a request event carries an attack. Events logged before the
    classifier existed are classified now, so day-one exploit payloads are not
    mistaken for a visitor's private data."""
    if "attacks" not in event:
        backfill_classifier(event)
    return bool(event.get("attacks"))


def anonymize(event: dict, salt: str, attack_rids: set[str]) -> dict:
    """Make an already-sanitized event safe to say about a person. Mutates and
    returns it. `attack_rids` are the request ids classified as attacks, so a
    credential event follows the request it came from."""
    if isinstance(event.get("ip"), str):
        event["ip"] = anonymize_ip(event["ip"], salt)
    kind = event.get("kind")
    private = (kind == "request" and not attacked(event)) or (
        kind == "credential" and event.get("rid") not in attack_rids)

    headers = event.get("headers")
    if isinstance(headers, list):
        for pair in headers:
            if not (isinstance(pair, list) and len(pair) == 2 and isinstance(pair[1], str)):
                continue
            name = str(pair[0]).lower()
            if name in _IP_HEADERS:
                pair[1] = _hash_ips_in(pair[1], salt)
            elif private and name in _PRIVATE_HEADERS:
                pair[1] = REDACTED
    if private and kind == "request":
        for field in _BODY_FIELDS:
            event.pop(field, None)
    if private and kind == "credential":
        for field in ("user", "password"):
            if event.get(field) is not None:
                event[field] = REDACTED
    if kind == "identity" and event.get("verdict") != "verified":
        event["rdns"] = None
    return event


def sanitize(event: dict, secret: bytes) -> dict | None:
    """A copy of the event that is safe to publish, or None if it can't be made safe."""
    out = copy.deepcopy(event)
    for field in _TOKEN_FIELDS:
        out.pop(field, None)
    if isinstance(out.get("honeytokens_issued"), list):
        out["honeytokens_issued"] = [{"kind": h.get("kind")} for h in out["honeytokens_issued"]]
    if isinstance(out.get("honeytokens"), list):
        out["honeytokens"] = [{k: v for k, v in h.items() if k != "token"} for h in out["honeytokens"]]

    # An AWS secret has no shape of its own; it is found through its key ID,
    # which may sit in a different field (key ID in a header, secret in a body).
    aws_secrets = {
        honeytokens.aws_secret_for(secret, token.payload)
        for text in _units(out)
        for token in _ours(secret, text)
        if token.kind == "aws_access_key"
    }
    out = _rewrite(out, _redactor(secret, aws_secrets))
    return None if leaks(out, secret) else out

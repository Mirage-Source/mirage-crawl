"""Honeytokens: fake credentials planted in decoy responses, and the detector
that notices one coming back to this host.

A honeytoken is the beacon idea (see beacons.py) squeezed into the smallest
credential we plant. An AWS access key ID is `AKIA` plus 16 base32 characters,
so 80 bits of payload; a full 152-bit beacon cannot fit. Rather than two
formats, every credential shape carries the same 80-bit token, rendered
differently:

    kind (4b) | hours since EPOCH (16b) | ip hash (20b) | MAC (40b)  = 80 bits

  * kind     which credential shape this was (append-only, see KINDS).
  * hours    when it was served; 16 bits of hours is ~7.5 years from EPOCH,
             after which the stamp saturates (the MAC still verifies).
  * ip hash  enough to say "same address as the one it was served to" with a
             ~1e-6 collision rate. The full identity is in the issuance event
             written at mint time, so the token only has to correlate.
  * MAC      40 bits of keyed BLAKE2s. A forged or typo'd token verifies with
             probability 2^-40, and the only party who could try is the
             attacker, one request at a time, against this host.

No user-agent hash (beacons have one): there is no room, and the replay comes
from a different tool than the one that harvested the file anyway.

SigV4 never transmits the secret access key, only the key ID, so the AWS secret
is a deterministic function of the key ID. We can serve a consistent pair and
still detect use from the ID alone.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import time
from dataclasses import dataclass

from . import decode
from .beacons import EPOCH

# Append-only, like beacons.STANDARD_CODES: renumbering silently changes what
# every token already served to an attacker means. 4 bits, so at most 15.
KINDS: dict[str, int] = {
    "aws_access_key": 1,
    "api_key": 2,
    "db_password": 3,
    "git_credentials": 4,
}
CODE_TO_KIND = {v: k for k, v in KINDS.items()}

_HOURS_MAX = 0xFFFF
_BODY_CAP = 262144


def _key(secret: bytes) -> bytes:
    # Own domain: a leaked honeytoken must reveal nothing about the beacon key.
    return hashlib.blake2b(secret, person=b"honeytoken", digest_size=32).digest()


def _ip_hash(ip: str) -> int:
    return int.from_bytes(hashlib.blake2s(ip.encode("utf-8", "replace"), digest_size=3).digest(), "big") >> 4


def _mac(key: bytes, head: int) -> int:
    digest = hmac.new(key, head.to_bytes(5, "big"), hashlib.blake2s).digest()
    return int.from_bytes(digest[:5], "big")


def mint(secret: bytes, kind: str, ip: str, now: float | None = None) -> str:
    """The 16-character base32 payload for (kind, ip, now)."""
    code = KINDS.get(kind)
    if code is None:
        raise ValueError(f"unknown honeytoken kind: {kind!r}")
    hours = min(max(int(((now if now is not None else time.time()) - EPOCH) // 3600), 0), _HOURS_MAX)
    head = (code << 36) | (hours << 20) | _ip_hash(ip)
    bits = (head << 40) | _mac(_key(secret), head)
    return base64.b32encode(bits.to_bytes(10, "big")).decode("ascii")


@dataclass(frozen=True)
class Token:
    kind: str
    payload: str
    minted_at: float
    ip_hash: int

    def matches_ip(self, ip: str) -> bool:
        return self.ip_hash == _ip_hash(ip)


def parse(secret: bytes, payload: str) -> Token | None:
    """Verify a 16-char payload. None for anything we did not mint."""
    try:
        raw = base64.b32decode(payload.upper())
    except (binascii.Error, ValueError):
        return None
    if len(raw) != 10:
        return None
    bits = int.from_bytes(raw, "big")
    head, mac = bits >> 40, bits & ((1 << 40) - 1)
    if not hmac.compare_digest(mac.to_bytes(5, "big"), _mac(_key(secret), head).to_bytes(5, "big")):
        return None
    kind = CODE_TO_KIND.get(head >> 36)
    if kind is None:
        return None
    return Token(kind, base64.b32encode(raw).decode("ascii"), ((head >> 20) & _HOURS_MAX) * 3600 + EPOCH,
                 head & 0xFFFFF)


# -- rendering --------------------------------------------------------------

@dataclass(frozen=True)
class Credential:
    kind: str
    value: str            # the identifying string (key id, api key, password, token)
    secret: str | None    # AWS only: the secret access key paired with `value`
    payload: str


def _filler(secret: bytes, kind: str, payload: str, n: int, alphabet: str) -> str:
    digest = hmac.new(_key(secret), f"fill:{kind}:{payload}".encode(), hashlib.blake2s).digest()
    return "".join(alphabet[b % len(alphabet)] for b in digest[:n])


_HEX = "0123456789abcdef"
_ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def render(secret: bytes, kind: str, ip: str, now: float | None = None) -> Credential:
    p = mint(secret, kind, ip, now)
    if kind == "aws_access_key":
        raw = hmac.new(_key(secret), f"aws-secret:{p}".encode(), hashlib.blake2b).digest()[:30]
        return Credential(kind, "AKIA" + p, base64.b64encode(raw).decode("ascii"), p)
    if kind == "api_key":
        return Credential(kind, "sk_live_" + p.lower() + _filler(secret, kind, p, 8, _HEX), None, p)
    if kind == "db_password":
        return Credential(kind, f"{p[:8]}-{p[8:]}-{_filler(secret, kind, p, 2, '0123456789')}", None, p)
    return Credential(kind, "ghp_" + p.lower() + _filler(secret, kind, p, 20, _ALNUM), None, p)


_PLACEHOLDER = re.compile(r"\{\{ht:(aws_access_key|aws_secret|api_key|db_password|git_credentials)\}\}")


def blank(text: str) -> str:
    """The decoy with every placeholder emptied: what is served when
    CRAWL_HUNT_DECOYS is off, so a raw placeholder never leaves the sensor."""
    return _PLACEHOLDER.sub("", text.replace("{{host}}", "localhost"))


def fill(
    secret: bytes, text: str, ip: str, now: float | None = None, host: str | None = None
) -> tuple[str, list[dict]]:
    """Replace {{ht:<kind>}} placeholders. One token per kind per response, so
    the key id and secret of an AWS pair belong together. {{host}} becomes our
    own hostname. Returns the text and what was issued (for the issuance event)."""
    text = text.replace("{{host}}", host or "localhost")
    if "{{ht:" not in text:
        return text, []
    now = now if now is not None else time.time()
    cache: dict[str, Credential] = {}

    def cred(kind: str) -> Credential:
        if kind not in cache:
            cache[kind] = render(secret, kind, ip, now)
        return cache[kind]

    def sub(m: re.Match) -> str:
        kind = m.group(1)
        if kind == "aws_secret":
            return cred("aws_access_key").secret or ""
        return cred(kind).value

    out = _PLACEHOLDER.sub(sub, text)
    return out, [{"kind": c.kind, "token": c.value} for c in cache.values()]


# -- detection --------------------------------------------------------------

# Case-sensitive on purpose: the shapes are fixed, and the lookarounds stop a
# match from starting mid-word. Each captures the 16-char payload.
_SHAPES = (
    re.compile(r"(?<![A-Za-z0-9])AKIA([A-Z2-7]{16})(?![A-Za-z0-9])"),
    re.compile(r"(?<![A-Za-z0-9])sk_live_([a-z2-7]{16})[0-9a-f]{8}(?![A-Za-z0-9])"),
    re.compile(r"(?<![A-Za-z0-9])([A-Z2-7]{8})-([A-Z2-7]{8})-\d{2}(?![A-Za-z0-9])"),
    re.compile(r"(?<![A-Za-z0-9])ghp_([a-z2-7]{16})[A-Za-z0-9]{20}(?![A-Za-z0-9])"),
)


def _candidates(text: str):
    for shape in _SHAPES:
        for m in shape.finditer(text):
            yield "".join(m.groups())


def _units(path, query, headers, body):
    if path:
        yield "path", path
    if query:
        yield "query", query
    for name, value in headers:
        value = str(value)
        yield f"header:{name}", value
        if name.lower() == "authorization" and value.lower().startswith("basic "):
            try:
                yield f"header:{name}", base64.b64decode(value[6:].strip(), validate=True).decode("utf-8", "replace")
            except (binascii.Error, ValueError):
                pass
    if body:
        yield "body", body[:_BODY_CAP].decode("latin-1")


def scan_request(secret: bytes, path, query, headers, body, ip: str | None,
                 now: float | None = None) -> list[dict]:
    """Every honeytoken of ours present in the request, verified by MAC."""
    now = now if now is not None else time.time()
    found: dict[tuple[str, str, str], dict] = {}
    for location, text in _units(path, query, headers or [], body):
        for layer in decode.url_layers(text[:32768]):
            for payload in _candidates(layer):
                token = parse(secret, payload)
                if token is None:
                    continue
                key = (token.kind, location, token.payload)
                if key not in found:
                    found[key] = {
                        "kind": token.kind, "location": location, "minted_at": token.minted_at,
                        "age_s": max(0.0, now - token.minted_at),
                        "same_ip": token.matches_ip(ip) if ip else None, "token": token.payload,
                    }
    return list(found.values())

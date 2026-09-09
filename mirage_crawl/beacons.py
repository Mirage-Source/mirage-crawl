"""Stateless, self-authenticating trap tokens.

A beacon is a short opaque string embedded in a path that appears in exactly
one policy file (robots.txt, llms.txt, ...) and is linked from nowhere else on
the site. Fetching that path is therefore proof that the client read that
specific file.

The token carries its own provenance rather than referencing a database row:

    ts (4B) | standard (1B) | ip hash (4B) | ua hash (4B) | HMAC (6B)  = 19B
    -> 26 URL-safe base64 characters

This buys three things that a lookup table does not:

  * No state. The sensor can restart, be reinstalled, or run behind a load
    balancer, and every token minted before the restart still resolves.
  * Split-fleet detection with no join. The token carries a hash of the IP it
    was served to, so at fetch time we can tell immediately whether the client
    fetching the path is the same one that read the policy file.
  * Forgery resistance. Without the secret an attacker cannot mint a token that
    would poison the dataset with a fabricated policy read.

The full identity of the reader is still written to the event log at mint time;
the token only needs to carry enough to correlate the two events.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import struct
import time
from dataclasses import dataclass

# Fixed origin so the 4-byte timestamp stays valid for ~136 years.
EPOCH = 1_735_689_600  # 2025-01-01T00:00:00Z

_PAYLOAD_FMT = ">IB"
_PAYLOAD_LEN = 4 + 1 + 4 + 4
_MAC_LEN = 6
_TOKEN_BYTES = _PAYLOAD_LEN + _MAC_LEN
TOKEN_CHARS = 26

_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{%d}$" % TOKEN_CHARS)

# Every policy surface we serve gets a stable numeric code so the token itself
# records which file leaked the path. Codes are append-only -- never renumber,
# or historical tokens silently change meaning.
STANDARD_CODES: dict[str, int] = {
    "robots": 1,
    "robots_wellknown": 2,
    "llms": 3,
    "llms_full": 4,
    "ai": 5,
    "ai_wellknown": 6,
    "tdm_wellknown": 7,
    "tdm_root": 8,
    "sitemap": 9,
    "sitemap_index": 10,
    "security": 11,
    "security_root": 12,
    "humans": 13,
    "ai_plugin": 14,
    "dnt_policy": 15,
    "gpc": 16,
    "ads": 17,
    "noai_file": 18,
    "meta_noai": 19,
    "nofollow": 20,
    "hidden_link": 21,
    "js_beacon": 22,
    "css_beacon": 23,
    "linked_disallow": 24,
    "control_allow": 25,
}

CODE_TO_STANDARD: dict[int, str] = {v: k for k, v in STANDARD_CODES.items()}


def _h32(value: str) -> bytes:
    return hashlib.blake2s(value.encode("utf-8", "replace"), digest_size=4).digest()


@dataclass(frozen=True)
class Beacon:
    """A parsed, MAC-verified token."""

    token: str
    standard: str
    minted_at: float
    ip_hash: bytes
    ua_hash: bytes

    def age_seconds(self, now: float | None = None) -> float:
        return (now if now is not None else time.time()) - self.minted_at

    def matches_ip(self, ip: str) -> bool:
        return hmac.compare_digest(self.ip_hash, _h32(ip))

    def matches_ua(self, ua: str) -> bool:
        return hmac.compare_digest(self.ua_hash, _h32(ua))


def mint(secret: bytes, standard: str, ip: str, user_agent: str, now: float | None = None) -> str:
    """Create a token recording that `standard` was served to (ip, user_agent)."""
    code = STANDARD_CODES.get(standard)
    if code is None:
        raise ValueError(f"unknown policy standard: {standard!r}")

    ts = int((now if now is not None else time.time()) - EPOCH)
    if ts < 0:
        ts = 0

    payload = struct.pack(_PAYLOAD_FMT, ts, code) + _h32(ip) + _h32(user_agent)
    mac = hmac.new(secret, payload, hashlib.blake2s).digest()[:_MAC_LEN]
    return base64.urlsafe_b64encode(payload + mac).rstrip(b"=").decode("ascii")


def parse(secret: bytes, token: str) -> Beacon | None:
    """Verify and decode a token. Returns None for anything not minted by us."""
    if not _TOKEN_RE.match(token):
        return None

    try:
        raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
    except Exception:
        return None

    if len(raw) != _TOKEN_BYTES:
        return None

    payload, mac = raw[:_PAYLOAD_LEN], raw[_PAYLOAD_LEN:]
    expected = hmac.new(secret, payload, hashlib.blake2s).digest()[:_MAC_LEN]
    if not hmac.compare_digest(mac, expected):
        return None

    ts, code = struct.unpack(_PAYLOAD_FMT, payload[:5])
    standard = CODE_TO_STANDARD.get(code)
    if standard is None:
        return None

    return Beacon(
        token=token,
        standard=standard,
        minted_at=ts + EPOCH,
        ip_hash=payload[5:9],
        ua_hash=payload[9:13],
    )


def find_in_path(secret: bytes, path: str) -> Beacon | None:
    """Scan a request path for a token in any segment.

    Kept independent of the path templates so trap URLs can be shaped to look
    like plausible private content without the parser having to know the shape.
    """
    for segment in path.split("/"):
        if not _TOKEN_RE.match(segment):
            continue
        beacon = parse(secret, segment)
        if beacon is not None:
            return beacon
    return None

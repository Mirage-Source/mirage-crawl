"""JA4 TLS client fingerprinting from a raw ClientHello.

A user agent is a claim. A JA4 fingerprint is a property of the TLS stack that
produced the connection, and changing it means changing the library — not a
string. It is the strongest identity signal available at this layer, which is
why a client claiming to be Chrome while fingerprinting as Go's crypto/tls is
caught cold no matter what headers it sends.

Format (FoxIO JA4 spec):

    ja4 = a_b_c

    a = protocol(1) tls_version(2) sni(1) cipher_count(2) ext_count(2) alpn(2)
    b = sha256(sorted cipher suites, comma separated)[:12]
    c = sha256(sorted extensions without SNI/ALPN + "_" + sig algs)[:12]

GREASE values (RFC 8701) are stripped everywhere, since their whole purpose is
to be random per connection and including them would make every fingerprint
unique.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

# Extensions excluded from the JA4_c hash but still counted in JA4_a.
EXT_SNI = 0x0000
EXT_ALPN = 0x0010
EXT_SUPPORTED_VERSIONS = 0x002B
EXT_SIGNATURE_ALGORITHMS = 0x000D

_VERSION_NAMES = {
    0x0304: "13",
    0x0303: "12",
    0x0302: "11",
    0x0301: "10",
    0x0300: "s3",
    0x0002: "s2",
}


def is_grease(value: int) -> bool:
    """RFC 8701 GREASE: 0x0a0a, 0x1a1a, ... 0xfafa."""
    return (value & 0x0F0F) == 0x0A0A and ((value >> 8) & 0xFF) == (value & 0xFF)


@dataclass(frozen=True)
class ClientHello:
    tls_version: int
    ciphers: tuple[int, ...]
    extensions: tuple[int, ...]
    sig_algs: tuple[int, ...]
    alpn: tuple[str, ...]
    sni: str | None
    supported_versions: tuple[int, ...]

    @property
    def effective_version(self) -> int:
        """Highest non-GREASE version offered, preferring supported_versions."""
        real = [v for v in self.supported_versions if not is_grease(v)]
        if real:
            return max(real)
        return self.tls_version


class ParseError(ValueError):
    pass


def _u16(data: bytes, offset: int) -> int:
    if offset + 2 > len(data):
        raise ParseError("truncated")
    return struct.unpack_from(">H", data, offset)[0]


def parse_client_hello(record: bytes) -> ClientHello:
    """Parse a TLS record containing a ClientHello handshake message."""
    if len(record) < 6:
        raise ParseError("too short for a TLS record")
    if record[0] != 0x16:
        raise ParseError("not a TLS handshake record")

    record_length = _u16(record, 3)
    body = record[5 : 5 + record_length]
    if len(body) < 4:
        raise ParseError("truncated handshake")
    if body[0] != 0x01:
        raise ParseError("not a ClientHello")

    handshake_length = int.from_bytes(body[1:4], "big")
    hello = body[4 : 4 + handshake_length]
    if len(hello) < handshake_length:
        raise ParseError("incomplete ClientHello")

    pos = 0
    legacy_version = _u16(hello, pos)
    pos += 2
    pos += 32  # random

    if pos >= len(hello):
        raise ParseError("truncated at session id")
    session_id_len = hello[pos]
    pos += 1 + session_id_len

    cipher_len = _u16(hello, pos)
    pos += 2
    if cipher_len % 2:
        raise ParseError("odd cipher suite length")
    ciphers = tuple(
        _u16(hello, pos + i) for i in range(0, cipher_len, 2)
    )
    pos += cipher_len

    if pos >= len(hello):
        raise ParseError("truncated at compression")
    compression_len = hello[pos]
    pos += 1 + compression_len

    extensions: list[int] = []
    sig_algs: tuple[int, ...] = ()
    alpn: list[str] = []
    sni: str | None = None
    supported_versions: list[int] = []

    if pos + 2 <= len(hello):
        ext_total = _u16(hello, pos)
        pos += 2
        end = min(pos + ext_total, len(hello))

        while pos + 4 <= end:
            ext_type = _u16(hello, pos)
            ext_len = _u16(hello, pos + 2)
            pos += 4
            payload = hello[pos : pos + ext_len]
            pos += ext_len
            extensions.append(ext_type)

            if ext_type == EXT_SIGNATURE_ALGORITHMS and len(payload) >= 2:
                list_len = _u16(payload, 0)
                sig_algs = tuple(
                    _u16(payload, 2 + i) for i in range(0, min(list_len, len(payload) - 2), 2)
                )
            elif ext_type == EXT_ALPN and len(payload) >= 2:
                list_len = _u16(payload, 0)
                cursor = 2
                while cursor < 2 + list_len and cursor < len(payload):
                    name_len = payload[cursor]
                    cursor += 1
                    alpn.append(payload[cursor : cursor + name_len].decode("ascii", "replace"))
                    cursor += name_len
            elif ext_type == EXT_SNI and len(payload) >= 5:
                cursor = 2
                if cursor < len(payload) and payload[cursor] == 0:
                    name_len = _u16(payload, cursor + 1)
                    # Already punycode on the wire, so ASCII is correct; the
                    # idna codec rejects error handlers outright.
                    sni = (
                        payload[cursor + 3 : cursor + 3 + name_len].decode("ascii", "replace")
                        if name_len
                        else None
                    )
            elif ext_type == EXT_SUPPORTED_VERSIONS and payload:
                list_len = payload[0]
                supported_versions = [
                    _u16(payload, 1 + i) for i in range(0, min(list_len, len(payload) - 1), 2)
                ]

    return ClientHello(
        tls_version=legacy_version,
        ciphers=ciphers,
        extensions=tuple(extensions),
        sig_algs=sig_algs,
        alpn=tuple(alpn),
        sni=sni,
        supported_versions=tuple(supported_versions),
    )


def _truncated_sha256(value: str) -> str:
    if not value:
        # The spec uses all-zeroes when the list is empty, so an absent list is
        # distinguishable from a hash that happens to start with zeroes.
        return "000000000000"
    return hashlib.sha256(value.encode("ascii")).hexdigest()[:12]


def _alpn_code(alpn: tuple[str, ...]) -> str:
    if not alpn:
        return "00"
    first = alpn[0]
    if len(first) < 2:
        return "00"
    return f"{first[0]}{first[-1]}"


def ja4(hello: ClientHello, protocol: str = "t") -> str:
    """Compute the JA4 fingerprint string."""
    ciphers = [c for c in hello.ciphers if not is_grease(c)]
    extensions = [e for e in hello.extensions if not is_grease(e)]
    sig_algs = [s for s in hello.sig_algs if not is_grease(s)]

    version = _VERSION_NAMES.get(hello.effective_version, "00")
    sni_flag = "d" if hello.sni else "i"

    part_a = (
        f"{protocol}{version}{sni_flag}"
        f"{min(len(ciphers), 99):02d}"
        f"{min(len(extensions), 99):02d}"
        f"{_alpn_code(hello.alpn)}"
    )

    part_b = _truncated_sha256(",".join(f"{c:04x}" for c in sorted(ciphers)))

    # SNI and ALPN are excluded from the hash (they vary per destination and
    # per negotiation) but remain counted in part A.
    hashed_exts = sorted(e for e in extensions if e not in (EXT_SNI, EXT_ALPN))
    ext_str = ",".join(f"{e:04x}" for e in hashed_exts)
    sig_str = ",".join(f"{s:04x}" for s in sig_algs)
    part_c = _truncated_sha256(f"{ext_str}_{sig_str}" if sig_str else ext_str)

    return f"{part_a}_{part_b}_{part_c}"


def fingerprint(record: bytes, protocol: str = "t") -> tuple[str, ClientHello]:
    hello = parse_client_hello(record)
    return ja4(hello, protocol), hello


def client_hello_complete(buffer: bytes) -> bool:
    """Whether `buffer` holds a whole TLS record."""
    if len(buffer) < 5:
        return False
    if buffer[0] != 0x16:
        return False
    return len(buffer) >= 5 + _u16(buffer, 3)

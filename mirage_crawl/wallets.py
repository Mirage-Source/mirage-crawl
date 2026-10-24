"""Checksum validation for wallet addresses found in payloads.

A regex alone is not enough once every header is scanned: a 32-character hex
ETag or a beacon token is base58-shaped often enough to be reported as a
bitcoin address, and a wallet address is a *join key* across campaigns, so a
false one would merge unrelated actors. Bitcoin addresses carry checksums
(Base58Check for legacy, bech32/bech32m for segwit), so validate them.
"""

from __future__ import annotations

import hashlib

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58)}


def _b58decode(text: str) -> bytes | None:
    num = 0
    for char in text:
        digit = _B58_INDEX.get(char)
        if digit is None:
            return None
        num = num * 58 + digit
    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad = len(text) - len(text.lstrip("1"))
    return b"\x00" * pad + body


def valid_base58check_btc(address: str) -> bool:
    """Legacy P2PKH (version 0x00, '1...') or P2SH (0x05, '3...')."""
    raw = _b58decode(address)
    if raw is None or len(raw) != 25 or raw[0] not in (0x00, 0x05):
        return False
    return hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()[:4] == raw[21:]


_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_CONST = 1
_BECH32M_CONST = 0x2BC830A3


def _polymod(values: list[int]) -> int:
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for i, gen in enumerate(generators):
            if (top >> i) & 1:
                chk ^= gen
    return chk


def _convertbits(data: list[int], frombits: int, tobits: int) -> list[int] | None:
    acc = bits = 0
    out = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & maxv)
    if bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return out


def valid_segwit_btc(address: str) -> bool:
    """bech32 (witness v0, BIP173) or bech32m (v1+, BIP350) mainnet address."""
    if address.lower() != address and address.upper() != address:
        return False
    address = address.lower()
    hrp, sep, data_part = address.rpartition("1")
    if hrp != "bc" or not sep or len(data_part) < 7:
        return False
    try:
        data = [_BECH32.index(c) for c in data_part]
    except ValueError:
        return False
    version = data[0]
    const = _polymod([ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + data)
    if const != (_BECH32_CONST if version == 0 else _BECH32M_CONST) or version > 16:
        return False
    program = _convertbits(data[1:-6], 5, 8)
    if program is None or not 2 <= len(program) <= 40:
        return False
    return version != 0 or len(program) in (20, 32)


def valid_bitcoin(address: str) -> bool:
    if address.lower().startswith("bc1"):
        return valid_segwit_btc(address)
    return valid_base58check_btc(address)

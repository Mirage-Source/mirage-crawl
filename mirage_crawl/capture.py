"""What gets recorded about a request, independent of how it is routed.

On a honeypot the request *is* the data. Header values carry exploit strings
(Log4Shell lives in User-Agent and X-Api-Version far more than in paths),
Authorization and Cookie carry the credentials an attacker is trying, and the
raw, undecoded path is the only place a double-encoded traversal is visible.
So everything is kept, bounded so a hostile client cannot make one log line
arbitrarily large.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
from dataclasses import dataclass

HEADER_VALUE_CAP = 1024
HEADERS_TOTAL_CAP = 8 * 1024


def header_pairs(
    raw_headers, drop_first: frozenset[str] | set[str] = frozenset()
) -> tuple[list[list[str]], bool]:
    """All headers as [name, value] in wire order, plus a truncation flag.

    Bytes are decoded as latin-1, which maps every byte to one character and
    so loses nothing. `drop_first` removes the first occurrence of headers we
    injected ourselves (the TLS front's), so the list is the client's own.
    Authorization and Cookie are kept verbatim on purpose: here they are
    attacker-supplied credentials, not user secrets.
    """
    pending = {name.lower() for name in drop_first}
    pairs: list[list[str]] = []
    total = 0
    truncated = False
    for raw_name, raw_value in raw_headers:
        name = raw_name.decode("latin-1")
        if name.lower() in pending:
            pending.discard(name.lower())
            continue
        value = raw_value.decode("latin-1")
        if len(value) > HEADER_VALUE_CAP:
            value = value[:HEADER_VALUE_CAP]
            truncated = True
        if total + len(name) + len(value) > HEADERS_TOTAL_CAP:
            truncated = True
            break
        total += len(name) + len(value)
        pairs.append([name, value])
    return pairs, truncated


def split_raw(raw_path: str) -> tuple[str, str | None]:
    """Split aiohttp's raw_path (path plus query, still percent-encoded)."""
    path, sep, query = raw_path.partition("?")
    return path, (query if sep else None)


@dataclass(frozen=True)
class Body:
    data: bytes
    truncated: bool
    declared: int | None  # Content-Length as sent, if any

    def text(self) -> str:
        return self.data.decode("utf-8", "replace")


async def read_body(request, limit: int, timeout: float = 10.0) -> Body | None:
    """Read a request body once, up to `limit` bytes. None if there is none.

    Handlers use the result instead of reading the stream again. A client that
    trickles its body is cut off at `timeout` with whatever arrived.
    """
    if not request.body_exists:
        return None
    declared = request.content_length
    chunks: list[bytes] = []
    size = 0
    truncated = False

    async def _read() -> None:
        nonlocal size
        while size <= limit:
            chunk = await request.content.read(limit + 1 - size)
            if not chunk:
                return
            chunks.append(chunk)
            size += len(chunk)

    try:
        await asyncio.wait_for(_read(), timeout)
    except asyncio.TimeoutError:
        truncated = True
    except Exception:
        truncated = True

    data = b"".join(chunks)
    if len(data) > limit:
        data, truncated = data[:limit], True
    if declared is not None and declared > len(data):
        truncated = True
    return Body(data, truncated, declared)


def body_fields(body: Body | None, log_bytes: int) -> dict:
    """Event fields for a body: a full hash plus a bounded, lossless prefix."""
    if body is None:
        return {}
    fields = {
        "body_len": len(body.data),
        "body_sha256": hashlib.sha256(body.data).hexdigest(),
        "body_truncated": body.truncated,
        "content_length": body.declared,
    }
    try:
        fields["body"] = body.data.decode("utf-8")[:log_bytes]
        fields["body_encoding"] = "utf-8"
    except UnicodeDecodeError:
        fields["body"] = base64.b64encode(body.data[:log_bytes]).decode("ascii")
        fields["body_encoding"] = "base64"
    return fields

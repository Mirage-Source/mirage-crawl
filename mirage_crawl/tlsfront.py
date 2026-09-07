"""TLS-terminating front that fingerprints the ClientHello.

    python -m mirage_crawl.tlsfront --cert fullchain.pem --key privkey.pem

Sits on :443, computes JA4 from the raw ClientHello *before* the handshake
completes, terminates TLS itself, and forwards plaintext to the sensor with the
fingerprint and the real client address injected as headers.

The handshake is driven manually through memory BIOs rather than
`loop.start_tls`, because the ClientHello has to be read off the socket to be
fingerprinted and `start_tls` cannot replay bytes that were already consumed.
Feeding the buffered bytes into an `ssl.SSLObject` is the only way to both see
the ClientHello and still complete the handshake.

Client-supplied copies of the injected headers are stripped before injection.
Without that, any client could set its own JA4 and forge its source address —
which would make the strongest signal in the instrument the easiest to fake.
"""

from __future__ import annotations

import argparse
import asyncio
import ssl
import sys
from pathlib import Path

from . import ja4 as ja4mod

HEAD_LIMIT = 32 * 1024
HELLO_LIMIT = 16 * 1024


def _strip_injected(head: bytes, names: tuple[bytes, ...]) -> bytes:
    """Remove client-supplied copies of headers we are about to inject."""
    lines = head.split(b"\r\n")
    kept = [lines[0]]
    for line in lines[1:]:
        lowered = line.lower()
        if any(lowered.startswith(name) for name in names):
            continue
        kept.append(line)
    return b"\r\n".join(kept)


def inject_headers(head: bytes, ja4: str | None, client_ip: str, ja4_header: str) -> bytes:
    """Insert our headers after the request line of an HTTP head."""
    header_lc = ja4_header.lower().encode("ascii") + b":"
    head = _strip_injected(head, (header_lc, b"x-forwarded-for:", b"x-real-ip:"))

    split = head.find(b"\r\n")
    if split < 0:
        return head

    additions = [f"X-Forwarded-For: {client_ip}".encode("ascii")]
    if ja4:
        additions.append(f"{ja4_header}: {ja4}".encode("ascii"))

    return head[:split] + b"\r\n" + b"\r\n".join(additions) + head[split:]


class RequestRewriter:
    """Injects our headers into every request on a connection, not just the first.

    A keep-alive connection carries many requests. Rewriting only the first
    would leave every later one without a JA4 and without the real client
    address — and since the sensor falls back to the socket peer when
    X-Forwarded-For is absent, those requests would be silently attributed to
    127.0.0.1. Quietly wrong data is worse than missing data, so the stream is
    split on request boundaries and each head is rewritten.

    Bodies are followed by Content-Length. A chunked request switches the
    connection to pass-through, because tracking chunk framing to re-find the
    next head is more machinery than bot traffic justifies; such requests keep
    working, they just do not get a fingerprint.
    """

    HEAD = "head"
    BODY = "body"
    PASSTHROUGH = "passthrough"

    def __init__(self, ja4: str | None, client_ip: str, ja4_header: str) -> None:
        self.ja4 = ja4
        self.client_ip = client_ip
        self.ja4_header = ja4_header
        self.state = self.HEAD
        self.buffer = b""
        self.remaining = 0

    def feed(self, data: bytes) -> bytes:
        self.buffer += data
        out = b""

        while self.buffer:
            if self.state == self.PASSTHROUGH:
                out += self.buffer
                self.buffer = b""

            elif self.state == self.BODY:
                take = min(self.remaining, len(self.buffer))
                out += self.buffer[:take]
                self.buffer = self.buffer[take:]
                self.remaining -= take
                if self.remaining == 0:
                    self.state = self.HEAD

            else:
                end = self.buffer.find(b"\r\n\r\n")
                if end < 0:
                    if len(self.buffer) > HEAD_LIMIT:
                        out += self.buffer
                        self.buffer = b""
                        self.state = self.PASSTHROUGH
                    break

                head, rest = self.buffer[:end], self.buffer[end:]
                out += inject_headers(head, self.ja4, self.client_ip, self.ja4_header)
                out += b"\r\n\r\n"
                self.buffer = rest[4:]

                lowered = head.lower()
                if b"\r\ntransfer-encoding:" in lowered:
                    self.state = self.PASSTHROUGH
                    continue

                self.remaining = 0
                for line in head.split(b"\r\n")[1:]:
                    if line.lower().startswith(b"content-length:"):
                        try:
                            self.remaining = int(line.split(b":", 1)[1].strip())
                        except ValueError:
                            self.remaining = 0
                        break
                self.state = self.BODY if self.remaining > 0 else self.HEAD

        return out


class Front:
    def __init__(
        self,
        cert: str,
        key: str,
        backend_host: str,
        backend_port: int,
        ja4_header: str = "X-Mirage-JA4",
        on_hello=None,
    ) -> None:
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert, key)
        self.context.set_alpn_protocols(["http/1.1"])
        self.backend_host = backend_host
        self.backend_port = backend_port
        self.ja4_header = ja4_header
        self.on_hello = on_hello

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)
        client_ip = peer[0]

        try:
            await self._session(reader, writer, client_ip)
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            pass
        except ssl.SSLError:
            pass
        except Exception as exc:  # never let one connection kill the listener
            print(f"tlsfront: {client_ip} {exc.__class__.__name__}: {exc}", file=sys.stderr)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _session(self, reader, writer, client_ip: str) -> None:
        # 1. Buffer the ClientHello and fingerprint it.
        buffered = b""
        while not ja4mod.client_hello_complete(buffered) and len(buffered) < HELLO_LIMIT:
            chunk = await reader.read(8192)
            if not chunk:
                return
            buffered += chunk

        fingerprint = None
        hello = None
        try:
            fingerprint, hello = ja4mod.fingerprint(buffered)
        except ja4mod.ParseError:
            pass

        if self.on_hello is not None:
            self.on_hello(client_ip, fingerprint, hello)

        # 2. Complete the handshake from the buffered bytes.
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        tls = self.context.wrap_bio(incoming, outgoing, server_side=True)
        incoming.write(buffered)

        while True:
            try:
                tls.do_handshake()
                break
            except ssl.SSLWantReadError:
                pending = outgoing.read()
                if pending:
                    writer.write(pending)
                    await writer.drain()
                chunk = await reader.read(16384)
                if not chunk:
                    return
                incoming.write(chunk)

        pending = outgoing.read()
        if pending:
            writer.write(pending)
            await writer.drain()

        # 3. Connect to the sensor and pump both directions.
        backend_reader, backend_writer = await asyncio.open_connection(
            self.backend_host, self.backend_port
        )

        # Whichever direction ends first ends the session, and the other is
        # cancelled. Awaiting both would deadlock: when the client goes away
        # the backend-to-client pump is still blocked on a socket that will
        # never produce another byte.
        pumps = [
            asyncio.ensure_future(
                self._to_backend(reader, writer, tls, incoming, outgoing,
                                 backend_writer, fingerprint, client_ip)
            ),
            asyncio.ensure_future(self._to_client(backend_reader, writer, tls, outgoing)),
        ]
        try:
            done, pending_tasks = await asyncio.wait(
                pumps, return_when=asyncio.FIRST_COMPLETED
            )
            for task in pending_tasks:
                task.cancel()
            await asyncio.gather(*pending_tasks, return_exceptions=True)
            for task in done:
                exc = task.exception()
                if exc is not None and not isinstance(
                    exc, (ConnectionResetError, BrokenPipeError, ssl.SSLError)
                ):
                    raise exc
        finally:
            backend_writer.close()
            try:
                await backend_writer.wait_closed()
            except Exception:
                pass

    async def _to_backend(
        self, reader, writer, tls, incoming, outgoing, backend_writer, fingerprint, client_ip
    ) -> None:
        rewriter = RequestRewriter(fingerprint, client_ip, self.ja4_header)

        while True:
            plaintext = b""
            while True:
                try:
                    chunk = tls.read(16384)
                except ssl.SSLWantReadError:
                    break
                except (ssl.SSLZeroReturnError, ssl.SSLError):
                    return
                if not chunk:
                    return
                plaintext += chunk

            if plaintext:
                rewritten = rewriter.feed(plaintext)
                if rewritten:
                    backend_writer.write(rewritten)
                    await backend_writer.drain()

            chunk = await reader.read(16384)
            if not chunk:
                return
            incoming.write(chunk)

            pending = outgoing.read()
            if pending:
                writer.write(pending)
                await writer.drain()

    async def _to_client(self, backend_reader, writer, tls, outgoing) -> None:
        while True:
            chunk = await backend_reader.read(16384)
            if not chunk:
                return
            try:
                tls.write(chunk)
            except ssl.SSLError:
                return
            pending = outgoing.read()
            if pending:
                writer.write(pending)
                await writer.drain()


async def serve(args) -> None:
    def log_hello(ip: str, fingerprint, hello) -> None:
        sni = getattr(hello, "sni", None)
        alpn = ",".join(getattr(hello, "alpn", ()) or ())
        print(f"{ip}  ja4={fingerprint or '-'}  sni={sni or '-'}  alpn={alpn or '-'}")

    front = Front(
        cert=args.cert,
        key=args.key,
        backend_host=args.backend_host,
        backend_port=args.backend_port,
        ja4_header=args.ja4_header,
        on_hello=log_hello if args.verbose else None,
    )
    server = await asyncio.start_server(front.handle, args.host, args.port)
    addresses = ", ".join(str(s.getsockname()) for s in server.sockets or ())
    print(f"mirage-crawl TLS front on {addresses} -> {args.backend_host}:{args.backend_port}")
    async with server:
        await server.serve_forever()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mirage-crawl-tlsfront")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--cert", required=True, help="PEM certificate chain")
    parser.add_argument("--key", required=True, help="PEM private key")
    parser.add_argument("--backend-host", default="127.0.0.1")
    parser.add_argument("--backend-port", type=int, default=8080)
    parser.add_argument("--ja4-header", default="X-Mirage-JA4")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    for path in (args.cert, args.key):
        if not Path(path).exists():
            print(f"missing {path}", file=sys.stderr)
            print(
                "Get a real certificate — crawlers that validate will refuse a self-signed one:\n"
                "  certbot certonly --standalone -d docs.example.org",
                file=sys.stderr,
            )
            return 1

    try:
        asyncio.run(serve(args))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Runtime configuration, read once from the environment."""

from __future__ import annotations

import hashlib
import os
import re
import secrets
from dataclasses import dataclass, field
from pathlib import Path


def _flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _path_or_none(name: str, default: str) -> Path | None:
    """A path setting where an empty value disables the feature."""
    raw = os.environ.get(name, default)
    return Path(raw) if raw else None


@dataclass
class Config:
    host: str = "0.0.0.0"
    port: int = 8080
    sensor_id: str = "crawl-01"
    origin: str = "http://localhost:8080"

    log_dir: Path = field(default_factory=lambda: Path("data/events"))
    secret_file: Path = field(default_factory=lambda: Path("data/beacon.secret"))
    ranges_file: Path = field(default_factory=lambda: Path("config/crawler_ranges.json"))

    site_seed: str = "mirage-crawl-v1"
    projects: int = 40
    pages_per_project: int = 12
    fork_every: int = 5

    verify_identity: bool = True
    dns_timeout: float = 3.0
    identity_ttl: float = 3600.0

    # Serving a policy file mints a token. A client that refetches robots.txt in
    # a tight loop would otherwise mint thousands, so identical (ip, ua) pairs
    # reuse a token within this window. Set to 0 to mint on every request.
    beacon_reuse_seconds: int = 300

    # Header trust is a property of the listener a request arrived on, never
    # of the header itself. The TLS front connects over `front_socket`, and
    # only requests on that socket may set X-Forwarded-For and the JA4 header.
    # The admin socket serves /healthz and nothing else.
    front_socket: Path | None = field(default_factory=lambda: Path("data/front.sock"))
    admin_socket: Path | None = field(default_factory=lambda: Path("data/admin.sock"))

    # For a reverse proxy you cannot avoid: requests on `proxy_listen`
    # ("host:port") take their address from `trust_proxy_header`. Nothing on
    # the public port ever does.
    trust_proxy_header: str = ""
    proxy_listen: str = ""

    # Serve plausible responses to compute-hijack probes. A 404 ends the
    # interaction; a decoy makes the bot proceed to the stage that carries the
    # payload, which is the only stage with wallet addresses in it. The decoys
    # are static JSON and nothing is ever executed.
    hunt_decoys: bool = True

    # Request bodies are read once, on every route, up to body_bytes. The
    # sha256 covers everything captured; the event carries a prefix of
    # body_log_bytes so one hostile upload cannot bloat the log.
    body_bytes: int = 65_536
    body_log_bytes: int = 16_384

    # Header carrying the JA4 fingerprint, injected by the TLS front.
    ja4_header: str = "X-Mirage-JA4"

    # Server header sent on every response. aiohttp's default announces the
    # Python/aiohttp stack, which is a honeypot tell; a plain, common value
    # hides it. Per-persona overrides come later (a PHP persona wants a
    # PHP-shaped Server + X-Powered-By).
    server_header: str = "nginx"

    @classmethod
    def from_env(cls) -> "Config":
        cfg = cls(
            host=os.environ.get("CRAWL_HOST", "0.0.0.0"),
            port=_int("CRAWL_PORT", 8080),
            sensor_id=os.environ.get("CRAWL_SENSOR_ID", "crawl-01"),
            origin=os.environ.get("CRAWL_ORIGIN", "").rstrip("/"),
            log_dir=Path(os.environ.get("CRAWL_LOG_DIR", "data/events")),
            secret_file=Path(os.environ.get("CRAWL_SECRET_FILE", "data/beacon.secret")),
            ranges_file=Path(os.environ.get("CRAWL_RANGES_FILE", "config/crawler_ranges.json")),
            site_seed=os.environ.get("CRAWL_SITE_SEED", "mirage-crawl-v1"),
            projects=_int("CRAWL_PROJECTS", 40),
            pages_per_project=_int("CRAWL_PAGES_PER_PROJECT", 12),
            fork_every=_int("CRAWL_FORK_EVERY", 5),
            verify_identity=_flag("CRAWL_VERIFY_IDENTITY", True),
            beacon_reuse_seconds=_int("CRAWL_BEACON_REUSE_SECONDS", 300),
            front_socket=_path_or_none("CRAWL_FRONT_SOCKET", "data/front.sock"),
            admin_socket=_path_or_none("CRAWL_ADMIN_SOCKET", "data/admin.sock"),
            trust_proxy_header=os.environ.get("CRAWL_TRUST_PROXY_HEADER", ""),
            proxy_listen=os.environ.get("CRAWL_PROXY_LISTEN", ""),
            hunt_decoys=_flag("CRAWL_HUNT_DECOYS", True),
            # CRAWL_HUNT_BODY_BYTES is the old name, kept as an alias.
            body_bytes=_int("CRAWL_BODY_BYTES", _int("CRAWL_HUNT_BODY_BYTES", 65_536)),
            body_log_bytes=_int("CRAWL_BODY_LOG_BYTES", 16_384),
            ja4_header=os.environ.get("CRAWL_JA4_HEADER", "X-Mirage-JA4"),
            server_header=os.environ.get("CRAWL_SERVER_HEADER", "nginx"),
        )
        if not cfg.origin:
            cfg.origin = f"http://localhost:{cfg.port}"
        return cfg

    def load_secret(self) -> bytes:
        """Load or create the beacon signing key.

        The key must be stable across restarts or every token minted before the
        restart stops verifying, silently discarding trap hits. So this never
        regenerates an existing file: a file that exists but cannot be read as
        a key is an error the operator has to look at, not something to paper
        over with a fresh key.

        Format: new keys are 64 hex characters (a trailing newline is allowed,
        so `echo`-written keys work). Anything else of 32+ bytes is a legacy
        raw key and is used byte-for-byte -- no stripping, because a random
        key can legitimately end in a whitespace byte.
        """
        env_secret = os.environ.get("CRAWL_BEACON_SECRET")
        if env_secret:
            return hashlib.blake2b(env_secret.encode("utf-8"), digest_size=32).digest()

        path = self.secret_file
        path.parent.mkdir(parents=True, exist_ok=True)

        if path.exists():
            return _parse_secret(path.read_bytes(), path)

        key = secrets.token_bytes(32)
        # O_EXCL: if another process created the file between our exists()
        # check and now, fail rather than overwrite whatever it wrote.
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return _parse_secret(path.read_bytes(), path)
        with os.fdopen(fd, "w", encoding="ascii") as handle:
            handle.write(key.hex() + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return key


_HEX_KEY_RE = re.compile(rb"^[0-9a-fA-F]{64}(\r?\n)?$")


def _parse_secret(raw: bytes, path: Path) -> bytes:
    if _HEX_KEY_RE.match(raw):
        return bytes.fromhex(raw.decode("ascii").strip())
    if len(raw) >= 32:
        return raw
    raise ValueError(
        f"{path} exists but is not a usable beacon key ({len(raw)} bytes). "
        "Refusing to replace it: every token minted under the old key would stop "
        "verifying. Restore the original file, or delete it deliberately."
    )

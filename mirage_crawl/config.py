"""Runtime configuration, read once from the environment."""

from __future__ import annotations

import hashlib
import os
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

    trust_proxy_header: str = ""

    # Serve plausible responses to compute-hijack probes. A 404 ends the
    # interaction; a decoy makes the bot proceed to the stage that carries the
    # payload, which is the only stage with wallet addresses in it. The decoys
    # are static JSON and nothing is ever executed.
    hunt_decoys: bool = True
    hunt_body_bytes: int = 65_536

    # Header carrying the JA4 fingerprint, injected by the TLS front.
    ja4_header: str = "X-Mirage-JA4"

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
            trust_proxy_header=os.environ.get("CRAWL_TRUST_PROXY_HEADER", ""),
            hunt_decoys=_flag("CRAWL_HUNT_DECOYS", True),
            hunt_body_bytes=_int("CRAWL_HUNT_BODY_BYTES", 65_536),
            ja4_header=os.environ.get("CRAWL_JA4_HEADER", "X-Mirage-JA4"),
        )
        if not cfg.origin:
            cfg.origin = f"http://localhost:{cfg.port}"
        return cfg

    def load_secret(self) -> bytes:
        """Load or create the beacon signing key.

        The key must be stable across restarts or every token minted before the
        restart stops verifying, silently discarding trap hits. It is generated
        once and persisted with owner-only permissions.
        """
        path = self.secret_file
        path.parent.mkdir(parents=True, exist_ok=True)

        env_secret = os.environ.get("CRAWL_BEACON_SECRET")
        if env_secret:
            return hashlib.blake2b(env_secret.encode("utf-8"), digest_size=32).digest()

        if path.exists():
            raw = path.read_bytes().strip()
            if len(raw) >= 32:
                return raw

        raw = secrets.token_bytes(32)
        path.write_bytes(raw)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return raw

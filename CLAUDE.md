# mirage-crawl — working context

HTTP sensor: instruments robots.txt/llms.txt/ai.txt-class policy surfaces
with unforgeable per-request beacons, verifies claimed-crawler identity
(FCrDNS, published ranges, JA4 TLS fingerprinting), and detects
compute-hijack reconnaissance. Sibling to `mirage-core`, same idea applied to
HTTP instead of SSH. See `README.md` for the full design and
`docs/UPDATE-tls-and-hunt.md` for the JA4/hunt addition.

Convention and cross-project defaults are in `~/.claude/CLAUDE.md` and
`../CLAUDE.md` (the Mirage-wide root) — this file holds only what's specific
to mirage-crawl. Nontrivial choices go in `DECISIONS.md`, logged live as
they're made, not backfilled.

## Things that are easy to get wrong here

- **The beacon signing key (`data/beacon.secret`) must stay stable across
  restarts.** Rotating or losing it invalidates every token minted so far —
  in-flight trap hits stop verifying and go undetected, not loudly rejected.
  Never regenerate it as a side effect of unrelated config changes.
- **`STANDARD_CODES` in `beacons.py` is append-only.** Renumbering an existing
  code silently changes what historical tokens mean — a token minted last
  week would decode to a different policy standard after the change. Add new
  codes at the end; never reuse or reassign one.
- **`CRAWL_SITE_SEED` is fix-once, not a tunable.** Changing it regenerates
  every page and ETag, which breaks conditional-request measurement
  continuity (before/after become incomparable). Treat it like a migration,
  not a config value to tweak.
- **Per-request rendering is instrumentation, not cloaking.** Every requester
  gets identical substantive rules (same Disallow/Allow semantics); only the
  opaque trap token differs per requester. If a change ever makes the
  sensor serve *different substantive rules* to different clients, that's a
  line this project has explicitly committed not to cross — flag it rather
  than shipping it.
- **`config/crawler_ranges.json` can go stale.** A stale (not missing) range
  file is the dangerous state — addresses an operator added after the
  snapshot get called impersonators. Don't treat a range file's mere presence
  as sufficient; check when `scripts/refresh_ranges.py` last ran before
  trusting an `impersonating` verdict in anything published.
- **Run on :80 directly, not behind a reverse proxy, when possible.** A proxy
  normalises header order, which is the fallback identity signal below JA4.
  If a proxy is unavoidable, `CRAWL_TRUST_PROXY_HEADER` exists but the
  fingerprint becomes the proxy's, not the client's — say so wherever that
  data surfaces.
- **This is a decoy host.** `CRAWL_HUNT_DECOYS=true` deliberately makes the
  host look exploitable to attract compute-hijack recon. Nothing is ever
  executed (no process-execution import in the codebase) and no packet ever
  leaves — keep that ceiling intact in any change to `hunt.py`. Don't deploy
  this on a domain anyone cares about.

## Relationship to the rest of Mirage

Standalone today — no database, no shared state, not yet wired to
`mirage-fleet` or `mirage-web`. See the root `../CLAUDE.md` for the target
direction (an operator picking sensor types from `mirage-web`, `mirage-fleet`
staying sensor-agnostic) that this repo will eventually plug into. Wallet
addresses extracted by `hunt.py`'s payload scanner are the join key to
`mirage-core`'s SSH-side extraction — the same actor dropping a miner over
SSH and probing GPU infra over HTTP should become one entity, not two,
whenever that correlation gets built.

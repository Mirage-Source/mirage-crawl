# Decision log

Append-only. One entry per nontrivial choice, in this shape:

```
## YYYY-MM-DD — <short title>
**Chose:** <what>
**Why:** <reasoning>
**Alternative considered:** <what else, and why not>
**My answer before seeing yours:** <my guess, or "n/a" if none was asked>
```

This log starts empty as of the file's creation (2026-09-09) — the design
choices already made in this repo (beacon token structure, no-database
architecture, FCrDNS + published-range identity verification, decoy-based
compute-hijack detection, etc.) predate this file and are documented in
`README.md` and `docs/UPDATE-tls-and-hunt.md` instead of being backfilled
here. New nontrivial choices from this point forward go here, live.

## 2026-09-09 — Containerized deploy: named volumes, JA4 deferred to a second pass

**Chose:** `Dockerfile` + `docker-compose.yml` added for a real deploy (same
Nuremberg VPS as `mirage-core`, ports 80/443 free there). `/app/data` and
`/app/config` mount as named Docker volumes, not host bind mounts, and the
Dockerfile creates + chowns `/app/data` to the non-root `crawl` user before
`USER crawl` -- same fix `mirage-core`'s Dockerfile needed after its
`fleet_queue` volume shipped root-owned and silently dropped writes.
Bind mounts would reintroduce that exact bug here (a bind mount's ownership
comes from the host directory, not the image). Shipping without JA4/
`tlsfront` for now -- plain sensor + header-order fingerprinting only; JA4
needs a second container (`tlsfront`, which manually reads the raw TLS
ClientHello before completing the handshake) plus a cert, neither of which
exist yet. A standard reverse proxy (Caddy, nginx) can't substitute for
`tlsfront` here -- terminating TLS itself consumes the raw ClientHello
before the app ever sees it, which is the one thing JA4 needs.
**Why:** avoid repeating a bug found and fixed hours earlier in a sibling
repo, and ship the sensor sooner rather than blocking launch on a TLS-
fingerprinting component that's a genuine second phase, not a launch
blocker -- header-order fingerprinting still works meanwhile, just weaker.
**Alternative considered:** Caddy in front of the sensor, for TLS +
convenience. Rejected once it was clear Caddy terminating TLS itself
defeats JA4 structurally, not just as an implementation detail -- Caddy
could still front a *future* cert-only role, but not replace `tlsfront`.
**My answer before seeing yours:** n/a -- user asked directly whether Caddy
could substitute once JA4's actual requirement (raw ClientHello access) was
explained; this entry reflects that exchange, not an unprompted model
choice.

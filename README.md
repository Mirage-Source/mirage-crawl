# mirage-crawl

A measurement sensor for automated web clients. It answers questions that an
access log cannot:

- **Which** machine-readable policy file did this client actually read —
  `robots.txt`, `llms.txt`, `ai.txt`, TDMRep, a meta tag, or none of them?
- Did it read the file and **obey** it, read it and **ignore** it, or read it
  and **mine it for URLs**?
- Is the machine that read the policy the **same machine** that crawled?
- Is the client **who it says it is**?
- How much of its traffic is **waste** — refetching content it already has?

It also detects **compute-hijack reconnaissance** — bots sweeping for exposed
GPU and cluster infrastructure to take over — and fingerprints every client's
TLS stack with JA4. See
[docs/UPDATE-tls-and-hunt.md](docs/UPDATE-tls-and-hunt.md).

It is a sibling to `mirage-core`. Same idea — instrument a surface, capture
what arrives, treat your own corpus as suspect — applied to HTTP instead of
SSH. It runs on the same host, shares no state with it, and needs no database.

---

## Quick start

```bash
cd mirage-crawl
python -m venv .venv && .venv/bin/pip install -r requirements.txt
python run.py
```

Then, in another terminal:

```bash
python scripts/demo.py
```

That drives eight synthetic crawler personas at a throwaway instance and prints
the report, so you can see what every detector looks like when it fires before
a single real crawler shows up.

```bash
python tests/test_units.py    # 44 checks
python tests/test_e2e.py      # 31 checks, real server, real requests
```

---

## The core idea: beacons

A path that appears in **exactly one policy file and nowhere else on the
site**. It is not linked. It is not in the sitemap. A crawler cannot find it by
crawling. So a request for it is proof — not inference — that the client read
that specific file.

Each beacon is a 26-character token that carries its own provenance:

```
ts (4B) | standard (1B) | hash of the IP it was served to (4B) | hash of the UA (4B) | HMAC (6B)
```

Three consequences:

**No database.** The token verifies itself. Restart the sensor, reinstall it,
put it behind a load balancer — every token minted beforehand still resolves.
The only state that must survive is the signing key in `data/beacon.secret`.

**Split-fleet detection for free.** The token knows which address it was served
to. When the trap is fetched, comparing that hash against the fetching address
is one operation — no join, no lookup. If they differ, one machine read your
policy and a different machine did the crawling. That is the single most
interesting thing this sensor can catch, and it is invisible to every other
method.

**Forgery resistance.** Without the key nobody can mint a token that would
inject a fake policy read into your dataset. Every single-character mutation of
a valid token is rejected — that is tested.

### Why this separates cases nothing else can

| | fetched a disallowed path | read the policy | verdict |
|---|---|---|---|
| Never read robots.txt, crawled everything | yes | no | **ignorant** |
| Read robots.txt, crawled anyway | yes | yes | **defiant** |
| Read robots.txt, obeyed | no | yes | **compliant** |
| Read robots.txt **to find URLs** | yes, an unlinked one | yes | **miner** |

Rows 1 and 2 are identical in an access log. Row 4 is invisible in one — a
miner's requests look like ordinary crawling unless *you planted the URL*.

---

## Every trap, and what each one proves

| Trap | Where it appears | A hit proves |
|---|---|---|
| `robots` | `robots.txt` `Disallow:` | read robots.txt **and** used it as a URL source |
| `robots_wellknown` | `/.well-known/robots.txt` | probes the non-standard location |
| `llms`, `llms_full` | `llms.txt`, `llms-full.txt` | reads the LLM-specific convention |
| `ai`, `ai_wellknown` | `ai.txt` (both locations) | reads the Spawning opt-out |
| `tdm_wellknown`, `tdm_root` | `tdmrep.json` | reads the W3C TDM reservation |
| `sitemap`, `sitemap_index` | `sitemap.xml` | uses sitemaps (an invitation, not a violation) |
| `security`, `security_root` | `security.txt` | reads RFC 9116 |
| `humans` | `humans.txt` | reads it at all — almost nothing does |
| `ai_plugin` | `/.well-known/ai-plugin.json` | probes for plugin manifests |
| `dnt_policy`, `gpc` | DNT / Global Privacy Control | reads privacy signals |
| `ads` | `ads.txt` | ad-tech tooling rather than a crawler |
| `noai_file` | `/.noai` | reads the file-level noai convention |
| `meta_noai` | link on a page carrying `<meta name="robots" content="noai">` | **ignores page-level noai** |
| `nofollow` | link with `rel="nofollow"` | ignores nofollow |
| `hidden_link` | link inside `display:none` | not a browser, and not careful |
| `js_beacon` | fetched only by executing JavaScript | **runs JS** |
| `css_beacon` | `background-image` in the stylesheet | parses CSS like a browser |
| `control_allow` | robots.txt `Allow:`, unlinked | read the file and mined it for URLs *without* violating — the specificity control |

Plus two **stable** paths, identical for every visitor
(`STABLE_DISALLOW_UNLINKED`, `STABLE_ALLOW_UNLINKED`). A fleet sharing one
cached `robots.txt` still trips these, and they survive caching proxies that
would flatten a per-request token.

`control_allow` matters more than it looks. If a client fetches the disallowed
beacon *and* the allowed one, it is not evaluating policy — it is scraping URLs
out of the file. If it fetches only the allowed one, it read the file and
respected the distinction. Without that control you cannot tell mining from
compliance.

Note the difference between **prohibition** files (robots, ai, tdm, llms) and
**invitation** files (sitemap, humans, security). Their trap paths sit under
different prefixes, so `disallowed` is true for the first group and false for
the second. Following a sitemap URL is a crawler doing its job; following a
robots.txt `Disallow` URL is not.

---

## Getting the truth out of a lying client

Five independent mechanisms, none of which the client controls.

**1 · Forward-confirmed reverse DNS.** Reverse-resolve the address, then
forward-resolve the name it gives and require the original address back. An
impersonator controls neither the reverse zone for the address nor the forward
record for the domain. Google, Bing, Yandex, Apple and Ahrefs all document this
as *the* verification method. Strongest signal available.

**2 · Published address ranges.** OpenAI, Anthropic, Perplexity, Apple and
Amazon publish the CIDR blocks their crawlers use. A UA claiming GPTBot from
outside every published OpenAI block is an impersonation, full stop.

**3 · Header order.** Every HTTP client emits headers in a sequence baked into
its implementation, and almost nobody spoofs it. A request claiming Chrome
whose header order matches Go's `net/http` is lying, and the ordering is far
harder to fake convincingly than the string it contradicts. Captured verbatim
from `raw_headers` and hashed for grouping.

**4 · Capability probes.** The `js_beacon` is fetched only if JavaScript runs.
The `css_beacon` only if the stylesheet was parsed. A client claiming to be
Chrome that never touches either is not Chrome.

**5 · Header-set thinness.** Real browser navigations carry
`accept-language`, `accept-encoding`, `sec-fetch-mode`, `sec-ch-ua`. A browser
claim with fewer than two of those raises `browser_claim_thin_headers`.

### The verdicts are deliberately careful

`unverifiable` is kept strictly separate from `impersonating`. An operator with
no published verification mechanism cannot be confirmed *or* refuted, and
recording that as a failure would manufacture a finding. Only a claim
contradicted by a mechanism **the operator themselves publishes** counts as
impersonation.

This is why a missing range file is safe: absent ranges yield `unverifiable`.
A *stale* range file is the dangerous state, because addresses the operator
added after your snapshot get called liars. Refresh before you publish
anything:

```bash
python scripts/refresh_ranges.py
```

`config/crawler_ranges.json` ships with the publication URLs and an empty
`operators` map. **Verify those URLs before relying on them** — operators move
them, and the file says so.

---

## What each file does

```
run.py                     Entrypoint. Reads env config, builds the app, serves.

mirage_crawl/
  config.py                Environment config. Loads or generates the beacon
                           signing key and persists it 0600. The key must stay
                           stable across restarts or tokens minted earlier stop
                           verifying and trap hits are silently dropped.

  beacons.py               Mint, parse and locate tokens. 19 bytes packed into
                           26 URL-safe chars: timestamp, standard code, IP hash,
                           UA hash, truncated HMAC. `find_in_path` scans a
                           request path for any segment shaped like a token, so
                           trap URLs can look like plausible private content
                           without the parser knowing their shape.
                           STANDARD_CODES is append-only — renumbering it
                           silently changes what historical tokens mean.

  policies.py              All 18 policy surfaces and their renderers, the trap
                           path template per standard, and `disallowed()`.
                           Files are rendered per request so the beacon is
                           fresh. The substantive rules are identical for every
                           requester; only the opaque token differs.

  sitegen.py               Deterministic site. Projects, pages, and forks that
                           duplicate an earlier project with one changed
                           paragraph. Nothing is stored — every page derives
                           from its path via a seeded hash, so content, ETag and
                           Last-Modified are stable across restarts. That
                           stability is what makes conditional-request
                           measurement meaningful. Also mints the per-page
                           canary strings.

  fingerprint.py           Per-request client fingerprint: header order and its
                           hash, the declared-crawler table (~45 patterns with
                           the verification mechanism each operator publishes),
                           browser-claim detection, and the thin-header signal.

  identity.py              FCrDNS and published-CIDR verification, the four
                           verdicts, and a TTL cache so DNS never lands on the
                           request path. RangeTable loads blocks from config and
                           refuses to call anything an impersonation when it has
                           no ranges for that operator.

  eventlog.py              Append-only JSONL, one file per UTC day, written by a
                           background task through a bounded queue. If the disk
                           cannot keep up, events are dropped and counted rather
                           than consuming unbounded memory — a gap in the record
                           is recoverable, an OOM-killed sensor is not.
                           `read_events` iterates back, skipping malformed lines.

  server.py                The aiohttp application. Routes, the recording
                           middleware, conditional-request handling, and the
                           catch-all where trap hits land. Identity verification
                           is fired off as a background task, deduplicated per
                           (address, claim), and never blocks a response.

  classify.py              Events -> per-client profiles. The four-way
                           compliance state machine, fleet aggregation by
                           (UA, claimed crawler), waste ratio, duplicate-content
                           counting, capability flags.

  report.py                CLI report: compliance split, the crawler x standard
                           adoption matrix, identity verdicts, split fleets,
                           waste, capability, top clients. `--json` emits the
                           profiles for downstream analysis.

scripts/
  refresh_ranges.py        Fetches published CIDR lists into the config file.
                           Keeps existing blocks when a fetch fails, because a
                           partial list produces false accusations.
  demo.py                  Eight synthetic personas against a throwaway sensor,
                           then the report. Shows every detector firing.

tests/
  test_units.py            Beacons (including every single-char mutation),
                           determinism, fork near-duplication, UA precedence,
                           all four identity verdicts, the state machine.
  test_e2e.py              Boots the real server and drives real HTTP at it:
                           polite, ignorant, defiant, miner, split fleet,
                           conditional refetch, liar. Asserts against the log.

config/crawler_ranges.json Publication URLs plus the fetched blocks.
deploy/mirage-crawl.service systemd unit; binds :80 via CAP_NET_BIND_SERVICE
                           without running as root.
```

---

## The event log

Four record types, all JSON objects, one per line, in `data/events/YYYY-MM-DD.jsonl`.

**`request`** — every request. Address, method, path, status, bytes, duration,
`header_order` (verbatim, in wire order) and its hash, `claimed_crawler`,
`claims_browser`, `browser_header_score`, `conditional`, `signals`,
`resource` (what was served), `content_hash`, `fork_of`.

**`policy_read`** — a policy surface was served. Address, `standard`, the
minted `token`, UA, claimed crawler.

**`trap_hit`** — a beacon path was fetched. `standard` (which file leaked it),
`minted_at`, `delay_seconds` between read and fetch, `same_ip`, `same_ua`,
`split_fleet`, `disallowed`.

**`identity`** — a verification result. `verdict`, `method`, `detail`, `rdns`,
`matched_range`.

Join `trap_hit.token` back to `policy_read.token` for the full picture of a
single read-then-fetch, including which address read and which fetched.

```bash
python -m mirage_crawl.report data/events
python -m mirage_crawl.report data/events --json > profiles.json
```

---

## Running it next to mirage-core

It is a separate process with separate storage. Nothing is shared.

```
mirage-core   :22    SSH honeypot
mirage-api    :8080  (localhost only)
mirage-web    :3000  (localhost only)
mirage-crawl  :80    this sensor — must be publicly reachable
```

**Give it its own hostname.** Crawlers arrive via DNS and links, not by
scanning. A sensor nobody can name gets no traffic. Point a subdomain at the
host and let it be indexed.

**Run it directly on :80, not behind a reverse proxy, if you can.** A proxy
normalises header order and re-serialises the request, which costs you the
strongest impersonation signal in the instrument. If you must proxy, set
`CRAWL_TRUST_PROXY_HEADER` and accept that header-order fingerprinting becomes
a fingerprint of your proxy.

**Do not point it at a domain you care about.** It serves generated text that
is deliberately attractive to scrapers.

---

## Limits, honestly

**No TLS fingerprinting.** JA3/JA4 requires the raw ClientHello, which means
terminating TLS yourself and peeking at the handshake. That is the strongest
identity signal that exists and it is not here yet. Header order is the
substitute and it is weaker.

**Cached policy files blunt per-request beacons.** A crawler that fetched
`robots.txt` yesterday and crawls today carries a token from yesterday — which
is fine, and `delay_seconds` measures exactly that — but a fleet sharing one
cache across many machines will attribute everything to the one reader. The
stable paths exist to catch that case.

**Absence of evidence.** A client that never fetched a trap may have read the
policy and obeyed it, or may never have found the file. `compliant` means "read
a policy file and violated nothing we could observe", not "well-behaved".
`indeterminate` is an honest verdict and appears often.

**Small-N inference.** A handful of requests tells you nothing. The compliance
state of a client with four requests is noise; treat `requests` as a confidence
weight.

**Per-request rendering is instrumentation, not cloaking.** Every requester
sees the same rules about the real site. Only the opaque trap token differs.
Worth stating plainly before a reviewer asks, and worth not crossing: if you
ever serve *different substantive rules* to different clients, the measurement
stops being about their behaviour and starts being about yours.

---

## A research protocol worth following

1. **Fix the seed and leave it.** Changing `CRAWL_SITE_SEED` regenerates every
   page and every ETag, which makes conditional-request measurements before and
   after incomparable. Set it once, at the start.
2. **Refresh ranges before analysing**, and record the date you refreshed.
   Verdicts are only as good as the snapshot.
3. **Run for weeks, not days.** Crawl schedules are slow. `delay_seconds`
   between a policy read and a trap hit is routinely hours.
4. **Report `indeterminate` alongside the rest.** A compliance breakdown that
   silently drops the clients you could not judge is the same class of error
   `internal/validity` exists to catch in mirage-core.
5. **Pre-register the analysis.** Decide what counts as a violation before you
   see who violated. The temptation to widen the definition once you know which
   company tripped it is the failure mode this whole design is built against.
6. **Canaries are a long game.** Every page carries `MIRAGE-CANARY-<hash>`.
   They cost nothing now and become a training-data provenance test later —
   but only if the site stays up and the seed never changes.

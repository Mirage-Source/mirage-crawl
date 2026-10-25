# mirage.actor/1: the shared actor record

Every Mirage sensor (mirage-crawl over HTTP, mirage-core over SSH/telnet) can
export one JSON record per actor in this shape. A correlator merges records
from different sensors into entities, so that the actor who probes GPU
infrastructure over HTTP and drops a miner over SSH becomes one entity, not two.

Reference implementation: `mirage_crawl/actors.py`
(`python -m mirage_crawl.actors <log_dir> > actors.jsonl`).
Conformance vectors: `docs/actor-schema/vectors.json`.

## Where this sits

This is a **read-side export**. It does not replace what a sensor pushes to
mirage-fleet. Fleet's decision stands: "the shared surface is the HTTP
contract, not a shared schema", so each sensor's native payload is stored
as-is and can change without a fleet migration. An actor record is derived
from that native data, one layer up. A sensor can change its internals freely,
as long as its exporter still emits this shape.

## The record

```json
{
  "schema": "mirage.actor/1",
  "sensor": {"type": "http", "id": "crawl-01"},
  "actor": "fe9cab4946df5...",
  "actor_basis": "header_order",
  "first_seen": "2026-10-24T20:01:00Z",
  "last_seen": "2026-10-24T21:14:09Z",
  "events": 51,
  "reached_payload": true,
  "fingerprints": [{"type": "header_order", "value": "..."}],
  "indicators": [
    {"type": "infra_ip", "value": "217.60.102.5", "strength": "strong"},
    {"type": "ip", "value": "103.91.65.178", "strength": "weak"}
  ],
  "mitre": ["T1190"],
  "detail": {}
}
```

| Field | Meaning |
|---|---|
| `schema` | Always `mirage.actor/1` for this version. |
| `sensor.type` | `http`, `ssh` or `telnet`. |
| `sensor.id` | The sensor's own id (`crawl-01`, `nuremberg-01`). |
| `actor` | **Sensor-local** id. Each sensor keys its own HMAC, so ids from two sensors are never comparable and never joined. |
| `actor_basis` | What the sensor grouped on: `ja4`, `header_order`, `session`, `hassh`. |
| `first_seen`, `last_seen` | RFC 3339, UTC, `Z` suffix, whole seconds. |
| `events` | Number of sensor events folded into this actor. |
| `reached_payload` | The one shared stage bit: the actor *delivered* something (an exploit payload, a command, a file, a replayed honeytoken), not just probed. Each sensor's richer ladder lives in `detail`. |
| `fingerprints` | Client-stack fingerprints (`ja4`, `header_order`, `hassh`, `ssh_banner`). Protocol-local: a JA4 never matches a HASSH, so these join actors within one protocol only. |
| `indicators` | Typed, normalised, strength-tagged values: the cross-sensor join keys. Sorted by (`type`, `value`). |
| `mitre` | ATT&CK technique ids, sorted. |
| `detail` | Sensor-specific facts. Free-form and **never** used for joining. |

Top-level keys are exactly the list above. Anything else goes in `detail`.

## Indicators

| Type | Value | Strength | Why |
|---|---|---|---|
| `ip` | source address | weak | CGNAT, cloud egress, proxies and Tor exits put unrelated actors on one address |
| `credential` | `["user","password"]` (compact JSON) | weak | `root:admin` is on every list; thousands of actors try it |
| `miner` | binary name | weak | everyone runs xmrig |
| `cve` | `CVE-YYYY-NNNN` | weak | one exploit, thousands of actors |
| `tool` | scanner, botnet or kit name | weak | names a family, not an operator |
| `infra_ip` | an address the payload points at | strong | stage-2 and C2 hosts are chosen by the operator |
| `domain` | a hostname the payload points at, or an OAST callback | strong | same |
| `url` | a stage-2 or payload URL | strong | same |
| `wallet` | `<chain>:<address>` | strong | where the money goes |
| `pool` | stratum URL or pool host | strong | operator configuration |
| `sha256` | exploit body or uploaded file | strong | byte-identical payloads cluster one kit |
| `honeytoken` | a credential we planted, seen coming back | strong | proves the data stolen from one sensor was used |

### Join rule

**Join only on strong indicators.** Weak indicators may *corroborate* a merge
(for example the same source IP and tool inside one hour), but never cause one
on their own. A false merge, two unrelated actors becoming one entity, corrupts
every count built on top of it. A missed join only under-counts. Given that
asymmetry, the conservative rule is the right one.

The cost, measured on mirage-crawl's first day (426 actors): strong keys merge
RedTail's three source IPs into one entity (through the stage-2 host
`217.60.102.5` and identical exploit bodies), and the two IPs of the bissa
React2Shell kit through a byte-identical body. They do **not** merge two
further RedTail actors whose only attacks were bodyless GETs. Those share
only an IP and a tool name with the rest, which are weak keys, so they stay
separate. A kit that randomises its multipart boundary (the WebKit-boundary
React2Shell kit, 3 IPs) also defeats the body hash. Joining on IP alone would
have touched 60 shared addresses.

### Normalisation

Two sensors must emit byte-identical strings for the same indicator, or the
join silently misses. The rules:

- **ip / infra_ip**: canonical text form; IPv6 compressed and lower-case;
  IPv4-mapped IPv6 becomes the IPv4 address. Invalid values are dropped.
- **domain**: lower-case, trailing dot removed, IDNA (punycode) encoded. At
  least two labels, each 1-63 of `[a-z0-9-]`, not starting or ending with `-`.
- **url**: `http`/`https` only. Scheme and host lower-cased, default port
  removed, fragment removed, path and query kept byte-for-byte (they are
  payload, not identity).
- **wallet**: `<chain>:<address>` with chain in `monero`, `bitcoin`,
  `ethereum`. Ethereum and bech32 (`bc1…`) addresses are lower-cased; other
  addresses keep their case (base58 is case-sensitive).
- **pool**, **miner**, **tool**: trimmed, lower-cased.
- **sha256**: 64 lower-case hex characters, else dropped.
- **cve**: upper-cased, must match `CVE-\d{4}-\d{4,}`.
- **credential**: `json.dumps([user, password], separators=(",", ":"),
  ensure_ascii=False)`. A missing half is `null`.
- **honeytoken**: as issued, case kept.

`docs/actor-schema/vectors.json` lists `{type, raw, normalized}` cases, with
`normalized: null` meaning "drop". Any exporter must pass all of them.
`tests/test_actors.py` runs them for this repo.

## Mapping mirage-core onto it (not built yet)

mirage-core keeps no extracted indicators today. URLs, wallets and pool
hosts exist only inside `commands.raw_input_b64` / `parsed_command`. So its
exporter needs one extraction step, with the same rules as above:

| mirage-core source | Becomes |
|---|---|
| `sessions.client_ip` | `ip` (weak) |
| `sessions.hassh`, `ssh_client_banner` | `fingerprints` |
| `auth_attempts (username, credential)` | `credential` (weak) |
| `file_transfers.sha256` | `sha256` (strong) |
| URLs and hosts in command text (`wget`/`curl`/`tftp` targets) | `url`, `infra_ip`, `domain` (strong) |
| wallets, stratum URLs, pool hosts, miner names in command text | `wallet`, `pool` (strong), `miner` (weak) |
| `sessions.mitre_techniques` | `mitre` |

The extractor should reproduce mirage-crawl's indicator scanner
(`hunt.scan_payload`: percent-decoding, base64 two layers deep, wallet
checksum validation, shell punctuation ending a URL). Otherwise the two
sides extract different strings from the same command. The cheapest way is
to run the Python scanner over exported command text rather than port it
to Go.

mirage-core actors are SSH sessions, which is a narrower grouping than an
HTTP actor. The correlator handles that difference, not the exporters.

## Versioning

- **Additive within `/1`**: a new indicator type, a new fingerprint type, a
  new `detail` key. Consumers must ignore types they do not know.
- **New version (`/2`)**: changing what an existing type's value means, a
  normalisation rule, or a type's strength.

## Known gaps

- No time window: one record spans an actor's whole history in the log.
  Exporting a window means filtering the log first.
- `credential` pairs are capped at 100 per actor.
- Strength is per type, not per value. A strong `infra_ip` that is a shared
  bulletproof host or a public paste site can still over-merge. If that shows
  up in practice, the fix is a correlator-side denylist, not a weaker type.

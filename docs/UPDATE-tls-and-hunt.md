# Update: TLS fingerprinting and compute-hijack detection

Two additions that change what the sensor can see. Both are tested end to end
against real handshakes and real payloads, not mocks.

---

## 1 · JA4 — identity below the application layer

A user agent is a claim. A header order is a strong hint. A **JA4 fingerprint
is a property of the TLS stack that produced the connection** — changing it
means changing the library, not editing a string. A client claiming to be
Chrome while fingerprinting as Go's `crypto/tls` is caught regardless of what
headers it sends.

### Running it

```bash
# terminal 1 — the sensor, plaintext, bound to localhost only
CRAWL_HOST=127.0.0.1 CRAWL_PORT=8080 python run.py

# terminal 2 — the TLS front on :443
python -m mirage_crawl.tlsfront \
    --cert /etc/letsencrypt/live/docs.example.org/fullchain.pem \
    --key  /etc/letsencrypt/live/docs.example.org/privkey.pem \
    --backend-port 8080 --verbose
```

The front buffers the ClientHello, computes JA4 *before* the handshake
completes, terminates TLS itself, and forwards plaintext to the sensor with
`X-Mirage-JA4` and the real client address injected as headers.

### Why the handshake is driven by hand

The ClientHello has to be read off the socket to be fingerprinted, and
`loop.start_tls()` cannot replay bytes that were already consumed. So the front
feeds the buffered bytes into an `ssl.SSLObject` backed by memory BIOs and
pumps the handshake manually. That is the only way to both see the ClientHello
and still complete the handshake.

### Two details that matter more than they look

**Client-supplied copies of the injected headers are stripped before
injection.** Without that, any client could set its own `X-Mirage-JA4` and
forge `X-Forwarded-For`, which would make the strongest signal in the
instrument the easiest one to fake. There is a test asserting a forged JA4 does
not survive.

**Every request on a keep-alive connection is rewritten, not just the first.**
This was a real bug caught by the end-to-end test. `RequestRewriter` splits the
plaintext stream on request boundaries and follows `Content-Length`; a chunked
request drops the connection to pass-through. Rewriting only the first request
would leave every later one with no fingerprint *and* no real client address —
and because the sensor falls back to the socket peer when `X-Forwarded-For` is
absent, those requests would have been silently attributed to `127.0.0.1`.
Quietly wrong data is worse than missing data.

### What it buys you

One TLS fingerprint appearing under several claimed identities is one operator
wearing different user agents. The report flags exactly that:

```
TLS FINGERPRINTS  (JA4)
  t13d1516h2_8daaf6152771_02713d6af862   412   <- one TLS stack, several claimed identities
      GPTBot
      Mozilla/5.0 (Windows NT 10.0; Win6
      python-requests
```

---

## 2 · Compute-hijack reconnaissance

**Crypto miners do not crawl websites.** What hits an HTTP sensor constantly is
the reconnaissance that *precedes* a miner: bots sweeping the internet for
exposed compute to take over.

The modern version is more interesting than crypto. A hijacked GPU box is worth
more running or reselling AI compute than it is mining, and the software that
exposes GPUs — Ray, Jupyter, Ollama, MLflow, ComfyUI — ships with weak defaults
and gets deployed by people who are not operators.

### 31 signatures across six intents

| Intent | Targets | What the bot wants |
|---|---|---|
| `llm_inference` | Ollama, vLLM / LM Studio / llama.cpp, Automatic1111 | free generation on someone else's GPU |
| `gpu_ml` | Ray, Jupyter, MLflow, Triton, TensorBoard, Airflow, ComfyUI | code execution on GPU-backed hosts |
| `crypto_mining` | Hadoop YARN, Spark, Flink, Solr | submit a mining job to a compute cluster |
| `container` | Docker API, Kubernetes, kubelet, registry | run a privileged container |
| `cloud_creds` | `.env`, `.aws/credentials`, `.git`, Spring Actuator | keys that rent GPUs on the victim's account |
| `exploit` | PHPUnit, Shellshock, Jenkins console, Confluence | the RCE that drops the miner |

YARN's `/ws/v1/cluster/apps/new-application` is the canonical cryptojacking
path and has been for years. Ray's `/api/jobs/` is its GPU-era successor.

### Decoys are what make it work

A probe for `/api/tags` that gets a 404 ends there. One that gets a plausible
Ollama model list proceeds to the *next* request — which is where the payload
is. The decoys are static JSON with realistic, slightly-old version numbers,
because a target that looks patched is not worth a payload.

Nothing is ever executed. The sensor has no code path that runs a command.

### Payload extraction is where the intelligence comes from

Once a bot believes it found a target it sends configuration, and configuration
carries hard indicators:

- Monero, Bitcoin and Ethereum wallet addresses
- `stratum+tcp://` pool URLs and 16 known pool hostnames
- Miner binary names — xmrig, t-rex, phoenixminer, nbminer, and 15 more
- Downloader invocations and the URLs they pull from
- Log4Shell JNDI strings and cloud-metadata SSRF attempts
- **One base64 layer is decoded and rescanned**, because miner config is
  routinely wrapped once inside a JSON field or a shell one-liner

Real output from the demo:

```
HARD INDICATORS EXTRACTED FROM PAYLOADS
  python-requests
    wallet monero    48edfHu7V9Z84YzzMa6fUueoELZ9ZRXq9VetWzYGzKt52XU5xvqgz...
    pool             stratum+tcp://pool.supportxmr.com:3333
    pool             supportxmr
    miner            xmrig
    url              http://45.9.148.99/xmrig

  MITRE: T1190, T1496
```

**A wallet address clusters campaigns across unrelated source addresses far
better than any behavioural signal.** It is also directly comparable to what
mirage-core already extracts from SSH sessions — which is the join between the
two sensors. The same actor dropping `xmrig` over SSH and probing YARN over
HTTP becomes one entity instead of two unrelated observations.

---

## New files

```
mirage_crawl/
  ja4.py         ClientHello parser and JA4 computation. Handles GREASE
                 (RFC 8701), supported_versions, ALPN and SNI per the FoxIO
                 spec. Verified against real ClientHellos captured from a live
                 TLS stack, not hand-made byte strings.

  tlsfront.py    TLS-terminating front. Buffers and fingerprints the
                 ClientHello, completes the handshake through memory BIOs,
                 pipes plaintext to the sensor. RequestRewriter injects headers
                 into every request on a keep-alive connection. Whichever pump
                 direction finishes first cancels the other — awaiting both
                 deadlocks on an idle socket, which is how the first version
                 hung.

  hunt.py        31 probe signatures with target, intent and MITRE mapping;
                 the decoy responses; and the payload scanner that pulls
                 wallets, pools, miner binaries, URLs, JNDI and SSRF out of a
                 request body.

tests/
  test_tls.py       Generates a throwaway certificate, boots the sensor and the
                    front, drives a real TLS client through it, and asserts the
                    JA4 computed from the handshake reaches the event log —
                    and that a client-forged JA4 does not.
  test_hunt_ja4.py  Probe matching, no collision with the sensor's own paths,
                    payload extraction including the base64 layer, JA4 shape
                    and sensitivity, and the keep-alive rewriter.
```

## Changed files

- `eventlog.py` — two new event kinds, `hunt` and `tls`
- `config.py` — `CRAWL_HUNT_DECOYS`, `CRAWL_HUNT_BODY_BYTES`, `CRAWL_JA4_HEADER`
- `server.py` — the hunt handler in the catch-all, body capture, and `ja4` on
  every request event
- `classify.py` — hunt counters, wallet/pool/miner sets, JA4 set per client
- `report.py` — a compute-hijack section, hard-indicator listing, and a JA4
  table that flags one fingerprint under several identities
- `scripts/demo.py` — two more personas: a scanner sweeping for exposed
  compute, and a dropper that posts a base64-wrapped miner config

## Tests

```bash
python tests/test_units.py      # 44 checks
python tests/test_e2e.py        # 31 checks, real HTTP
python tests/test_hunt_ja4.py   # 44 checks
python tests/test_tls.py        # 27 checks, real TLS handshake
```

---

## One more honest limit

The decoys make this host look exploitable. That is deliberate, and it is the
same posture mirage-core already takes on port 22 — but it is a posture, not a
neutral observation, and it belongs in the ethics section of anything you
publish.

The ceiling is the same one mirage-core holds and it is worth restating: the
sensor imports no process-execution module, nothing is ever run, and no packet
ever leaves. Set `CRAWL_HUNT_DECOYS=false` to observe without baiting.

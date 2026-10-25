"""Detection of compute-hijack reconnaissance.

Crypto miners do not crawl websites. What hits an HTTP sensor constantly is the
*reconnaissance that precedes a miner*: bots sweeping the internet for exposed
compute they can take over. The modern version of that is far more interesting
than crypto, because a hijacked GPU box is worth more running or reselling AI
compute than it is mining, and the infrastructure that exposes GPUs — Ray,
Jupyter, Ollama, MLflow, ComfyUI — ships with weak defaults and gets deployed
by people who are not operators.

So this module recognises four intents behind a probe:

    crypto_mining   classic cryptojacking targets: YARN, Spark, Docker, Redis
    gpu_ml          ML infrastructure that implies a GPU behind it
    llm_inference   exposed inference endpoints, abused for free generation
    cloud_creds     credential files that lead to a GPU instance elsewhere
    exploit         known RCE probes used to drop miners

Two things make this more than a path blocklist.

First, the decoy responses. A probe for Ollama's /api/tags that gets a 404 ends
there. One that gets a plausible model list proceeds to the *next* request,
which is where the payload lives. The decoys are static JSON and nothing is
ever executed — the sensor has no code path that runs a command.

Second, payload extraction. Once a bot believes it found a target it sends
configuration, and that configuration contains wallet addresses, pool
hostnames, C2 URLs and miner binary names. Those are hard indicators: a wallet
address clusters campaigns across unrelated addresses far better than any
behavioural signal, and it is directly comparable to what mirage-core already
extracts from SSH sessions.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, field

from . import decode, wallets as wallet_check

CATEGORY_CRYPTO = "crypto_mining"
CATEGORY_GPU = "gpu_ml"
CATEGORY_LLM = "llm_inference"
CATEGORY_CLOUD = "cloud_creds"
CATEGORY_EXPLOIT = "exploit"
CATEGORY_CONTAINER = "container"


@dataclass(frozen=True)
class Probe:
    """One recognised reconnaissance signature."""

    pattern: re.Pattern
    family: str
    target: str
    category: str
    intent: str
    mitre: tuple[str, ...]
    decoy: str | None = None
    content_type: str = "application/json"


def _p(
    regex: str,
    family: str,
    target: str,
    category: str,
    intent: str,
    mitre: tuple[str, ...],
    decoy: str | None = None,
    content_type: str = "application/json",
) -> Probe:
    return Probe(
        re.compile(regex, re.I), family, target, category, intent, mitre, decoy, content_type
    )


# Decoys are deliberately plausible but inert. Version numbers are real-looking
# and slightly old, because a target that looks patched is not worth a payload.
_OLLAMA_TAGS = json.dumps(
    {
        "models": [
            {"name": "llama3:8b", "size": 4661224676, "details": {"parameter_size": "8B"}},
            {"name": "mistral:7b", "size": 4109865159, "details": {"parameter_size": "7B"}},
        ]
    }
)
_OPENAI_MODELS = json.dumps(
    {"object": "list", "data": [{"id": "local-model", "object": "model", "owned_by": "local"}]}
)
_RAY_VERSION = json.dumps({"result": True, "data": {"version": "2.9.0", "pythonVersion": "3.10.12"}})
_DOCKER_VERSION = json.dumps(
    {"Version": "24.0.7", "ApiVersion": "1.43", "Os": "linux", "Arch": "amd64"}
)
_YARN_NEW_APP = json.dumps(
    {"application-id": "application_1700000000000_0001", "maximum-resource-capability":
     {"memory": 8192, "vCores": 4}}
)
_JUPYTER_KERNELS = json.dumps([])
_COMFY_STATS = json.dumps(
    {
        "system": {"os": "posix", "python_version": "3.10.12", "comfyui_version": "0.1.3"},
        "devices": [
            {"name": "cuda:0 NVIDIA GeForce RTX 4090", "type": "cuda",
             "vram_total": 25757220864, "vram_free": 24696061952}
        ],
    }
)
_TRITON_READY = ""
# Honeytoken decoys. {{ht:<kind>}} is filled per requester at serve time (see
# honeytokens.fill); the file layout is identical for everyone, only the opaque
# credential strings differ. Fake and inert: nothing here is ever used by us.
_DOTENV = (
    "APP_NAME=api\nAPP_ENV=production\nAPP_DEBUG=false\n"
    "DB_HOST=10.0.4.12\nDB_PORT=5432\nDB_DATABASE=app\nDB_USERNAME=app\n"
    "DB_PASSWORD={{ht:db_password}}\n"
    "AWS_ACCESS_KEY_ID={{ht:aws_access_key}}\nAWS_SECRET_ACCESS_KEY={{ht:aws_secret}}\n"
    "AWS_DEFAULT_REGION=us-east-1\nPAYMENTS_API_KEY={{ht:api_key}}\n"
)
_AWS_CREDENTIALS = (
    "[default]\naws_access_key_id = {{ht:aws_access_key}}\n"
    "aws_secret_access_key = {{ht:aws_secret}}\n"
)
# {{host}} is our own hostname: self-detection only sees a credential that is
# tried against this host, and pointing at a real forge would send attacker
# traffic to a third party.
_GIT_CREDENTIALS = "https://deploy:{{ht:git_credentials}}@{{host}}\n"
_GIT_CONFIG = (
    "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n"
    "[remote \"origin\"]\n\turl = https://deploy:{{ht:git_credentials}}@{{host}}/infra/api.git\n"
    "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
    "[branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n"
)
_CONFIG_JSON = (
    '{"database": {"host": "10.0.4.12", "user": "app", "password": "{{ht:db_password}}"},'
    ' "aws": {"accessKeyId": "{{ht:aws_access_key}}", "secretAccessKey": "{{ht:aws_secret}}"},'
    ' "apiKey": "{{ht:api_key}}"}'
)
_MLFLOW_EXPERIMENTS = json.dumps({"experiments": [{"experiment_id": "0", "name": "Default"}]})

PROBES: tuple[Probe, ...] = (
    # -- LLM inference endpoints ------------------------------------------
    _p(r"^/api/tags/?$", "ollama", "Ollama", CATEGORY_LLM,
       "enumerate locally hosted models before abusing them for free inference",
       ("T1046", "T1496"), _OLLAMA_TAGS),
    # Ollama and Ray both answer /api/version. Ollama's shape goes first: it
    # is the more heavily scanned of the two. Per-port personas remove the
    # ambiguity properly (Ollama on :11434, Ray on :8265).
    _p(r"^/api/version/?$", "ollama", "Ollama", CATEGORY_LLM,
       "fingerprint the Ollama build before choosing an exploit", ("T1046", "T1592"),
       json.dumps({"version": "0.1.32"})),
    _p(r"^/api/(generate|chat|pull|push|create)/?$", "ollama", "Ollama", CATEGORY_LLM,
       "drive or poison a local model server", ("T1496",),
       json.dumps({"model": "llama3:8b", "done": True, "response": ""})),
    _p(r"^/v1/(models|chat/completions|completions|embeddings)/?$", "openai_compat",
       "vLLM / LM Studio / llama.cpp", CATEGORY_LLM,
       "find an unauthenticated OpenAI-compatible endpoint to resell",
       ("T1046", "T1496"), _OPENAI_MODELS),
    _p(r"^/sdapi/v1/", "automatic1111", "Stable Diffusion WebUI", CATEGORY_LLM,
       "hijack GPU image generation", ("T1496",),
       json.dumps({"sd_model_checkpoint": "v1-5-pruned.ckpt"})),
    _p(r"^/(system_stats|object_info|prompt|queue)/?$", "comfyui", "ComfyUI", CATEGORY_GPU,
       "read GPU inventory before queueing work on it", ("T1082", "T1496"), _COMFY_STATS),

    # -- GPU / ML infrastructure ------------------------------------------
    _p(r"^/api/(jobs|serve/applications|cluster_status)/?", "ray", "Ray dashboard",
       CATEGORY_GPU, "submit arbitrary jobs to a GPU cluster (ShadowRay pattern)",
       ("T1190", "T1496", "T1610"), _RAY_VERSION),
    # Ray also answers /api/version, but Ollama's rule above wins on a shared
    # port (it is scanned more). On the Ray persona port, family-scoped
    # matching reaches this one instead.
    _p(r"^/api/version/?$", "ray", "Ray dashboard", CATEGORY_GPU,
       "fingerprint the Ray version before the ShadowRay job-submit chain",
       ("T1046", "T1592"), _RAY_VERSION),
    _p(r"^/(api/kernels|api/sessions|api/contents|tree|lab)(/|$)", "jupyter", "Jupyter",
       CATEGORY_GPU, "obtain code execution on a notebook host, usually GPU-backed",
       ("T1190", "T1059.006"), _JUPYTER_KERNELS),
    _p(r"^/(ajax-)?api/2\.0/mlflow/", "mlflow", "MLflow", CATEGORY_GPU,
       "enumerate experiments and artifact stores", ("T1046", "T1552.001"),
       _MLFLOW_EXPERIMENTS),
    _p(r"^/v2/(health/ready|health/live|models)", "triton", "Triton Inference Server",
       CATEGORY_GPU, "locate a GPU inference server", ("T1046",), _TRITON_READY, "text/plain"),
    _p(r"^/data/plugin/", "tensorboard", "TensorBoard", CATEGORY_GPU,
       "read training runs and paths", ("T1046",)),
    _p(r"^/(api/v1/dags|admin/airflow)", "airflow", "Apache Airflow", CATEGORY_GPU,
       "schedule arbitrary tasks on a worker fleet", ("T1190", "T1053")),

    # -- Classic cryptojacking targets ------------------------------------
    _p(r"^/ws/v1/cluster/apps(/new-application)?/?$", "yarn", "Hadoop YARN", CATEGORY_CRYPTO,
       "submit a mining job to a compute cluster — the canonical cryptojacking path",
       ("T1190", "T1496"), _YARN_NEW_APP),
    _p(r"^/(cluster/apps|ws/v1/cluster/(info|metrics|nodes))", "yarn", "Hadoop YARN",
       CATEGORY_CRYPTO, "size the cluster before submitting", ("T1046", "T1082")),
    _p(r"^/v1/submissions/(create|status|kill)", "spark", "Apache Spark", CATEGORY_CRYPTO,
       "submit a driver that pulls a miner", ("T1190", "T1496"),
       json.dumps({"action": "CreateSubmissionResponse", "success": True})),
    _p(r"^/jars/upload/?$", "flink", "Apache Flink", CATEGORY_CRYPTO,
       "upload a JAR for execution", ("T1190", "T1496")),
    _p(r"^/solr/admin/(cores|info)", "solr", "Apache Solr", CATEGORY_EXPLOIT,
       "reach a known Solr RCE", ("T1190",)),

    # -- Containers and orchestration -------------------------------------
    _p(r"^/v1\.\d+/(containers|images|version|info|exec)", "docker", "Docker Engine API",
       CATEGORY_CONTAINER, "create a privileged container to mine in",
       ("T1610", "T1613", "T1496"), _DOCKER_VERSION),
    _p(r"^/(containers/json|images/json|version)$", "docker", "Docker Engine API",
       CATEGORY_CONTAINER, "enumerate containers on an exposed daemon",
       ("T1613",), _DOCKER_VERSION),
    _p(r"^/v2/_catalog", "registry", "Docker Registry", CATEGORY_CONTAINER,
       "list images in an open registry", ("T1613",),
       json.dumps({"repositories": ["internal/api", "internal/worker"]})),
    _p(r"^/(api/v1/namespaces|apis/apps/v1|api/v1/pods)", "kubernetes", "Kubernetes API",
       CATEGORY_CONTAINER, "schedule workloads on a cluster", ("T1610", "T1613")),
    _p(r"^/(runningpods|pods|run/|exec/)", "kubelet", "Kubelet", CATEGORY_CONTAINER,
       "execute in a pod through an unauthenticated kubelet", ("T1610", "T1609")),

    # -- Cloud credentials that lead to GPU instances ----------------------
    _p(r"^/\.env(\.|$)|^/\.env$", "dotenv", "application .env", CATEGORY_CLOUD,
       "harvest cloud keys, then rent GPU capacity on the victim's account",
       ("T1552.001", "T1078.004"), _DOTENV, "text/plain"),
    _p(r"^/\.aws/credentials|^/\.aws/config", "aws", "AWS credentials file", CATEGORY_CLOUD,
       "direct cloud account takeover", ("T1552.001", "T1078.004"), _AWS_CREDENTIALS, "text/plain"),
    _p(r"^/\.git-credentials$", "git", "git credential store", CATEGORY_CLOUD,
       "take over a source-control account", ("T1552.001", "T1078.004"), _GIT_CREDENTIALS,
       "text/plain"),
    # config before HEAD: HEAD must not be answered with a config body.
    _p(r"^/\.git/config$", "git", "exposed .git", CATEGORY_CLOUD,
       "recover source and embedded secrets", ("T1552.001",), _GIT_CONFIG, "text/plain"),
    _p(r"^/\.git/(config|HEAD)", "git", "exposed .git", CATEGORY_CLOUD,
       "recover source and embedded secrets", ("T1552.001",)),
    _p(r"^/actuator/(env|heapdump|configprops)", "spring", "Spring Boot Actuator",
       CATEGORY_CLOUD, "dump configuration including credentials", ("T1552.001",)),
    _p(r"^/(config\.json|secrets\.json|credentials\.json|appsettings\.json)$", "config",
       "configuration file", CATEGORY_CLOUD, "harvest embedded secrets", ("T1552.001",),
       _CONFIG_JSON),

    # -- Known RCE probes used to deliver miners ---------------------------
    _p(r"^/vendor/phpunit/", "phpunit", "PHPUnit eval-stdin", CATEGORY_EXPLOIT,
       "remote code execution via a shipped test harness", ("T1190",)),
    _p(r"^/(cgi-bin/|bin/sh)", "shellshock", "CGI / Shellshock", CATEGORY_EXPLOIT,
       "command execution through CGI", ("T1190",)),
    _p(r"^/script$|^/scriptText$", "jenkins", "Jenkins script console", CATEGORY_EXPLOIT,
       "Groovy execution on a build fleet", ("T1190", "T1496")),
    _p(r"^/setup/setupadministrator\.action|^/rest/api/latest/", "confluence", "Confluence",
       CATEGORY_EXPLOIT, "known Atlassian RCE chain", ("T1190",)),
    _p(r"^/(phpinfo\.php|server-status|server-info)$", "recon", "server info", CATEGORY_EXPLOIT,
       "environment disclosure", ("T1082",)),
)

# -- payload indicators ----------------------------------------------------

MONERO_RE = re.compile(r"\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
BITCOIN_RE = re.compile(r"\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
ETHEREUM_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
STRATUM_RE = re.compile(r"stratum\+(?:tcp|ssl)://[^\s\"'<>]+", re.I)
# Payload URLs mostly arrive inside shell one-liners, so shell punctuation
# (; | ) and backtick) ends a URL: "(wget -qO- https://h/sh || curl ...)"
# must yield https://h/sh, not https://h/sh) or a URL swallowing the next
# command after a ';'.
URL_RE = re.compile(r"https?://[^\s\"'<>\\;|)`]{4,200}", re.I)
JNDI_RE = re.compile(
    r"\$\{jndi:(?:ldaps?|rmi|dns|iiop|corba|nds|nis|https?)://[^}]{1,200}\}", re.I
)
# Shellshock: a function definition at the start of a value, "() { ...; }".
# Anchored so "function() { return x; }" in a script body does not match.
SHELLSHOCK_RE = re.compile(r"(?:^|[\s=:'\"])\(\)\s*\{[^}]*;\s*\}")
B64_DEPTH = 2
METADATA_RE = re.compile(r"169\.254\.169\.254|metadata\.google\.internal", re.I)

POOL_HOSTS = (
    "supportxmr", "minexmr", "nanopool", "f2pool", "hashvault", "moneroocean",
    "xmrpool", "pool.hashvault", "2miners", "herominers", "unmineable",
    "c3pool", "monerohash", "dxpool", "ethermine", "sparkpool",
)

MINER_BINARIES = (
    "xmrig", "xmr-stak", "ccminer", "cpuminer", "minerd", "t-rex", "trex",
    "phoenixminer", "lolminer", "nbminer", "gminer", "teamredminer", "srbminer",
    "ethminer", "bfgminer", "cgminer", "kryptex", "nicehash", "randomx",
)

# "(?!/)": "curl/8.14.1" and "Wget/1.21" are product tokens in a User-Agent
# (the tool identifying itself), not a download command.
DOWNLOADER_RE = re.compile(
    r"\b(?:curl|wget|fetch|tftp|certutil|bitsadmin|Invoke-WebRequest|iwr)\b(?!/)", re.I
)
B64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


@dataclass
class PayloadFindings:
    wallets: dict[str, list[str]] = field(default_factory=dict)
    pools: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    miners: list[str] = field(default_factory=list)
    downloaders: list[str] = field(default_factory=list)
    jndi: list[str] = field(default_factory=list)
    jndi_obfuscated: bool = False
    shellshock: bool = False
    metadata_ssrf: bool = False
    decoded_layers: int = 0  # base64 depth at which something was found
    url_decoded_layers: int = 0

    def any(self) -> bool:
        return bool(
            self.wallets or self.pools or self.urls or self.miners
            or self.downloaders or self.jndi or self.metadata_ssrf or self.shellshock
        )

    def merge(self, other: "PayloadFindings") -> None:
        for currency, addresses in other.wallets.items():
            self.wallets[currency] = _dedupe(self.wallets.get(currency, []) + addresses)[:5]
        self.pools = _dedupe(self.pools + other.pools)[:10]
        self.urls = _dedupe(self.urls + other.urls)[:10]
        self.miners = _dedupe(self.miners + other.miners)
        self.downloaders = _dedupe(self.downloaders + other.downloaders)[:5]
        self.jndi = _dedupe(self.jndi + other.jndi)[:5]
        self.jndi_obfuscated = self.jndi_obfuscated or other.jndi_obfuscated
        self.shellshock = self.shellshock or other.shellshock
        self.metadata_ssrf = self.metadata_ssrf or other.metadata_ssrf
        self.decoded_layers = max(self.decoded_layers, other.decoded_layers)
        self.url_decoded_layers = max(self.url_decoded_layers, other.url_decoded_layers)

    def as_dict(self) -> dict:
        return {
            "wallets": self.wallets,
            "pools": self.pools,
            "urls": self.urls[:10],
            "miners": self.miners,
            "downloaders": self.downloaders,
            "jndi": self.jndi[:5],
            "jndi_obfuscated": self.jndi_obfuscated,
            "shellshock": self.shellshock,
            "metadata_ssrf": self.metadata_ssrf,
            "decoded_layers": self.decoded_layers,
            "url_decoded_layers": self.url_decoded_layers,
        }


def _dedupe(values) -> list[str]:
    seen: dict[str, None] = {}
    for value in values:
        seen.setdefault(value, None)
    return list(seen)


def _scan_layer(text: str, urls: bool) -> PayloadFindings:
    """Indicators in one already-decoded form of the text."""
    findings = PayloadFindings()
    lowered = text.lower()

    monero = _dedupe(MONERO_RE.findall(text))
    bitcoin = [a for a in _dedupe(BITCOIN_RE.findall(text)) if wallet_check.valid_bitcoin(a)]
    ethereum = _dedupe(ETHEREUM_RE.findall(text))
    for currency, found in (("monero", monero), ("bitcoin", bitcoin), ("ethereum", ethereum)):
        if found:
            findings.wallets[currency] = found[:5]

    pools = _dedupe(STRATUM_RE.findall(text))
    pools.extend(host for host in POOL_HOSTS if host in lowered)
    findings.pools = _dedupe(pools)[:10]

    if urls:
        findings.urls = _dedupe(URL_RE.findall(text))[:10]
    findings.miners = [m for m in MINER_BINARIES if m in lowered]
    findings.downloaders = _dedupe(DOWNLOADER_RE.findall(text))[:5]
    findings.metadata_ssrf = bool(METADATA_RE.search(text))
    findings.shellshock = bool(SHELLSHOCK_RE.search(text))

    plain_jndi = JNDI_RE.findall(text)
    clear = decode.deobfuscate_log4j(text)
    found_jndi = JNDI_RE.findall(clear) if clear != text else plain_jndi
    findings.jndi = _dedupe(found_jndi)[:5]
    findings.jndi_obfuscated = bool(found_jndi) and not plain_jndi
    return findings


def scan_payload(text: str, _depth: int = 0, urls: bool = True) -> PayloadFindings:
    """Extract hard indicators from a request body, path, query or header value.

    Every percent-decoding layer (up to three) is scanned, Log4j lookups are
    collapsed before matching, and base64 blobs are decoded up to two layers
    deep, because miner configuration is routinely wrapped in base64 inside
    a JSON field or a shell one-liner. `urls=False` skips URL extraction, for
    places where URLs are normal (a crawler's User-Agent, a Referer).
    """
    findings = PayloadFindings()
    if not text:
        return findings

    layers = decode.url_layers(text)
    findings.url_decoded_layers = len(layers) - 1
    for layer in layers:
        findings.merge(_scan_layer(layer, urls))

    if _depth < B64_DEPTH:
        for blob in _dedupe(b for layer in layers for b in B64_RE.findall(layer))[:5]:
            try:
                decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
            except (binascii.Error, ValueError):
                continue
            decoded_text = decoded.decode("utf-8", "ignore")
            if len(decoded_text) < 8:
                continue
            inner = scan_payload(decoded_text, _depth=_depth + 1, urls=urls)
            if inner.any():
                inner.decoded_layers += 1
                inner.url_decoded_layers = 0
                findings.merge(inner)

    return findings


def match(path: str) -> Probe | None:
    """First probe signature matching this path, in declaration order."""
    for probe in PROBES:
        if probe.pattern.search(path):
            return probe
    return None


def categories() -> dict[str, int]:
    counts: dict[str, int] = {}
    for probe in PROBES:
        counts[probe.category] = counts.get(probe.category, 0) + 1
    return counts

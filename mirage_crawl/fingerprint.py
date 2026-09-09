"""Client fingerprinting from the request itself.

A user agent string is a claim, not evidence. These are the cheap signals that
either corroborate or contradict it, computed from a single request with no
network round trip.

The strongest of them is header order. Every HTTP client emits its headers in a
characteristic sequence baked into its implementation, and almost no crawler
bothers to spoof it. A request claiming to be Chrome whose header order matches
Go's net/http is lying, and the ordering is far harder to fake convincingly
than the UA string it contradicts.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

# Declared crawlers. `verify` names the mechanism that can confirm the claim:
#   rdns  -- forward-confirmed reverse DNS, the operator documents a domain
#   cidr  -- the operator publishes an IP range list
#   none  -- no published verification mechanism exists
DECLARED_CRAWLERS: tuple[tuple[str, str, str, str], ...] = (
    # (regex, canonical name, operator, verification mechanism)
    (r"GPTBot", "GPTBot", "OpenAI", "cidr"),
    (r"OAI-SearchBot", "OAI-SearchBot", "OpenAI", "cidr"),
    (r"ChatGPT-User", "ChatGPT-User", "OpenAI", "cidr"),
    (r"ClaudeBot", "ClaudeBot", "Anthropic", "cidr"),
    (r"Claude-Web", "Claude-Web", "Anthropic", "cidr"),
    (r"anthropic-ai", "anthropic-ai", "Anthropic", "cidr"),
    (r"Claude-User", "Claude-User", "Anthropic", "cidr"),
    (r"Claude-SearchBot", "Claude-SearchBot", "Anthropic", "cidr"),
    (r"PerplexityBot", "PerplexityBot", "Perplexity", "cidr"),
    (r"Perplexity-User", "Perplexity-User", "Perplexity", "cidr"),
    (r"CCBot", "CCBot", "Common Crawl", "none"),
    (r"Google-Extended", "Google-Extended", "Google", "rdns"),
    (r"Googlebot", "Googlebot", "Google", "rdns"),
    (r"GoogleOther", "GoogleOther", "Google", "rdns"),
    (r"bingbot", "bingbot", "Microsoft", "rdns"),
    (r"BingPreview", "BingPreview", "Microsoft", "rdns"),
    (r"Applebot-Extended", "Applebot-Extended", "Apple", "cidr"),
    (r"Applebot", "Applebot", "Apple", "cidr"),
    (r"Amazonbot", "Amazonbot", "Amazon", "cidr"),
    (r"Bytespider", "Bytespider", "ByteDance", "none"),
    (r"Meta-ExternalAgent", "Meta-ExternalAgent", "Meta", "none"),
    (r"Meta-ExternalFetcher", "Meta-ExternalFetcher", "Meta", "none"),
    (r"facebookexternalhit", "facebookexternalhit", "Meta", "none"),
    (r"YandexBot", "YandexBot", "Yandex", "rdns"),
    (r"DuckDuckBot", "DuckDuckBot", "DuckDuckGo", "cidr"),
    (r"MojeekBot", "MojeekBot", "Mojeek", "none"),
    (r"SemrushBot", "SemrushBot", "Semrush", "none"),
    (r"AhrefsBot", "AhrefsBot", "Ahrefs", "rdns"),
    (r"DataForSeoBot", "DataForSeoBot", "DataForSEO", "none"),
    (r"Diffbot", "Diffbot", "Diffbot", "none"),
    (r"omgili|Webz", "Omgili", "Webz.io", "none"),
    (r"ImagesiftBot", "ImagesiftBot", "Hive", "none"),
    (r"Timpibot", "Timpibot", "Timpi", "none"),
    (r"cohere-ai|cohere-training-data-crawler", "cohere-ai", "Cohere", "none"),
    (r"YouBot", "YouBot", "You.com", "none"),
    (r"Scrapy", "Scrapy", "library", "none"),
    (r"python-requests", "python-requests", "library", "none"),
    (r"aiohttp", "aiohttp", "library", "none"),
    (r"Go-http-client", "Go-http-client", "library", "none"),
    (r"curl/", "curl", "library", "none"),
    (r"Wget", "wget", "library", "none"),
    (r"node-fetch|axios|undici", "node-http", "library", "none"),
    (r"okhttp", "okhttp", "library", "none"),
    (r"libwww-perl|LWP::", "libwww-perl", "library", "none"),
    (r"Java/", "java", "library", "none"),
)

_COMPILED = tuple(
    (re.compile(pattern, re.I), name, operator, verify)
    for pattern, name, operator, verify in DECLARED_CRAWLERS
)

# A UA claiming to be a real browser. If one of these never executes JavaScript
# or fetches a stylesheet, the claim is false.
_BROWSER_RE = re.compile(
    r"Mozilla/5\.0.*(Chrome/\d|Safari/\d|Firefox/\d|Edg/\d|OPR/\d)", re.I
)
# Headless signatures that admit what they are.
_HEADLESS_RE = re.compile(r"HeadlessChrome|PhantomJS|Puppeteer|Playwright|Selenium", re.I)

# Headers a genuine browser navigation essentially always carries.
_BROWSER_HEADERS = ("accept-language", "accept-encoding", "sec-fetch-mode", "sec-ch-ua")


@dataclass(frozen=True)
class Fingerprint:
    user_agent: str
    claimed_crawler: str | None
    operator: str | None
    verify_method: str | None
    claims_browser: bool
    admits_headless: bool
    header_order: tuple[str, ...]
    header_order_hash: str
    header_count: int
    browser_header_score: int
    http_version: str
    accepts_encoding: bool
    sends_accept_language: bool
    has_referer: bool
    conditional: bool
    signals: tuple[str, ...] = field(default=())


def classify_ua(user_agent: str) -> tuple[str | None, str | None, str | None]:
    """Return (canonical name, operator, verification mechanism) for a UA."""
    for pattern, name, operator, verify in _COMPILED:
        if pattern.search(user_agent):
            return name, operator, verify
    return None, None, None


def build(
    *,
    user_agent: str,
    raw_header_names: list[str],
    http_version: str,
) -> Fingerprint:
    """Derive a fingerprint from the wire-order header names of one request."""
    lowered = tuple(h.lower() for h in raw_header_names)
    order_hash = hashlib.blake2s(
        "|".join(lowered).encode("utf-8"), digest_size=8
    ).hexdigest()

    name, operator, verify = classify_ua(user_agent)
    claims_browser = bool(_BROWSER_RE.search(user_agent)) and name is None
    present = set(lowered)
    score = sum(1 for h in _BROWSER_HEADERS if h in present)

    signals: list[str] = []
    if claims_browser and score <= 1:
        # Claims to be a browser but sends almost none of the headers a browser
        # sends. Strong evidence of a spoofed UA.
        signals.append("browser_claim_thin_headers")
    if claims_browser and http_version == "1.0":
        signals.append("browser_claim_http10")
    if not user_agent:
        signals.append("no_user_agent")
    if "from" in present:
        # RFC 9110 From:, conventionally set by well-behaved crawlers.
        signals.append("sets_from_header")
    if "accept-encoding" not in present:
        signals.append("no_accept_encoding")

    return Fingerprint(
        user_agent=user_agent,
        claimed_crawler=name,
        operator=operator,
        verify_method=verify,
        claims_browser=claims_browser,
        admits_headless=bool(_HEADLESS_RE.search(user_agent)),
        header_order=lowered,
        header_order_hash=order_hash,
        header_count=len(lowered),
        browser_header_score=score,
        http_version=http_version,
        accepts_encoding="accept-encoding" in present,
        sends_accept_language="accept-language" in present,
        has_referer="referer" in present,
        conditional=("if-none-match" in present or "if-modified-since" in present),
        signals=tuple(signals),
    )

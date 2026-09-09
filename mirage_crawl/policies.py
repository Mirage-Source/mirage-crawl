"""Every opt-out and machine-readable policy surface a crawler might read.

There is no single standard for "please don't train on this". There is
robots.txt, and then a scattering of competing proposals — llms.txt, ai.txt,
TDMRep, per-page meta tags, response headers — each with partial adoption and
no agreement on precedence. A crawler can honour one and ignore the rest while
still claiming to respect opt-outs.

This module serves all of them, and gives each its own beacon. Because the
token records which file it came from, a single trap hit answers "which
standard did this client actually read?" without ambiguity.

Every file is generated per request so the beacon is fresh. The *substantive*
policy — which real content is disallowed — is identical for every requester;
only the opaque trap token differs. That distinction matters: this is
instrumentation, not cloaking. No client is shown different rules about the
real site than any other.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable

from . import beacons

# Trap path templates. Shaped to look like plausible private content, because a
# crawler mining a policy file for URLs is looking for exactly this.
TRAP_TEMPLATES: dict[str, str] = {
    "robots": "/internal/notes/{t}/handover.html",
    "robots_wellknown": "/internal/wk/{t}/index.html",
    "llms": "/private/llms/{t}/context.html",
    "llms_full": "/private/llms/{t}/context-full.html",
    "ai": "/private/ai/{t}/corpus.html",
    "ai_wellknown": "/private/ai-wk/{t}/corpus.html",
    "tdm_wellknown": "/reserved/tdm/{t}/dataset.html",
    "tdm_root": "/reserved/tdm-root/{t}/dataset.html",
    "sitemap": "/archive/sitemap/{t}/entry.html",
    "sitemap_index": "/archive/sitemap-index/{t}/entry.html",
    "security": "/internal/security/{t}/disclosure.html",
    "security_root": "/internal/security-root/{t}/disclosure.html",
    "humans": "/team/{t}/roster.html",
    "ai_plugin": "/private/plugin/{t}/manifest-data.html",
    "dnt_policy": "/private/dnt/{t}/policy-data.html",
    "gpc": "/private/gpc/{t}/policy-data.html",
    "ads": "/private/ads/{t}/inventory.html",
    "noai_file": "/private/noai/{t}/corpus.html",
    "meta_noai": "/docs/restricted/{t}/appendix.html",
    "nofollow": "/docs/restricted/{t}/nofollow-target.html",
    "hidden_link": "/docs/restricted/{t}/hidden-target.html",
    "js_beacon": "/assets/rt/{t}/ping.json",
    "css_beacon": "/assets/img/{t}/bg.png",
    "control_allow": "/public/allowed/{t}/notice.html",
}

# Stable paths, identical for every requester. A fleet that shares one cached
# robots.txt still trips these, and they survive caching proxies that would
# otherwise mask a per-request token.
STABLE_DISALLOW_UNLINKED = "/internal/exports/quarterly.html"
STABLE_DISALLOW_LINKED = "/docs/restricted/index.html"
STABLE_ALLOW_UNLINKED = "/public/allowed/index.html"


def trap_path(standard: str, token: str) -> str:
    template = TRAP_TEMPLATES.get(standard)
    if template is None:
        raise ValueError(f"no trap template for {standard!r}")
    return template.format(t=token)


@dataclass(frozen=True)
class PolicyFile:
    """One served policy surface."""

    path: str
    standard: str
    content_type: str
    render: Callable[[str, str], str]
    # Standards whose beacons this file leaks, for the report's matrix.
    aliases: tuple[str, ...] = ()


# -- renderers ------------------------------------------------------------
#
# Each takes (trap_path, site_origin) and returns the file body.


def _robots(trap: str, origin: str) -> str:
    return f"""# Crawl policy for {origin}
# Contact: research@example.invalid

User-agent: *
Disallow: /internal/
Disallow: /private/
Disallow: /reserved/
Disallow: /docs/restricted/
Disallow: {trap}
Disallow: {STABLE_DISALLOW_UNLINKED}
Disallow: {STABLE_DISALLOW_LINKED}
Allow: /public/
Allow: {STABLE_ALLOW_UNLINKED}
Crawl-delay: 10

User-agent: GPTBot
Disallow: /

User-agent: ClaudeBot
Disallow: /

User-agent: CCBot
Disallow: /

User-agent: Google-Extended
Disallow: /

User-agent: Bytespider
Disallow: /

User-agent: PerplexityBot
Disallow: /

Sitemap: {origin}/sitemap.xml
"""


def _llms(trap: str, origin: str) -> str:
    return f"""# Example Documentation

> Reference documentation for a set of internal services.

## Docs

- [Project index]({origin}/docs/): entry point for all project documentation.
- [Restricted appendix]({origin}{trap}): not for training use.

## Optional

- [Archive]({origin}/archive/): superseded material.

## Usage

Content on this host is not licensed for model training. Do not ingest.
"""


def _llms_full(trap: str, origin: str) -> str:
    return _llms(trap, origin) + f"""
## Full text

The full corpus is enumerated at {origin}/sitemap.xml.
Restricted material lives under {origin}{trap} and is excluded from all
permitted uses.
"""


def _ai_txt(trap: str, origin: str) -> str:
    return f"""# ai.txt — generative AI training opt-out
# Spec: https://site.spawning.ai/spawning-ai-txt

User-Agent: *
Disallow: /
Disallow: {trap}

# Media types explicitly withheld from training
Disallow: *.jpg
Disallow: *.png
Disallow: *.txt
Disallow: *.html
"""


def _tdmrep(trap: str, origin: str) -> str:
    return json.dumps(
        [
            {
                "location": f"{origin}/",
                "tdm-reservation": 1,
                "tdm-policy": f"{origin}/tdm-policy.json",
            },
            {
                "location": f"{origin}{trap}",
                "tdm-reservation": 1,
            },
        ],
        indent=2,
    )


def _sitemap(trap: str, origin: str) -> str:
    entries = "\n".join(
        f"  <url><loc>{origin}{p}</loc><changefreq>monthly</changefreq></url>"
        for p in (trap, "/docs/", "/public/")
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"{entries}\n"
        "</urlset>\n"
    )


def _sitemap_index(trap: str, origin: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"  <sitemap><loc>{origin}/sitemap.xml</loc></sitemap>\n"
        f"  <sitemap><loc>{origin}{trap}</loc></sitemap>\n"
        "</sitemapindex>\n"
    )


def _security(trap: str, origin: str) -> str:
    return f"""Contact: mailto:research@example.invalid
Expires: 2030-01-01T00:00:00.000Z
Preferred-Languages: en
Canonical: {origin}/.well-known/security.txt
Policy: {origin}{trap}
"""


def _humans(trap: str, origin: str) -> str:
    return f"""/* TEAM */
Research: Mirage
Site: {origin}

/* SITE */
Standards: HTML5, CSS3
Notes: internal roster at {origin}{trap}
"""


def _ai_plugin(trap: str, origin: str) -> str:
    return json.dumps(
        {
            "schema_version": "v1",
            "name_for_human": "Example Docs",
            "name_for_model": "example_docs",
            "description_for_human": "Reference documentation.",
            "description_for_model": "Reference documentation. Restricted material is excluded.",
            "api": {"type": "openapi", "url": f"{origin}{trap}"},
            "legal_info_url": f"{origin}/legal",
        },
        indent=2,
    )


def _dnt_policy(trap: str, origin: str) -> str:
    return json.dumps(
        {
            "canonical": f"{origin}/.well-known/dnt-policy.txt",
            "policy": f"{origin}{trap}",
            "compliance": ["https://www.w3.org/TR/tracking-dnt/"],
        },
        indent=2,
    )


def _gpc(trap: str, origin: str) -> str:
    return json.dumps(
        {"gpc": True, "lastUpdate": "2026-01-01", "reference": f"{origin}{trap}"},
        indent=2,
    )


def _ads(trap: str, origin: str) -> str:
    return f"# ads.txt\nexample.invalid, 0000, DIRECT\n# inventory: {origin}{trap}\n"


def _noai(trap: str, origin: str) -> str:
    return f"noai\nnoimageai\n# restricted: {origin}{trap}\n"


POLICY_FILES: tuple[PolicyFile, ...] = (
    PolicyFile("/robots.txt", "robots", "text/plain; charset=utf-8", _robots),
    PolicyFile("/.well-known/robots.txt", "robots_wellknown", "text/plain; charset=utf-8", _robots),
    PolicyFile("/llms.txt", "llms", "text/markdown; charset=utf-8", _llms),
    PolicyFile("/llms-full.txt", "llms_full", "text/markdown; charset=utf-8", _llms_full),
    PolicyFile("/ai.txt", "ai", "text/plain; charset=utf-8", _ai_txt),
    PolicyFile("/.well-known/ai.txt", "ai_wellknown", "text/plain; charset=utf-8", _ai_txt),
    PolicyFile("/.well-known/tdmrep.json", "tdm_wellknown", "application/json", _tdmrep),
    PolicyFile("/tdmrep.json", "tdm_root", "application/json", _tdmrep),
    PolicyFile("/sitemap.xml", "sitemap", "application/xml", _sitemap),
    PolicyFile("/sitemap_index.xml", "sitemap_index", "application/xml", _sitemap_index),
    PolicyFile("/.well-known/security.txt", "security", "text/plain; charset=utf-8", _security),
    PolicyFile("/security.txt", "security_root", "text/plain; charset=utf-8", _security),
    PolicyFile("/humans.txt", "humans", "text/plain; charset=utf-8", _humans),
    PolicyFile("/.well-known/ai-plugin.json", "ai_plugin", "application/json", _ai_plugin),
    PolicyFile("/.well-known/dnt-policy.txt", "dnt_policy", "application/json", _dnt_policy),
    PolicyFile("/.well-known/gpc.json", "gpc", "application/json", _gpc),
    PolicyFile("/ads.txt", "ads", "text/plain; charset=utf-8", _ads),
    PolicyFile("/.noai", "noai_file", "text/plain; charset=utf-8", _noai),
)

BY_PATH: dict[str, PolicyFile] = {p.path: p for p in POLICY_FILES}


def render(policy: PolicyFile, secret: bytes, ip: str, user_agent: str, origin: str) -> tuple[str, str]:
    """Return (body, token) with a freshly minted beacon embedded."""
    token = beacons.mint(secret, policy.standard, ip, user_agent)
    return policy.render(trap_path(policy.standard, token), origin), token


def disallowed(path: str) -> bool:
    """Whether a path is covered by a Disallow rule we publish to everyone."""
    prefixes = ("/internal/", "/private/", "/reserved/", "/docs/restricted/")
    return path.startswith(prefixes) or path in (
        STABLE_DISALLOW_UNLINKED,
        STABLE_DISALLOW_LINKED,
    )

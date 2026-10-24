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
import re
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
    # Under /internal/ on purpose: robots.txt Disallows /internal/ and Allows
    # this exact path, so only a client applying longest-match fetches it.
    "control_allow": "/internal/allowed/{t}/notice.html",
}

# What fetching a beacon's trap path *means* depends on how the file that
# leaked it presented the path. One table, read by the classifier, so the
# meaning of a code is defined in exactly one place.
#
#   prohibition  the file forbids the path (Disallow, "not for training",
#                a TDM reservation). Fetching it is mining a prohibition.
#   invitation   the file offers the path without forbidding it (a sitemap
#                entry, a policy link). Fetching it proves the file was read,
#                nothing more -- following a sitemap is what sitemaps are for.
#   capability   proves what the client can do (run JS, load CSS, see hidden
#                links) rather than what it read.
#   control      measures rule interpretation: control_allow is an Allow that
#                is more specific than a covering Disallow, so fetching it shows
#                the client applies longest-match correctly.
KIND_PROHIBITION = "prohibition"
KIND_INVITATION = "invitation"
KIND_CAPABILITY = "capability"
KIND_CONTROL = "control"

STANDARD_KIND: dict[str, str] = {
    "robots": KIND_PROHIBITION,
    "robots_wellknown": KIND_PROHIBITION,
    "llms": KIND_PROHIBITION,
    "llms_full": KIND_PROHIBITION,
    "ai": KIND_PROHIBITION,
    "ai_wellknown": KIND_PROHIBITION,
    "tdm_wellknown": KIND_PROHIBITION,
    "tdm_root": KIND_PROHIBITION,
    "sitemap": KIND_INVITATION,
    "sitemap_index": KIND_INVITATION,
    "security": KIND_INVITATION,
    "security_root": KIND_INVITATION,
    "humans": KIND_INVITATION,
    "ai_plugin": KIND_INVITATION,
    "dnt_policy": KIND_INVITATION,
    "gpc": KIND_INVITATION,
    "ads": KIND_INVITATION,
    "noai_file": KIND_PROHIBITION,
    "meta_noai": KIND_CAPABILITY,
    "nofollow": KIND_CAPABILITY,
    "hidden_link": KIND_CAPABILITY,
    "js_beacon": KIND_CAPABILITY,
    "css_beacon": KIND_CAPABILITY,
    # Reserved code, never minted today. A linked page under a Disallow.
    "linked_disallow": KIND_CONTROL,
    "control_allow": KIND_CONTROL,
}


def kind_of(standard: str) -> str | None:
    return STANDARD_KIND.get(standard)


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
    render: Callable[..., str]
    # Further beacons this file carries besides its own, passed to the
    # renderer as keyword arguments (standard -> trap path).
    extras: tuple[str, ...] = ()


# -- renderers ------------------------------------------------------------
#
# Each takes (trap_path, site_origin) and returns the file body.


# -- robots.txt as data -----------------------------------------------------
#
# The rules are data, not a string template, because the same rules are
# needed twice: once to render robots.txt and once to judge whether a fetch
# broke them. Two copies would drift (they already had: the old judge ignored
# the per-UA groups entirely, so GPTBot fetching /docs/ under "Disallow: /"
# looked compliant).


@dataclass(frozen=True)
class RobotsRule:
    directive: str  # "allow" | "disallow"
    path: str
    # A rule whose path is a per-requester trap. "self" is the serving file's
    # own standard; anything else names a standard in TRAP_TEMPLATES.
    trap: str | None = None

    def patterns(self) -> tuple[str, ...]:
        """The path(s) as a judge sees them: a trap's token becomes a wildcard.

        "self" depends on which robots file served it, so it judges as both.
        """
        if self.trap is None:
            return (self.path,)
        standards = ROBOTS_STANDARDS if self.trap == "self" else (self.trap,)
        return tuple(TRAP_TEMPLATES[std].format(t="*") for std in standards)


@dataclass(frozen=True)
class RobotsGroup:
    agents: tuple[str, ...]
    rules: tuple[RobotsRule, ...]
    crawl_delay: int | None = None


# The two files that carry the robots rules. "Defiant" means a client read one
# of these and then broke a rule in it.
ROBOTS_STANDARDS = ("robots", "robots_wellknown")

ROBOTS_GROUPS: tuple[RobotsGroup, ...] = (
    RobotsGroup(
        ("*",),
        (
            RobotsRule("disallow", "/internal/"),
            RobotsRule("disallow", "/private/"),
            RobotsRule("disallow", "/reserved/"),
            RobotsRule("disallow", "/docs/restricted/"),
            RobotsRule("disallow", "", trap="self"),
            RobotsRule("disallow", STABLE_DISALLOW_UNLINKED),
            RobotsRule("disallow", STABLE_DISALLOW_LINKED),
            RobotsRule("allow", "/public/"),
            RobotsRule("allow", STABLE_ALLOW_UNLINKED),
            RobotsRule("allow", "", trap="control_allow"),
        ),
        crawl_delay=10,
    ),
    *(
        RobotsGroup((agent,), (RobotsRule("disallow", "/"),))
        for agent in ("GPTBot", "ClaudeBot", "CCBot", "Google-Extended", "Bytespider", "PerplexityBot")
    ),
)


def _robots(trap: str, origin: str, control_allow: str = "") -> str:
    traps = {"self": trap, "control_allow": control_allow}
    out = [f"# Crawl policy for {origin}", "# Contact: research@example.invalid", ""]
    for group in ROBOTS_GROUPS:
        out.extend(f"User-agent: {agent}" for agent in group.agents)
        for rule in group.rules:
            path = traps.get(rule.trap, "") if rule.trap else rule.path
            if rule.trap and not path:
                continue
            out.append(f"{rule.directive.capitalize()}: {path}")
        if group.crawl_delay is not None:
            out.append(f"Crawl-delay: {group.crawl_delay}")
        out.append("")
    out.append(f"Sitemap: {origin}/sitemap.xml")
    return "\n".join(out) + "\n"


def parse_robots(text: str) -> tuple[RobotsGroup, ...]:
    """Parse robots.txt text into groups (RFC 9309 section 2.2).

    Consecutive user-agent lines open one group; a rule line after them
    closes the agent list. Unknown lines (Sitemap, Crawl-delay, comments)
    are ignored for judging.
    """
    groups: list[RobotsGroup] = []
    agents: list[str] = []
    rules: list[RobotsRule] = []
    in_rules = False
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", 1))
        key = key.lower()
        if key == "user-agent":
            if in_rules:
                groups.append(RobotsGroup(tuple(agents), tuple(rules)))
                agents, rules, in_rules = [], [], False
            agents.append(value)
        elif key in ("allow", "disallow") and agents:
            in_rules = True
            rules.append(RobotsRule(key, value))
    if agents:
        groups.append(RobotsGroup(tuple(agents), tuple(rules)))
    return tuple(groups)


def _agent_matches(token: str, user_agent: str) -> bool:
    # Case-insensitive, and the token must stand alone ("GPTBot" matches
    # "compatible; GPTBot/1.2" but not "NotGPTBotX").
    return re.search(
        r"(?<![A-Za-z0-9_-])" + re.escape(token) + r"(?![A-Za-z0-9_-])", user_agent, re.I
    ) is not None


def _pattern_regex(pattern: str) -> re.Pattern:
    anchored = pattern.endswith("$")
    body = pattern[:-1] if anchored else pattern
    regex = ".*".join(re.escape(part) for part in body.split("*"))
    return re.compile(regex + ("$" if anchored else ""))


def evaluate(groups: tuple[RobotsGroup, ...], path: str, user_agent: str) -> bool:
    """True if `path` is disallowed for `user_agent` under `groups`.

    RFC 9309: every group naming this agent is merged; if none does, the "*"
    groups apply. The longest matching rule wins, and Allow wins a tie.
    /robots.txt itself is always allowed.
    """
    if path == "/robots.txt":
        return False
    specific = [g for g in groups if any(a != "*" and _agent_matches(a, user_agent) for a in g.agents)]
    chosen = specific or [g for g in groups if "*" in g.agents]

    best_len, best_allow = -1, True
    for group in chosen:
        for rule in group.rules:
            for pattern in rule.patterns():
                if not pattern:
                    continue  # "Disallow:" with no value allows everything
                if not _pattern_regex(pattern).match(path):
                    continue
                allow = rule.directive == "allow"
                if len(pattern) > best_len or (len(pattern) == best_len and allow):
                    best_len, best_allow = len(pattern), allow
    return not best_allow


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
    PolicyFile("/robots.txt", "robots", "text/plain; charset=utf-8", _robots, ("control_allow",)),
    PolicyFile("/.well-known/robots.txt", "robots_wellknown", "text/plain; charset=utf-8", _robots,
               ("control_allow",)),
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


def render_with(policy: PolicyFile, mint: Callable[[str], str], origin: str) -> tuple[str, dict[str, str]]:
    """Render a policy file, minting its own beacon and any extras through `mint`.

    Returns (body, {standard: token}).
    """
    tokens = {policy.standard: mint(policy.standard)}
    extra_paths = {}
    for standard in policy.extras:
        tokens[standard] = mint(standard)
        extra_paths[standard] = trap_path(standard, tokens[standard])
    return policy.render(trap_path(policy.standard, tokens[policy.standard]), origin, **extra_paths), tokens


def render(policy: PolicyFile, secret: bytes, ip: str, user_agent: str, origin: str) -> tuple[str, dict[str, str]]:
    """Return (body, tokens) with freshly minted beacons embedded."""
    return render_with(policy, lambda std: beacons.mint(secret, std, ip, user_agent), origin)


def disallowed(path: str, user_agent: str = "") -> bool:
    """Whether robots.txt, as we publish it, forbids `path` to `user_agent`."""
    return evaluate(ROBOTS_GROUPS, path, user_agent)

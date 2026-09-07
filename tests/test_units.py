"""Unit tests for the pieces the end-to-end run cannot reach.

Identity verification in particular: the e2e run talks to 127.0.0.1, which has
no PTR record and is in nobody's published range, so the interesting verdicts
have to be driven directly.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mirage_crawl import beacons, policies  # noqa: E402
from mirage_crawl.classify import (  # noqa: E402
    STATE_COMPLIANT, STATE_DEFIANT, STATE_IGNORANT, STATE_MINER, Profile,
)
from mirage_crawl.fingerprint import build, classify_ua  # noqa: E402
from mirage_crawl.identity import (  # noqa: E402
    VERDICT_IMPERSONATING, VERDICT_UNDECLARED, VERDICT_UNVERIFIABLE, VERDICT_VERIFIED,
    RangeTable, verify,
)
from mirage_crawl.sitegen import Site  # noqa: E402

failures: list[str] = []




def check(name: str, condition: bool, detail: str = "") -> None:
    print(f"  {'PASS' if condition else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not condition else ""))
    if not condition:
        failures.append(name)


def test_beacons() -> None:
    print("\nbeacons")
    secret = b"k" * 32
    token = beacons.mint(secret, "robots", "1.2.3.4", "GPTBot")
    parsed = beacons.parse(secret, token)
    check("round trip", parsed is not None and parsed.standard == "robots")
    check("ip binds", parsed.matches_ip("1.2.3.4") and not parsed.matches_ip("1.2.3.5"))
    check("ua binds", parsed.matches_ua("GPTBot") and not parsed.matches_ua("CCBot"))
    check("wrong secret rejected", beacons.parse(b"j" * 32, token) is None)

    # Flipping any single character must invalidate the MAC.
    corrupted = 0
    for i in range(len(token)):
        swapped = "A" if token[i] != "A" else "B"
        mutant = token[:i] + swapped + token[i + 1:]
        if beacons.parse(secret, mutant) is None:
            corrupted += 1
    check("every single-char mutation rejected", corrupted == len(token), f"{corrupted}/{len(token)}")

    check("every standard has a code", all(s in beacons.STANDARD_CODES for s in policies.TRAP_TEMPLATES))
    check("codes are unique", len(set(beacons.STANDARD_CODES.values())) == len(beacons.STANDARD_CODES))
    check("token length is stable", all(
        len(beacons.mint(secret, s, f"10.0.0.{i}", "ua")) == beacons.TOKEN_CHARS
        for i, s in enumerate(list(beacons.STANDARD_CODES)[:20])
    ))


def test_site() -> None:
    print("\nsite generation")
    a = Site("s", projects=20, pages_per_project=6)
    b = Site("s", projects=20, pages_per_project=6)
    check("deterministic across instances", a.page("p003", 2).content_hash == b.page("p003", 2).content_hash)
    check("etag matches content hash", a.page("p003", 2).etag.strip('"') == a.page("p003", 2).content_hash)
    check("out of range returns None", a.page("p003", 99) is None and a.page("zzz", 0) is None)
    check("canaries are unique per path",
          len({a.canary(p) for p in a.all_page_paths()}) == len(a.all_page_paths()))
    forks = [p for p in a.projects if p.fork_of]
    check("forks exist", len(forks) > 0)
    if forks:
        f = forks[0]
        orig, fork = a.page(f.fork_of, 1), a.page(f.pid, 1)
        shared = sum(1 for x, y in zip(orig.body, fork.body) if x == y)
        check("fork is near-duplicate but not identical",
              0 < shared < len(orig.body) and orig.content_hash != fork.content_hash)
    check("no fork points at itself", all(p.fork_of != p.pid for p in a.projects))


def test_fingerprint() -> None:
    print("\nfingerprinting")
    name, operator, method = classify_ua("Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)")
    check("GPTBot recognised", (name, operator, method) == ("GPTBot", "OpenAI", "cidr"))
    check("Googlebot uses rdns", classify_ua("Googlebot/2.1")[2] == "rdns")
    check("Google-Extended before Googlebot",
          classify_ua("Mozilla/5.0 (compatible; Google-Extended)")[0] == "Google-Extended")
    check("Applebot-Extended before Applebot",
          classify_ua("Applebot-Extended/1.0")[0] == "Applebot-Extended")
    check("unknown UA yields nothing", classify_ua("SomeRandomThing/1.0")[0] is None)

    liar = build(
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
        raw_header_names=["Host", "User-Agent", "Accept"],
        http_version="1.1",
    )
    check("browser claim detected", liar.claims_browser)
    check("thin headers flagged", "browser_claim_thin_headers" in liar.signals)
    check("no accept-encoding flagged", "no_accept_encoding" in liar.signals)

    real = build(
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
        raw_header_names=["Host", "sec-ch-ua", "User-Agent", "Accept", "Accept-Encoding", "Accept-Language", "Sec-Fetch-Mode"],
        http_version="1.1",
    )
    check("real browser not flagged", "browser_claim_thin_headers" not in real.signals)
    check("header order differs between the two", real.header_order_hash != liar.header_order_hash)
    check("order is preserved, not sorted", real.header_order[1] == "sec-ch-ua")


def test_identity() -> None:
    print("\nidentity verification")
    ranges = RangeTable()
    ranges.load_mapping({"OpenAI": ["203.0.113.0/24"], "Anthropic": ["198.51.100.0/24"]})

    async def run():
        inside = await verify("203.0.113.9", "GPTBot", "OpenAI", "cidr", ranges)
        outside = await verify("8.8.8.8", "GPTBot", "OpenAI", "cidr", ranges)
        no_ranges = await verify("8.8.8.8", "PerplexityBot", "Perplexity", "cidr", ranges)
        undeclared = await verify("8.8.8.8", None, None, None, ranges)
        library = await verify("8.8.8.8", "curl", "library", "none", ranges)
        no_mechanism = await verify("8.8.8.8", "CCBot", "Common Crawl", "none", ranges)
        return inside, outside, no_ranges, undeclared, library, no_mechanism

    inside, outside, no_ranges, undeclared, library, no_mechanism = asyncio.run(run())

    check("in-range claim verified", inside.verdict == VERDICT_VERIFIED)
    check("verified records the block", inside.matched_range == "203.0.113.0/24")
    check("out-of-range claim is impersonation", outside.verdict == VERDICT_IMPERSONATING)
    check("operator with no loaded ranges is unverifiable, not a liar",
          no_ranges.verdict == VERDICT_UNVERIFIABLE, no_ranges.verdict)
    check("no claim means undeclared", undeclared.verdict == VERDICT_UNDECLARED)
    check("library UA is undeclared, not impersonating", library.verdict == VERDICT_UNDECLARED)
    check("operator publishing nothing is unverifiable", no_mechanism.verdict == VERDICT_UNVERIFIABLE)

    check("bad cidr ignored", RangeTable().load_mapping({"X": ["not-a-cidr", "10.0.0.0/8"]}) == 1)
    check("missing file is not fatal", RangeTable().load_file("does/not/exist.json") == 0)


def test_states() -> None:
    print("\ncompliance state machine")
    compliant = Profile("ua", None, standards_read={"robots"})
    ignorant = Profile("ua", None, disallowed_paths={"/internal/x"})
    defiant = Profile("ua", None, standards_read={"robots"}, disallowed_paths={"/internal/x"})
    miner = Profile("ua", None, standards_read={"robots"}, standards_mined={"robots"})

    check("read + clean = compliant", compliant.state == STATE_COMPLIANT)
    check("no read + violation = ignorant", ignorant.state == STATE_IGNORANT)
    check("read + violation = defiant", defiant.state == STATE_DEFIANT)
    check("mined = miner", miner.state == STATE_MINER)
    check("mining outranks defiance",
          Profile("ua", None, standards_read={"robots"}, standards_mined={"robots"},
                  disallowed_paths={"/internal/x"}).state == STATE_MINER)

    waste = Profile("ua", None, repeat_fetches=10, wasteful_refetches=7)
    check("waste ratio", abs(waste.waste_ratio - 0.7) < 1e-9)
    check("no divide by zero", Profile("ua", None).waste_ratio == 0.0)


def test_policies() -> None:
    print("\npolicy surfaces")
    secret = b"s" * 32
    for policy in policies.POLICY_FILES:
        body, token = policies.render(policy, secret, "1.1.1.1", "ua", "https://x.test")
        path = policies.trap_path(policy.standard, token)
        found = beacons.find_in_path(secret, path)
        if path not in body or found is None or found.standard != policy.standard:
            check(f"{policy.path} embeds its own beacon", False, path)
            return
    check(f"all {len(policies.POLICY_FILES)} surfaces embed their own beacon", True)
    check("paths are unique per standard",
          len({policies.TRAP_TEMPLATES[s] for s in policies.TRAP_TEMPLATES}) == len(policies.TRAP_TEMPLATES))
    check("disallowed() covers trap prefixes",
          all(policies.disallowed(policies.trap_path(s, "x" * 26))
              for s in ("robots", "llms", "ai", "tdm_wellknown")))
    check("public paths are not disallowed", not policies.disallowed("/docs/p001/00.html"))
    check("control path is allowed", not policies.disallowed(policies.STABLE_ALLOW_UNLINKED))


if __name__ == "__main__":
    test_beacons()
    test_site()
    test_fingerprint()
    test_identity()
    test_states()
    test_policies()
    if failures:
        print("\nFAILURES: " + ", ".join(failures))
    else:
        print("\nall unit checks passed")
    sys.exit(1 if failures else 0)

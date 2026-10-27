"""Attack classifier: which exploit class, where in the request, and which tool sent it.

hunt.py answers "what did this path probe for" (recon). This module answers
"what payload is in the request" (attack), and the two stay separate on purpose:
a GET /.env is recon, not an attack, so nothing here fires on a path that names
an exploit without carrying one.

Three layers, deliberately kept apart:

  plumbing  - split a request into (location, text) units: path, each query
              piece, each form/JSON/multipart body field, each header.
  RULES     - the table below. Each rule is a regex plus the locations it may
              fire in. This is where the false-positive budget is won or lost.
  dedup     - at most one label per (class, location); a rule that names a CVE
              or signature beats a generic one on the same slot.

Design stance on false positives: every rule demands an *adjacent pair* of
attack tokens (union immediately followed by select, a quote immediately
followed by or, a command separator immediately followed by a command), not a
single keyword. Prose that merely mentions SQL or shell words ("select a union
rep", "rm -rf explained") has the words in the wrong order or without the
separator, so it stays silent. Rules that would otherwise be too loose are
gated on the parameter name (RFI/wrapper rules only fire in include-style
parameters, never in redirect= or url=).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from urllib.parse import unquote, unquote_plus

from . import decode

CLASSES = (
    "sqli", "lfi", "rfi", "xss", "cmd_injection", "php_code",
    "deserialization", "log4shell", "shellshock",
)

EVIDENCE_CAP = 200
MAX_VIEW = 32768        # chars of any one field we run regexes over
MAX_BODY = 262144       # bytes of body we look at
MAX_PIECES = 200        # query pieces / form fields / JSON leaves per request

PATH, QUERY, BODY, HEADER = "path", "query", "body", "header"


@dataclass(frozen=True)
class Attack:
    cls: str
    location: str
    evidence: str
    decoded: bool = False
    sig: str | None = None
    cve: str | None = None

    def as_dict(self) -> dict:
        return {
            "cls": self.cls, "location": self.location, "evidence": self.evidence,
            "decoded": self.decoded, "sig": self.sig, "cve": self.cve,
        }


@dataclass(frozen=True)
class Rule:
    cls: str
    name: str
    pattern: re.Pattern
    where: frozenset
    params: re.Pattern | None = None   # fire only when the parameter name matches
    hint: re.Pattern | None = None     # must also match the *raw* (undecoded) text
    sig: str | None = None
    cve: str | None = None


def _rule(cls, name, pattern, where, params=None, hint=None, sig=None, cve=None) -> Rule:
    return Rule(
        cls, name, re.compile(pattern, re.I), frozenset(where.split()),
        re.compile(params, re.I) if params else None,
        re.compile(hint, re.I) if hint else None, sig, cve,
    )


# A command separator (or substitution opener) immediately before a command.
# The separator is what separates "rm -rf explained" (prose) from "x; rm -rf /".
_SEP = r"(?:[;|&`\n(]|\$\()\s*"

# Parameter names that plausibly feed an include()/file-read. Gating RFI and
# stream-wrapper rules on these keeps redirect=, url=, next=, callback= clean.
_INCLUDE_PARAMS = (
    r"^(?:page|pg|p|file|filename|path|include|inc|require|template|tpl|lang|language|"
    r"module|mod|view|doc|document|dir|folder|load|conf|config|style|theme|layout|"
    r"content|src|source|read|show|display)$"
)

# Order matters only for ties: dedup keeps the first rule per (cls, location)
# unless a later one carries a CVE/signature.
RULES: tuple[Rule, ...] = (
    # -- deserialization --------------------------------------------------
    # React Flight protocol pollution: the "$1:__proto__:then" self-reference,
    # the forged resolved_model chunk, and the constructor-of-constructor
    # gadget are not strings a legitimate client ever sends.
    _rule("deserialization", "react2shell",
          r"\$\d+:__proto__:then|\$\d+:constructor:constructor|[\"']resolved_model[\"']",
          "query body", sig="react2shell", cve="CVE-2025-55182"),
    # Java stream magic: base64 "rO0AB[XY]", raw AC ED 00 05, or its hex form.
    # The base64 form must start a token so it cannot match mid-word.
    _rule("deserialization", "java-serialized",
          r"(?<![A-Za-z0-9+/])rO0AB[XY]|\xac\xed\x00\x05|(?<![0-9a-f])aced0005",
          "query body header"),
    # PHP object notation O:<len>:"Class":<n>:{ ; the quoted class and brace
    # make a stray "O:8" harmless.
    _rule("deserialization", "php-serialized",
          r"(?<![\w])[OC]:\d{1,3}:\"[\w\\]{1,80}\":\d+:\{",
          "query body header"),
    _rule("deserialization", "yaml-python-tag", r"!!python/(?:object|name|module)",
          "query body"),

    # -- log4shell / shellshock ------------------------------------------
    # Matched after Log4j lookup de-obfuscation so ${${lower:j}ndi:...} resolves.
    _rule("log4shell", "jndi-lookup", r"\$\{\s*jndi\s*:", "path query body header"),
    # Bash function-definition-in-env: "() { ...; }; cmd". Headers only: the
    # same bytes in a body are just JavaScript.
    _rule("shellshock", "bash-function-env", r"\(\s*\)\s*\{[^}]{0,80}\}\s*;", "header"),

    # -- lfi ---------------------------------------------------------------
    # CVE-2021-42013 is the double-encoded retry of 41773. `hint` pins the CVE
    # to the raw encoding style, so a plain %2F traversal stays unattributed.
    _rule("lfi", "apache-traversal-double", r"(?:\.\.[/\\]){2,}", "path",
          hint=r"%%32%65|%252e", cve="CVE-2021-42013"),
    _rule("lfi", "apache-traversal", r"(?:\.\.[/\\]){2,}", "path",
          hint=r"\.%2e|%2e\.", cve="CVE-2021-41773"),
    # Two or more ../ in a row. One ../ appears in ordinary relative links.
    _rule("lfi", "dot-dot-slash", r"(?:\.\.[/\\]){2,}", "path query body"),
    # nginx `location /static { alias ...; }` off-by-slash: /static../secret.
    _rule("lfi", "alias-off-by-slash", r"[A-Za-z0-9_-]\.\./", "path"),
    # Sensitive absolute targets. query/body only: a bare GET /etc/passwd is
    # recon (hunt.py), a parameter carrying it is an attempted read.
    _rule("lfi", "sensitive-file",
          r"(?:^|[/=\s\"'])/?etc/(?:passwd|shadow|group|hosts)\b|/proc/self/|\bboot\.ini\b|\bwin\.ini\b|\\windows\\system32",
          "query body"),
    _rule("lfi", "stream-wrapper", r"^\s*(?:php|expect|phar|zip|data|glob|file)://",
          "query body", params=_INCLUDE_PARAMS),

    # -- rfi ---------------------------------------------------------------
    _rule("rfi", "remote-include", r"^\s*(?:https?|ftps?)://", "query body",
          params=_INCLUDE_PARAMS),

    # -- php_code ----------------------------------------------------------
    # php-cgi argument injection: ini overrides smuggled into the query string.
    # allow_url_include / auto_prepend_file are the pair that turns php://input
    # into code execution. The CVE depends on the dash: a raw soft hyphen
    # (%AD, or %25AD double-encoded) is the 2024 Windows best-fit bypass of the
    # 2012 fix; a plain "-d" only works on php-cgi unpatched since 2012.
    _rule("php_code", "php-cgi-ini-override-softhyphen",
          r"\ballow_url_include\s*=|\bauto_prepend_file\s*=\s*php://",
          "query body", hint=r"%(?:25)?ad", cve="CVE-2024-4577"),
    _rule("php_code", "php-cgi-ini-override",
          r"\ballow_url_include\s*=|\bauto_prepend_file\s*=\s*php://",
          "query body", cve="CVE-2012-1823"),
    _rule("php_code", "thinkphp-invokefunction",
          r"think[\\/]+app[\\/]+invoke(?:function|class)",
          "path query body", cve="CVE-2018-20062"),
    # PHP2Shell (Oct 2026, CVE-2026-109618/109619) is reported to be reachable
    # through PHP's session upload-progress handling, which a request opts into
    # by sending a multipart field with this exact default name. The name is the
    # signal, not the value: the rule gates on the parameter name and matches
    # any short value, so the field is labelled even when it is empty.
    # No `cve` on purpose. The field is the surface the bugs sit behind, not
    # proof of exploitation (a harmless progress-bar upload carries it too), so
    # it is recorded as a signature and left for the analyst to attribute.
    _rule("php_code", "php-session-upload-progress", r"^.{0,64}",
          "body", params=r"^PHP_SESSION_UPLOAD_PROGRESS$", sig="php-session-upload-progress"),
    _rule("php_code", "php-open-tag",
          r"<\?(?:php\b|=)|<\?\s*(?:echo|eval|system|exec|passthru|shell_exec|assert|include|require)\b",
          "query body"),
    _rule("php_code", "dangerous-call",
          r"\b(?:eval|assert|system|passthru|shell_exec|exec|popen|proc_open|call_user_func(?:_array)?)"
          r"\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|stripslashes|\$_(?:GET|POST|REQUEST|COOKIE|SERVER)|[\"'])"
          r"|\bphpinfo\s*\(\s*\)|\$_(?:GET|POST|REQUEST|COOKIE)\s*\[",
          "query body"),

    # -- cmd_injection -----------------------------------------------------
    _rule("cmd_injection", "pipe-to-shell", r"\|\s*(?:/(?:usr/)?bin/)?(?:ba|da|z|k)?sh\b",
          "query body"),
    _rule("cmd_injection", "fetch-payload",
          _SEP + r"(?:busybox\s+)?(?:wget|curl|tftp|ftpget)\s+[^\n;|]*?"
          r"(?:(?:https?|ftp|tftp)://|\d{1,3}(?:\.\d{1,3}){3})",
          "query body"),
    _rule("cmd_injection", "read-system-file",
          _SEP + r"(?:cat|ls|head|tail|more|less|nl|tac|cp|mv)\s+(?:-\S+\s+)*[/.~]",
          "query body"),
    _rule("cmd_injection", "stage-in-tmp",
          _SEP + r"(?:cd\s+/(?:tmp|var|dev|root|home|etc|usr)|rm\s+-\w*[rf]|chmod\s+(?:[0-7]{3,4}|[ugoa]*[+-][rwx]+)\s+\S"
          r"|(?:killall|pkill)\s+-?\w)",
          "query body"),
    _rule("cmd_injection", "command-substitution",
          r"\$\(\s*(?:uname|id|whoami|cat|ls|wget|curl|sleep|ping|nslookup)\b"
          r"|`\s*(?:uname|id|whoami|cat|ls|wget|curl|sleep|ping|nslookup)\b[^`]{0,50}`",
          "query body"),
    _rule("cmd_injection", "recon-command",
          r"[;|&`\n]\s*(?:id|whoami|uname(?:\s+-\w+)*|hostname|ifconfig|pwd)\s*(?:$|[;|&)\s])"
          r"|[;|&`\n]\s*(?:sleep\s+\d+|ping\s+-c\s*\d+)",
          "query body"),
    _rule("cmd_injection", "reverse-shell",
          r"/dev/tcp/|\bnc(?:at)?\s+(?:-\w+\s+)*\S+\s+\d+\s+-e\b|\bbash\s+-i\b|\bmkfifo\b"
          r"|python\S*\s+-c\s+[\"']?import\s+(?:socket|os|pty)",
          "query body"),

    # -- sqli --------------------------------------------------------------
    # UNION must be directly followed by SELECT. "select a union rep" has them
    # reversed with words between; that is the budget's named negative case.
    _rule("sqli", "union-select",
          r"\bunion\b(?:\s|/\*.*?\*/)+(?:all\s+|distinct\s+)?select\b", "path query body"),
    # Tautologies: `or 1=1` (same literal both sides), or a quote closing a
    # string then or/and then a comparison. O'Reilly or not: the quote is not
    # directly before "or".
    _rule("sqli", "tautology",
          r"\b(?:or|and)\s+(\d+)\s*=\s*\1\b|['\")]\s*(?:or|and|\|\||&&)\s*['\"(]?\s*\w+['\"]?\s*(?:=|like)\s*['\"]?\w",
          "query body"),
    _rule("sqli", "time-or-error-based",
          r"\b(?:sleep|benchmark|pg_sleep)\s*\(\s*\d|\bwaitfor\s+delay\b|\b(?:extractvalue|updatexml)\s*\(",
          "query body"),
    _rule("sqli", "schema-or-file",
          r"\binformation_schema\b|\bload_file\s*\(|\binto\s+(?:out|dump)file\b"
          r"|;\s*(?:drop|truncate)\s+table\b",
          "query body"),

    # -- xss ---------------------------------------------------------------
    _rule("xss", "script-tag", r"<\s*/?\s*script\b", "path query body"),
    # A tag followed by an on* handler attribute: <svg/onload=, <img src=x onerror=.
    _rule("xss", "event-handler",
          r"<\s*[a-z][a-z0-9]*[\s/]+(?:[^>]{0,200}?[\s\"'/])?on[a-z]{3,20}\s*=", "path query body"),
    _rule("xss", "active-tag", r"<\s*(?:iframe|embed|object|svg|math)\b", "path query body"),
    _rule("xss", "javascript-uri", r"javascript:\s*[a-z_$][\w$.]*\s*\(", "query body"),
)


# -- plumbing: split a request into (location, text) units ------------------

_IDENT = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,39}$")


def _field_location(kind: str, name: str | None) -> tuple[str, str | None]:
    if name is not None and _IDENT.match(name):
        return f"{kind}:{name}", name
    return kind, None


def _header(headers, name: str) -> str:
    for h in headers:
        if h[0].lower() == name:
            return h[1]
    return ""


def _split_pairs(raw: str, kind: str):
    """Yield (location, param, text) for each &-piece of a query/form string.

    '+' is turned into a space here: that is how the server would parse the
    field, so it is not counted as an attacker-applied "decoded" layer.
    """
    for piece in raw.split("&")[:MAX_PIECES]:
        if not piece:
            continue
        if "=" in piece:
            name, value = piece.split("=", 1)
            location, param = _field_location(kind, unquote_plus(name))
            if param is not None:
                yield location, param, value.replace("+", " ")
                continue
        yield kind, None, piece.replace("+", " ")


def _multipart(body: bytes, boundary: str):
    for seg in body.split(b"--" + boundary.encode())[1:MAX_PIECES + 1]:
        if seg.startswith(b"--"):
            break
        seg = seg.lstrip(b"\r\n")
        head, sep, value = seg.partition(b"\r\n\r\n")
        if not sep:
            head, sep, value = seg.partition(b"\n\n")
        m = re.search(rb'name="([^"]*)"', head)
        name = m.group(1).decode("latin-1") if m else None
        location, param = _field_location(BODY, name)
        yield location, param, value.rstrip(b"\r\n").decode("utf-8", "replace")


def _json_leaves(value, depth=0):
    if depth > 6:
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield str(k)
            yield from _json_leaves(v, depth + 1)
    elif isinstance(value, list):
        for v in value:
            yield from _json_leaves(v, depth + 1)


def _body_units(headers, body: bytes | None):
    if not body:
        return
    body = body[:MAX_BODY]
    ctype = _header(headers, "content-type")
    low = ctype.lower()
    if "multipart/form-data" in low:
        m = re.search(r'boundary="?([^";]+)', ctype, re.I)
        if m:
            yield from _multipart(body, m.group(1))
            return
    elif "json" in low:
        try:
            doc = json.loads(body.decode("utf-8", "replace"))
        except ValueError:
            doc = None
        if isinstance(doc, dict):
            for key, value in list(doc.items())[:MAX_PIECES]:
                location, param = _field_location(BODY, str(key))
                for leaf in list(_json_leaves(value))[:MAX_PIECES]:
                    yield location, param, leaf
            return
        if doc is not None:
            for leaf in list(_json_leaves(doc))[:MAX_PIECES]:
                yield BODY, None, leaf
            return
    elif "x-www-form-urlencoded" in low:
        yield from _split_pairs(body.decode("latin-1"), BODY)
        return
    # latin-1 keeps every byte: Java's AC ED 00 05 magic must survive.
    yield BODY, None, body.decode("latin-1")


def _units(raw_path, raw_query, headers, body):
    """Every (kind, location, param, text) a rule could apply to."""
    if raw_path:
        yield PATH, PATH, None, raw_path
    if raw_query:
        for location, param, text in _split_pairs(raw_query, QUERY):
            yield QUERY, location, param, text
    for location, param, text in _body_units(headers, body):
        yield BODY, location, param, text
    for h in headers:
        yield HEADER, f"header:{h[0]}", None, str(h[1])


def _views(text: str) -> list[tuple[str, bool]]:
    """(text, decoded) for the raw text, each percent-decoded layer, and each
    Log4j de-obfuscated form. Raw comes first so a plain match is not
    mislabelled as decoded."""
    text = text[:MAX_VIEW]
    layers = decode.url_layers(text)
    views = [(layers[0], False)] + [(layer, True) for layer in layers[1:]]
    seen = {v for v, _ in views}
    for layer in layers:
        plain = decode.deobfuscate_log4j(layer)
        if plain not in seen:
            seen.add(plain)
            views.append((plain, True))
    return views


def _evidence(view: str, m: re.Match) -> str:
    start = max(0, m.start() - 20)
    return view[start:min(m.end() + 20, start + EVIDENCE_CAP, len(view))][:EVIDENCE_CAP]


def classify(raw_path, raw_query, headers, body_bytes) -> list[Attack]:
    found: dict[tuple[str, str], Attack] = {}
    for kind, location, param, text in _units(raw_path, raw_query, headers or [], body_bytes):
        rules = [r for r in RULES
                 if kind in r.where and (r.params is None or (param is not None and r.params.search(param)))]
        if not rules:
            continue
        views = _views(text)
        raw = views[0][0]
        for rule in rules:
            key = (rule.cls, location)
            current = found.get(key)
            if current is not None and (current.cve or current.sig or not (rule.cve or rule.sig)):
                continue
            if rule.hint is not None and not rule.hint.search(raw):
                continue
            for view, decoded in views:
                m = rule.pattern.search(view)
                if m:
                    found[key] = Attack(rule.cls, location, _evidence(view, m), decoded, rule.sig, rule.cve)
                    break
    return list(found.values())


# -- tool attribution -------------------------------------------------------

@dataclass(frozen=True)
class Tool:
    name: str
    kind: str   # botnet | scanner | attack_tool | research | exploit_kit

    def as_dict(self) -> dict:
        return {"name": self.name, "kind": self.kind}


_UA_TOOLS = tuple((re.compile(p, re.I), n, k) for p, n, k in (
    (r"libredtail", "redtail", "botnet"),
    (r"zgrab", "zgrab", "scanner"),
    (r"\bnmap\b|nmap-http", "nmap", "scanner"),
    (r"\bzmap\b", "zmap", "scanner"),
    (r"\bsqlmap\b", "sqlmap", "attack_tool"),
    (r"\bnuclei\b", "nuclei", "attack_tool"),
    (r"\bnikto\b", "nikto", "attack_tool"),
    (r"\bwpscan\b", "wpscan", "attack_tool"),
    (r"fuzz faster u fool|\bffuf\b", "ffuf", "attack_tool"),
    (r"censysinspect", "censys", "research"),
    (r"palo alto networks", "xpanse", "research"),
    (r"infrawatch", "infrawatch", "research"),
))

_BODY_TOOLS = tuple((re.compile(p, re.I), n, k) for p, n, k in (
    (r"bissa_cve_boundary", "bissa", "exploit_kit"),
    (r"\"clientInfo\"\s*:\s*\{\s*\"name\"\s*:\s*\"mcp-fingerprint-probe\"", "mcp-fingerprint-probe", "scanner"),
))


def tools(headers, body: bytes | None) -> list[Tool]:
    found: dict[tuple[str, str], Tool] = {}
    for pattern, name, kind in _UA_TOOLS:
        if pattern.search(_header(headers or [], "user-agent")):
            found[(name, kind)] = Tool(name, kind)
    text = _header(headers or [], "content-type") + "\n" + (body or b"")[:MAX_BODY].decode("latin-1")
    for pattern, name, kind in _BODY_TOOLS:
        if pattern.search(text):
            found[(name, kind)] = Tool(name, kind)
    return list(found.values())


# -- out-of-band callback domains ------------------------------------------

# Needs at least one label in front of the service, so "oast.fun is a site"
# and "burpcollaborator.net.example.com" do not match. Extracted, never resolved.
_OAST = re.compile(
    r"(?<![a-z0-9-])((?:[a-z0-9-]+\.)+(?:oast\.[a-z]{2,10}|interact\.sh|burpcollaborator\.net|oastify\.com|dnslog\.cn))"
    r"(?![a-z0-9-]|\.[a-z0-9])",
    re.I,
)


def oast_domains(texts) -> list[str]:
    out: list[str] = []
    for text in texts:
        if not text:
            continue
        # Only the fully decoded form: a %2F left in front of a label would
        # otherwise glue "2Fzz" onto the domain.
        flat = decode.deobfuscate_log4j(decode.url_layers(text[:MAX_VIEW])[-1])
        for m in _OAST.finditer(flat):
            domain = m.group(1).lower()
            if domain not in out:
                out.append(domain)
    return out


# -- one call for the middleware -------------------------------------------

@dataclass
class Analysis:
    attacks: list[Attack] = field(default_factory=list)
    tools: list[Tool] = field(default_factory=list)
    oast: list[str] = field(default_factory=list)

    def event_fields(self) -> dict:
        return {
            "attacks": [a.as_dict() for a in self.attacks] or None,
            "tools": [t.as_dict() for t in self.tools] or None,
            "oast": self.oast or None,
        }


def analyze(raw_path, raw_query, headers, body) -> Analysis:
    headers = headers or []
    texts = [raw_path, raw_query] + [str(h[1]) for h in headers]
    if body:
        texts.append(body[:MAX_BODY].decode("latin-1"))
    return Analysis(
        classify(raw_path, raw_query, headers, body),
        tools(headers, body),
        oast_domains(texts),
    )

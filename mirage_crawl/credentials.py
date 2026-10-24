"""Credentials attackers try, pulled out of whatever carried them.

On a honeypot every credential is attacker-supplied, so they are kept
verbatim: the interesting questions are which pairs are tried, against which
persona, and whether one of our own planted honeytokens comes back.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from urllib.parse import parse_qsl

from .capture import Body

VALUE_CAP = 256

USER_FIELDS = (
    "username", "user", "login", "log", "email", "uname", "usr", "user_login",
    "j_username", "pma_username", "account", "userid", "user_id",
)
PASSWORD_FIELDS = (
    "password", "pass", "pwd", "passwd", "pw", "passw", "j_password",
    "pma_password", "user_pass", "secret",
)
API_KEY_HEADERS = ("x-api-key", "api-key", "x-auth-token", "private-token", "x-access-token")


@dataclass(frozen=True)
class Credential:
    scheme: str   # basic | bearer | digest | api_key | form | <other auth scheme>
    source: str   # authorization | header:<Name> | body | json | query
    user: str | None
    password: str | None

    def as_dict(self) -> dict:
        return {"scheme": self.scheme, "source": self.source, "user": self.user, "password": self.password}


def _cap(value: str | None) -> str | None:
    return None if value is None else value[:VALUE_CAP]


def _from_authorization(value: str) -> Credential:
    scheme, _, rest = value.strip().partition(" ")
    scheme_lc = scheme.lower()
    rest = rest.strip()
    if scheme_lc == "basic":
        try:
            decoded = base64.b64decode(rest, validate=True).decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            return Credential("basic", "authorization", None, _cap(rest))
        user, sep, password = decoded.partition(":")
        return Credential("basic", "authorization", _cap(user), _cap(password) if sep else None)
    return Credential(scheme_lc or "unknown", "authorization", None, _cap(rest or scheme))


def _from_mapping(fields: dict[str, str], source: str) -> Credential | None:
    lowered = {k.lower(): v for k, v in fields.items() if isinstance(v, str)}
    password = next((lowered[k] for k in PASSWORD_FIELDS if k in lowered), None)
    if password is None:
        return None
    user = next((lowered[k] for k in USER_FIELDS if k in lowered), None)
    return Credential("form", source, _cap(user), _cap(password))


def extract(headers: list[list[str]], raw_query: str | None, body: Body | None) -> list[Credential]:
    found: list[Credential] = []
    content_type = ""
    for name, value in headers:
        lowered = name.lower()
        if lowered == "authorization":
            found.append(_from_authorization(value))
        elif lowered in API_KEY_HEADERS:
            found.append(Credential("api_key", f"header:{name}", None, _cap(value)))
        elif lowered == "content-type":
            content_type = value.lower()

    if raw_query:
        cred = _from_mapping(dict(parse_qsl(raw_query, keep_blank_values=True)), "query")
        if cred:
            found.append(cred)

    if body is not None and body.data:
        text = body.text()
        if "json" in content_type or text.lstrip().startswith("{"):
            try:
                parsed = json.loads(text)
            except ValueError:
                parsed = None
            if isinstance(parsed, dict):
                cred = _from_mapping(parsed, "json")
                if cred:
                    found.append(cred)
        elif "multipart" not in content_type:
            cred = _from_mapping(dict(parse_qsl(text, keep_blank_values=True)), "body")
            if cred:
                found.append(cred)
    return found

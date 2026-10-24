"""The decode pipeline shared by the indicator scanner and the attack classifier.

Attackers encode payloads to get past naive matching: percent-encoding stacked
two or three deep, base64 inside a parameter, Log4j lookups that assemble
"jndi" out of nested defaults. Every detector should see the same peeled
forms, so peeling lives here, once.
"""

from __future__ import annotations

import re
from urllib.parse import unquote

URL_ROUNDS = 3


def url_layers(text: str, rounds: int = URL_ROUNDS) -> list[str]:
    """The text and each successive percent-decoding of it, until it stops changing.

    `unquote`, not `unquote_plus`: a literal '+' matters (stratum+tcp://,
    base64), and turning it into a space would destroy exactly what we want.
    """
    layers = [text]
    for _ in range(rounds):
        decoded = unquote(layers[-1])
        if decoded == layers[-1]:
            break
        layers.append(decoded)
    return layers


# Log4j lookups that evaluate to a literal, used to spell "jndi" without
# writing it: ${lower:j}, ${upper:J}, ${::-j}, ${env:UNSET:-j}, ${date:'j'}.
_LOOKUP_CASE = re.compile(r"\$\{(lower|upper):([^{}$]*)\}", re.I)
_LOOKUP_DEFAULT = re.compile(r"\$\{[^{}$]*?:-([^{}$]*)\}")
_LOOKUP_DATE = re.compile(r"\$\{date:'([^'{}$]*)'\}", re.I)


def deobfuscate_log4j(text: str, max_rounds: int = 10) -> str:
    """Collapse literal-valued Log4j lookups, innermost first, until stable."""
    if "${" not in text:
        return text
    for _ in range(max_rounds):
        before = text
        text = _LOOKUP_CASE.sub(
            lambda m: m.group(2).lower() if m.group(1).lower() == "lower" else m.group(2).upper(), text
        )
        text = _LOOKUP_DATE.sub(lambda m: m.group(1), text)
        text = _LOOKUP_DEFAULT.sub(lambda m: m.group(1), text)
        if text == before:
            break
    return text

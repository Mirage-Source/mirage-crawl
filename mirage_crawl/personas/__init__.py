"""Per-service personas bound to their own ports.

A single HTTP sensor on :80 has to guess which product a probe is aimed at
from the path alone, and paths collide (Ollama and Ray both answer
`/api/version`). A persona *port* removes the guess: on :11434 the request is
for Ollama, full stop. Each persona therefore scopes matching to its own
service family and carries that service's Server header, so a banner grab sees
a consistent, plausible target.

Personas reuse the probe decoys in `hunt.py` rather than redefining them: the
same ShadowRay/YARN/Docker knowledge, now addressable by port. Multi-stage
decoys (3.3) and the PHP web-app face (3.4) build on this.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .. import hunt
from . import stages
from .stages import Stage

# A stage handler sees (method, path, client_ip, id_key) and returns a Stage
# when it recognises a step of its service's workflow.
StageFn = Callable[[str, str, str, bytes], "Stage | None"]


@dataclass(frozen=True)
class Persona:
    name: str
    families: frozenset[str]            # hunt families this persona owns
    server_header: str                  # banner a scanner expects from it
    # A default decoy for an unrecognised path on this port, if any. A real
    # service answers *something* on its own port, so silence is itself a tell.
    default_decoy: str | None = None
    default_content_type: str = "application/json"
    # Multi-stage workflow handler (Ray job -> status, Docker create -> start
    # -> inspect). Tried before the static probe decoys.
    stage: StageFn | None = None

    def match(self, path: str) -> hunt.Probe | None:
        """First probe of one of this persona's families that matches `path`.

        Family-scoped, so `/api/version` on the Ollama port is Ollama's
        version decoy, never Ray's.
        """
        for probe in hunt.PROBES:
            if probe.family in self.families and probe.pattern.search(path):
                return probe
        return None


# Ports a persona listens on by convention, used when CRAWL_PERSONA_PORTS
# names a persona without a port.
DEFAULT_PORTS: dict[str, int] = {
    "ollama": 11434,
    "ray": 8265,
    "docker": 2375,
    "jupyter": 8888,
}

_OLLAMA_404 = '{"error":"model not found, try pulling it first"}'
_DOCKER_404 = '{"message":"page not found"}'

PERSONAS: dict[str, Persona] = {
    "ollama": Persona(
        "ollama", frozenset({"ollama", "openai_compat"}),
        server_header="Ollama", default_decoy=_OLLAMA_404,
    ),
    "ray": Persona(
        "ray", frozenset({"ray"}),
        server_header="Werkzeug/2.3.7 Python/3.10.12",
        stage=stages.ray,
    ),
    "docker": Persona(
        "docker", frozenset({"docker", "registry"}),
        server_header="Docker/24.0.7 (linux)", default_decoy=_DOCKER_404,
        stage=stages.docker,
    ),
    "jupyter": Persona(
        "jupyter", frozenset({"jupyter"}),
        server_header="TornadoServer/6.3.3",
    ),
}


def get(name: str) -> Persona | None:
    return PERSONAS.get(name)


def parse_ports(spec: str) -> list[tuple[str, int]]:
    """Parse "ollama:11434,ray,docker:2375" into [(persona, port), ...].

    A bare name uses the persona's conventional port. Unknown persona names
    and bad ports raise, so a typo fails at startup rather than silently
    opening nothing.
    """
    out: list[tuple[str, int]] = []
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        name, sep, port = item.partition(":")
        name = name.strip()
        if name not in PERSONAS:
            raise ValueError(f"unknown persona {name!r}; known: {', '.join(sorted(PERSONAS))}")
        if sep:
            port_num = int(port)
        elif name in DEFAULT_PORTS:
            port_num = DEFAULT_PORTS[name]
        else:
            raise ValueError(f"persona {name!r} has no default port; give one as {name}:PORT")
        out.append((name, port_num))
    return out

"""Deterministic content generation.

The sensor serves a documentation site that looks like something worth
crawling: projects, pages, and — deliberately — forks that duplicate an
existing project with one changed paragraph.

Nothing is stored. Every page is derived from its own path via a seeded hash,
so the whole site is reproducible from `SITE_SEED` alone, costs no disk, and
returns byte-identical content (and therefore a stable ETag) across restarts.
That stability is what makes conditional-request measurement possible: if a
client refetches an unchanged page without `If-None-Match`, it is doing so by
choice, not because we changed anything.

Forks exist to measure the redundancy problem directly. `p017` may be a fork of
`p004` whose pages are identical apart from one paragraph, so a crawler that
fetches both is transferring near-duplicate bytes. The content hash is logged
per response, which turns "how much duplicate content did this crawler pull?"
into a group-by.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone

_SUBJECTS = (
    "the scheduler", "the ingest worker", "the retry queue", "a cold cache",
    "the migration runner", "the replica set", "the token bucket", "the parser",
    "a partial write", "the compaction pass", "the write-ahead log", "the shard map",
)
_VERBS = (
    "blocks until", "retries when", "falls back to", "short-circuits if",
    "serialises against", "defers to", "reconciles with", "yields to",
)
_OBJECTS = (
    "the previous batch completes", "the lease expires", "a quorum is reached",
    "the buffer drains", "the checkpoint lands", "backpressure clears",
    "the leader changes", "the index is rebuilt",
)
_CLAUSES = (
    "This is intentional and documented here so it is not rediscovered.",
    "The behaviour changed in the 2.4 series and is not backported.",
    "Callers should treat the result as advisory rather than authoritative.",
    "There is a known edge case when the clock moves backwards.",
    "The timeout is deliberately shorter than the upstream default.",
    "Prefer the batched form; the single-item path exists for tests.",
)
_TITLES = (
    "Configuration reference", "Failure modes", "Upgrade notes", "Internals",
    "Rate limits", "Storage layout", "Retry semantics", "Observability",
    "Migration guide", "Tuning", "Schema notes", "Operational runbook",
)


def _rng_bytes(seed: str, n: int = 32) -> bytes:
    return hashlib.blake2b(seed.encode("utf-8"), digest_size=n).digest()


class _Stream:
    """A tiny deterministic index picker driven by a hash digest."""

    def __init__(self, seed: str) -> None:
        self._buf = _rng_bytes(seed, 64)
        self._i = 0

    def _next(self) -> int:
        if self._i >= len(self._buf):
            self._buf = hashlib.blake2b(self._buf, digest_size=64).digest()
            self._i = 0
        value = self._buf[self._i]
        self._i += 1
        return value

    def pick(self, options: tuple) -> str:
        return options[self._next() % len(options)]

    def below(self, n: int) -> int:
        return self._next() % n


@dataclass(frozen=True)
class Page:
    project: str
    index: int
    path: str
    title: str
    body: tuple[str, ...]
    canary: str
    etag: str
    last_modified: str
    content_hash: str
    fork_of: str | None


@dataclass(frozen=True)
class Project:
    pid: str
    name: str
    path: str
    page_count: int
    fork_of: str | None


class Site:
    """A reproducible documentation site."""

    def __init__(
        self,
        seed: str,
        projects: int = 40,
        pages_per_project: int = 12,
        fork_every: int = 5,
    ) -> None:
        self.seed = seed
        self.n_projects = max(projects, 1)
        self.pages_per_project = max(pages_per_project, 1)
        self.fork_every = max(fork_every, 2)
        self._projects = [self._build_project(i) for i in range(self.n_projects)]
        self._by_id = {p.pid: p for p in self._projects}

    # -- structure ---------------------------------------------------------

    def _build_project(self, i: int) -> Project:
        pid = f"p{i:03d}"
        rng = _Stream(f"{self.seed}:project:{pid}")
        # Every `fork_every`-th project duplicates an earlier one. The fork
        # target is deterministic and always earlier, so the graph is acyclic.
        fork_of = None
        if i >= self.fork_every and i % self.fork_every == 0:
            fork_of = f"p{(i // self.fork_every - 1) % max(i, 1):03d}"
            if fork_of == pid:
                fork_of = None
        name = f"{rng.pick(('atlas', 'ferrite', 'kestrel', 'lumen', 'orbit', 'quarry', 'tessera', 'vellum'))}-{pid[1:]}"
        return Project(
            pid=pid,
            name=name if fork_of is None else f"{name}-fork",
            path=f"/docs/{pid}/",
            page_count=self.pages_per_project,
            fork_of=fork_of,
        )

    @property
    def projects(self) -> list[Project]:
        return list(self._projects)

    def project(self, pid: str) -> Project | None:
        return self._by_id.get(pid)

    # -- content -----------------------------------------------------------

    def page(self, pid: str, index: int) -> Page | None:
        project = self._by_id.get(pid)
        if project is None or not (0 <= index < project.page_count):
            return None

        # A fork renders its parent's content, with exactly one paragraph
        # replaced. Byte-level near-duplication is the point.
        source_pid = project.fork_of or pid
        rng = _Stream(f"{self.seed}:page:{source_pid}:{index}")

        title = f"{rng.pick(_TITLES)} — {source_pid}/{index:02d}"
        paragraphs = []
        for para in range(3 + rng.below(3)):
            sentences = []
            for _ in range(3 + rng.below(3)):
                sentences.append(
                    f"{rng.pick(_SUBJECTS).capitalize()} {rng.pick(_VERBS)} "
                    f"{rng.pick(_OBJECTS)}. {rng.pick(_CLAUSES)}"
                )
            paragraphs.append(" ".join(sentences))

        if project.fork_of is not None and paragraphs:
            drift = _Stream(f"{self.seed}:fork:{pid}:{index}")
            slot = drift.below(len(paragraphs))
            paragraphs[slot] = (
                f"Forked from {project.fork_of}. {drift.pick(_CLAUSES)} "
                f"{drift.pick(_SUBJECTS).capitalize()} {drift.pick(_VERBS)} {drift.pick(_OBJECTS)}."
            )

        path = f"/docs/{pid}/{index:02d}.html"
        canary = self.canary(path)
        body = tuple(paragraphs)
        content_hash = hashlib.blake2s(
            ("\n".join(body)).encode("utf-8"), digest_size=16
        ).hexdigest()

        # Last-Modified is derived from the content, not the clock, so it never
        # moves unless the content does.
        stamp = int.from_bytes(_rng_bytes(f"{self.seed}:mtime:{source_pid}:{index}", 4), "big")
        modified = datetime.fromtimestamp(
            1_700_000_000 + (stamp % 30_000_000), tz=timezone.utc
        )

        return Page(
            project=pid,
            index=index,
            path=path,
            title=title,
            body=body,
            canary=canary,
            etag=f'"{content_hash}"',
            last_modified=modified.strftime("%a, %d %b %Y %H:%M:%S GMT"),
            content_hash=content_hash,
            fork_of=project.fork_of,
        )

    def canary(self, path: str) -> str:
        """A unique, searchable string planted in every page.

        If one of these ever turns up in a model's output, that page reached
        training data. The prefix is deliberately distinctive so it can be
        grepped for across corpora and probed for in model responses.
        """
        digest = hashlib.blake2s(
            f"{self.seed}:canary:{path}".encode("utf-8"), digest_size=8
        ).hexdigest()
        return f"MIRAGE-CANARY-{digest.upper()}"

    def all_page_paths(self) -> list[str]:
        return [
            f"/docs/{p.pid}/{i:02d}.html"
            for p in self._projects
            for i in range(p.page_count)
        ]

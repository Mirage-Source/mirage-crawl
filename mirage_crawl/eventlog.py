"""Append-only JSONL event log.

One file per UTC day, one JSON object per line, never rewritten. This is the
same shape Mirage already publishes its command corpus in, and for a capture
sensor it beats a database on every axis that matters here: no schema migration
while the instrument is still changing, crash-safe by construction, trivially
shipped to a laptop, and readable by pandas, DuckDb or `jq` without a server.

Writes go through a background task so a slow disk cannot add latency to a
response. The queue is bounded: if the sensor is ever flooded faster than the
disk can keep up, events are dropped and the drop is counted rather than
allowed to consume unbounded memory. A gap in the record is recoverable; an
OOM-killed sensor is not.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EVENT_REQUEST = "request"
EVENT_POLICY_READ = "policy_read"
EVENT_TRAP_HIT = "trap_hit"
EVENT_IDENTITY = "identity"
EVENT_HUNT = "hunt"
EVENT_TLS = "tls"
EVENT_SENSOR = "sensor"


class EventLog:
    def __init__(self, directory: str | Path, sensor_id: str, queue_size: int = 10_000) -> None:
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.sensor_id = sensor_id
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=queue_size)
        self._task: asyncio.Task | None = None
        self._handle = None
        self._day: str | None = None
        self.written = 0
        self.dropped = 0

    # -- lifecycle ---------------------------------------------------------

    async def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._drain(), name="eventlog")

    async def stop(self) -> None:
        if self._task is not None:
            await self._queue.put({"__stop__": True})
            await self._task
            self._task = None
        self._close()

    def _close(self) -> None:
        if self._handle is not None:
            self._handle.flush()
            os.fsync(self._handle.fileno())
            self._handle.close()
            self._handle = None
            self._day = None

    def _open_for(self, day: str):
        if self._day != day:
            self._close()
            self._handle = open(self.dir / f"{day}.jsonl", "a", encoding="utf-8", buffering=1)
            self._day = day
        return self._handle

    # -- writing -----------------------------------------------------------

    def emit(self, kind: str, **fields: Any) -> None:
        """Queue an event. Never blocks and never raises."""
        record = {
            "kind": kind,
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "sensor": self.sensor_id,
            **fields,
        }
        try:
            self._queue.put_nowait(record)
        except asyncio.QueueFull:
            self.dropped += 1

    async def _drain(self) -> None:
        while True:
            record = await self._queue.get()
            if record.get("__stop__"):
                self._flush_remaining()
                return
            self._write(record)

    def _flush_remaining(self) -> None:
        while not self._queue.empty():
            record = self._queue.get_nowait()
            if not record.get("__stop__"):
                self._write(record)

    def _write(self, record: dict[str, Any]) -> None:
        try:
            day = record["ts"][:10]
            handle = self._open_for(day)
            handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
            self.written += 1
        except Exception:
            # A logging failure must never take the sensor down.
            self.dropped += 1


def read_events(directory: str | Path, kinds: set[str] | None = None):
    """Iterate every logged event, oldest file first. Skips malformed lines."""
    directory = Path(directory)
    for path in sorted(directory.glob("*.jsonl")):
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if kinds is None or record.get("kind") in kinds:
                    yield record

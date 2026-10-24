"""Multi-stage decoy workflows, with state derived rather than stored.

A single static decoy ends the conversation: a scanner that gets a model list
or a version string has what it came for and leaves, and the payload-bearing
*next* request never happens. A real service instead hands back an identifier
and answers follow-up calls about it. These handlers do that for the workflows
scanners actually walk — Ray's job submit then poll, Docker's create then start
then inspect — so the attacker proceeds to the stage that carries the payload.

No database: an identifier is an HMAC of (sensor key, client ip, seed), so the
same client sees the same "job" or "container" across restarts and the sensor
keeps no state. Nothing is executed; the job only ever "runs" in the JSON.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Stage:
    family: str
    target: str
    category: str
    intent: str
    status: int
    content_type: str
    body: str


def _id(key: bytes, client_ip: str, seed: str, length: int = 16) -> str:
    return hmac.new(key, f"{client_ip}:{seed}".encode("utf-8"), hashlib.sha256).hexdigest()[:length]


_RAY_SUBMIT = re.compile(r"^/api/jobs/?$")
_RAY_STATUS = re.compile(r"^/api/jobs/(?P<id>[A-Za-z0-9_-]{1,64})/?$")


def ray(method: str, path: str, client_ip: str, key: bytes) -> Stage | None:
    """Ray dashboard job API: submit returns an id, polling reports RUNNING."""
    if method == "POST" and _RAY_SUBMIT.match(path):
        job = "raysubmit_" + _id(key, client_ip, "ray-job", 12)
        return Stage(
            "ray", "Ray dashboard", "gpu_ml",
            "submit a job to a GPU cluster (ShadowRay) and receive a handle",
            200, "application/json",
            json.dumps({"job_id": job, "submission_id": job}),
        )
    m = _RAY_STATUS.match(path)
    if method == "GET" and m:
        return Stage(
            "ray", "Ray dashboard", "gpu_ml",
            "poll a submitted job, confirming the cluster accepted it",
            200, "application/json",
            json.dumps({
                "job_id": m.group("id"), "status": "RUNNING",
                "message": "Job is currently running.",
                "entrypoint": "", "start_time": 1700000000000,
            }),
        )
    return None


_DK_CREATE = re.compile(r"^/(v[0-9.]+/)?containers/create/?$")
_DK_START = re.compile(r"^/(v[0-9.]+/)?containers/(?P<id>[A-Za-z0-9_-]+)/start/?$")
_DK_INSPECT = re.compile(r"^/(v[0-9.]+/)?containers/(?P<id>[A-Za-z0-9_-]+)/json/?$")


def docker(method: str, path: str, client_ip: str, key: bytes) -> Stage | None:
    """Docker Engine API: create returns an id, start 204s, inspect says running."""
    if method == "POST" and _DK_CREATE.match(path):
        cid = _id(key, client_ip, "docker-container", 64)
        return Stage(
            "docker", "Docker Engine API", "container",
            "create a container on an exposed daemon and receive its id",
            201, "application/json",
            json.dumps({"Id": cid, "Warnings": []}),
        )
    m = _DK_START.match(path)
    if method == "POST" and m:
        return Stage(
            "docker", "Docker Engine API", "container",
            "start the created container (no process is ever run)",
            204, "application/json", "",
        )
    m = _DK_INSPECT.match(path)
    if method == "GET" and m:
        cid = m.group("id")
        return Stage(
            "docker", "Docker Engine API", "container",
            "inspect the container, which reports itself running",
            200, "application/json",
            json.dumps({
                "Id": cid,
                "State": {"Status": "running", "Running": True, "Pid": 1234, "ExitCode": 0},
                "Config": {"Image": "alpine:latest", "Cmd": ["/bin/sh"]},
                "Image": "sha256:" + ("0" * 64),
            }),
        )
    return None

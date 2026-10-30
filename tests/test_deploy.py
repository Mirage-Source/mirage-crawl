"""deploy/deploy.sh: what the forced-command deploy key can and cannot make the server do.

Runs the script against a throwaway git checkout with a fake systemctl; never touches /opt.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "deploy" / "deploy.sh"
FAILED = []


def check(name, ok, detail=""):
    print(("  PASS  " if ok else "  FAIL  ") + name + ("" if ok else f"  {detail}"))
    if not ok:
        FAILED.append(name)


def git(cwd, *args):
    return subprocess.run(["git", "-C", str(cwd), "-c", "user.name=t", "-c", "user.email=t@t", *args],
                          check=True, capture_output=True, text=True).stdout.strip()


def make_origin_and_app(tmp: Path):
    origin = tmp / "origin"
    origin.mkdir()
    git(origin, "init", "-q", "-b", "main")
    (origin / "requirements.txt").write_text("")
    (origin / "v.txt").write_text("one")
    git(origin, "add", "-A")
    git(origin, "commit", "-q", "-m", "one")
    first = git(origin, "rev-parse", "HEAD")
    (origin / "v.txt").write_text("two")
    git(origin, "commit", "-qam", "two")
    second = git(origin, "rev-parse", "HEAD")
    app = tmp / "app"
    subprocess.run(["git", "clone", "-q", str(origin), str(app)], check=True)
    (app / "data").mkdir()
    (app / "data" / "beacon.secret").write_text("KEEP-ME")
    (app / ".gitignore").write_text("data/\n.venv/\n")
    git(app, "checkout", "-q", "--detach", first)
    return origin, app, first, second


def run(app, tmp, arg=None, orig=None):
    fake = tmp / "systemctl"
    fake.write_text('#!/bin/sh\necho "$@" >> "$(dirname "$0")/systemctl.log"\n'
                    '[ "$1" = is-active ] && [ -n "$FAKE_INACTIVE" ] && exit 3\nexit 0\n')
    fake.chmod(0o755)
    env = {**os.environ, "APP_DIR": str(app), "SYSTEMCTL": str(fake), "SKIP_PIP": "1", "HEALTH_WAIT": "0"}
    env.pop("SSH_ORIGINAL_COMMAND", None)
    if orig is not None:
        env["SSH_ORIGINAL_COMMAND"] = orig
    args = [str(SCRIPT)] + ([arg] if arg else [])
    return subprocess.run(args, env=env, capture_output=True, text=True)


with tempfile.TemporaryDirectory() as t:
    tmp = Path(t)
    origin, app, first, second = make_origin_and_app(tmp)

    r = run(app, tmp, arg=second)
    check("deploys a valid sha", r.returncode == 0 and git(app, "rev-parse", "HEAD") == second, r.stderr + r.stdout)
    check("keeps data/ (beacon.secret) untouched", (app / "data" / "beacon.secret").read_text() == "KEEP-ME")
    check("restarts the service", "restart mirage-crawl" in (tmp / "systemctl.log").read_text())
    check("prints previous and new sha", first in r.stdout and second in r.stdout, r.stdout)

    r = run(app, tmp, orig=f"/opt/mirage-crawl/deploy/deploy.sh {first}")
    check("accepts the sha from SSH_ORIGINAL_COMMAND (forced-command key)", r.returncode == 0 and git(app, "rev-parse", "HEAD") == first, r.stderr)

    log_before = (tmp / "systemctl.log").read_text()
    for bad in ("main", "HEAD", f"{second}; rm -rf /", "$(id)", second[:12], "--help"):
        r = run(app, tmp, arg=bad)
        check(f"rejects non-sha argument {bad!r}", r.returncode != 0 and git(app, "rev-parse", "HEAD") == first, r.stdout)
    check("no restart on rejected input", (tmp / "systemctl.log").read_text() == log_before)

    r = run(app, tmp, arg="0" * 40)
    check("rejects a sha that does not exist", r.returncode != 0 and git(app, "rev-parse", "HEAD") == first)

    (app / "v.txt").write_text("local edit")
    r = run(app, tmp, arg=second)
    check("refuses to overwrite local changes", r.returncode != 0 and (app / "v.txt").read_text() == "local edit")
    git(app, "checkout", "--", "v.txt")

    os.environ["FAKE_INACTIVE"] = "1"
    before = git(app, "rev-parse", "HEAD")
    r = run(app, tmp, arg=second)
    del os.environ["FAKE_INACTIVE"]
    check("rolls back and fails when the service does not come up",
          r.returncode != 0 and git(app, "rev-parse", "HEAD") == before and "rolling back" in r.stderr, r.stderr)
    check("restarts again after rollback", (tmp / "systemctl.log").read_text().count("restart mirage-crawl") >= 4)

    notgit = tmp / "notgit"
    notgit.mkdir()
    r = run(notgit, tmp, arg=second)
    check("fails clearly when APP_DIR is not a git checkout", r.returncode != 0 and "not a git checkout" in (r.stdout + r.stderr))

print()
if FAILED:
    print("FAILED:", ", ".join(FAILED))
    sys.exit(1)
print("all deploy checks passed")

"""deploy/deploy.sh: what the forced-command deploy key can and cannot make the server do.

Runs the script against a throwaway git checkout with a fake `docker compose`; never touches /opt.
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
    (origin / "v.txt").write_text("one")
    (origin / "hook.sh").write_text("#!/bin/sh\n")
    git(origin, "add", "-A")
    git(origin, "commit", "-q", "-m", "one")
    first = git(origin, "rev-parse", "HEAD")
    (origin / "v.txt").write_text("two")
    git(origin, "commit", "-qam", "two")
    second = git(origin, "rev-parse", "HEAD")
    git(origin, "checkout", "-q", "-b", "side")
    (origin / "v.txt").write_text("side branch only")
    git(origin, "commit", "-qam", "side")
    side = git(origin, "rev-parse", "HEAD")
    git(origin, "checkout", "-q", "main")
    app = tmp / "app"
    subprocess.run(["git", "clone", "-q", str(origin), str(app)], check=True)
    (app / ".gitignore").write_text(".env\n")
    (app / ".env").write_text("KEEP-ME")
    git(app, "checkout", "-q", "--detach", first)
    return origin, app, first, second, side


def run(app, tmp, arg=None, orig=None):
    fake = tmp / "compose"
    fake.write_text(
        '#!/bin/sh\necho "$@" >> "$(dirname "$0")/compose.log"\n'
        'if [ "$1" = ps ]; then [ -n "$FAKE_DOWN" ] || printf "crawl\\ntlsfront\\n"; fi\nexit 0\n')
    fake.chmod(0o755)
    env = {**os.environ, "APP_DIR": str(app), "COMPOSE": str(fake), "HEALTH_WAIT": "0"}
    env.pop("SSH_ORIGINAL_COMMAND", None)
    if orig is not None:
        env["SSH_ORIGINAL_COMMAND"] = orig
    args = [str(SCRIPT)] + ([arg] if arg else [])
    return subprocess.run(args, env=env, capture_output=True, text=True)


def ups(tmp):
    log = tmp / "compose.log"
    return log.read_text().count("up --build -d") if log.exists() else 0


with tempfile.TemporaryDirectory() as t:
    tmp = Path(t)
    origin, app, first, second, side = make_origin_and_app(tmp)

    r = run(app, tmp, arg=second)
    check("deploys a valid sha", r.returncode == 0 and git(app, "rev-parse", "HEAD") == second, r.stderr + r.stdout)
    check("keeps .env untouched", (app / ".env").read_text() == "KEEP-ME")
    check("builds and starts exactly the two sensor services", "up --build -d crawl tlsfront" in (tmp / "compose.log").read_text())
    check("prints previous and new sha", first in r.stdout and second in r.stdout, r.stdout)

    r = run(app, tmp, orig=f"/opt/mirage/mirage-crawl/deploy/deploy.sh {first}")
    check("accepts the sha from SSH_ORIGINAL_COMMAND (forced-command key)", r.returncode == 0 and git(app, "rev-parse", "HEAD") == first, r.stderr)

    before = ups(tmp)
    for bad in ("main", "HEAD", f"{second}; rm -rf /", "$(id)", second[:12], "--help"):
        r = run(app, tmp, arg=bad)
        check(f"rejects non-sha argument {bad!r}", r.returncode != 0 and git(app, "rev-parse", "HEAD") == first, r.stdout)
    check("nothing is rebuilt on rejected input", ups(tmp) == before)

    r = run(app, tmp, arg="0" * 40)
    check("rejects a sha that does not exist", r.returncode != 0 and git(app, "rev-parse", "HEAD") == first)

    r = run(app, tmp, arg=side)
    check("refuses a commit that is not on origin/main", r.returncode != 0 and "origin/main" in r.stderr
          and git(app, "rev-parse", "HEAD") == first, r.stderr)

    (app / "v.txt").write_text("local edit")
    r = run(app, tmp, arg=second)
    check("refuses to overwrite local changes", r.returncode != 0 and (app / "v.txt").read_text() == "local edit")
    git(app, "checkout", "--", "v.txt")

    (app / "hook.sh").chmod(0o755)
    r = run(app, tmp, arg=second)
    check("a file-mode-only difference is not a local change", r.returncode == 0 and git(app, "rev-parse", "HEAD") == second, r.stderr)
    run(app, tmp, arg=first)

    os.environ["FAKE_DOWN"] = "1"
    before_sha, before_ups = git(app, "rev-parse", "HEAD"), ups(tmp)
    r = run(app, tmp, arg=second)
    del os.environ["FAKE_DOWN"]
    check("rolls back and fails when the services do not come up",
          r.returncode != 0 and git(app, "rev-parse", "HEAD") == before_sha and "rolling back" in r.stderr, r.stderr)
    check("rebuilds the previous commit after rollback", ups(tmp) == before_ups + 2)

    notgit = tmp / "notgit"
    notgit.mkdir()
    r = run(notgit, tmp, arg=second)
    check("fails clearly when APP_DIR is not a git checkout", r.returncode != 0 and "not a git checkout" in (r.stdout + r.stderr))

print()
if FAILED:
    print("FAILED:", ", ".join(FAILED))
    sys.exit(1)
print("all deploy checks passed")

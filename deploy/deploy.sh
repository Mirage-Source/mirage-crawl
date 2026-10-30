#!/usr/bin/env bash
# Deploy one exact commit of mirage-crawl and restart the sensor.
#
# This is the ONLY thing the CI deploy key may run (forced command in authorized_keys, see deploy/DEPLOY.md), so it
# accepts nothing but a 40-hex commit SHA: a leaked key can redeploy commits that are already in the repo, no more.
#
#   deploy.sh <sha>                       direct use
#   SSH_ORIGINAL_COMMAND="... <sha>"      forced-command use (the SHA is the last token)
#
# It never touches data/ or .env (both gitignored): data/beacon.secret must survive every deploy, because rotating it
# orphans every beacon and honeytoken already minted (see CLAUDE.md).
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/mirage-crawl}"
SYSTEMCTL="${SYSTEMCTL:-sudo systemctl}"
UNIT="${UNIT:-mirage-crawl}"

if [ -n "${1:-}" ]; then
  candidate="$1"
else
  candidate="$(printf '%s\n' "${SSH_ORIGINAL_COMMAND:-}" | sed '/^[[:space:]]*$/d' | tail -n1 | awk '{print $NF}')"
fi
if ! [[ "$candidate" =~ ^[0-9a-f]{40}$ ]]; then
  echo "refusing: expected a 40-hex commit sha" >&2
  exit 2
fi
sha="$candidate"

[ -d "$APP_DIR/.git" ] || { echo "refusing: $APP_DIR is not a git checkout (see deploy/DEPLOY.md)" >&2; exit 1; }
cd "$APP_DIR"

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "refusing: $APP_DIR has uncommitted changes; resolve them by hand first" >&2
  exit 1
fi

prev="$(git rev-parse HEAD)"
git fetch -q origin
git cat-file -e "${sha}^{commit}" 2>/dev/null || { echo "refusing: $sha is not a commit in this repo" >&2; exit 1; }

git checkout -q --detach "$sha"
if [ -z "${SKIP_PIP:-}" ]; then
  .venv/bin/pip install -q -r requirements.txt
fi

# $SYSTEMCTL is deliberately unquoted: it may be "sudo systemctl".
$SYSTEMCTL restart "$UNIT"
sleep "${HEALTH_WAIT:-3}"
if ! $SYSTEMCTL is-active --quiet "$UNIT"; then
  echo "FAILED: $UNIT is not active after restart; rolling back to $prev" >&2
  git checkout -q --detach "$prev"
  $SYSTEMCTL restart "$UNIT"
  exit 1
fi

echo "deployed prev=$prev new=$sha at $(date -u +%Y-%m-%dT%H:%M:%SZ)"

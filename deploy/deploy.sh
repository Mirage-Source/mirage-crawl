#!/usr/bin/env bash
# Deploy one exact commit of mirage-crawl: check it out, rebuild and restart the sensor containers.
#
# This is the ONLY thing the CI deploy key may run (forced command in authorized_keys, see deploy/DEPLOY.md), so it
# accepts nothing but a 40-hex commit SHA: a leaked key can redeploy commits that are already in the repo, no more.
#
#   deploy.sh <sha>                       direct use
#   SSH_ORIGINAL_COMMAND="... <sha>"      forced-command use (the SHA is the last token)
#
# State lives in the named volumes crawl_data and crawl_config, and secrets in .env (gitignored), so a rebuild never
# touches the beacon secret: rotating it would orphan every beacon and honeytoken already minted (see CLAUDE.md).
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/mirage/mirage-crawl}"
COMPOSE="${COMPOSE:-docker compose}"
SERVICES="${SERVICES:-crawl tlsfront}"

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

# A file-mode-only difference (for example an executable bit set by hand) is not a local change.
g() { git -c core.fileMode=false "$@"; }

if ! g diff --quiet || ! g diff --cached --quiet; then
  echo "refusing: $APP_DIR has uncommitted changes; resolve them by hand first" >&2
  exit 1
fi

prev="$(git rev-parse HEAD)"
g fetch -q origin
g cat-file -e "${sha}^{commit}" 2>/dev/null || { echo "refusing: $sha is not a commit in this repo" >&2; exit 1; }
# Only code that reached main may run as root here: a commit on an unreviewed branch can carry any Dockerfile.
g merge-base --is-ancestor "$sha" origin/main || { echo "refusing: $sha is not on origin/main" >&2; exit 1; }

up() {
  # $COMPOSE and $SERVICES are deliberately unquoted: they may hold several words.
  BUILD_SHA="$1" $COMPOSE up --build -d $SERVICES
}

g checkout -q --detach "$sha"
up "$sha"
sleep "${HEALTH_WAIT:-10}"

running="$($COMPOSE ps --status running --services)"
for svc in $SERVICES; do
  if ! printf '%s\n' "$running" | grep -qx "$svc"; then
    echo "FAILED: $svc is not running after the rebuild; rolling back to $prev" >&2
    g checkout -q --detach "$prev"
    up "$prev"
    exit 1
  fi
done

echo "deployed prev=$prev new=$sha at $(date -u +%Y-%m-%dT%H:%M:%SZ)"

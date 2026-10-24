#!/bin/sh
# certbot --pre-hook: free :80 for the HTTP-01 challenge by stopping the crawl
# container (it owns :80 and the persona ports). Runs only when a renewal is
# actually attempted, so the brief downtime happens ~once per renewal, not on
# every twice-daily check. The project dir is derived from this script's path.
set -e
PROJECT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$PROJECT"
docker compose stop crawl

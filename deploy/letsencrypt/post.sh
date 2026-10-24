#!/bin/sh
# certbot --post-hook: bring the sensor back up after the challenge and reload
# the TLS front so it picks up the new cert. Idempotent (up -d), so it restores
# crawl even if the renewal itself failed after the pre-hook stopped it.
set -e
PROJECT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$PROJECT"
docker compose up -d crawl
docker compose restart tlsfront

#!/bin/sh
# certbot --deploy-hook: runs only when a cert was actually issued/renewed.
# Copies the live cert into deploy/certs (what the compose mount serves) and
# gives it to uid 999 -- the image's non-root `crawl` user, which the tlsfront
# runs as and otherwise cannot read a root-owned 600 key.
set -e
PROJECT=$(cd "$(dirname "$0")/../.." && pwd)
CERTS="$PROJECT/deploy/certs"
cp -L "$RENEWED_LINEAGE/fullchain.pem" "$CERTS/fullchain.pem"
cp -L "$RENEWED_LINEAGE/privkey.pem"  "$CERTS/privkey.pem"
chown 999:999 "$CERTS/fullchain.pem" "$CERTS/privkey.pem"
chmod 644 "$CERTS/fullchain.pem"
chmod 600 "$CERTS/privkey.pem"

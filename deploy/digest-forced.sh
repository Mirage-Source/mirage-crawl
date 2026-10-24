#!/bin/sh
# Forced command for the restricted "crawl digest" SSH key.
#
# Installed as:
#   command="/opt/mirage/mirage-crawl/deploy/digest-forced.sh",no-port-forwarding,\
#   no-agent-forwarding,no-pty,no-X11-forwarding ssh-ed25519 AAAA... crawl-digest
#
# in the authorized_keys of a user that can read the crawl event volume (root,
# since /var/lib/docker/volumes is root-only). The key can then do ONE thing:
# print the digest. SSH_ORIGINAL_COMMAND carries only the window in days; it is
# validated to a small integer, so nothing else can be injected.
set -eu

EV=/var/lib/docker/volumes/mirage-crawl_crawl_data/_data/events
DIGEST=/opt/mirage/mirage-crawl/scripts/digest.py

days="${SSH_ORIGINAL_COMMAND:-3}"
case "$days" in
    ''|*[!0-9]*) days=3 ;;        # not a plain integer -> default
esac
[ "$days" -ge 1 ] 2>/dev/null || days=3
[ "$days" -le 30 ] 2>/dev/null || days=30

exec python3 "$DIGEST" "$EV" --days "$days" --emit

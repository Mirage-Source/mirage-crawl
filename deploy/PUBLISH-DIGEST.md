# Publishing the crawl digest to gh-pages

`.github/workflows/publish-digest.yml` runs every 2 days: a GitHub runner SSHes
to the box with a **restricted key that can only emit the digest**, then commits
`summary.json` + `REPORT.md` to the `gh-pages` branch under `crawl-dataset/`.
No git credential or GitHub token ever lives on the honeypot; the key cannot
get a shell or read anything but the digest.

This mirrors mirage-core's publish pattern. One-time setup:

## 1. Create a dedicated key (on your laptop)

```sh
ssh-keygen -t ed25519 -f crawl-digest -N "" -C "crawl-digest"
```

## 2. Authorize it on the box, locked to the digest (on the sensor, as root)

The event logs live under `/var/lib/docker/volumes` (root-only), so the key
goes in **root's** authorized_keys on the admin sshd (`:2222`), restricted to
the forced command:

```sh
# paste the PUBLIC key (crawl-digest.pub) into this line:
printf 'command="/opt/mirage/mirage-crawl/deploy/digest-forced.sh",no-port-forwarding,no-agent-forwarding,no-pty,no-X11-forwarding %s\n' \
  "$(cat crawl-digest.pub)" >> /root/.ssh/authorized_keys
chmod +x /opt/mirage/mirage-crawl/deploy/digest-forced.sh
```

Verify it only ever prints the digest (and ignores injected commands):

```sh
ssh -i crawl-digest -p 2222 root@152.53.239.121 'rm -rf /' | head -c 80   # runs the digest, not rm
```

## 3. Add repo secrets (mirage-crawl → Settings → Secrets → Actions)

| Secret | Value |
|---|---|
| `CRAWL_DEPLOY_HOST` | `152.53.239.121` |
| `CRAWL_DEPLOY_PORT` | `2222` |
| `CRAWL_DEPLOY_USER` | `root` |
| `CRAWL_DIGEST_SSH_KEY` | contents of the **private** key `crawl-digest` |
| `CRAWL_KNOWN_HOSTS` | `ssh-keyscan -p 2222 152.53.239.121` output (pin the host key) |

Then trigger once from the Actions tab (**Run workflow**) to confirm it
publishes `crawl-dataset/latest/REPORT.md` on `gh-pages`.

> The digest is cheap (flat-file pass, no DB) and small (aggregates + a bounded
> follow-up list only) — raw request logs leave the box only through the
> sanitized R2 export (`scripts/export_r2.py`, `mirage_crawl/publish.py`).

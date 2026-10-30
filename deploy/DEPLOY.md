# Deploying mirage-crawl from GitHub Actions

`.github/workflows/deploy.yml` lets anyone with write access deploy an exact commit without SSH access to the server.
The server side is a one-time setup done by whoever has SSH access. Nothing below has been exercised against the real
server or against GitHub Actions: `tests/test_deploy.py` covers `deploy.sh` against a throwaway checkout only.

## What the server needs

1. **`/opt/mirage-crawl` must be a git checkout** of this repo (the deploy script refuses otherwise). `data/` and `.env`
   are gitignored, so a checkout never touches `data/beacon.secret`, which must stay stable across deploys (CLAUDE.md).
   If the directory was populated some other way, convert it once without deleting `data/`:
   ```
   cd /opt/mirage-crawl && git init -q && git remote add origin https://github.com/Mirage-Source/mirage-crawl
   git fetch origin && git reset --mixed origin/main    # keeps every file on disk, only adopts the index
   git status --short                                    # must show no unexpected changes; resolve them by hand
   ```
2. **A deploy user** that owns the checkout (or can write it) and may restart exactly one unit. In `/etc/sudoers.d/mirage-crawl-deploy`:
   ```
   mirage-deploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart mirage-crawl, /usr/bin/systemctl is-active --quiet mirage-crawl
   ```
3. **A dedicated SSH key**, forced to the deploy script, in that user's `~/.ssh/authorized_keys`:
   ```
   command="/opt/mirage-crawl/deploy/deploy.sh",restrict ssh-ed25519 AAAA... crawl-deploy-ci
   ```
   With a forced command the script reads the SHA from `SSH_ORIGINAL_COMMAND` and refuses anything that is not a
   40-hex commit SHA.
4. **GitHub repository secrets** (Settings, Secrets and variables, Actions): `CRAWL_DEPLOY_HOST`, `CRAWL_DEPLOY_PORT`,
   `CRAWL_DEPLOY_USER`, `CRAWL_DEPLOY_KEY` (the private half of the key above). `publish-digest.yml` already uses the
   first three; do not reuse its digest key.
5. Recommended: create a GitHub Environment (for example `crawl-production`) with required reviewers and put
   `environment: crawl-production` on the `deploy` job, so a second person approves each deploy.

## Running a deploy

Actions, Deploy mirage-crawl, Run workflow: choose a ref (default `main`), tick the ledger box. The job tests the commit
(44 unit, 31 end-to-end, and the deploy-script checks), then the server checks out that exact SHA, installs
`requirements.txt` and restarts `mirage-crawl`. If the unit is not active 3 s later the script rolls back to the previous
commit and the job fails.

**Rollback:** run the workflow with the previous SHA (printed in the job log as `prev=`).

## Things this does not do, on purpose

- It does not install or change systemd units under `deploy/systemd/` or `deploy/dataset-export/`. Those need a person on the
  server.
- It does not change `.env`, `CRAWL_SITE_SEED`, or anything under `data/`.
- It does not record the build in the sensor's events, so the ledger in mirage-lab is the only record of which commit
  produced which data. Fill it in for every deploy.

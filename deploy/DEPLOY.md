# Deploying mirage-crawl from GitHub Actions

`.github/workflows/deploy.yml` deploys an exact commit without anyone needing an interactive SSH session.

## How the sensor runs on the server

Checked on the host on 2026-10-30:

- Docker Compose runs two containers from this repo, `crawl` and `tlsfront`, in `/opt/mirage/mirage-crawl`, a git checkout
  of this repo.
- State lives in the named volumes `crawl_data` and `crawl_config`, and secrets in `.env` (gitignored). Neither is
  touched by a checkout or a rebuild. `data/beacon.secret` must stay stable across deploys (see `CLAUDE.md`).
- The systemd timers (`mirage-crawl-export`, `-ranges`, `-rotate`) are separate from the containers and are not changed
  by a deploy.
- `deploy/mirage-crawl.service` in this repo is not what runs the sensor on that host.

## One-time server setup

1. A dedicated SSH key, forced to the deploy script, in the deploy user's `~/.ssh/authorized_keys`:
   ```
   command="/opt/mirage/mirage-crawl/deploy/deploy.sh",restrict ssh-ed25519 AAAA... crawl-deploy-ci
   ```
   With a forced command the script reads the SHA from `SSH_ORIGINAL_COMMAND` and refuses anything that is not a 40-hex
   commit SHA. The user needs permission to run `docker compose` and to write the checkout.
2. Repository secrets: `CRAWL_DEPLOY_HOST`, `CRAWL_DEPLOY_PORT`, `CRAWL_DEPLOY_USER`, `CRAWL_DEPLOY_KEY` (the private
   half of the key above). Do not reuse the digest key.
3. Recommended: a GitHub Environment with required reviewers, and `environment:` on the `deploy` job, so a second person
   approves each deploy.

## Running a deploy

Actions, Deploy mirage-crawl, Run workflow: choose a ref (default `main`) and tick the ledger box. The job tests the
commit, then the server checks out that exact SHA and runs `docker compose up --build -d crawl tlsfront`. If either
container is not running 10 s later, the script rolls back to the previous commit and the job fails.

**Rollback:** run the workflow with the previous SHA (printed in the job log as `prev=`).

## What a deploy does not do

- It does not change `.env`, the data volumes, the timers, or the TLS certificates.
- It refuses to run if the checkout has uncommitted changes, except file-mode-only differences.
- It restarts the containers, so the sensor is briefly unavailable and open connections drop.
- Every deploy is a change to what the sensor records, so it belongs in the change ledger.

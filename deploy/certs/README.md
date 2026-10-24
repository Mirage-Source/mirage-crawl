# TLS certificates for the front

`docker-compose.yml` mounts `./deploy/certs` into the `tlsfront` container
read-only at `/certs`, and the front reads `/certs/fullchain.pem` and
`/certs/privkey.pem`.

The `.pem`/`.key` files here are git-ignored (see the repo `.gitignore`), this
README is not. Put the real files here, or point the mount at an existing
certificate directory:

- **certbot / Let's Encrypt:** change the compose mount to your live dir, e.g.
  `/etc/letsencrypt/live/docs.example.org:/certs:ro`. Note certbot stores the
  key as `privkey.pem` and the chain as `fullchain.pem` already.
- **self-signed, for a throwaway box** (this is a decoy host — do not use a
  certificate for a domain anyone cares about):

  ```sh
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout deploy/certs/privkey.pem -out deploy/certs/fullchain.pem \
    -subj "/CN=docs.example.org"
  ```

The front strips any client-supplied JA4 header and injects its own computed
from the raw ClientHello, then forwards over the Unix front socket. That socket
is the only listener allowed to assert a client's address and fingerprint.

## Let's Encrypt (production)

crawl owns :80, so HTTP-01 needs :80 freed during the challenge. The hooks in
`deploy/letsencrypt/` do exactly that and nothing more:

- `pre.sh` stops the crawl container (frees :80),
- `deploy.sh` copies the issued cert here and chowns it to uid 999 (the front's
  non-root user),
- `post.sh` starts crawl again and reloads the front.

Issue once (hooks are saved into the renewal config and reused by the
twice-daily `certbot.timer`, which only triggers the hooks when a renewal is
actually due):

```sh
certbot certonly --standalone --preferred-challenges http-01 \
  -d scannersnoop.com --non-interactive --agree-tos \
  --register-unsafely-without-email \
  --pre-hook  /opt/mirage/mirage-crawl/deploy/letsencrypt/pre.sh \
  --deploy-hook /opt/mirage/mirage-crawl/deploy/letsencrypt/deploy.sh \
  --post-hook /opt/mirage/mirage-crawl/deploy/letsencrypt/post.sh
```

Renewal downtime is a few seconds of :80/persona ports, roughly every 60 days.
A zero-downtime alternative (serving the ACME webroot from crawl itself) is a
possible later refinement.

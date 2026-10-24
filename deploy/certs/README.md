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

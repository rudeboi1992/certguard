# Deploying certguard

certguard ships as a single static binary with an embedded web UI. First-run
setup happens **in the browser** — open the page and create your admin account
(no CLI needed). Add more admins later from **Settings → Users**.

## 1. All-in-one: one container, automatic HTTPS (recommended)

certguard fetches and renews its own Let's Encrypt certificate — no reverse
proxy to run. This is the easiest secure install for a domain with multiple
admins.

```sh
# 1) point your domain's DNS (A/AAAA) at this host
# 2) create a .env file:
echo 'CERTGUARD_ACME_DOMAIN=certguard.example.com' > .env
# 3) start (ports 80+443 must be reachable for the certificate):
docker compose -f docker-compose.aio.yml up -d
```

Open `https://certguard.example.com`, create your admin account, then add the
other admins under Settings → Users. Certs, the database, and the vault key all
persist in the `certguard_data` volume.

Native (non-Docker) equivalent:

```sh
CERTGUARD_ACME_DOMAIN=certguard.example.com ./certguard serve
```

No public domain (a LAN / internal deployment)? Use `docker-compose.internal.yml`
— bundled Caddy issues a trusted certificate from its own local CA, and the
"Download CA certificate" button in Settings lets users install trust. Already
run a reverse proxy for several apps? Point it at `certguard:8181` and set
`CERTGUARD_COOKIE_SECURE=true` (see the reference Caddyfile in `deploy/`).

### Portainer

A published image (`ghcr.io/rudeboi1992/certguard:latest`, multi-arch) is built
by CI, so you can deploy without building from source:

1. One-time: make the GHCR package **public** (GitHub → Packages → certguard →
   Package settings → visibility), or add GHCR credentials to Portainer.
2. Portainer → **Stacks → Add stack → Web editor** and paste
   `deploy/portainer-stack.yml`.
3. Under **Environment variables**, set `CERTGUARD_ACME_DOMAIN` (and optionally
   `CERTGUARD_ACME_EMAIL`), then **Deploy the stack**.
4. Open `https://<your-domain>` and create your admin account.

(Portainer can't build from a private repo's `Dockerfile` in the web editor,
which is why the stack pulls the prebuilt image.)

### Already running Caddy (or another reverse proxy)?

Don't start a second Caddy. Run only certguard, join it to your proxy's Docker
network, and add a site block to your existing Caddyfile:

```sh
echo 'CADDY_NETWORK=caddy' > .env          # your existing Caddy network name
docker compose -f docker-compose.external-caddy.yml up -d
# then add deploy/certguard.caddy's block to your Caddyfile and reload Caddy
```

certguard authenticates its own users (admin/viewer), so a reverse proxy alone
is all you need. To put it behind an SSO gate like **Authentik** so users are
logged straight in, run certguard with `CERTGUARD_PROXY_AUTH_HEADER` set to the
header the proxy injects (e.g. `X-Authentik-Email`) and use forward-auth in the
proxy — see `deploy/certguard.caddy`.

## 2. Docker (plain HTTP — localhost / VPN only)

```sh
docker compose up -d
```

Then open `http://<host>:8181` and create your admin account. Fine on localhost
or a trusted VPN. **Do not expose this on a network with the secret vault** — use
option 1, or set `CERTGUARD_TLS_AUTO=true` for a self-signed cert.

Postgres instead of SQLite: uncomment the `CERTGUARD_DB_*` lines in
`docker-compose.yml` and start with `docker compose --profile postgres up -d`.

## 3. Binary (native)

```sh
./certguard serve
```

Open `http://localhost:8181` and create your admin account. The SQLite database
and the secret-vault key are created next to the binary (`certguard.db`,
`certguard.key`) unless you set `CERTGUARD_DB_DSN` / `CERTGUARD_KEY_FILE`.

To serve HTTPS directly (no reverse proxy):

```sh
# self-signed (browsers warn; good for a LAN/VPN):
CERTGUARD_TLS_AUTO=true CERTGUARD_TLS_HOSTS=certguard.lan ./certguard serve
# or bring your own certificate:
CERTGUARD_TLS_CERT=/path/fullchain.pem CERTGUARD_TLS_KEY=/path/privkey.pem ./certguard serve
```

Serving over HTTPS automatically marks the session cookie `Secure`.

A minimal systemd unit:

```ini
[Unit]
Description=certguard
After=network-online.target

[Service]
ExecStart=/opt/certguard/certguard serve
WorkingDirectory=/opt/certguard
Restart=on-failure
User=certguard

[Install]
WantedBy=multi-user.target
```

## Secret vault

Entries can store their real secret value (API key, token, PEM), encrypted at
rest with AES-256-GCM. The master key is taken from `CERTGUARD_MASTER_KEY` if
set; otherwise certguard generates one on first run and saves it to
`CERTGUARD_KEY_FILE` (in Docker: `/data/certguard.key`, inside the volume).

- **Back up the key file** together with — but ideally stored separately from —
  the database. Lose it and stored secrets are unrecoverable; leak it *and* the
  database and the secrets are exposed.
- Revealing a secret sends it to the browser in plaintext, so only reveal over
  **HTTPS or a private VPN**, never plain HTTP across a network.
- To keep the key off-disk entirely, set `CERTGUARD_MASTER_KEY` from your own
  secret store instead of relying on the key file.

## Configuration reference

Key environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `CERTGUARD_ADDR` | `:8181` | listen address |
| `CERTGUARD_DB_DRIVER` / `CERTGUARD_DB_DSN` | `sqlite` / `certguard.db` | database |
| `CERTGUARD_MASTER_KEY` | *(auto)* | secret-vault key (overrides the key file) |
| `CERTGUARD_KEY_FILE` | `certguard.key` | where the auto-generated key is stored |
| `CERTGUARD_ACME_DOMAIN` | – | automatic Let's Encrypt HTTPS for this domain (serves :80+:443) |
| `CERTGUARD_ACME_EMAIL` | – | optional ACME account contact |
| `CERTGUARD_TLS_AUTO` | `false` | serve HTTPS with a self-signed cert |
| `CERTGUARD_TLS_CERT` / `CERTGUARD_TLS_KEY` | – | serve HTTPS with your cert |
| `CERTGUARD_COOKIE_SECURE` | `false` | mark cookies Secure (auto-on with TLS; set true behind an HTTPS proxy) |
| `CERTGUARD_TRUSTED_PROXY` | `false` | trust `X-Forwarded-For` for rate-limiting — only behind a proxy you control |
| `CERTGUARD_ALLOW_PRIVATE_WEBHOOKS` | `false` | allow notification webhooks to reach private/loopback/link-local addresses |
| `CERTGUARD_RP_ID` | _(Host header)_ | WebAuthn relying party ID for security keys — must be a domain |
| `CERTGUARD_RP_ORIGINS` | _(request origin)_ | comma-separated origins allowed to present security keys |
| `CERTGUARD_CHECK_INTERVAL` | `6h` | background rescan/notify cadence |
| `CERTGUARD_MAIL_*` | – | SMTP for email notifications |

Migrations run automatically on startup for both SQLite and Postgres.

## Security keys need a hostname

WebAuthn forbids an IP address as a relying party ID, so an instance reached at
`https://192.168.0.154` cannot register a security key — the browser refuses
before certguard is even consulted. Reaching it by name fixes this, and nothing
needs to be exposed publicly: an internal DNS record is enough.

1. **Add an A record** on your internal DNS, e.g. `certguard.example.local` →
   the instance's address.
2. **Cover the name with the certificate.** With the built-in self-signed cert,
   add the hostname to `CERTGUARD_TLS_HOSTS` and delete `tls-cert.pem` /
   `tls-key.pem` from the data volume so a new one is generated:

   ```
   -e CERTGUARD_TLS_AUTO=1 -e CERTGUARD_TLS_HOSTS=certguard.example.local
   ```

   Regenerating means re-installing the CA on any machine that trusted the old
   one. Listing **both** the hostname and the old IP in `CERTGUARD_TLS_HOSTS`
   keeps existing bookmarks working during the switch.
3. **Reach it by name.** Credentials are bound to whatever the RP ID was at
   registration, so keys registered against one hostname stop working if the
   hostname changes later. Pick the name before registering keys, not after.

Behind a reverse proxy that rewrites `Host`, set `CERTGUARD_RP_ID` and
`CERTGUARD_RP_ORIGINS` explicitly rather than relying on the header.

### Exposing certguard beyond a LAN

The sign-in page is designed not to leak who has an account. There is no
endpoint that answers "does this address have a key", and the passkey challenge
is byte-identical whatever accounts exist — no address is submitted and no
credential list is returned. Password sign-in likewise answers the same way for
an unknown address and a wrong password.

If you put certguard on the public internet, also:

- Use a **real certificate** (`CERTGUARD_ACME_DOMAIN`) rather than the
  self-signed one, so users are not trained to click through warnings.
- Set **`CERTGUARD_COOKIE_SECURE=true`** if TLS terminates at a proxy.
- **Do not set `CERTGUARD_TRUSTED_PROXY`** unless a proxy you control sets
  `X-Forwarded-For`. Exposed directly, a forged header would let an attacker
  give every login attempt its own rate-limit bucket and brute-force the
  password. Behind a trusted proxy you *must* set it, or every client shares
  the proxy's single IP.
- Leave **`CERTGUARD_ALLOW_PRIVATE_WEBHOOKS`** off. Any signed-in user can add a
  notification webhook; off, the server refuses to connect one to a private,
  loopback, or link-local address, so it cannot be turned into a probe of your
  internal network.
- Leave **`CERTGUARD_STATUS_PUBLIC`** off unless you want the counts-only status
  page readable by anyone who can reach the host.
- Encourage **passkeys with user verification**. A passwordless sign-in already
  demands it; requiring a PIN or biometric is what keeps a stolen key from being
  a whole credential.

## Backups

- **SQLite:** back up `certguard.db` **and** `certguard.key` (Docker: the
  `certguard_data` volume holds both).
- **Postgres:** `pg_dump` the database; back up the key file separately.

## Hardening notes

- The Docker image runs as non-root (uid 65532). For **bind mounts**, ensure the
  host `/data` dir is writable by that uid.
- There is no public registration — accounts are created by an admin.
- Give automation its own API token (`certguard token create`) on a `viewer`
  user if it only needs read access.

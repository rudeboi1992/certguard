# Deploying certguard

certguard ships as a single static binary with an embedded web UI. First-run
setup happens **in the browser** — open the page and create your admin account
(no CLI needed). Add more admins later from **Settings → Users**.

## 1. Docker + HTTPS for a domain (recommended)

The cleanest secure setup for a real domain with multiple admins: certguard runs
on the private network and **Caddy** provisions and renews a trusted TLS
certificate automatically.

```sh
# 1) point your domain's DNS (A/AAAA) at this host
# 2) create a .env file:
echo 'CERTGUARD_DOMAIN=certguard.example.com' > .env
# 3) start (ports 80+443 must be reachable for the certificate):
docker compose -f docker-compose.caddy.yml up -d
```

Open `https://certguard.example.com`, create your admin account, then add the
other admins under Settings → Users. For an **internal-only** domain (not
reachable by Let's Encrypt), switch the Caddyfile block to `tls internal`.

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
| `CERTGUARD_TLS_AUTO` | `false` | serve HTTPS with a self-signed cert |
| `CERTGUARD_TLS_CERT` / `CERTGUARD_TLS_KEY` | – | serve HTTPS with your cert |
| `CERTGUARD_COOKIE_SECURE` | `false` | mark cookies Secure (auto-on with TLS; set true behind an HTTPS proxy) |
| `CERTGUARD_CHECK_INTERVAL` | `6h` | background rescan/notify cadence |
| `CERTGUARD_MAIL_*` | – | SMTP for email notifications |

Migrations run automatically on startup for both SQLite and Postgres.

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

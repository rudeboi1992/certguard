# certguard

An **active** TLS certificate expiry monitor. Point it at a `host:port` and it
connects, reads the leaf certificate directly, and tracks its expiry — no more
typing dates by hand. Ships as a single static binary (SQLite built in) for
self-hosting via Docker or natively.

This is a Go rebuild of the ideas in
[ExpiryGuard](https://github.com/sanjayselvaraj/expiryguard), keeping its two
best parts — privacy-preserving client-side file parsing and a
notification-escalation state machine — while adding the feature that turns a
manual registry into a real monitoring tool: **active endpoint scanning**.

## Quick start

certguard is **one app, one image** — the paths below just differ in how HTTPS
is handled. All of them end the same way: open the page and **create your admin
account in the browser** (no CLI). Not sure which? Most self-hosters want the
first one.

📖 **Full step-by-step for every method (with per-OS certificate steps) is in
[docs/INSTALL.md](docs/INSTALL.md).**

### ★ Internal network, no public domain — the usual self-hosted choice

Running this on a LAN with no public domain (homelab, small office)? This is for
you. One stack gives you certguard **plus a real, trusted green padlock** — not a
scary self-signed warning — because bundled Caddy issues the certificate from its
own local CA:

```
CERTGUARD_DOMAIN=certguard.lan docker compose -f docker-compose.internal.yml up -d
```

1. Point `certguard.lan` at the host in your internal DNS (or a hosts-file entry).
2. Open `https://certguard.lan` and create your admin.
3. Go to **Settings → Download CA certificate** and install it once per device
   (or push it to all machines via Group Policy). Done — encrypted, trusted, no
   warnings.

Only use this if nothing else on the host already owns ports 80/443.

### Proxmox — one line, whole thing

On a Proxmox VE host, this creates a Debian LXC, installs Docker, deploys
certguard, and prints the URL:

```
bash -c "$(curl -fsSL https://raw.githubusercontent.com/rudeboi1992/certguard/main/deploy/proxmox-install.sh)"
```

Then open the `http://<ip>:8181` it gives you and create your admin. Override
defaults inline, e.g. `CORES=4 RAM=2048 bash -c "$(curl -fsSL …)"`.

Want a trusted HTTPS padlock instead of plain HTTP? Add `MODE=internal` — it
bundles Caddy with a local CA and serves `https://<ip>` (install the CA once from
`https://<ip>/ca.crt`):

```
MODE=internal bash -c "$(curl -fsSL https://raw.githubusercontent.com/rudeboi1992/certguard/main/deploy/proxmox-install.sh)"
```

### Try it in 60 seconds (localhost, plain HTTP)

Just kicking the tyres on your own machine:

```
docker run -d --name certguard -p 8181:8181 -v certguard-data:/data \
  ghcr.io/rudeboi1992/certguard:latest
```

Open **http://localhost:8181**. Plain HTTP is fine on localhost or a trusted VPN;
don't expose it on a network without TLS.

### You have a public domain — automatic HTTPS

One container, a real Let's Encrypt certificate, no reverse proxy to run:

```
CERTGUARD_ACME_DOMAIN=certguard.example.com docker compose -f docker-compose.aio.yml up -d
```

Needs ports 80 + 443 reachable and the domain's DNS pointing here. Open
`https://certguard.example.com`.

> ⚠ **This exposes certguard to the internet.** It holds a secret vault, so
> before you do: enable **2FA** for every admin, turn on the **zero-knowledge
> vault**, and ideally front it with **SSO**. For an internal tool, prefer the
> internal recipe above + a VPN — only go public if you truly need it.

### Portainer (one click)

1. Portainer → **Settings → App Templates** → set the URL to:
   `https://raw.githubusercontent.com/rudeboi1992/certguard/main/deploy/portainer-template.json`
2. **App Templates** → pick **certguard** → fill the short form → **Deploy**.
3. Open `http://<host>:8181` and create your admin (or set the Admin email/password
   fields in the form to have it created for you).

### Behind a reverse proxy you already run

Already run Nginx Proxy Manager, Traefik, or Caddy? Deploy the `docker run` /
Portainer option above, point your proxy at `certguard:8181`, and set
`CERTGUARD_COOKIE_SECURE=true` so the session cookie is marked Secure. See
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

> **One rule for all of them:** the `certguard-data` volume holds your database
> and the secret-vault key. Back it up; don't delete it.

See **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)** for Postgres, secret-vault modes
(including zero-knowledge), backups, and hardening.

## Status: Phases 1–2 — working

```
# provision the first user (no public registration)
certguard user add you@example.com --role admin --password '...'
certguard token create you@example.com --name laptop   # prints a bearer token once

certguard scan github.com          # scan an endpoint over TLS and store it
certguard scan --dry host:8443     # scan without storing
certguard serve                    # run the JSON API on :8181
```

Scanning **completes the handshake even for expired or untrusted certificates**,
so those are exactly the cases it reports on (via `trust_error`) rather than
failing.

### Auth

Every `/api/v1` route except login requires authentication, via either:

- **`Authorization: Bearer <token>`** — for automation (`certguard token create`).
- **Session cookie** — from `POST /api/v1/auth/login`, for the web UI (Phase 3).

Users are **admin-provisioned** through the CLI; there is no public registration.
Writes (scanning) require the **admin** role; **viewer** is read-only. Tokens and
session ids are stored only as SHA-256 hashes — plaintext is shown once.

### API

| Method | Path                   | Auth   | Purpose                                  |
|--------|------------------------|--------|------------------------------------------|
| GET    | `/healthz`             | none   | liveness                                 |
| POST   | `/api/v1/auth/login`   | none   | `{"email","password"}` → sets session cookie |
| POST   | `/api/v1/auth/logout`  | any    | invalidate the session                   |
| GET    | `/api/v1/auth/whoami`  | any    | current principal                        |
| GET    | `/api/v1/version`      | any    | running build: version, commit, build date, Go/OS/arch |
| GET    | `/api/v1/certs`        | any    | list tracked certs, soonest expiry first |
| POST   | `/api/v1/scan`         | admin  | scan `{"target":"host:port","dry_run":false}` |
| POST   | `/api/v1/certs`        | admin  | add a manual/file cert `{"name","expires_at",...}` |
| DELETE | `/api/v1/certs/{id}`   | admin  | soft-delete a cert                       |
| GET    | `/api/v1/channels`     | any    | list your notification channels          |
| POST   | `/api/v1/channels`     | any    | add a channel `{"type","target","thresholds"}` |
| DELETE | `/api/v1/channels/{id}`| any    | remove your channel                      |
| POST   | `/api/v1/channels/{id}/test` | any | send a test notification            |

### Notifications & scheduling

`serve` runs a background job (default every 6h) that **re-scans auto-rescan
endpoints** to refresh expiry, then evaluates notification thresholds. Alerts
fire at **30, 7, and 3 days** using a state machine that escalates but never
repeats a level, so frequent runs never spam. Certificate rotation (a new
fingerprint) resets the state so the new cert is tracked fresh.

Domain registrations use an earlier ladder — **60, 30, and 7 days** — because a
lapsed domain enters redemption and costs a restore fee, while a lapsed
certificate is reissued in minutes.

**Chain expiry** is evaluated separately from the certificate. A leaf is only as
good as the path beneath it: if an intermediate expires first, clients cannot
build a trust path and the endpoint breaks on *that* date, while the
certificate's own expiry still looks months away. certguard records the
intermediates served with each endpoint and alerts on the soonest one that
expires **before** the leaf, on its own escalation counter so a certificate
alert cannot silence it. An intermediate that outlives the leaf is deliberately
ignored — renewing on the normal schedule fetches a fresh chain anyway. The
remedy differs too, and the alert says so: reissuing from the same CA can return
the same expiring intermediate, so you need a chain that no longer includes it.

Channels are **per-user** but alert on the whole shared inventory. Supported
types: `email` (SMTP), `slack`, `discord`, and generic `webhook` (JSON POST).
Each channel can restrict which thresholds it wants (e.g. only `3`).

```
certguard channel add you@example.com --type slack --target https://hooks.slack.com/... 
certguard channel add you@example.com --type webhook --target https://my/hook --thresholds 7,3
certguard channel list you@example.com
certguard channel test 1
```

### Web UI

`serve` also hosts a browser UI at `/` (embedded in the binary via `go:embed`):
a login page, a dashboard listing tracked certs with urgency colouring and
trust badges, a "scan a live endpoint" form, and a drag-and-drop zone that
parses `.pem/.cer/.crt/.p12/.pfx` files **entirely client-side** (vendored
node-forge, no CDN) — the file never leaves the browser; only extracted metadata
is sent to the API. Viewers see a read-only dashboard; admin controls are hidden
from them (and enforced server-side).

## Configuration

All optional; defaults give a working SQLite-backed service with no setup.

| Env var                  | Default         | Meaning                          |
|--------------------------|-----------------|----------------------------------|
| `CERTGUARD_ADDR`         | `:8181`         | HTTP listen address              |
| `CERTGUARD_DB_DRIVER`    | `sqlite`        | `sqlite` or `postgres`           |
| `CERTGUARD_DB_DSN`       | `certguard.db`  | sqlite file path / postgres URL  |
| `CERTGUARD_SCAN_TIMEOUT` | `10s`           | per-scan dial + handshake budget |
| `CERTGUARD_SESSION_TTL`  | `720h`          | web session lifetime             |
| `CERTGUARD_COOKIE_SECURE`| `false`         | set `true` when served over HTTPS|
| `CERTGUARD_CHECK_INTERVAL`| `6h`           | scheduler rescan + notify period |
| `CERTGUARD_SCHEDULER_ENABLED`| `true`      | run the background job           |
| `CERTGUARD_MAIL_HOST`    | _(unset)_       | SMTP host (email channels)       |
| `CERTGUARD_MAIL_PORT`    | `587`           | SMTP port (STARTTLS)             |
| `CERTGUARD_MAIL_USER` / `_PASS` / `_FROM` | _(unset)_ | SMTP auth + From address |

## Build & run

```
go build -o certguard .     # pure Go, no CGO (modernc.org/sqlite)
go test ./...
```

### Docker

The image is ~17MB (distroless static) and includes CA certificates for TLS
scanning:

```
docker compose up -d
docker compose exec certguard /certguard user add you@example.com --role admin
```

SQLite by default; Postgres is a one-line switch. See
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for native, Docker, Postgres, reverse
proxy, and backup guidance. Release binaries for linux/macOS/windows ×
amd64/arm64 are built with [goreleaser](.goreleaser.yaml).

## Architecture

```
main.go                    CLI dispatch (serve | scan | user | token | version)
internal/scanner           active TLS scan → Result (the core)
internal/model             Cert + User/APIToken + Channel domain types
internal/auth              password hashing, token/session secrets, roles
internal/notify            threshold state machine + email/webhook senders
internal/scheduler         background rescan + notification job
internal/store             SQLite/Postgres dialect layer + migrations + CRUD
internal/server            JSON API + auth middleware
internal/server/web        embedded UI (go:embed): pages + static assets
internal/config            env-based config
```

## Roadmap

- [x] **Phase 1** — active scanner, enriched model, SQLite + migrations, scan CLI, minimal API
- [x] **Phase 2** — token + session auth, admin-provisioned users, roles, `user`/`token` CLI, auth tests
- [x] **Phase 3** — embedded web UI (dashboard, scan form, client-side drag-drop file parser), cert create/delete API
- [x] **Phase 4** — notifications (email + Slack/Discord/generic webhook), per-user channels + thresholds, scheduled rescan + notify job, escalation state machine
- [x] **Phase 5** — Postgres dialect (dialect layer + per-dialect migrations), distroless Docker image (~17MB), goreleaser cross-builds, deployment docs

The roadmap is complete: certguard actively scans, authenticates, has a web UI,
notifies, and self-hosts on SQLite or Postgres via binary or Docker.

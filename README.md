# certguard

An **active** TLS certificate expiry monitor. Point it at a `host:port` and it
connects, reads the leaf certificate directly, and tracks its expiry — no more
typing dates by hand. It's a single static binary with SQLite built in, shipped
as a Docker image (or build it from source).

This is a Go rebuild of the ideas in
[ExpiryGuard](https://github.com/sanjayselvaraj/expiryguard), keeping its two
best parts — privacy-preserving client-side file parsing and a
notification-escalation state machine — while adding the feature that turns a
manual registry into a real monitoring tool: **active endpoint scanning**.

## Install

certguard is **one app, one image**. The only real choice is **how HTTPS is
handled**, and it comes down to a single question:

> **Do you have a public domain name pointing at this host?**

That's the whole fork, because **Let's Encrypt only issues certificates for
public domains it can reach and validate over the internet.** It cannot issue
for `certguard.lan`, a private `192.168.x.x` address, or any host that isn't
internet-reachable — so an internal network needs a different answer.

| Your situation | What you get | Recipe |
|---|---|---|
| Just trying it on your own machine | plain HTTP | [Quick try](#quick-try--localhost) |
| Internal network, **no public domain** (homelab, office) | trusted cert from a **private CA** | [Internal](#-internal-network-no-public-domain) ★ |
| **Public domain**, internet-facing | **Let's Encrypt**, automatic | [Public](#public-domain--automatic-lets-encrypt) |
| You already run Nginx Proxy Manager / Traefik / Caddy | whatever your proxy issues | [Behind your proxy](#behind-a-reverse-proxy-you-already-run) |

Every recipe ends the same way: open the page and **create your admin account in
the browser** — no CLI. Not sure? Most self-hosters want **Internal**.

📖 Full step-by-step, with per-OS certificate-install steps, is in
[docs/INSTALL.md](docs/INSTALL.md).

### Quick try — localhost

Kicking the tyres on your own machine, plain HTTP:

```
docker run -d --name certguard -p 8181:8181 -v certguard-data:/data \
  ghcr.io/rudeboi1992/certguard:latest
```

Open **http://localhost:8181**. Plain HTTP is fine on localhost or a trusted VPN
— don't expose it on a network without TLS.

### ★ Internal network, no public domain

The usual homelab / small-office case. Let's Encrypt can't help here (it won't
issue for a private name), so bundled **Caddy runs its own local CA** and issues
a real certificate from it — a genuine green padlock once you install that CA,
not a self-signed warning:

```
CERTGUARD_DOMAIN=certguard.lan docker compose -f docker-compose.internal.yml up -d
```

1. Point `certguard.lan` at this host in your internal DNS (or a hosts-file entry).
2. Open `https://certguard.lan` and create your admin.
3. **Settings → Download CA certificate** → install it once per device (or push
   via Group Policy). Trusted, encrypted, no warnings.

Only use this if nothing else on the host already owns ports 80/443.

### Public domain — automatic Let's Encrypt

One container, a real Let's Encrypt certificate, no reverse proxy to run —
certguard fetches and renews it itself:

```
CERTGUARD_ACME_DOMAIN=certguard.example.com docker compose -f docker-compose.aio.yml up -d
```

Needs ports 80 + 443 reachable **from the internet** and the domain's DNS
pointing here. Open `https://certguard.example.com`.

> ⚠ **This puts certguard on the public internet.** It holds a secret vault, so
> first: enable **2FA / passkeys** for every admin, turn on the **zero-knowledge
> vault**, and ideally front it with **SSO**. Prefer the internal recipe + a VPN
> unless you genuinely need public reachability. See the
> [public-exposure checklist](docs/DEPLOYMENT.md).

*Rather let Caddy (or another proxy) do Let's Encrypt instead of certguard? That
is the next recipe — the proxy handles the certificate and certguard just serves
HTTP behind it.*

### Behind a reverse proxy you already run

Already run Nginx Proxy Manager, Traefik, or Caddy? They already do Let's
Encrypt for you, so run certguard plain behind them — no published ports, joined
to your proxy's Docker network:

```
# set CADDY_NETWORK (your proxy's network) in a .env file first — see the file header
docker compose -f docker-compose.external-caddy.yml up -d
```

Point the proxy at `certguard:8181` and set `CERTGUARD_COOKIE_SECURE=true`. A
ready Caddy site block is in [deploy/certguard.caddy](deploy/certguard.caddy);
full details in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

### Running it a different way

The recipes above use Docker Compose, but the **packaging is interchangeable** —
the HTTPS choice above is what matters; pick whatever wrapper you already use:

- **Portainer** — App Templates → add
  `https://raw.githubusercontent.com/rudeboi1992/certguard/main/deploy/portainer-template.json`,
  pick **certguard**, fill the form, Deploy. (Plain HTTP; put a proxy in front for TLS.)
- **Proxmox** — one line builds a Debian LXC, installs Docker, and deploys:
  ```
  bash -c "$(curl -fsSL https://raw.githubusercontent.com/rudeboi1992/certguard/main/deploy/proxmox-install.sh)"
  ```
  Defaults to plain HTTP. Add `MODE=internal` for a trusted-after-install
  self-signed cert, or `MODE=public DOMAIN=certguard.example.com` for automatic
  Let's Encrypt (needs a public DNS record + ports 80/443 forwarded to the LXC).
  Override sizing inline, e.g. `CORES=4 RAM=2048 bash -c "$(curl -fsSL …)"`.
- **Plain Docker / other** — `docker run` (as in *Quick try*) or the base
  [docker-compose.yml](docker-compose.yml) (SQLite; add `--profile postgres` for Postgres).
- **From source** — clone and `docker build .`, or `go build`.

### Which image tag?

- **`:latest`** — the newest release; what the recipes above use. Fine for a
  homelab, but it moves whenever you `docker pull`.
- **`:0.4`** — tracks the 0.4.x line: bug-fix and security updates, no surprise
  feature jumps. A good default if you want predictable upgrades.
- **`:0.4.2`** (or `:v0.4.2`) — pins one exact build; nothing changes until you
  bump it yourself.

> **The one rule for every recipe:** the `certguard-data` volume holds your
> database and the secret-vault key. Back it up; don't delete it.

See **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)** for Postgres, secret-vault modes
(including zero-knowledge), backups, and the public-exposure hardening checklist.

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

#### Second factor

An account can hold a **TOTP** secret, one or more **security keys**
(WebAuthn/FIDO2 — YubiKey, passkey, Windows Hello), or both. After the password
is accepted, certguard reports which factors the account actually has so the
sign-in page offers exactly those.

A registered key can also sign you in **on its own**, with no password and no
address typed. The browser offers your saved passkeys — in the email field's
autofill, or behind the "Sign in with a passkey" button — and the authenticator
reports which account it belongs to. Because the passkey is then the only
factor, certguard **requires user verification** for that path: the key must
check a PIN or biometric, so it stays two factors (something you have plus
something you know or are). A key that cannot verify a user is refused there and
remains usable as a second factor next to the password.

**Nothing on the sign-in page reveals who is registered.** certguard has no
endpoint that answers "does this address have a key", and the passkey challenge
is identical whatever accounts exist — no address is sent and no credential list
comes back. That matters for an instance reachable beyond a LAN: the login page
is an oracle for account enumeration if you let it be one. Which layout appears
first is remembered **in your browser**, not on the server.

> **Security keys require a hostname.** The WebAuthn spec forbids an IP address
> as a Relying Party ID, and browsers refuse outright, so keys cannot be
> registered on an instance reached as `https://192.168.0.154`. Give certguard a
> DNS name and reach it by that name. By default the RP ID is taken from the
> `Host` header; pin it with `CERTGUARD_RP_ID` (and `CERTGUARD_RP_ORIGINS`) when
> behind a proxy that rewrites Host.
>
> **Credentials are bound to the RP ID.** Changing the hostname later
> invalidates every registered key, and they have to be registered again.

A security key can also **unlock the secret vault**, using the WebAuthn `prf`
extension to derive a key that unwraps the same data key your passphrase does.
It is deliberately a *second* door: the passphrase keyring is always kept, so
losing a key never costs you the stored secrets. Not every authenticator and
browser combination supports `prf`; certguard says so when pairing rather than
failing obscurely, and the key still works as a second factor either way.
Pairing needs the vault unlocked — you cannot hand over a key you do not
currently hold.

### API

| Method | Path                   | Auth   | Purpose                                  |
|--------|------------------------|--------|------------------------------------------|
| GET    | `/healthz`             | none   | liveness                                 |
| POST   | `/api/v1/auth/login`   | none   | `{"email","password"}` → sets session cookie |
| POST   | `/api/v1/auth/passkey/begin` | none | usernameless passkey challenge; identical for every caller |
| POST   | `/api/v1/auth/passkey/finish` | none | verify the passkey → sets session cookie |
| POST   | `/api/v1/auth/logout`  | any    | invalidate the session                   |
| GET    | `/api/v1/auth/whoami`  | any    | current principal                        |
| GET    | `/api/v1/version`      | any    | running build: version, commit, build date, Go/OS/arch |
| GET    | `/api/v1/webauthn/credentials` | any | list your registered security keys       |
| DELETE | `/api/v1/webauthn/credentials/{id}` | any | unregister one of your keys        |
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
| `CERTGUARD_TRUSTED_PROXY`| `false`         | trust `X-Forwarded-For` for rate-limiting — **only** behind a proxy you control; leave off when exposed directly |
| `CERTGUARD_ALLOW_PRIVATE_WEBHOOKS`| `false`| let notification webhooks reach private/loopback addresses; off blocks SSRF into your network |
| `CERTGUARD_RP_ID`        | _(Host header)_ | WebAuthn relying party ID — a **domain**, never an IP |
| `CERTGUARD_RP_ORIGINS`   | _(request origin)_ | comma-separated origins allowed to present keys |
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

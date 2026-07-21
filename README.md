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
| GET    | `/api/v1/certs`        | any    | list tracked certs, soonest expiry first |
| POST   | `/api/v1/scan`         | admin  | scan `{"target":"host:port","dry_run":false}` |
| POST   | `/api/v1/certs`        | admin  | add a manual/file cert `{"name","expires_at",...}` |
| DELETE | `/api/v1/certs/{id}`   | admin  | soft-delete a cert                       |

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
| `CERTGUARD_DB_DRIVER`    | `sqlite`        | `sqlite` (postgres: later)       |
| `CERTGUARD_DB_DSN`       | `certguard.db`  | sqlite file path                 |
| `CERTGUARD_SCAN_TIMEOUT` | `10s`           | per-scan dial + handshake budget |
| `CERTGUARD_SESSION_TTL`  | `720h`          | web session lifetime             |
| `CERTGUARD_COOKIE_SECURE`| `false`         | set `true` when served over HTTPS|

## Build

```
go build -o certguard .     # pure Go, no CGO (modernc.org/sqlite)
go test ./...
```

## Architecture

```
main.go                    CLI dispatch (serve | scan | user | token | version)
internal/scanner           active TLS scan → Result (the core)
internal/model             Cert + User/APIToken domain types
internal/auth              password hashing, token/session secrets, roles
internal/store             SQLite open + embedded migrations + CRUD
internal/server            JSON API + auth middleware
internal/server/web        embedded UI (go:embed): pages + static assets
internal/config            env-based config
```

## Roadmap

- [x] **Phase 1** — active scanner, enriched model, SQLite + migrations, scan CLI, minimal API
- [x] **Phase 2** — token + session auth, admin-provisioned users, roles, `user`/`token` CLI, auth tests
- [x] **Phase 3** — embedded web UI (dashboard, scan form, client-side drag-drop file parser), cert create/delete API
- [ ] **Phase 4** — notifications (email + Slack/Discord/generic), per-user subscriptions + thresholds, scheduled auto-rescan
- [ ] **Phase 5** — Postgres dialect, multi-stage `scratch` Docker image, goreleaser cross-builds, docs

> Postgres was originally slated for Phase 2 but deferred: auth was the higher
> priority (painful to retrofit), and SQLite covers the default self-host case.

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

## Status: Phase 1 (core scanner) — working

```
certguard scan github.com          # scan an endpoint over TLS and store it
certguard scan --dry host:8443     # scan without storing
certguard serve                    # run the JSON API on :8181
```

Scanning **completes the handshake even for expired or untrusted certificates**,
so those are exactly the cases it reports on (via `trust_error`) rather than
failing.

### API (Phase 1, unauthenticated — see roadmap)

| Method | Path              | Purpose                                  |
|--------|-------------------|------------------------------------------|
| GET    | `/healthz`        | liveness                                 |
| POST   | `/api/v1/scan`    | scan `{"target":"host:port","dry_run":false}` |
| GET    | `/api/v1/certs`   | list tracked certs, soonest expiry first |

## Configuration

All optional; defaults give a working SQLite-backed service with no setup.

| Env var                  | Default         | Meaning                          |
|--------------------------|-----------------|----------------------------------|
| `CERTGUARD_ADDR`         | `:8181`         | HTTP listen address              |
| `CERTGUARD_DB_DRIVER`    | `sqlite`        | `sqlite` or `postgres` (Phase 2) |
| `CERTGUARD_DB_DSN`       | `certguard.db`  | sqlite file path / postgres URL  |
| `CERTGUARD_SCAN_TIMEOUT` | `10s`           | per-scan dial + handshake budget |

## Build

```
go build -o certguard .     # pure Go, no CGO (modernc.org/sqlite)
go test ./...
```

## Architecture

```
main.go                    CLI dispatch (serve | scan | version)
internal/scanner           active TLS scan → Result (the core)
internal/model             Cert domain type (+ escalation state)
internal/store             SQLite open + embedded migrations + CRUD
internal/server            JSON API
internal/config            env-based config
```

## Roadmap

- [x] **Phase 1** — active scanner, enriched model, SQLite + migrations, scan CLI, minimal API
- [ ] **Phase 2** — JSON API hardening, token auth, admin-provisioned users, sessions; Postgres dialect
- [ ] **Phase 3** — embedded web UI (keeps client-side drag-drop file parser)
- [ ] **Phase 4** — notifications (email + Slack/Discord/generic), per-user/per-secret thresholds, scheduled auto-rescan
- [ ] **Phase 5** — tests to coverage, multi-stage `scratch` Docker image, goreleaser cross-builds, docs

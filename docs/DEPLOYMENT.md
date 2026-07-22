# Deploying certguard

certguard ships as a single static binary with an embedded web UI. There are
three common ways to run it.

## 1. Binary (native)

Download the archive for your platform from the releases page (or build with
`go build .`), then:

```sh
./certguard user add you@example.com --role admin   # first user; prompts for password
./certguard serve
```

Open http://localhost:8181 and sign in. The SQLite database is created next to
the binary as `certguard.db` unless you set `CERTGUARD_DB_DSN`.

Run it under a process manager for production. A minimal systemd unit:

```ini
[Unit]
Description=certguard
After=network-online.target

[Service]
ExecStart=/opt/certguard/certguard serve
WorkingDirectory=/opt/certguard
Environment=CERTGUARD_DB_DSN=/opt/certguard/certguard.db
Environment=CERTGUARD_COOKIE_SECURE=true
Restart=on-failure
User=certguard

[Install]
WantedBy=multi-user.target
```

## 2. Docker

The image is ~17MB (distroless static) and includes CA certificates for TLS
scanning.

```sh
docker build -t certguard:latest .
docker volume create certguard_data
docker run -d --name certguard -p 8181:8181 -v certguard_data:/data certguard:latest
docker exec certguard /certguard user add you@example.com --role admin --password 'change-me'
```

Or with Compose (SQLite by default):

```sh
docker compose up -d
docker compose exec certguard /certguard user add you@example.com --role admin
```

## 3. Docker + Postgres

For multi-instance or larger deployments, use Postgres. Uncomment the
`CERTGUARD_DB_*` lines in `docker-compose.yml` and start with the profile:

```sh
docker compose --profile postgres up -d
```

Or point a native/Docker instance at any Postgres:

```sh
export CERTGUARD_DB_DRIVER=postgres
export CERTGUARD_DB_DSN='postgres://user:pass@host:5432/certguard?sslmode=disable'
./certguard serve
```

Migrations run automatically on startup for both SQLite and Postgres.

## Reverse proxy & TLS

certguard serves plain HTTP; terminate TLS at a reverse proxy (Caddy, nginx,
Traefik). When doing so, set `CERTGUARD_COOKIE_SECURE=true` so session cookies
are only sent over HTTPS. Example Caddy:

```
certs.example.com {
    reverse_proxy localhost:8181
}
```

## Configuration reference

See the environment variable table in the main [README](../README.md#configuration).

## Backups

- **SQLite:** stop the service (or use `sqlite3 certguard.db ".backup"`) and copy
  `certguard.db`. With Docker, back up the `certguard_data` volume.
- **Postgres:** use `pg_dump` as usual.

## Notes on hardening

- The Docker image runs as a non-root user (uid 65532). Named volumes inherit
  the writable `/data` ownership; for **bind mounts**, ensure the host directory
  is writable by uid 65532.
- Provision users with `certguard user add`; there is no public registration.
- Give automation its own API token (`certguard token create`) with a `viewer`
  user if it only needs to read.

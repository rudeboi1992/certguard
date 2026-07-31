// Package config loads runtime configuration from environment variables with
// sensible, zero-dependency defaults. A fresh self-hoster should be able to run
// the binary with no configuration at all and get a working SQLite-backed
// service.
package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	// Addr is the HTTP listen address, e.g. ":8181".
	Addr string
	// DBDriver is "sqlite" (default) or "postgres".
	DBDriver string
	// DBDSN is the data source. For sqlite this is a file path (default
	// "certguard.db"); for postgres a standard connection URL.
	DBDSN string
	// ScanTimeout bounds a single endpoint scan.
	ScanTimeout time.Duration
	// SessionTTL is how long a web login session stays valid.
	SessionTTL time.Duration
	// CookieSecure sets the Secure flag on the session cookie. Leave false for
	// plain-HTTP local use; set true when served over HTTPS (e.g. behind a
	// TLS-terminating reverse proxy).
	CookieSecure bool

	// CheckInterval is how often the background scheduler re-scans endpoints and
	// evaluates notification thresholds.
	CheckInterval time.Duration
	// SchedulerEnabled toggles the background job (set false to run serve as a
	// pure API/UI with no outbound scanning or notifications).
	SchedulerEnabled bool

	// Mail holds SMTP settings for email notifications. If Host or User is
	// empty, email channels are treated as unconfigured and skipped.
	Mail MailConfig

	// AdminEmail/AdminPassword bootstrap the first admin on an empty database, so
	// a container deploy needs no shell access. They are used ONCE — only when no
	// users exist yet — and ignored afterward. Set both, or neither.
	AdminEmail    string
	AdminPassword string

	// MasterKey enables the encrypted secret vault. When set (env), the secret
	// value of an entry is encrypted at rest with AES-256-GCM using a key derived
	// from this value. When empty, serve auto-generates a key and persists it to
	// KeyFile so the vault works with no setup — set the env var instead to keep
	// the key off-disk. Generate one with: openssl rand -hex 32
	MasterKey string
	// KeyFile is where the auto-generated master key is stored/read when MasterKey
	// is not supplied via the environment.
	KeyFile string

	// TLS: serve HTTPS directly. TLSCert+TLSKey use a supplied certificate; if
	// they are empty and TLSAuto is true, a self-signed certificate is generated
	// and persisted. When any of these serves HTTPS, the Secure cookie flag is
	// forced on. (For a real domain, terminating TLS at a reverse proxy such as
	// Caddy — see docker-compose.caddy.yml — is usually preferable.)
	TLSCert  string
	TLSKey   string
	TLSAuto  bool
	TLSHosts string // SAN hostnames for the self-signed cert (comma-separated)

	// ACME: fully automatic HTTPS. When ACMEDomain is set, serve obtains and
	// renews a real Let's Encrypt certificate for it (no reverse proxy needed) —
	// this is the "just give it a domain" install. Needs ports 80 + 443 reachable
	// and the domain's DNS pointing at the host. Certs are cached in ACMECacheDir.
	ACMEDomain   string // comma-separated hostnames
	ACMEEmail    string // optional contact for the ACME account
	ACMECacheDir string
}

// TLSEnabled reports whether serve should listen over HTTPS with a static/self-
// signed certificate (as opposed to automatic ACME).
func (c Config) TLSEnabled() bool {
	return (c.TLSCert != "" && c.TLSKey != "") || c.TLSAuto
}

// ACMEEnabled reports whether serve should fetch a certificate automatically.
func (c Config) ACMEEnabled() bool { return c.ACMEDomain != "" }

type MailConfig struct {
	Host string
	Port int
	User string
	Pass string
	From string // defaults to User when empty
}

func Load() Config {
	return Config{
		Addr:         env("CERTGUARD_ADDR", ":8181"),
		DBDriver:     env("CERTGUARD_DB_DRIVER", "sqlite"),
		DBDSN:        env("CERTGUARD_DB_DSN", "certguard.db"),
		ScanTimeout:  envDuration("CERTGUARD_SCAN_TIMEOUT", 10*time.Second),
		SessionTTL:   envDuration("CERTGUARD_SESSION_TTL", 720*time.Hour), // 30 days
		CookieSecure: envBool("CERTGUARD_COOKIE_SECURE", false),

		CheckInterval:    envDuration("CERTGUARD_CHECK_INTERVAL", 6*time.Hour),
		SchedulerEnabled: envBool("CERTGUARD_SCHEDULER_ENABLED", true),
		MasterKey:        env("CERTGUARD_MASTER_KEY", ""),
		KeyFile:          env("CERTGUARD_KEY_FILE", "certguard.key"),
		TLSCert:          env("CERTGUARD_TLS_CERT", ""),
		TLSKey:           env("CERTGUARD_TLS_KEY", ""),
		TLSAuto:          envBool("CERTGUARD_TLS_AUTO", false),
		TLSHosts:         env("CERTGUARD_TLS_HOSTS", "localhost"),
		ACMEDomain:       env("CERTGUARD_ACME_DOMAIN", ""),
		ACMEEmail:        env("CERTGUARD_ACME_EMAIL", ""),
		ACMECacheDir:     env("CERTGUARD_ACME_CACHE", "certguard-acme"),
		AdminEmail:    env("CERTGUARD_ADMIN_EMAIL", ""),
		AdminPassword: env("CERTGUARD_ADMIN_PASSWORD", ""),
		Mail: MailConfig{
			Host: env("CERTGUARD_MAIL_HOST", ""),
			Port: envInt("CERTGUARD_MAIL_PORT", 587),
			User: env("CERTGUARD_MAIL_USER", ""),
			Pass: env("CERTGUARD_MAIL_PASS", ""),
			From: env("CERTGUARD_MAIL_FROM", ""),
		},
	}
}

func envInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envBool(key string, def bool) bool {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		if secs, err := strconv.Atoi(v); err == nil {
			return time.Duration(secs) * time.Second
		}
	}
	return def
}

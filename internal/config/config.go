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

	// MasterKey enables the encrypted secret vault. When set (env), the secret
	// value of an entry is encrypted at rest with AES-256-GCM using a key derived
	// from this value. When empty, serve auto-generates a key and persists it to
	// KeyFile so the vault works with no setup — set the env var instead to keep
	// the key off-disk. Generate one with: openssl rand -hex 32
	MasterKey string
	// KeyFile is where the auto-generated master key is stored/read when MasterKey
	// is not supplied via the environment.
	KeyFile string
}

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

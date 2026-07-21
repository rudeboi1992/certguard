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
}

func Load() Config {
	return Config{
		Addr:        env("CERTGUARD_ADDR", ":8181"),
		DBDriver:    env("CERTGUARD_DB_DRIVER", "sqlite"),
		DBDSN:       env("CERTGUARD_DB_DSN", "certguard.db"),
		ScanTimeout: envDuration("CERTGUARD_SCAN_TIMEOUT", 10*time.Second),
	}
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

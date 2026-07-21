// Command certguard is an active TLS certificate expiry monitor.
//
// Usage:
//
//	certguard serve                 run the HTTP API/UI server
//	certguard scan <host[:port]>    scan an endpoint (and store it)
//	certguard scan --dry <target>   scan without storing
//	certguard version               print version
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/bfalcher/certguard/internal/config"
	"github.com/bfalcher/certguard/internal/scanner"
	"github.com/bfalcher/certguard/internal/server"
	"github.com/bfalcher/certguard/internal/store"
)

var version = "0.1.0-dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		os.Exit(cmdServe())
	case "scan":
		os.Exit(cmdScan(os.Args[2:]))
	case "version", "-v", "--version":
		fmt.Println("certguard", version)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `certguard - active TLS certificate expiry monitor

Commands:
  serve                 run the HTTP API server
  scan <host[:port]>    scan an endpoint over TLS and store the result
  scan --dry <target>   scan without storing
  version               print version

Environment:
  CERTGUARD_ADDR         listen address (default ":8181")
  CERTGUARD_DB_DRIVER    "sqlite" (default) or "postgres"
  CERTGUARD_DB_DSN       sqlite file path or postgres URL (default "certguard.db")
  CERTGUARD_SCAN_TIMEOUT per-scan timeout (default "10s")
`)
}

func cmdServe() int {
	cfg := config.Load()
	st, err := store.Open(cfg.DBDriver, cfg.DBDSN)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	defer st.Close()

	srv := server.New(cfg, st)
	httpSrv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	fmt.Printf("certguard %s listening on %s (db: %s)\n", version, cfg.Addr, cfg.DBDriver)
	if err := httpSrv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, "server error:", err)
		return 1
	}
	return 0
}

func cmdScan(args []string) int {
	dry := false
	var target string
	for _, a := range args {
		switch a {
		case "--dry", "-n":
			dry = true
		default:
			target = a
		}
	}
	if target == "" {
		fmt.Fprintln(os.Stderr, "usage: certguard scan [--dry] <host[:port]>")
		return 2
	}

	cfg := config.Load()
	host, port, err := scanner.ParseTarget(target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	res, err := scanner.Scan(context.Background(), host, port, scanner.Options{Timeout: cfg.ScanTimeout})
	if err != nil {
		fmt.Fprintln(os.Stderr, "scan failed:", err)
		return 1
	}

	days := res.DaysUntilExpiry(time.Now().UTC())
	fmt.Printf("%s:%d\n", res.Host, res.Port)
	fmt.Printf("  subject:   %s\n", res.Subject)
	fmt.Printf("  issuer:    %s\n", res.Issuer)
	fmt.Printf("  expires:   %s (%d days)\n", res.NotAfter.Format(time.RFC3339), days)
	fmt.Printf("  key:       %s / %s\n", res.KeyType, res.SigAlg)
	fmt.Printf("  sha256:    %s\n", res.SHA256)
	if len(res.DNSNames) > 0 {
		fmt.Printf("  sans:      %v\n", res.DNSNames)
	}
	if res.TrustError != "" {
		fmt.Printf("  trust:     UNTRUSTED (%s)\n", res.TrustError)
	} else {
		fmt.Printf("  trust:     ok\n")
	}

	if !dry {
		st, err := store.Open(cfg.DBDriver, cfg.DBDSN)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error opening store:", err)
			return 1
		}
		defer st.Close()
		if _, err := st.UpsertScan("", res); err != nil {
			fmt.Fprintln(os.Stderr, "error saving:", err)
			return 1
		}
		fmt.Println("  saved to", cfg.DBDSN)
	}

	_ = json.Marshal // reserved for a future --json flag
	return 0
}

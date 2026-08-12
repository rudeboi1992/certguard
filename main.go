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
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/bfalcher/certguard/internal/auth"
	"github.com/bfalcher/certguard/internal/config"
	"github.com/bfalcher/certguard/internal/model"
	"github.com/bfalcher/certguard/internal/notify"
	"github.com/bfalcher/certguard/internal/scanner"
	"github.com/bfalcher/certguard/internal/scheduler"
	"github.com/bfalcher/certguard/internal/selfsign"
	"github.com/bfalcher/certguard/internal/server"
	"github.com/bfalcher/certguard/internal/store"
)

// Stamped at link time by the release build:
//
//	-X main.version=v0.1.0 -X main.commit=abc1234 -X main.buildDate=2026-08-11T00:00:00Z
//
// A plain `go build` leaves commit and buildDate empty and they are recovered
// from the VCS stamp the toolchain embeds. See internal/server/version.go.
var (
	version   = "0.1.0-dev"
	commit    = ""
	buildDate = ""
)

func main() {
	// Hand the build stamp to the server package so the CLI and the API report
	// the same thing.
	server.SetBuildInfo(version, commit, buildDate)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		os.Exit(cmdServe())
	case "scan":
		os.Exit(cmdScan(os.Args[2:]))
	case "user":
		os.Exit(cmdUser(os.Args[2:]))
	case "token":
		os.Exit(cmdToken(os.Args[2:]))
	case "channel":
		os.Exit(cmdChannel(os.Args[2:]))
	case "version", "-v", "--version":
		printVersion()
	default:
		usage()
		os.Exit(2)
	}
}

// printVersion reports the running build in the same detail the API does, so a
// bug report from the CLI and one from the UI carry the same facts.
func printVersion() {
	v := server.BuildInfo()
	fmt.Println("certguard", v.Version)
	if v.Commit != "" {
		dirty := ""
		if v.Dirty {
			dirty = " (modified)"
		}
		fmt.Printf("  commit:  %s%s\n", v.Commit, dirty)
	}
	if v.BuildDate != "" {
		fmt.Printf("  built:   %s\n", v.BuildDate)
	}
	fmt.Printf("  go:      %s %s/%s\n", v.GoVersion, v.OS, v.Arch)
}

func usage() {
	fmt.Fprint(os.Stderr, `certguard - active TLS certificate expiry monitor

Commands:
  serve                          run the HTTP API server
  scan <host[:port]>             scan an endpoint over TLS and store the result
  scan --dry <target>            scan without storing
  user add <email> [--role admin|viewer] [--password PW]
  user list
  token create <email> [--name NAME]
  token list <email>
  channel add <email> --type email|slack|discord|webhook --target VAL [--thresholds 30,7,3]
  channel list <email>
  channel test <id>
  channel rm <id>
  version                        print version

If --password is omitted, CERTGUARD_PASSWORD is used, else it is read from stdin.

Environment:
  CERTGUARD_ADDR         listen address (default ":8181")
  CERTGUARD_DB_DRIVER    "sqlite" (default) or "postgres"
  CERTGUARD_DB_DSN       sqlite file path or postgres URL (default "certguard.db")
  CERTGUARD_SCAN_TIMEOUT per-scan timeout (default "10s")
`)
}

// bootstrapAdmin creates an initial admin user. Called only when the database
// has no users, so it is safe to run on every start (it no-ops thereafter).
func bootstrapAdmin(st *store.Store, email, password string) error {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		return fmt.Errorf("CERTGUARD_ADMIN_EMAIL is empty")
	}
	if len(password) < 8 {
		return fmt.Errorf("CERTGUARD_ADMIN_PASSWORD must be at least 8 characters")
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	_, err = st.CreateUser(email, hash, string(auth.RoleAdmin))
	return err
}

func cmdServe() int {
	cfg := config.Load()
	st, err := store.Open(cfg.DBDriver, cfg.DBDSN)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	defer st.Close()

	if n, err := st.CountUsers(); err == nil && n == 0 {
		// First run on an empty database: optionally create an admin from the
		// environment so a container deploy needs no shell access. This runs only
		// while zero users exist; on later restarts it is skipped (users > 0).
		if cfg.AdminEmail != "" && cfg.AdminPassword != "" {
			if err := bootstrapAdmin(st, cfg.AdminEmail, cfg.AdminPassword); err != nil {
				fmt.Fprintln(os.Stderr, "admin bootstrap failed:", err)
				return 1
			}
			fmt.Printf("bootstrapped admin %s from environment (delete CERTGUARD_ADMIN_PASSWORD after first login)\n", cfg.AdminEmail)
		} else {
			fmt.Println("NOTE: no users exist yet — the API is locked until you create one:")
			fmt.Println("      certguard user add <email> --role admin")
			fmt.Println("      (or set CERTGUARD_ADMIN_EMAIL + CERTGUARD_ADMIN_PASSWORD and restart)")
		}
	}

	if cfg.TLSEnabled() || cfg.ACMEEnabled() {
		cfg.CookieSecure = true // browser talks HTTPS → the session cookie must be Secure
	}

	sender := notify.NewRealSender(cfg.Mail, cfg.AllowPrivateWebhooks)
	srv := server.New(cfg, st, sender) // bootstraps/loads the secret vault keyring
	if enabled, unlocked, passphrase := srv.VaultInfo(); enabled {
		switch {
		case passphrase && !unlocked:
			fmt.Println("secret vault on: PASSPHRASE-PROTECTED and locked — an admin must unlock it in the UI before secrets can be used")
		case passphrase:
			fmt.Println("secret vault on: passphrase-protected")
		default:
			fmt.Println("secret vault on: entries can store encrypted secrets (auto-unlocks via key file)")
		}
		if !cfg.CookieSecure {
			fmt.Println("  note: serve over HTTPS (or a private VPN) before revealing secrets over the network")
		}
	}

	// Background rescan + notification job.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if cfg.SchedulerEnabled {
		scheduler.New(st, sender, cfg.CheckInterval, cfg.ScanTimeout, nil).Start(ctx)
		fmt.Printf("scheduler on: rescan + notify every %s\n", cfg.CheckInterval)
	}

	httpSrv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	if cfg.ACMEEnabled() {
		// Fully automatic HTTPS: obtain/renew a real cert for the domain(s). The
		// HTTP listener on :80 answers ACME challenges and redirects to HTTPS.
		domains := splitHosts(cfg.ACMEDomain)
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(domains...),
			Cache:      autocert.DirCache(cfg.ACMECacheDir),
			Email:      cfg.ACMEEmail,
		}
		go func() {
			// challenge responder + HTTP→HTTPS redirect
			_ = http.ListenAndServe(":80", m.HTTPHandler(nil))
		}()
		httpSrv.Addr = ":443"
		httpSrv.TLSConfig = m.TLSConfig()
		fmt.Printf("certguard %s listening on :443 with automatic HTTPS for %s (db: %s)\n",
			version, strings.Join(domains, ", "), cfg.DBDriver)
		err = httpSrv.ListenAndServeTLS("", "") // certs come from the ACME manager
	} else if cfg.TLSEnabled() {
		certPath, keyPath := cfg.TLSCert, cfg.TLSKey
		if cfg.TLSAuto {
			// Self-signed: generate (once) to the given paths, or default paths.
			// Point CERTGUARD_TLS_CERT/KEY at the data volume to persist the cert
			// across container recreates so its fingerprint stays stable.
			if certPath == "" || keyPath == "" {
				certPath, keyPath = "certguard-cert.pem", "certguard-key.pem"
			}
			if e := selfsign.EnsureCert(certPath, keyPath, cfg.TLSHosts, time.Now()); e != nil {
				fmt.Fprintln(os.Stderr, "tls: could not generate self-signed certificate:", e)
				return 1
			}
			fmt.Println("tls: self-signed certificate (browsers will warn) — use CERTGUARD_ACME_DOMAIN with a real domain for a trusted cert")
		}
		fmt.Printf("certguard %s listening on %s over HTTPS (db: %s)\n", version, cfg.Addr, cfg.DBDriver)
		err = httpSrv.ListenAndServeTLS(certPath, keyPath)
	} else {
		fmt.Printf("certguard %s listening on %s (db: %s)\n", version, cfg.Addr, cfg.DBDriver)
		err = httpSrv.ListenAndServe()
	}
	if err != nil {
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

// splitHosts turns a comma-separated host list into a trimmed slice.
func splitHosts(s string) []string {
	var out []string
	for _, h := range strings.Split(s, ",") {
		if h = strings.TrimSpace(h); h != "" {
			out = append(out, h)
		}
	}
	return out
}

// openStore is a small helper for CLI commands that touch the database.
func openStore() (*store.Store, error) {
	cfg := config.Load()
	return store.Open(cfg.DBDriver, cfg.DBDSN)
}

// readPassword returns a password from --password, then CERTGUARD_PASSWORD, then
// a single line of stdin.
func readPassword(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if v := os.Getenv("CERTGUARD_PASSWORD"); v != "" {
		return v
	}
	fmt.Fprint(os.Stderr, "Password: ")
	sc := bufio.NewScanner(os.Stdin)
	if sc.Scan() {
		return strings.TrimSpace(sc.Text())
	}
	return ""
}

func cmdUser(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: certguard user <add|list> ...")
		return 2
	}
	st, err := openStore()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	defer st.Close()

	switch args[0] {
	case "add":
		rest := args[1:]
		role := string(auth.RoleViewer)
		password := ""
		var email string
		for i := 0; i < len(rest); i++ {
			switch rest[i] {
			case "--role":
				if i+1 < len(rest) {
					i++
					role = rest[i]
				}
			case "--password":
				if i+1 < len(rest) {
					i++
					password = rest[i]
				}
			default:
				email = rest[i]
			}
		}
		if email == "" {
			fmt.Fprintln(os.Stderr, "usage: certguard user add <email> [--role admin|viewer] [--password PW]")
			return 2
		}
		if !auth.Role(role).Valid() {
			fmt.Fprintf(os.Stderr, "invalid role %q (want admin or viewer)\n", role)
			return 2
		}
		pw := readPassword(password)
		hash, err := auth.HashPassword(pw)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		u, err := st.CreateUser(email, hash, role)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error creating user:", err)
			return 1
		}
		fmt.Printf("created user %s (role=%s, id=%d)\n", u.Email, u.Role, u.ID)
		return 0

	case "list":
		users, err := st.ListUsers()
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		if len(users) == 0 {
			fmt.Println("(no users yet — create one with: certguard user add <email> --role admin)")
			return 0
		}
		for _, u := range users {
			fmt.Printf("%-4d %-30s %-7s created %s\n", u.ID, u.Email, u.Role, u.CreatedAt.Format(time.RFC3339))
		}
		return 0

	default:
		fmt.Fprintln(os.Stderr, "usage: certguard user <add|list> ...")
		return 2
	}
}

func cmdToken(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: certguard token <create|list> <email> ...")
		return 2
	}
	st, err := openStore()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	defer st.Close()

	switch args[0] {
	case "create":
		rest := args[1:]
		name := ""
		var email string
		for i := 0; i < len(rest); i++ {
			switch rest[i] {
			case "--name":
				if i+1 < len(rest) {
					i++
					name = rest[i]
				}
			default:
				email = rest[i]
			}
		}
		if email == "" {
			fmt.Fprintln(os.Stderr, "usage: certguard token create <email> [--name NAME]")
			return 2
		}
		u, err := st.GetUserByEmail(email)
		if err != nil {
			fmt.Fprintln(os.Stderr, "no such user:", email)
			return 1
		}
		plaintext, err := auth.GenerateToken()
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		if _, err := st.CreateToken(u.ID, name, auth.HashSecret(plaintext)); err != nil {
			fmt.Fprintln(os.Stderr, "error creating token:", err)
			return 1
		}
		fmt.Printf("token for %s (name=%q):\n\n    %s\n\n", u.Email, name, plaintext)
		fmt.Println("This is shown once and cannot be recovered. Store it now.")
		fmt.Println("Use it as:  Authorization: Bearer <token>")
		return 0

	case "list":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: certguard token list <email>")
			return 2
		}
		u, err := st.GetUserByEmail(args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "no such user:", args[1])
			return 1
		}
		tokens, err := st.ListTokens(u.ID)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		if len(tokens) == 0 {
			fmt.Println("(no tokens)")
			return 0
		}
		for _, t := range tokens {
			last := "never"
			if t.LastUsedAt != nil {
				last = t.LastUsedAt.Format(time.RFC3339)
			}
			fmt.Printf("%-4d %-20s created %s  last used %s\n", t.ID, t.Name, t.CreatedAt.Format(time.RFC3339), last)
		}
		return 0

	default:
		fmt.Fprintln(os.Stderr, "usage: certguard token <create|list> <email> ...")
		return 2
	}
}

func cmdChannel(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: certguard channel <add|list|test|rm> ...")
		return 2
	}
	st, err := openStore()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	defer st.Close()

	switch args[0] {
	case "add":
		rest := args[1:]
		var email, typ, target, thresholds string
		for i := 0; i < len(rest); i++ {
			switch rest[i] {
			case "--type":
				if i+1 < len(rest) {
					i++
					typ = rest[i]
				}
			case "--target":
				if i+1 < len(rest) {
					i++
					target = rest[i]
				}
			case "--thresholds":
				if i+1 < len(rest) {
					i++
					thresholds = rest[i]
				}
			default:
				email = rest[i]
			}
		}
		if email == "" || typ == "" || target == "" {
			fmt.Fprintln(os.Stderr, "usage: certguard channel add <email> --type TYPE --target VAL [--thresholds 30,7,3]")
			return 2
		}
		if !model.ValidChannelType(model.ChannelType(typ)) {
			fmt.Fprintf(os.Stderr, "invalid type %q (email|slack|discord|webhook)\n", typ)
			return 2
		}
		u, err := st.GetUserByEmail(email)
		if err != nil {
			fmt.Fprintln(os.Stderr, "no such user:", email)
			return 1
		}
		ch, err := st.CreateChannel(u.ID, model.ChannelType(typ), target, thresholds)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		fmt.Printf("created channel %d (%s) for %s\n", ch.ID, ch.Type, u.Email)
		return 0

	case "list":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: certguard channel list <email>")
			return 2
		}
		u, err := st.GetUserByEmail(args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "no such user:", args[1])
			return 1
		}
		chans, err := st.ListChannels(u.ID)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		if len(chans) == 0 {
			fmt.Println("(no channels)")
			return 0
		}
		for _, c := range chans {
			th := c.Thresholds
			if th == "" {
				th = "30,7,3"
			}
			fmt.Printf("%-4d %-8s %-45s thresholds=%s\n", c.ID, c.Type, c.Target, th)
		}
		return 0

	case "test":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: certguard channel test <id>")
			return 2
		}
		var id int64
		fmt.Sscanf(args[1], "%d", &id)
		ch, err := st.GetChannel(id)
		if err != nil {
			fmt.Fprintln(os.Stderr, "no such channel:", args[1])
			return 1
		}
		cfg := config.Load()
		sender := notify.NewRealSender(cfg.Mail, cfg.AllowPrivateWebhooks)
		sample := &model.Cert{Name: "certguard-test.example.com", ExpiresAt: time.Now().UTC().AddDate(0, 0, 3)}
		msg := notify.BuildMessage(sample, 3, time.Now().UTC())
		msg.Subject = "[certguard] test notification"
		if err := sender.Send(ch, msg); err != nil {
			fmt.Fprintln(os.Stderr, "send failed:", err)
			return 1
		}
		fmt.Printf("test notification sent via channel %d (%s)\n", ch.ID, ch.Type)
		return 0

	case "rm":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: certguard channel rm <id>")
			return 2
		}
		var id int64
		fmt.Sscanf(args[1], "%d", &id)
		if err := st.DeleteChannel(id, 0); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		fmt.Printf("deleted channel %d\n", id)
		return 0

	default:
		fmt.Fprintln(os.Stderr, "usage: certguard channel <add|list|test|rm> ...")
		return 2
	}
}

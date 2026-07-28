// Package store is the persistence layer: opening the database, applying
// embedded migrations, and CRUD for the cert model.
package store

import (
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/bfalcher/certguard/internal/model"
	"github.com/bfalcher/certguard/internal/scanner"

	_ "github.com/jackc/pgx/v5/stdlib" // registers "pgx"
	_ "modernc.org/sqlite"             // registers "sqlite"
)

//go:embed all:migrations
var migrationFS embed.FS

const rfc3339 = time.RFC3339

// Store wraps a *sql.DB with cert-aware helpers.
type Store struct {
	db            *sql.DB
	driver        string // "sqlite" or "postgres"
	migrationsDir string // embedded path holding this dialect's migrations
}

// Open connects using the given driver ("sqlite" or "postgres") and DSN, then
// applies any pending migrations. For sqlite, sensible pragmas are appended.
func Open(driver, dsn string) (*Store, error) {
	var sqlDriver, migrationsDir string
	switch driver {
	case "sqlite":
		sqlDriver = "sqlite" // modernc.org/sqlite registers as "sqlite"
		dsn = sqliteDSN(dsn)
		migrationsDir = "migrations/sqlite"
	case "postgres":
		sqlDriver = "pgx" // github.com/jackc/pgx/v5/stdlib registers as "pgx"
		migrationsDir = "migrations/postgres"
	default:
		return nil, fmt.Errorf("unsupported db driver %q (want sqlite or postgres)", driver)
	}
	db, err := sql.Open(sqlDriver, dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}
	s := &Store{db: db, driver: driver, migrationsDir: migrationsDir}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

func sqliteDSN(path string) string {
	if strings.Contains(path, "?") {
		return path
	}
	// WAL + busy_timeout + FK enforcement are the standard "well-behaved
	// embedded SQLite" pragmas.
	return "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
}

func (s *Store) Close() error { return s.db.Close() }

// migrate applies embedded migrations in filename order, tracked in a
// schema_migrations table. Each file runs at most once.
func (s *Store) migrate() error {
	if _, err := s.exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version TEXT PRIMARY KEY,
		applied_at TEXT NOT NULL
	)`); err != nil {
		return err
	}

	entries, err := migrationFS.ReadDir(s.migrationsDir)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		var exists string
		err := s.queryRow(`SELECT version FROM schema_migrations WHERE version = ?`, name).Scan(&exists)
		if err == nil {
			continue // already applied
		}
		if err != sql.ErrNoRows {
			return err
		}
		body, err := migrationFS.ReadFile(s.migrationsDir + "/" + name)
		if err != nil {
			return err
		}
		if _, err := s.exec(string(body)); err != nil {
			return fmt.Errorf("apply %s: %w", name, err)
		}
		if _, err := s.exec(`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
			name, time.Now().UTC().Format(rfc3339)); err != nil {
			return err
		}
	}
	return nil
}

// UpsertScan records a scan result as an endpoint cert. If a cert with the same
// host/port already exists it is updated in place (preserving notification
// state when the certificate is unchanged); otherwise a new row is inserted.
// Returns the stored cert.
func (s *Store) UpsertScan(name string, res *scanner.Result) (*model.Cert, error) {
	dns, _ := json.Marshal(res.DNSNames)
	now := time.Now().UTC()

	existing, err := s.findByHostPort(res.Host, res.Port)
	if err != nil {
		return nil, err
	}

	if existing != nil {
		// If the certificate rotated (new fingerprint), reset notification
		// escalation so the new cert's expiry is treated fresh.
		if existing.SHA256 != res.SHA256 {
			existing.LastNotifiedThreshold = 0
			existing.LastNotifiedOn = nil
		}
		_, err := s.exec(`UPDATE certs SET
			subject=?, issuer=?, serial=?, sha256=?, not_before=?, expires_at=?,
			dns_names=?, key_type=?, sig_alg=?, server_name=?,
			last_scanned_at=?, last_error=?,
			last_notified_threshold=?, last_notified_on=?
			WHERE id=?`,
			res.Subject, res.Issuer, res.Serial, res.SHA256,
			res.NotBefore.Format(rfc3339), res.NotAfter.Format(rfc3339),
			string(dns), res.KeyType, res.SigAlg, res.ServerName,
			now.Format(rfc3339), res.TrustError,
			existing.LastNotifiedThreshold, nullTime(existing.LastNotifiedOn),
			existing.ID)
		if err != nil {
			return nil, err
		}
		return s.GetByID(existing.ID)
	}

	if name == "" {
		name = res.Host
	}
	id, err := s.insertReturningID(`INSERT INTO certs
		(name, kind, category, host, port, server_name, subject, issuer, serial, sha256,
		 not_before, expires_at, dns_names, key_type, sig_alg,
		 auto_rescan, last_scanned_at, last_error, active, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		name, string(model.KindEndpoint), "certificate", res.Host, res.Port, res.ServerName,
		res.Subject, res.Issuer, res.Serial, res.SHA256,
		res.NotBefore.Format(rfc3339), res.NotAfter.Format(rfc3339),
		string(dns), res.KeyType, res.SigAlg,
		1, now.Format(rfc3339), res.TrustError, 1, now.Format(rfc3339))
	if err != nil {
		return nil, err
	}
	return s.GetByID(id)
}

// AddCert inserts a manually-entered or file-parsed cert. Only Name and
// ExpiresAt are required; the certificate-metadata fields are optional and used
// when a dropped file was parsed client-side. Kind defaults to manual.
func (s *Store) AddCert(c *model.Cert) (*model.Cert, error) {
	if c.Kind == "" {
		c.Kind = model.KindManual
	}
	dns, _ := json.Marshal(c.DNSNames)
	now := time.Now().UTC()
	id, err := s.insertReturningID(`INSERT INTO certs
		(name, kind, category, host, port, server_name, subject, issuer, serial, sha256,
		 not_before, expires_at, dns_names, key_type, sig_alg,
		 auto_rescan, last_error, notes, active, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		c.Name, string(c.Kind), c.Category, c.Host, c.Port, c.ServerName,
		c.Subject, c.Issuer, c.Serial, c.SHA256,
		timeOrEmpty(c.NotBefore), c.ExpiresAt.UTC().Format(rfc3339),
		string(dns), c.KeyType, c.SigAlg,
		boolToInt(c.Kind == model.KindEndpoint), "", c.Notes, 1, now.Format(rfc3339))
	if err != nil {
		return nil, err
	}
	return s.GetByID(id)
}

// UpdateEntry renames/re-labels an entry. Empty strings clear the field, so the
// caller should pass the current value for fields it doesn't intend to change.
func (s *Store) UpdateEntry(id int64, name, category, notes string) error {
	res, err := s.exec(`UPDATE certs SET name=?, category=?, notes=? WHERE id=? AND active=1`,
		name, category, notes, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchScanError records a failed scan attempt (bump last_scanned_at + store the
// error) so an on-demand rescan that couldn't connect still reflects the attempt.
func (s *Store) TouchScanError(id int64, msg string) error {
	now := time.Now().UTC().Format(rfc3339)
	_, err := s.exec(`UPDATE certs SET last_scanned_at=?, last_error=? WHERE id=? AND active=1`, now, msg, id)
	return err
}

// SetSecret stores (or clears, with empty enc/hint) the encrypted secret for an
// entry. The store never sees plaintext — enc is already-sealed ciphertext.
func (s *Store) SetSecret(id int64, enc, hint string) error {
	res, err := s.exec(`UPDATE certs SET secret_enc=?, secret_hint=? WHERE id=? AND active=1`, enc, hint, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SoftDelete marks a cert inactive so it drops out of listings and scans.
func (s *Store) SoftDelete(id int64) error {
	res, err := s.exec(`UPDATE certs SET active=0 WHERE id=? AND active=1`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func timeOrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(rfc3339)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (s *Store) findByHostPort(host string, port int) (*model.Cert, error) {
	row := s.queryRow(selectCols+` WHERE host=? AND port=? AND active=1`, host, port)
	c, err := scanRow(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return c, err
}

// GetByID fetches a single cert.
func (s *Store) GetByID(id int64) (*model.Cert, error) {
	row := s.queryRow(selectCols+` WHERE id=?`, id)
	return scanRow(row)
}

// List returns active certs ordered by soonest expiry.
func (s *Store) List() ([]*model.Cert, error) {
	rows, err := s.query(selectCols + ` WHERE active=1 ORDER BY expires_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Cert
	for rows.Next() {
		c, err := scanRowValues(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

const selectCols = `SELECT id, name, kind, category, host, port, server_name, subject, issuer,
	serial, sha256, not_before, expires_at, dns_names, key_type, sig_alg,
	auto_rescan, last_scanned_at, last_error, notes, active, created_at,
	last_notified_threshold, last_notified_on, secret_enc, secret_hint FROM certs`

type rowScanner interface{ Scan(dest ...any) error }

func scanRow(r rowScanner) (*model.Cert, error)      { return scanRowValues(r) }
func scanRowValues(r rowScanner) (*model.Cert, error) {
	var (
		c            model.Cert
		notBefore    string
		expiresAt    string
		dnsJSON      string
		autoRescan   int
		active       int
		lastScanned  sql.NullString
		createdAt    string
		lastNotifiedThreshold int
		lastNotifiedOn sql.NullString
	)
	err := r.Scan(&c.ID, &c.Name, &c.Kind, &c.Category, &c.Host, &c.Port, &c.ServerName,
		&c.Subject, &c.Issuer, &c.Serial, &c.SHA256, &notBefore, &expiresAt,
		&dnsJSON, &c.KeyType, &c.SigAlg, &autoRescan, &lastScanned, &c.LastError,
		&c.Notes, &active, &createdAt, &lastNotifiedThreshold, &lastNotifiedOn,
		&c.SecretEnc, &c.SecretHint)
	if err != nil {
		return nil, err
	}
	c.HasSecret = c.SecretEnc != ""
	c.NotBefore = parseTime(notBefore)
	c.ExpiresAt = parseTime(expiresAt)
	c.CreatedAt = parseTime(createdAt)
	c.AutoRescan = autoRescan != 0
	c.Active = active != 0
	c.LastNotifiedThreshold = lastNotifiedThreshold
	if dnsJSON != "" {
		_ = json.Unmarshal([]byte(dnsJSON), &c.DNSNames)
	}
	if lastScanned.Valid {
		t := parseTime(lastScanned.String)
		c.LastScannedAt = &t
	}
	if lastNotifiedOn.Valid {
		t := parseTime(lastNotifiedOn.String)
		c.LastNotifiedOn = &t
	}
	return &c, nil
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(rfc3339, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

func nullTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().Format(rfc3339)
}

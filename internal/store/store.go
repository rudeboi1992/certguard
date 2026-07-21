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

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

const rfc3339 = time.RFC3339

// Store wraps a *sql.DB with cert-aware helpers.
type Store struct {
	db *sql.DB
}

// Open connects using the given driver ("sqlite" or "postgres") and DSN, then
// applies any pending migrations. For sqlite, sensible pragmas are appended.
func Open(driver, dsn string) (*Store, error) {
	sqlDriver := driver
	if driver == "sqlite" {
		sqlDriver = "sqlite" // modernc.org/sqlite registers as "sqlite"
		dsn = sqliteDSN(dsn)
	}
	db, err := sql.Open(sqlDriver, dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}
	s := &Store{db: db}
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
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version TEXT PRIMARY KEY,
		applied_at TEXT NOT NULL
	)`); err != nil {
		return err
	}

	entries, err := migrationFS.ReadDir("migrations")
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
		err := s.db.QueryRow(`SELECT version FROM schema_migrations WHERE version = ?`, name).Scan(&exists)
		if err == nil {
			continue // already applied
		}
		if err != sql.ErrNoRows {
			return err
		}
		body, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		if _, err := s.db.Exec(string(body)); err != nil {
			return fmt.Errorf("apply %s: %w", name, err)
		}
		if _, err := s.db.Exec(`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
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
		_, err := s.db.Exec(`UPDATE certs SET
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
	result, err := s.db.Exec(`INSERT INTO certs
		(name, kind, host, port, server_name, subject, issuer, serial, sha256,
		 not_before, expires_at, dns_names, key_type, sig_alg,
		 auto_rescan, last_scanned_at, last_error, active, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		name, string(model.KindEndpoint), res.Host, res.Port, res.ServerName,
		res.Subject, res.Issuer, res.Serial, res.SHA256,
		res.NotBefore.Format(rfc3339), res.NotAfter.Format(rfc3339),
		string(dns), res.KeyType, res.SigAlg,
		1, now.Format(rfc3339), res.TrustError, 1, now.Format(rfc3339))
	if err != nil {
		return nil, err
	}
	id, _ := result.LastInsertId()
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
	res, err := s.db.Exec(`INSERT INTO certs
		(name, kind, host, port, server_name, subject, issuer, serial, sha256,
		 not_before, expires_at, dns_names, key_type, sig_alg,
		 auto_rescan, last_error, notes, active, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		c.Name, string(c.Kind), c.Host, c.Port, c.ServerName,
		c.Subject, c.Issuer, c.Serial, c.SHA256,
		timeOrEmpty(c.NotBefore), c.ExpiresAt.UTC().Format(rfc3339),
		string(dns), c.KeyType, c.SigAlg,
		boolToInt(c.Kind == model.KindEndpoint), "", c.Notes, 1, now.Format(rfc3339))
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return s.GetByID(id)
}

// SoftDelete marks a cert inactive so it drops out of listings and scans.
func (s *Store) SoftDelete(id int64) error {
	res, err := s.db.Exec(`UPDATE certs SET active=0 WHERE id=? AND active=1`, id)
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
	row := s.db.QueryRow(selectCols+` WHERE host=? AND port=? AND active=1`, host, port)
	c, err := scanRow(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return c, err
}

// GetByID fetches a single cert.
func (s *Store) GetByID(id int64) (*model.Cert, error) {
	row := s.db.QueryRow(selectCols+` WHERE id=?`, id)
	return scanRow(row)
}

// List returns active certs ordered by soonest expiry.
func (s *Store) List() ([]*model.Cert, error) {
	rows, err := s.db.Query(selectCols + ` WHERE active=1 ORDER BY expires_at ASC`)
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

const selectCols = `SELECT id, name, kind, host, port, server_name, subject, issuer,
	serial, sha256, not_before, expires_at, dns_names, key_type, sig_alg,
	auto_rescan, last_scanned_at, last_error, notes, active, created_at,
	last_notified_threshold, last_notified_on FROM certs`

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
	err := r.Scan(&c.ID, &c.Name, &c.Kind, &c.Host, &c.Port, &c.ServerName,
		&c.Subject, &c.Issuer, &c.Serial, &c.SHA256, &notBefore, &expiresAt,
		&dnsJSON, &c.KeyType, &c.SigAlg, &autoRescan, &lastScanned, &c.LastError,
		&c.Notes, &active, &createdAt, &lastNotifiedThreshold, &lastNotifiedOn)
	if err != nil {
		return nil, err
	}
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

package store

import (
	"database/sql"
	"time"

	"github.com/bfalcher/certguard/internal/model"
)

// Event kinds. Kept as constants so the API, the scheduler and the UI cannot
// drift apart on spelling.
const (
	EventAdded          = "added"
	EventUpdated        = "updated"
	EventDeleted        = "deleted"
	EventRenewed        = "renewed"
	EventScanFailed     = "scan_failed"
	EventScanRecovered  = "scan_recovered"
	EventCoverageBroken = "coverage_broken"
	EventChainExpiring  = "chain_expiring"
	EventNotified       = "notified"
)

// AddEvent appends one entry to the activity log.
//
// Errors are returned but every caller ignores them on purpose: an audit line
// that cannot be written must never fail the operation it describes. Losing a
// log row is a smaller problem than refusing to delete an entry because the
// log is full.
func (s *Store) AddEvent(e *model.Event) error {
	at := e.At
	if at.IsZero() {
		at = time.Now().UTC()
	}
	var certID any
	if e.CertID != 0 {
		certID = e.CertID
	}
	_, err := s.exec(
		`INSERT INTO events (at, kind, cert_id, cert_name, actor, detail) VALUES (?,?,?,?,?,?)`,
		at.UTC().Format(rfc3339), e.Kind, certID, e.CertName, e.Actor, e.Detail)
	return err
}

// ListEvents returns the most recent events first. kind filters by event kind
// when non-empty; limit is clamped by the caller.
func (s *Store) ListEvents(kind string, limit int) ([]*model.Event, error) {
	q := `SELECT id, at, kind, cert_id, cert_name, actor, detail FROM events`
	args := []any{}
	if kind != "" {
		q += ` WHERE kind=?`
		args = append(args, kind)
	}
	// id is the tiebreak: several events can share a timestamp (a scan sweep
	// writes them in the same second), and without it the order of those rows
	// is undefined and can shuffle between requests.
	q += ` ORDER BY at DESC, id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*model.Event{}
	for rows.Next() {
		var e model.Event
		var at string
		var certID sql.NullInt64
		if err := rows.Scan(&e.ID, &at, &e.Kind, &certID, &e.CertName, &e.Actor, &e.Detail); err != nil {
			return nil, err
		}
		e.At, _ = time.Parse(rfc3339, at)
		e.CertID = certID.Int64
		out = append(out, &e)
	}
	return out, rows.Err()
}

// PruneEvents drops entries older than the cutoff, so the log cannot grow
// without bound on a long-running instance.
func (s *Store) PruneEvents(before time.Time) (int64, error) {
	res, err := s.exec(`DELETE FROM events WHERE at < ?`, before.UTC().Format(rfc3339))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

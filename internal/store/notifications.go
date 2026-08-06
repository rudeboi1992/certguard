package store

import (
	"database/sql"
	"time"

	"github.com/bfalcher/certguard/internal/model"
)

// --- Notification channels ---

func (s *Store) CreateChannel(userID int64, typ model.ChannelType, target, thresholds string) (*model.Channel, error) {
	now := time.Now().UTC()
	id, err := s.insertReturningID(
		`INSERT INTO notification_channels (user_id, type, target, thresholds, enabled, created_at)
		 VALUES (?,?,?,?,1,?)`,
		userID, string(typ), target, thresholds, now.Format(rfc3339))
	if err != nil {
		return nil, err
	}
	return s.GetChannel(id)
}

const channelCols = `SELECT id, user_id, type, target, thresholds, enabled, created_at
	FROM notification_channels`

func (s *Store) GetChannel(id int64) (*model.Channel, error) {
	return scanChannel(s.queryRow(channelCols+` WHERE id=?`, id))
}

// ListChannels returns a single user's channels.
func (s *Store) ListChannels(userID int64) ([]*model.Channel, error) {
	return s.queryChannels(channelCols+` WHERE user_id=? ORDER BY created_at ASC`, userID)
}

// AllEnabledChannels returns every enabled channel across all users — the set
// the scheduler notifies.
func (s *Store) AllEnabledChannels() ([]*model.Channel, error) {
	return s.queryChannels(channelCols + ` WHERE enabled=1`)
}

func (s *Store) queryChannels(q string, args ...any) ([]*model.Channel, error) {
	rows, err := s.query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Channel
	for rows.Next() {
		c, err := scanChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteChannel removes a channel. If userID is non-zero the delete is scoped to
// that owner (used by the per-user API); pass 0 to delete by id (CLI).
func (s *Store) DeleteChannel(id, userID int64) error {
	var (
		res sql.Result
		err error
	)
	if userID != 0 {
		res, err = s.exec(`DELETE FROM notification_channels WHERE id=? AND user_id=?`, id, userID)
	} else {
		res, err = s.exec(`DELETE FROM notification_channels WHERE id=?`, id)
	}
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func scanChannel(r rowScanner) (*model.Channel, error) {
	var (
		c         model.Channel
		typ       string
		enabled   int
		createdAt string
	)
	err := r.Scan(&c.ID, &c.UserID, &typ, &c.Target, &c.Thresholds, &enabled, &createdAt)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	c.Type = model.ChannelType(typ)
	c.Enabled = enabled != 0
	c.CreatedAt = parseTime(createdAt)
	return &c, nil
}

// --- Cert helpers for the scheduler ---

// MarkNotified records that a cert was notified at the given threshold, so the
// escalation state machine won't re-notify at the same or less urgent level.
func (s *Store) MarkNotified(certID int64, threshold int) error {
	_, err := s.exec(
		`UPDATE certs SET last_notified_threshold=?, last_notified_on=? WHERE id=?`,
		threshold, time.Now().UTC().Format(rfc3339), certID)
	return err
}

// DomainsForRefresh returns active domain registrations with auto-refresh on.
// Separate from EndpointsForRescan because they are refreshed by a different
// mechanism — an RDAP query rather than a TLS handshake.
func (s *Store) DomainsForRefresh() ([]*model.Cert, error) {
	return s.listForRefresh(`WHERE active=1 AND kind='domain' AND auto_rescan=1 AND host!='' ORDER BY id ASC`)
}

// EndpointsForRescan returns active endpoint certs that have auto-rescan on.
func (s *Store) EndpointsForRescan() ([]*model.Cert, error) {
	return s.listForRefresh(`WHERE active=1 AND kind='endpoint' AND auto_rescan=1 AND host!='' ORDER BY id ASC`)
}

func (s *Store) listForRefresh(where string) ([]*model.Cert, error) {
	rows, err := s.query(selectCols + ` ` + where)
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

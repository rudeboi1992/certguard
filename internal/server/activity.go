package server

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bfalcher/certguard/internal/model"
)

// recordEvent appends one activity-log line, attributing it to the caller.
//
// The error is deliberately dropped: an audit row that cannot be written must
// never fail the operation it describes. Refusing to delete an entry because
// the log is unwritable would be a worse outcome than a missing log line.
func (s *Server) recordEvent(r *http.Request, kind string, c *model.Cert, detail string) {
	if c == nil {
		return
	}
	actor := ""
	if u := userFrom(r.Context()); u != nil {
		actor = u.Email
	}
	_ = s.store.AddEvent(&model.Event{
		Kind: kind, CertID: c.ID, CertName: c.Name, Actor: actor, Detail: detail,
	})
}

// handleListEvents returns the activity log, newest first.
func (s *Server) handleListEvents(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	// Capped regardless of what was asked for: this is read straight into a
	// page, and an unbounded limit is a way to make the server serialise the
	// entire table on request.
	if limit > 1000 {
		limit = 1000
	}
	events, err := s.store.ListEvents(r.URL.Query().Get("kind"), limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, events)
}

// handlePublicStatus serves aggregate health with no authentication, and only
// when explicitly enabled.
//
// Everything here is a count. No name, host, issuer, or expiry date is
// included, because the caller is unauthenticated and the point of the page is
// "is this being looked after" — which a reader can learn without learning
// what the inventory contains. Adding a name to this response would turn a
// status page into an asset inventory for anyone who can reach the port.
func (s *Server) handlePublicStatus(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.StatusPublic {
		http.NotFound(w, r) // 404, not 403: an unset feature should not advertise itself
		return
	}
	certs, err := s.store.List()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "unavailable")
		return
	}
	now := time.Now().UTC()
	out := struct {
		Tracked   int        `json:"tracked"`
		Healthy   int        `json:"healthy"`
		Expiring  int        `json:"expiring"` // 30 days or fewer, not yet expired
		Expired   int        `json:"expired"`
		Problems  int        `json:"problems"` // failed check, or a covered name that stopped resolving
		LastCheck *time.Time `json:"last_check,omitempty"`
		Now       time.Time  `json:"now"`
	}{Now: now}

	for _, c := range certs {
		out.Tracked++
		switch d := c.DaysRemaining(now); {
		case d < 0:
			out.Expired++
		case d <= 30:
			out.Expiring++
		default:
			out.Healthy++
		}
		if c.LastError != "" {
			out.Problems++
		} else {
			for _, n := range c.Coverage {
				if n.Status == "unreachable" {
					out.Problems++
					break
				}
			}
		}
		if c.LastScannedAt != nil && (out.LastCheck == nil || c.LastScannedAt.After(*out.LastCheck)) {
			out.LastCheck = c.LastScannedAt
		}
	}
	// Not cacheable by a shared proxy: it is small, cheap, and stale health is
	// worse than no health.
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}

// handleStatusPage serves the public status page, subject to the same switch.
func (s *Server) handleStatusPage(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.StatusPublic {
		http.NotFound(w, r)
		return
	}
	s.serveEmbedded(w, "web/status.html")
}

// applyNotes attaches a note to a freshly scanned or looked-up entry.
//
// Scans and RDAP lookups go through UpsertScan/UpsertDomain, which write the
// fields they discovered and know nothing about notes — so the note is a
// second write. Best-effort: an entry that was created successfully must not
// be reported as a failure because its note did not stick. Returns the updated
// entry, or the original if there was nothing to do.
func (s *Server) applyNotes(c *model.Cert, notes string) *model.Cert {
	if c == nil || strings.TrimSpace(notes) == "" {
		return c
	}
	if err := s.store.UpdateEntry(c.ID, c.Name, c.Category, notes); err != nil {
		return c
	}
	if updated, err := s.store.GetByID(c.ID); err == nil {
		return updated
	}
	return c
}

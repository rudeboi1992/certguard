// Package scheduler runs the unattended background job: periodically re-scan
// endpoint certs to refresh their expiry, then evaluate notification thresholds
// and deliver alerts. Because notification decisions are state-based (see
// notify.NotificationThreshold), running frequently never produces duplicate
// alerts.
package scheduler

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/bfalcher/certguard/internal/coverage"
	"github.com/bfalcher/certguard/internal/model"
	"github.com/bfalcher/certguard/internal/notify"
	"github.com/bfalcher/certguard/internal/rdap"
	"github.com/bfalcher/certguard/internal/scanner"
	"github.com/bfalcher/certguard/internal/store"
)

type Scheduler struct {
	store       *store.Store
	sender      notify.Sender
	interval    time.Duration
	scanTimeout time.Duration
	logger      *log.Logger
}

func New(st *store.Store, sender notify.Sender, interval, scanTimeout time.Duration, logger *log.Logger) *Scheduler {
	if logger == nil {
		logger = log.Default()
	}
	return &Scheduler{store: st, sender: sender, interval: interval, scanTimeout: scanTimeout, logger: logger}
}

// Report summarizes one pass.
type Report struct {
	Scanned    int
	ScanErrors int
	Notified   int
}

// Start launches the loop in a goroutine, returning immediately. It runs one
// pass shortly after startup, then every interval, until ctx is cancelled.
func (s *Scheduler) Start(ctx context.Context) {
	go func() {
		// Small delay so the server is serving before the first outbound scan.
		select {
		case <-time.After(15 * time.Second):
		case <-ctx.Done():
			return
		}
		s.runAndLog(ctx)

		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.runAndLog(ctx)
			}
		}
	}()
}

func (s *Scheduler) runAndLog(ctx context.Context) {
	r := s.RunOnce(ctx)
	s.logger.Printf("scheduler pass: rescanned=%d scan_errors=%d notifications_sent=%d",
		r.Scanned, r.ScanErrors, r.Notified)
}

// RunOnce performs a full pass: rescan endpoints, then send due notifications.
func (s *Scheduler) RunOnce(ctx context.Context) Report {
	scanned, scanErrs := s.rescan(ctx)
	sent := s.NotifyPass(time.Now().UTC())
	return Report{Scanned: scanned, ScanErrors: scanErrs, Notified: sent}
}

// event appends one activity-log line. The error is dropped on purpose: an
// audit row that cannot be written must not derail the sweep that produced it.
func (s *Scheduler) event(kind string, c *model.Cert, detail string) {
	_ = s.store.AddEvent(&model.Event{
		Kind: kind, CertID: c.ID, CertName: c.Name, Detail: detail,
	})
}

// newlyUnreachable returns the names that are unreachable now and were not
// before, so a name that has been broken for weeks is reported once.
func newlyUnreachable(before, after []model.CoveredName) []string {
	was := map[string]bool{}
	for _, n := range before {
		if n.Status == "unreachable" {
			was[n.Name] = true
		}
	}
	var out []string
	for _, n := range after {
		if n.Status == "unreachable" && !was[n.Name] {
			out = append(out, n.Name)
		}
	}
	return out
}

// rescan re-scans every auto-rescan endpoint, refreshing stored expiry.
func (s *Scheduler) rescan(ctx context.Context) (scanned, errs int) {
	eps, err := s.store.EndpointsForRescan()
	if err != nil {
		s.logger.Printf("scheduler: list endpoints: %v", err)
		return 0, 0
	}
	for _, c := range eps {
		if ctx.Err() != nil {
			break
		}
		res, err := scanner.Scan(ctx, c.Host, c.Port, scanner.Options{
			Timeout:    s.scanTimeout,
			ServerName: c.ServerName,
		})
		if err != nil {
			errs++
			// Persist the failure. It used to be logged and dropped, so an
			// endpoint that started failing on the 6-hourly sweep stayed
			// invisible in the UI until somebody happened to press Rescan —
			// the Problems card reads last_error, and nothing was setting it.
			// Recording it also makes the transition below meaningful.
			if c.LastError == "" {
				s.event(store.EventScanFailed, c, err.Error())
			}
			_ = s.store.TouchScanError(c.ID, err.Error())
			s.logger.Printf("scheduler: rescan %s:%d failed: %v", c.Host, c.Port, err)
			continue
		}
		stored, err := s.store.UpsertScan(c.Name, res)
		if err != nil {
			errs++
			s.logger.Printf("scheduler: store rescan %s:%d: %v", c.Host, c.Port, err)
			continue
		}
		// Only transitions are logged. A row per successful scan would be
		// thousands a week that all say "still fine", burying the few that
		// matter.
		if c.LastError != "" {
			s.event(store.EventScanRecovered, c, "")
		}
		if stored != nil && c.SHA256 != "" && stored.SHA256 != c.SHA256 {
			s.event(store.EventRenewed, stored,
				"new certificate expires "+stored.ExpiresAt.Format("2006-01-02"))
		}
		// Refresh coverage while we are here. A SAN that no longer resolves
		// will fail the next HTTP-01 renewal for the WHOLE certificate, so it
		// needs to surface on its own rather than only when someone thinks to
		// press the check button. Only worth doing when there is more than the
		// host itself to look at.
		if stored != nil && len(stored.DNSNames) > 1 {
			names, _ := coverage.Check(ctx, stored, s.scanTimeout)
			if err := s.store.SaveCoverage(stored.ID, names); err != nil {
				s.logger.Printf("scheduler: save coverage %d: %v", stored.ID, err)
			}
			// Newly-broken names only: an already-broken one would otherwise
			// log every six hours forever.
			if newly := newlyUnreachable(c.Coverage, names); len(newly) > 0 {
				s.event(store.EventCoverageBroken, stored, strings.Join(newly, ", ")+" no longer resolves")
			}
		}
		scanned++
	}

	// Domain registrations refresh on the same cycle. A registry lookup is not
	// a TLS handshake, but everything downstream — expiry, thresholds, alerts,
	// the calendar — works off expires_at and does not care which produced it.
	doms, err := s.store.DomainsForRefresh()
	if err != nil {
		s.logger.Printf("scheduler: list domains: %v", err)
		return scanned, errs
	}
	for _, c := range doms {
		if ctx.Err() != nil {
			break
		}
		res, err := rdap.Lookup(ctx, c.Host, rdap.Options{Timeout: s.scanTimeout})
		if err != nil {
			errs++
			// Record it so the failure surfaces on the entry rather than only
			// in the log — a domain that stopped resolving in RDAP is exactly
			// the kind of thing worth seeing on the dashboard.
			_ = s.store.TouchScanError(c.ID, err.Error())
			s.logger.Printf("scheduler: rdap %s failed: %v", c.Host, err)
			continue
		}
		if _, err := s.store.UpsertDomain(c.Name, res); err != nil {
			errs++
			s.logger.Printf("scheduler: store domain %s: %v", c.Host, err)
			continue
		}
		scanned++
	}
	return scanned, errs
}

// NotifyPass evaluates every active cert against every enabled channel and sends
// due notifications, marking certs as notified. Exported for testing.
func (s *Scheduler) NotifyPass(now time.Time) (sent int) {
	channels, err := s.store.AllEnabledChannels()
	if err != nil {
		s.logger.Printf("scheduler: load channels: %v", err)
		return 0
	}
	if len(channels) == 0 {
		return 0
	}
	certs, err := s.store.List()
	if err != nil {
		s.logger.Printf("scheduler: list certs: %v", err)
		return 0
	}
	for _, c := range certs {
		if th := notify.NotificationThreshold(c, now); th > 0 {
			delivered := s.deliver(channels, th, notify.BuildMessage(c, th, now))
			if delivered > 0 {
				if err := s.store.MarkNotified(c.ID, th); err != nil {
					s.logger.Printf("scheduler: mark notified cert %d: %v", c.ID, err)
				}
				// Escalation state means this fires once per threshold crossed, not
				// once per pass, so the log gets one line per real alert.
				s.event(store.EventNotified, c,
					fmt.Sprintf("%d-day alert to %d channel%s", th, delivered, plural(delivered)))
				sent += delivered
			}
		}
		// The chain is evaluated independently of the leaf, and on its own
		// escalation counter. Folding the two together would let an alert about
		// the certificate silence the warning that the path underneath it gives
		// out first — the exact blind spot this exists to close.
		if th := notify.ChainNotificationThreshold(c, now); th > 0 {
			delivered := s.deliver(channels, th, notify.BuildChainMessage(c, th, now))
			if delivered > 0 {
				if err := s.store.MarkChainNotified(c.ID, th); err != nil {
					s.logger.Printf("scheduler: mark chain notified cert %d: %v", c.ID, err)
				}
				risk, _ := c.ChainRisk()
				s.event(store.EventChainExpiring, c,
					fmt.Sprintf("chain certificate %q expires %s, before the certificate does",
						risk.Subject, risk.NotAfter.Format("2006-01-02")))
				sent += delivered
			}
		}
	}
	return sent
}

// deliver sends one rendered message to every channel that subscribes to the
// threshold, and reports how many accepted it. A channel that errors is logged
// and skipped so one bad webhook cannot suppress the rest.
func (s *Scheduler) deliver(channels []*model.Channel, th int, msg notify.Message) int {
	delivered := 0
	for _, ch := range channels {
		if !ch.WantsThreshold(th) {
			continue
		}
		if err := s.sender.Send(ch, msg); err != nil {
			s.logger.Printf("scheduler: send to channel %d (%s): %v", ch.ID, ch.Type, err)
			continue
		}
		delivered++
	}
	return delivered
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

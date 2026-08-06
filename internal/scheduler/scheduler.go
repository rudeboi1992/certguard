// Package scheduler runs the unattended background job: periodically re-scan
// endpoint certs to refresh their expiry, then evaluate notification thresholds
// and deliver alerts. Because notification decisions are state-based (see
// notify.NotificationThreshold), running frequently never produces duplicate
// alerts.
package scheduler

import (
	"context"
	"log"
	"time"

	"github.com/bfalcher/certguard/internal/coverage"
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
			s.logger.Printf("scheduler: rescan %s:%d failed: %v", c.Host, c.Port, err)
			continue
		}
		stored, err := s.store.UpsertScan(c.Name, res)
		if err != nil {
			errs++
			s.logger.Printf("scheduler: store rescan %s:%d: %v", c.Host, c.Port, err)
			continue
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
		th := notify.NotificationThreshold(c, now)
		if th <= 0 {
			continue
		}
		msg := notify.BuildMessage(c, th, now)
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
		if delivered > 0 {
			if err := s.store.MarkNotified(c.ID, th); err != nil {
				s.logger.Printf("scheduler: mark notified cert %d: %v", c.ID, err)
			}
			sent += delivered
		}
	}
	return sent
}

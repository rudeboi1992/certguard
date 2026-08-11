// Package notify implements certificate-expiry notifications: the
// threshold-escalation state machine, message formatting, and delivery to email
// and webhook (Slack/Discord/generic) channels.
package notify

import (
	"time"

	"github.com/bfalcher/certguard/internal/model"
)

// Default day-thresholds, most-to-least urgent.
var Thresholds = []int{3, 7, 30}

// DomainThresholds are the buckets for domain registrations. They start far
// earlier than a certificate's because the recovery story is worse: a lapsed
// certificate is reissued in minutes by an ACME client, while a lapsed domain
// enters redemption, costs a restore fee, and can eventually be bought by
// somebody else. Registrar transfer locks and billing disputes also take weeks,
// not hours, so 30 days is already late.
var DomainThresholds = []int{7, 30, 60}

// CurrentThreshold returns the most urgent threshold bucket for a given number
// of days remaining: 3, 7, 30, or -1 (nothing to notify, >30 days out).
// Expired certs (days < 0) fall into the 3-day (urgent) bucket.
func CurrentThreshold(days int) int {
	switch {
	case days <= 3:
		return 3
	case days <= 7:
		return 7
	case days <= 30:
		return 30
	default:
		return -1
	}
}

// CurrentDomainThreshold is CurrentThreshold's counterpart for registrations.
func CurrentDomainThreshold(days int) int {
	switch {
	case days <= 7:
		return 7
	case days <= 30:
		return 30
	case days <= 60:
		return 60
	default:
		return -1
	}
}

// thresholdFor picks the ladder appropriate to what the entry actually is.
func thresholdFor(c *model.Cert, days int) int {
	if c.Kind == model.KindDomain {
		return CurrentDomainThreshold(days)
	}
	return CurrentThreshold(days)
}

// NotificationThreshold decides whether a cert should be notified now, and at
// what threshold. It returns 3/7/30 to notify, or -1 for "nothing to do".
//
// State machine (ported from the original ExpiryGuard):
//   - never notified (LastNotifiedThreshold == 0) → notify at current threshold
//   - current threshold more urgent than last → escalate (notify)
//   - otherwise → already handled, stay quiet
//
// Because the decision is state-based rather than time-based, the scheduler can
// run as often as it likes without producing duplicate alerts.
func NotificationThreshold(c *model.Cert, now time.Time) int {
	current := thresholdFor(c, c.DaysRemaining(now))
	if current == -1 {
		return -1
	}
	last := c.LastNotifiedThreshold
	if last == 0 {
		return current
	}
	if current < last {
		return current // escalation to a more urgent level
	}
	return -1
}

// ChainNotificationThreshold is NotificationThreshold's counterpart for the
// certificate chain: it fires when an intermediate under the leaf expires
// before the leaf does, and is silent otherwise.
//
// It reuses the certificate ladder (30/7/3) rather than introducing a third
// one. The difference from a leaf alert is not urgency but remedy — you cannot
// fix this on your own schedule, because the replacement chain has to come from
// the CA — and the message carries that, not the thresholds.
func ChainNotificationThreshold(c *model.Cert, now time.Time) int {
	days, ok := c.ChainDaysRemaining(now)
	if !ok {
		return -1
	}
	current := CurrentThreshold(days)
	if current == -1 {
		return -1
	}
	last := c.LastChainNotifiedThreshold
	if last == 0 {
		return current
	}
	if current < last {
		return current
	}
	return -1
}

// UrgencyLabel is a human label for a threshold.
func UrgencyLabel(threshold int) string {
	switch threshold {
	case 3:
		return "URGENT"
	case 7:
		return "WARNING"
	case 30:
		return "NOTICE"
	default:
		return "INFO"
	}
}

// UrgencyEmoji is a leading glyph for chat notifications.
func UrgencyEmoji(threshold int) string {
	switch threshold {
	case 3:
		return "🚨"
	case 7:
		return "⚠️"
	case 30:
		return "📅"
	default:
		return "ℹ️"
	}
}

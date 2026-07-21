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
	current := CurrentThreshold(c.DaysRemaining(now))
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

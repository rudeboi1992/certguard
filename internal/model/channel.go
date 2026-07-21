package model

import (
	"strconv"
	"strings"
	"time"
)

// ChannelType is the delivery mechanism for a notification channel.
type ChannelType string

const (
	ChannelEmail   ChannelType = "email"
	ChannelSlack   ChannelType = "slack"
	ChannelDiscord ChannelType = "discord"
	ChannelWebhook ChannelType = "webhook" // generic JSON POST
)

// ValidChannelType reports whether t is a known channel type.
func ValidChannelType(t ChannelType) bool {
	switch t {
	case ChannelEmail, ChannelSlack, ChannelDiscord, ChannelWebhook:
		return true
	}
	return false
}

// Channel is a per-user notification destination. Because the cert inventory is
// shared, a channel is notified about every cert that crosses one of its
// thresholds — it is team-wide alerting scoped to the user who owns the channel.
type Channel struct {
	ID     int64       `json:"id"`
	UserID int64       `json:"user_id"`
	Type   ChannelType `json:"type"`
	// Target is the email address (email) or webhook URL (slack/discord/webhook).
	Target string `json:"target"`
	// Thresholds is a CSV of day-thresholds to alert on (e.g. "30,7,3"). Empty
	// means all default thresholds.
	Thresholds string    `json:"thresholds"`
	Enabled    bool      `json:"enabled"`
	CreatedAt  time.Time `json:"created_at"`
}

// WantsThreshold reports whether this channel should be notified at the given
// day-threshold. An empty Thresholds list means "all".
func (c *Channel) WantsThreshold(th int) bool {
	if strings.TrimSpace(c.Thresholds) == "" {
		return true
	}
	want := strconv.Itoa(th)
	for _, p := range strings.Split(c.Thresholds, ",") {
		if strings.TrimSpace(p) == want {
			return true
		}
	}
	return false
}

// Redacted returns a display-safe copy: webhook URLs are shortened so secrets
// in query strings are not echoed back to the UI/logs in full.
func (c *Channel) Redacted() Channel {
	cp := *c
	if c.Type != ChannelEmail && len(c.Target) > 40 {
		cp.Target = c.Target[:40] + "…"
	}
	return cp
}

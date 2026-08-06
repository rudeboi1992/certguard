package notify

import (
	"testing"
	"time"

	"github.com/bfalcher/certguard/internal/model"
)

func certExpiringIn(days, lastNotified int) *model.Cert {
	return &model.Cert{
		ExpiresAt:             time.Now().UTC().AddDate(0, 0, days),
		LastNotifiedThreshold: lastNotified,
	}
}

func TestCurrentThreshold(t *testing.T) {
	cases := map[int]int{
		-5: 3, 0: 3, 2: 3, 3: 3,
		4: 7, 7: 7,
		8: 30, 30: 30,
		31: -1, 90: -1,
	}
	for days, want := range cases {
		if got := CurrentThreshold(days); got != want {
			t.Errorf("CurrentThreshold(%d) = %d, want %d", days, got, want)
		}
	}
}

func TestNotificationEscalation(t *testing.T) {
	now := time.Now().UTC()

	// Never notified, 25 days out → notify at 30.
	if got := NotificationThreshold(certExpiringIn(25, 0), now); got != 30 {
		t.Errorf("first notice: got %d, want 30", got)
	}
	// Already notified at 30, still 25 days out → stay quiet.
	if got := NotificationThreshold(certExpiringIn(25, 30), now); got != -1 {
		t.Errorf("no re-notice at same level: got %d, want -1", got)
	}
	// Notified at 30, now 5 days out → escalate to 7.
	if got := NotificationThreshold(certExpiringIn(5, 30), now); got != 7 {
		t.Errorf("escalation to 7: got %d, want 7", got)
	}
	// Notified at 7, now 2 days out → escalate to 3.
	if got := NotificationThreshold(certExpiringIn(2, 7), now); got != 3 {
		t.Errorf("escalation to 3: got %d, want 3", got)
	}
	// Notified at 3, expired → already at most-urgent, stay quiet.
	if got := NotificationThreshold(certExpiringIn(-2, 3), now); got != -1 {
		t.Errorf("no re-notice after urgent: got %d, want -1", got)
	}
	// >30 days out, never notified → nothing.
	if got := NotificationThreshold(certExpiringIn(60, 0), now); got != -1 {
		t.Errorf("far future: got %d, want -1", got)
	}
}

func TestWantsThreshold(t *testing.T) {
	all := &model.Channel{Thresholds: ""}
	if !all.WantsThreshold(30) || !all.WantsThreshold(3) {
		t.Error("empty thresholds should want all")
	}
	only3 := &model.Channel{Thresholds: "3"}
	if only3.WantsThreshold(30) || !only3.WantsThreshold(3) {
		t.Error("'3' should want only 3")
	}
	multi := &model.Channel{Thresholds: "30, 7"}
	if !multi.WantsThreshold(7) || multi.WantsThreshold(3) {
		t.Error("'30, 7' should want 7 but not 3")
	}
}

// A domain registration must use the longer ladder. Thirty days is already late
// for a domain: transfer locks and billing disputes take weeks, and the
// recovery path after a lapse is redemption fees rather than a certbot run.
func TestDomainThresholdLadder(t *testing.T) {
	cases := []struct {
		days int
		want int
	}{
		{90, -1}, {61, -1}, {60, 60}, {45, 60}, {31, 60},
		{30, 30}, {8, 30},
		{7, 7}, {1, 7}, {0, 7}, {-5, 7}, // expired stays in the most urgent bucket
	}
	for _, c := range cases {
		if got := CurrentDomainThreshold(c.days); got != c.want {
			t.Errorf("CurrentDomainThreshold(%d) = %d, want %d", c.days, got, c.want)
		}
	}
}

// The ladder must be selected by kind, not applied globally: a certificate at
// 45 days is still quiet, while a domain at 45 days is already due.
func TestThresholdPicksLadderByKind(t *testing.T) {
	now := time.Now().UTC()
	at := func(days int) time.Time { return now.AddDate(0, 0, days) }

	cert := &model.Cert{Kind: model.KindEndpoint, ExpiresAt: at(45)}
	if got := NotificationThreshold(cert, now); got != -1 {
		t.Errorf("certificate at 45 days: got %d, want -1 (quiet)", got)
	}
	dom := &model.Cert{Kind: model.KindDomain, ExpiresAt: at(45)}
	if got := NotificationThreshold(dom, now); got != 60 {
		t.Errorf("domain at 45 days: got %d, want 60", got)
	}
	// And escalation still works within the domain ladder.
	dom2 := &model.Cert{Kind: model.KindDomain, ExpiresAt: at(20), LastNotifiedThreshold: 60}
	if got := NotificationThreshold(dom2, now); got != 30 {
		t.Errorf("domain escalating 60 -> 30: got %d, want 30", got)
	}
	// Already notified at the same level stays quiet.
	dom3 := &model.Cert{Kind: model.KindDomain, ExpiresAt: at(20), LastNotifiedThreshold: 30}
	if got := NotificationThreshold(dom3, now); got != -1 {
		t.Errorf("domain already notified at 30: got %d, want -1", got)
	}
}

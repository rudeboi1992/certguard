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

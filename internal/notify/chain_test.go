package notify

import (
	"strings"
	"testing"
	"time"

	"github.com/bfalcher/certguard/internal/model"
)

func at(n int) time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, n) }

func chainCert(leafDays, chainDays, lastChainThreshold int) *model.Cert {
	return &model.Cert{
		Name:                       "web",
		Host:                       "example.com",
		Port:                       443,
		ExpiresAt:                  at(leafDays),
		Chain:                      []model.ChainCert{{Subject: "CN=Some Intermediate", NotAfter: at(chainDays)}},
		LastChainNotifiedThreshold: lastChainThreshold,
	}
}

func TestChainThresholdSilentWhenChainOutlivesLeaf(t *testing.T) {
	c := chainCert(30, 400, 0)
	if th := ChainNotificationThreshold(c, at(0)); th != -1 {
		t.Errorf("threshold = %d, want -1 when the chain outlives the leaf", th)
	}
}

func TestChainThresholdFiresAndEscalates(t *testing.T) {
	// Chain gives out in 20 days, leaf in 300 — the leaf ladder puts 20 in the
	// 30-day bucket.
	c := chainCert(300, 20, 0)
	if th := ChainNotificationThreshold(c, at(0)); th != 30 {
		t.Fatalf("first alert = %d, want 30", th)
	}
	c.LastChainNotifiedThreshold = 30
	if th := ChainNotificationThreshold(c, at(0)); th != -1 {
		t.Errorf("repeat at same bucket = %d, want -1", th)
	}
	// 15 days later the chain is 5 days out, which is a more urgent bucket.
	if th := ChainNotificationThreshold(c, at(15)); th != 7 {
		t.Errorf("escalation = %d, want 7", th)
	}
}

func TestChainThresholdIndependentOfLeafState(t *testing.T) {
	// The leaf has already alerted all the way to 3 days. That must not silence
	// a chain warning — the two are different problems with different fixes.
	c := chainCert(300, 20, 0)
	c.LastNotifiedThreshold = 3
	if th := ChainNotificationThreshold(c, at(0)); th != 30 {
		t.Errorf("threshold = %d, want 30 despite leaf escalation state", th)
	}
}

func TestBuildChainMessageSaysWhatToDo(t *testing.T) {
	c := chainCert(300, 20, 0)
	m := BuildChainMessage(c, 30, at(0))
	if !strings.Contains(m.Subject, "chain certificate expires") {
		t.Errorf("subject does not name the problem: %q", m.Subject)
	}
	if !strings.Contains(m.Body, "CN=Some Intermediate") {
		t.Errorf("body does not name the at-risk link: %q", m.Body)
	}
	// The remedy differs from a leaf alert; reissuing alone may not fix it.
	if !strings.Contains(m.Body, "same intermediate") {
		t.Errorf("body does not warn that reissuing may return the same chain: %q", m.Body)
	}
	if m.Days != 20 {
		t.Errorf("Days = %d, want 20 (the chain's, not the leaf's)", m.Days)
	}
}

func TestBuildChainMessageFallsBackWhenNothingAtRisk(t *testing.T) {
	// Defensive: callers gate on the threshold, but this must not panic or
	// render nonsense if called anyway.
	c := chainCert(30, 400, 0)
	m := BuildChainMessage(c, 30, at(0))
	if m.Subject == "" || m.Body == "" {
		t.Error("fallback produced an empty message")
	}
}

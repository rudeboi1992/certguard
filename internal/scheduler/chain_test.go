package scheduler

import (
	"log"
	"strings"
	"testing"
	"time"

	"github.com/bfalcher/certguard/internal/model"
	"github.com/bfalcher/certguard/internal/scanner"
	"github.com/bfalcher/certguard/internal/store"
)

// scanWithChain stores an endpoint whose leaf is leafDays out and whose single
// intermediate is chainDays out.
func scanWithChain(t *testing.T, st *store.Store, name string, leafDays, chainDays int) *model.Cert {
	t.Helper()
	now := time.Now().UTC()
	c, err := st.UpsertScan(name, &scanner.Result{
		Host:      name,
		Port:      443,
		Subject:   "CN=" + name,
		SHA256:    "sha-" + name,
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.AddDate(0, 0, leafDays),
		Chain: []model.ChainCert{{
			Subject:  "CN=Intermediate for " + name,
			NotAfter: now.AddDate(0, 0, chainDays),
			SHA256:   "chain-" + name,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNotifyPassAlertsOnAChainThatExpiresFirst(t *testing.T) {
	st := newStore(t)
	u, _ := st.CreateUser("a@x.com", "hash", "admin")
	st.CreateChannel(u.ID, model.ChannelWebhook, "http://example/hook", "") // wants all
	// The certificate itself is nearly a year out — nothing about the leaf is
	// worth an alert. The chain under it gives out in 20 days.
	scanWithChain(t, st, "quiet.example.com", 300, 20)

	fs := &fakeSender{}
	s := New(st, fs, time.Hour, time.Second, log.New(&nopWriter{}, "", 0))

	if n := s.NotifyPass(time.Now().UTC()); n != 1 {
		t.Fatalf("sent=%d, want 1 — the chain alert is the whole point", n)
	}
	if len(fs.subjects) != 1 || !strings.Contains(fs.subjects[0], "chain certificate expires") {
		t.Fatalf("expected a chain alert, got %q", fs.subjects)
	}
	// Escalation state suppresses the repeat, exactly like the leaf path.
	if n := s.NotifyPass(time.Now().UTC()); n != 0 {
		t.Errorf("second pass sent=%d, want 0", n)
	}
}

func TestNotifyPassStaysQuietWhenTheChainOutlivesTheLeaf(t *testing.T) {
	st := newStore(t)
	u, _ := st.CreateUser("a@x.com", "hash", "admin")
	st.CreateChannel(u.ID, model.ChannelWebhook, "http://example/hook", "")
	// Leaf 300 days out, chain 900 — renewing the leaf will fetch a fresh
	// chain, so there is nothing to say. This is the false-positive guard.
	scanWithChain(t, st, "healthy.example.com", 300, 900)

	fs := &fakeSender{}
	s := New(st, fs, time.Hour, time.Second, log.New(&nopWriter{}, "", 0))
	if n := s.NotifyPass(time.Now().UTC()); n != 0 {
		t.Errorf("sent=%d, want 0 for a chain that outlives the leaf: %+v", n, fs.subjects)
	}
}

func TestNotifyPassSendsBothWhenLeafAndChainAreDue(t *testing.T) {
	st := newStore(t)
	u, _ := st.CreateUser("a@x.com", "hash", "admin")
	st.CreateChannel(u.ID, model.ChannelWebhook, "http://example/hook", "")
	// Both are inside a threshold, and the chain is the more urgent. Sharing a
	// single escalation counter would drop one of these on the floor.
	scanWithChain(t, st, "both.example.com", 25, 5)

	fs := &fakeSender{}
	s := New(st, fs, time.Hour, time.Second, log.New(&nopWriter{}, "", 0))
	if n := s.NotifyPass(time.Now().UTC()); n != 2 {
		t.Fatalf("sent=%d, want 2 (one leaf, one chain): %+v", n, fs.subjects)
	}
	var leaf, chain int
	for _, s := range fs.subjects {
		if strings.Contains(s, "chain certificate expires") {
			chain++
		} else {
			leaf++
		}
	}
	if leaf != 1 || chain != 1 {
		t.Errorf("got %d leaf and %d chain alerts, want 1 each: %+v", leaf, chain, fs.subjects)
	}
}

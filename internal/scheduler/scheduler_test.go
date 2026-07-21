package scheduler

import (
	"log"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/bfalcher/certguard/internal/model"
	"github.com/bfalcher/certguard/internal/notify"
	"github.com/bfalcher/certguard/internal/store"
)

// fakeSender records deliveries instead of sending them.
type fakeSender struct {
	mu   sync.Mutex
	sent []struct {
		ChannelID int64
		Threshold int
		CertName  string
	}
}

func (f *fakeSender) Send(ch *model.Channel, m notify.Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, struct {
		ChannelID int64
		Threshold int
		CertName  string
	}{ch.ID, m.Threshold, m.Cert.Name})
	return nil
}

func newStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open("sqlite", filepath.Join(t.TempDir(), "sched.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func addCert(t *testing.T, st *store.Store, name string, daysOut int) *model.Cert {
	t.Helper()
	c, err := st.AddCert(&model.Cert{
		Name:      name,
		Kind:      model.KindManual,
		ExpiresAt: time.Now().UTC().AddDate(0, 0, daysOut),
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNotifyPassEscalatesWithoutDuplicates(t *testing.T) {
	st := newStore(t)
	u, _ := st.CreateUser("a@x.com", "hash", "admin")
	st.CreateChannel(u.ID, model.ChannelWebhook, "http://example/hook", "") // wants all
	addCert(t, st, "soon.example.com", 20)                                   // 30-day bucket
	addCert(t, st, "far.example.com", 200)                                   // no notify

	fs := &fakeSender{}
	s := New(st, fs, time.Hour, time.Second, log.New(&nopWriter{}, "", 0))

	// First pass: notify the 20-day cert at threshold 30.
	if n := s.NotifyPass(time.Now().UTC()); n != 1 {
		t.Fatalf("first pass sent=%d, want 1", n)
	}
	// Second pass immediately after: state machine suppresses the duplicate.
	if n := s.NotifyPass(time.Now().UTC()); n != 0 {
		t.Fatalf("second pass sent=%d, want 0 (no duplicate)", n)
	}
	if len(fs.sent) != 1 || fs.sent[0].Threshold != 30 || fs.sent[0].CertName != "soon.example.com" {
		t.Fatalf("unexpected deliveries: %+v", fs.sent)
	}
}

func TestNotifyPassRespectsPerChannelThresholds(t *testing.T) {
	st := newStore(t)
	u, _ := st.CreateUser("a@x.com", "hash", "admin")
	// Channel only wants the 3-day (urgent) threshold.
	st.CreateChannel(u.ID, model.ChannelSlack, "http://example/slack", "3")
	addCert(t, st, "urgent.example.com", 2) // 3-day bucket

	fs := &fakeSender{}
	s := New(st, fs, time.Hour, time.Second, log.New(&nopWriter{}, "", 0))
	if n := s.NotifyPass(time.Now().UTC()); n != 1 {
		t.Fatalf("sent=%d, want 1", n)
	}

	// A cert in the 30-day bucket should NOT reach a 3-only channel.
	addCert(t, st, "notice.example.com", 25)
	fs2 := &fakeSender{}
	s2 := New(st, fs2, time.Hour, time.Second, log.New(&nopWriter{}, "", 0))
	s2.NotifyPass(time.Now().UTC())
	for _, d := range fs2.sent {
		if d.CertName == "notice.example.com" {
			t.Error("30-day cert was delivered to a 3-only channel")
		}
	}
}

func TestNotifyPassNoChannelsNoSend(t *testing.T) {
	st := newStore(t)
	addCert(t, st, "orphan.example.com", 1)
	fs := &fakeSender{}
	s := New(st, fs, time.Hour, time.Second, log.New(&nopWriter{}, "", 0))
	if n := s.NotifyPass(time.Now().UTC()); n != 0 {
		t.Errorf("sent=%d with no channels, want 0", n)
	}
}

type nopWriter struct{}

func (*nopWriter) Write(p []byte) (int, error) { return len(p), nil }

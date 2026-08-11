package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/bfalcher/certguard/internal/model"
	"github.com/bfalcher/certguard/internal/scanner"
)

func chainStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open("sqlite", filepath.Join(t.TempDir(), "chain.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func scanResult(chain []model.ChainCert, sha string) *scanner.Result {
	return &scanner.Result{
		Host:      "example.com",
		Port:      443,
		Subject:   "CN=example.com",
		SHA256:    sha,
		NotBefore: time.Now().Add(-time.Hour).UTC(),
		NotAfter:  time.Now().AddDate(1, 0, 0).UTC(),
		Chain:     chain,
	}
}

func TestChainRoundTrips(t *testing.T) {
	st := chainStore(t)
	notAfter := time.Now().AddDate(0, 0, 20).UTC().Truncate(time.Second)
	in := []model.ChainCert{{Subject: "CN=Intermediate A", Issuer: "CN=Root", NotAfter: notAfter, SHA256: "abc"}}

	c, err := st.UpsertScan("web", scanResult(in, "sha-1"))
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if len(c.Chain) != 1 {
		t.Fatalf("Chain has %d entries after insert, want 1", len(c.Chain))
	}
	if c.Chain[0].Subject != "CN=Intermediate A" || !c.Chain[0].NotAfter.Equal(notAfter) {
		t.Errorf("chain did not round-trip: %+v", c.Chain[0])
	}
	// And it is a real risk, since the leaf is a year out.
	if _, ok := c.ChainRisk(); !ok {
		t.Error("ChainRisk() false for an intermediate expiring well before the leaf")
	}
}

func TestChainEscalationResetsWhenTheChainChanges(t *testing.T) {
	st := chainStore(t)
	old := []model.ChainCert{{Subject: "CN=Old Intermediate", NotAfter: time.Now().AddDate(0, 0, 20).UTC()}}

	c, err := st.UpsertScan("web", scanResult(old, "sha-1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.MarkChainNotified(c.ID, 30); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.GetByID(c.ID); got.LastChainNotifiedThreshold != 30 {
		t.Fatalf("LastChainNotifiedThreshold = %d, want 30", got.LastChainNotifiedThreshold)
	}

	// Same leaf, same fingerprint — only the chain underneath swapped. The
	// warning must start over against the new link rather than stay silenced.
	fresh := []model.ChainCert{{Subject: "CN=New Intermediate", NotAfter: time.Now().AddDate(0, 0, 25).UTC()}}
	if _, err := st.UpsertScan("web", scanResult(fresh, "sha-1")); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetByID(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastChainNotifiedThreshold != 0 {
		t.Errorf("LastChainNotifiedThreshold = %d after a chain swap, want 0", got.LastChainNotifiedThreshold)
	}
	if len(got.Chain) != 1 || got.Chain[0].Subject != "CN=New Intermediate" {
		t.Errorf("stored chain not replaced: %+v", got.Chain)
	}
}

func TestChainEscalationSurvivesAnUnchangedRescan(t *testing.T) {
	st := chainStore(t)
	chain := []model.ChainCert{{Subject: "CN=Steady", NotAfter: time.Now().AddDate(0, 0, 20).UTC()}}

	c, err := st.UpsertScan("web", scanResult(chain, "sha-1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.MarkChainNotified(c.ID, 30); err != nil {
		t.Fatal(err)
	}
	// The 6-hourly sweep re-scans constantly; an unchanged chain must not reset
	// the counter, or every pass would re-alert.
	if _, err := st.UpsertScan("web", scanResult(chain, "sha-1")); err != nil {
		t.Fatal(err)
	}
	got, _ := st.GetByID(c.ID)
	if got.LastChainNotifiedThreshold != 30 {
		t.Errorf("LastChainNotifiedThreshold = %d after an unchanged rescan, want 30", got.LastChainNotifiedThreshold)
	}
}

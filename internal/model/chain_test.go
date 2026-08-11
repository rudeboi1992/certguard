package model

import (
	"testing"
	"time"
)

func day(n int) time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, n) }

func TestChainRiskIgnoresLinksOutlivingTheLeaf(t *testing.T) {
	c := &Cert{
		ExpiresAt: day(60),
		Chain: []ChainCert{
			{Subject: "CN=Intermediate", NotAfter: day(400)},
			{Subject: "CN=Cross-sign", NotAfter: day(900)},
		},
	}
	// Renewing the leaf on its own schedule fetches a fresh chain, so an
	// intermediate outliving it changes nothing and must stay silent.
	if risk, ok := c.ChainRisk(); ok {
		t.Errorf("ChainRisk() = %+v, true; want no risk when every link outlives the leaf", risk)
	}
}

func TestChainRiskPicksSoonestLinkBeforeTheLeaf(t *testing.T) {
	c := &Cert{
		ExpiresAt: day(60),
		Chain: []ChainCert{
			{Subject: "CN=Later", NotAfter: day(50)},
			{Subject: "CN=Soonest", NotAfter: day(20)},
			{Subject: "CN=Outlives", NotAfter: day(900)},
		},
	}
	risk, ok := c.ChainRisk()
	if !ok {
		t.Fatal("ChainRisk() = _, false; want the link expiring before the leaf")
	}
	if risk.Subject != "CN=Soonest" {
		t.Errorf("ChainRisk().Subject = %q, want CN=Soonest", risk.Subject)
	}
	days, ok := c.ChainDaysRemaining(day(0))
	if !ok || days != 20 {
		t.Errorf("ChainDaysRemaining = %d, %v; want 20, true", days, ok)
	}
}

func TestChainRiskSkipsZeroDates(t *testing.T) {
	// An entry stored before chains were captured has no dates; it must not be
	// read as "expires at the zero time", which would alert on everything.
	c := &Cert{
		ExpiresAt: day(60),
		Chain:     []ChainCert{{Subject: "CN=Unknown"}},
	}
	if risk, ok := c.ChainRisk(); ok {
		t.Errorf("ChainRisk() = %+v, true; want no risk from a zero NotAfter", risk)
	}
}

func TestChainRiskEmptyChain(t *testing.T) {
	c := &Cert{ExpiresAt: day(10)}
	if _, ok := c.ChainRisk(); ok {
		t.Error("ChainRisk() reported a risk with no chain at all")
	}
	if _, ok := c.ChainDaysRemaining(day(0)); ok {
		t.Error("ChainDaysRemaining reported a risk with no chain at all")
	}
}

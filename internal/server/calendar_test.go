package server

import (
	"strings"
	"testing"
	"time"

	"github.com/bfalcher/certguard/internal/model"
)

func TestBuildICS(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	certs := []*model.Cert{
		{ID: 1, Name: "Karakeep", Category: "service", ExpiresAt: time.Date(2026, 9, 15, 23, 59, 59, 0, time.UTC), Host: "bookmark.bri-10.com", Port: 443},
		{ID: 2, Name: "API key, prod", Category: "api-key", ExpiresAt: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)},
		{ID: 3, Name: "no-expiry"}, // zero ExpiresAt → skipped
	}
	out := buildICS(certs, now)

	if !strings.HasPrefix(out, "BEGIN:VCALENDAR\r\n") || !strings.HasSuffix(out, "END:VCALENDAR\r\n") {
		t.Fatal("missing calendar envelope / CRLF")
	}
	if n := strings.Count(out, "BEGIN:VEVENT"); n != 2 {
		t.Errorf("expected 2 events (zero-expiry skipped), got %d", n)
	}
	if !strings.Contains(out, "DTSTART;VALUE=DATE:20260915") {
		t.Error("expected all-day event on the expiry date")
	}
	if !strings.Contains(out, "SUMMARY:Karakeep expires") {
		t.Error("expected friendly-name summary with no type prefix")
	}
	if strings.Contains(out, "[service]") {
		t.Error("type prefix should not appear in the calendar summary")
	}
	// comma in a name must be escaped per RFC 5545
	if !strings.Contains(out, `API key\, prod`) {
		t.Error("expected comma in name to be escaped")
	}
	if !strings.Contains(out, "TRIGGER:-P7D") {
		t.Error("expected a 7-day reminder alarm")
	}
}

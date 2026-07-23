package server

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bfalcher/certguard/internal/model"
)

// writeICS sends entries as a downloadable iCalendar (.ics) file — the format
// Apple Calendar, Google Calendar, and Outlook all import.
func writeICS(w http.ResponseWriter, filename string, certs []*model.Cert) {
	w.Header().Set("Content-Type", "text/calendar; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	_, _ = w.Write([]byte(buildICS(certs, time.Now().UTC())))
}

// buildICS renders a VCALENDAR with one all-day VEVENT per entry on its expiry
// date, each carrying a 7-day-ahead reminder. Lines use CRLF per RFC 5545.
func buildICS(certs []*model.Cert, now time.Time) string {
	var b strings.Builder
	line := func(s string) { b.WriteString(s); b.WriteString("\r\n") }

	line("BEGIN:VCALENDAR")
	line("VERSION:2.0")
	line("PRODID:-//certguard//expiry tracker//EN")
	line("CALSCALE:GREGORIAN")
	line("METHOD:PUBLISH")
	line("X-WR-CALNAME:certguard expirations")

	stamp := now.Format("20060102T150405Z")
	for _, c := range certs {
		if c.ExpiresAt.IsZero() {
			continue
		}
		day := c.ExpiresAt.UTC().Format("20060102")
		next := c.ExpiresAt.UTC().AddDate(0, 0, 1).Format("20060102")

		summary := icsEscape(c.Name) + " expires"
		if c.Category != "" {
			summary = "[" + icsEscape(c.Category) + "] " + summary
		}
		desc := "Tracked by certguard."
		if c.Host != "" {
			desc = icsEscape(fmt.Sprintf("%s:%d", c.Host, c.Port)) + " — " + desc
		}

		line("BEGIN:VEVENT")
		line("UID:certguard-" + fmt.Sprintf("%d", c.ID) + "@certguard")
		line("DTSTAMP:" + stamp)
		line("DTSTART;VALUE=DATE:" + day)
		line("DTEND;VALUE=DATE:" + next)
		line("SUMMARY:" + summary)
		line("DESCRIPTION:" + desc)
		line("TRANSP:TRANSPARENT")
		line("BEGIN:VALARM")
		line("TRIGGER:-P7D")
		line("ACTION:DISPLAY")
		line("DESCRIPTION:" + summary + " in 7 days")
		line("END:VALARM")
		line("END:VEVENT")
	}
	line("END:VCALENDAR")
	return b.String()
}

// icsEscape escapes the characters that are special in iCalendar text values.
func icsEscape(s string) string {
	return strings.NewReplacer(
		`\`, `\\`,
		`;`, `\;`,
		`,`, `\,`,
		"\n", `\n`,
	).Replace(s)
}

package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/bfalcher/certguard/internal/config"
	"github.com/bfalcher/certguard/internal/model"
)

// Message is a rendered notification for one cert at one threshold.
type Message struct {
	Cert      *model.Cert
	Threshold int
	Days      int
	Subject   string
	Body      string
}

// BuildMessage renders a Message for a cert/threshold.
func BuildMessage(c *model.Cert, threshold int, now time.Time) Message {
	days := c.DaysRemaining(now)
	urgency := UrgencyLabel(threshold)
	when := "in " + itoa(days) + " days"
	if days < 0 {
		when = "expired " + itoa(-days) + " days ago"
	} else if days == 0 {
		when = "today"
	}
	subject := fmt.Sprintf("[certguard %s] %s expires %s", urgency, c.Name, when)
	body := fmt.Sprintf(
		"Certificate: %s\nExpires: %s (%s)\nUrgency: %s\n",
		c.Name, c.ExpiresAt.Format("2006-01-02"), when, urgency)
	if c.Host != "" {
		body += fmt.Sprintf("Endpoint: %s:%d\n", c.Host, c.Port)
	}
	if c.Issuer != "" {
		body += "Issuer: " + c.Issuer + "\n"
	}
	body += "\nRenew or replace it before it expires."
	return Message{Cert: c, Threshold: threshold, Days: days, Subject: subject, Body: body}
}

// BuildChainMessage renders the alert for an intermediate that expires before
// the leaf does.
//
// It is worded differently from BuildMessage on purpose. "Renew this
// certificate" is the wrong instruction here: the leaf is fine, and reissuing
// it from the same CA can hand back the very same expiring intermediate. What
// the operator has to do is get a chain that no longer includes this link,
// which is a conversation with the CA, not a cron job.
func BuildChainMessage(c *model.Cert, threshold int, now time.Time) Message {
	risk, ok := c.ChainRisk()
	if !ok {
		// Nothing at risk — render the ordinary message rather than something
		// nonsensical. Callers gate on ChainNotificationThreshold, so this is
		// defensive only.
		return BuildMessage(c, threshold, now)
	}
	days, _ := c.ChainDaysRemaining(now)
	urgency := UrgencyLabel(threshold)
	when := "in " + itoa(days) + " days"
	if days < 0 {
		when = "expired " + itoa(-days) + " days ago"
	} else if days == 0 {
		when = "today"
	}
	subject := fmt.Sprintf("[certguard %s] %s: chain certificate expires %s", urgency, c.Name, when)
	body := fmt.Sprintf(
		"Entry: %s\nThe certificate itself is valid until %s, but an intermediate in the chain it serves expires sooner.\n\n"+
			"Intermediate: %s\nChain expires: %s (%s)\nUrgency: %s\n",
		c.Name, c.ExpiresAt.Format("2006-01-02"),
		risk.Subject, risk.NotAfter.Format("2006-01-02"), when, urgency)
	if c.Host != "" {
		body += fmt.Sprintf("Endpoint: %s:%d\n", c.Host, c.Port)
	}
	body += "\nClients will fail to build a trust path once this link expires, even though the certificate is still in date. " +
		"Reissuing from the same CA may return the same intermediate — ask for a chain that does not include it, and redeploy the full chain."
	return Message{Cert: c, Threshold: threshold, Days: days, Subject: subject, Body: body}
}

// Sender delivers a rendered message to one channel.
type Sender interface {
	Send(ch *model.Channel, m Message) error
}

// RealSender delivers via SMTP and HTTP.
type RealSender struct {
	Mail   config.MailConfig
	Client *http.Client
}

// NewRealSender builds a RealSender with a bounded HTTP client. When
// allowPrivate is false the client refuses to connect to private, loopback, or
// link-local addresses, so a user-supplied webhook URL cannot be turned into a
// request against the server's own network.
func NewRealSender(mail config.MailConfig, allowPrivate bool) *RealSender {
	return &RealSender{
		Mail:   mail,
		Client: &http.Client{Timeout: 10 * time.Second, Transport: safeHTTPTransport(allowPrivate)},
	}
}

func (s *RealSender) Send(ch *model.Channel, m Message) error {
	switch ch.Type {
	case model.ChannelEmail:
		return s.sendEmail(ch.Target, m)
	case model.ChannelSlack:
		return s.postJSON(ch.Target, map[string]any{"text": slackText(m), "mrkdwn": true})
	case model.ChannelDiscord:
		return s.postJSON(ch.Target, map[string]any{"content": discordText(m)})
	case model.ChannelWebhook:
		return s.postJSON(ch.Target, genericPayload(m))
	default:
		return fmt.Errorf("unknown channel type %q", ch.Type)
	}
}

func (s *RealSender) sendEmail(to string, m Message) error {
	if s.Mail.Host == "" || s.Mail.User == "" {
		return fmt.Errorf("email not configured (set CERTGUARD_MAIL_HOST and CERTGUARD_MAIL_USER)")
	}
	from := s.Mail.From
	if from == "" {
		from = s.Mail.User
	}
	addr := fmt.Sprintf("%s:%d", s.Mail.Host, s.Mail.Port)
	auth := smtp.PlainAuth("", s.Mail.User, s.Mail.Pass, s.Mail.Host)
	// Backstop against header injection: the Subject carries the entry name,
	// and a name containing a CR or LF would otherwise smuggle extra headers
	// into the message. Callers sanitize on write, but a value reaching here
	// from any other path must not be trusted to be single-line.
	subject := headerSafe(m.Subject)
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\n"+
		"Content-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n",
		from, to, subject, m.Body)
	return smtp.SendMail(addr, auth, from, []string{to}, []byte(msg))
}

// headerSafe strips CR and LF so a value cannot terminate one header and start
// another when placed in a message header line.
func headerSafe(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

func (s *RealSender) postJSON(url string, payload any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return nil
}

func slackText(m Message) string {
	return fmt.Sprintf("%s *[%s]* %s — expires *%s* (%d days)",
		UrgencyEmoji(m.Threshold), UrgencyLabel(m.Threshold), m.Cert.Name,
		m.Cert.ExpiresAt.Format("2006-01-02"), m.Days)
}

func discordText(m Message) string {
	return fmt.Sprintf("%s **[%s]** %s — expires **%s** (%d days)",
		UrgencyEmoji(m.Threshold), UrgencyLabel(m.Threshold), m.Cert.Name,
		m.Cert.ExpiresAt.Format("2006-01-02"), m.Days)
}

func genericPayload(m Message) map[string]any {
	return map[string]any{
		"event":          "cert_expiry_warning",
		"name":           m.Cert.Name,
		"expires_at":     m.Cert.ExpiresAt.Format(time.RFC3339),
		"days_remaining": m.Days,
		"threshold":      m.Threshold,
		"urgency":        UrgencyLabel(m.Threshold),
		"host":           m.Cert.Host,
		"sha256":         m.Cert.SHA256,
	}
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }

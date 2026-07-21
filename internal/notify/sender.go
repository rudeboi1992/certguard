package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
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

// Sender delivers a rendered message to one channel.
type Sender interface {
	Send(ch *model.Channel, m Message) error
}

// RealSender delivers via SMTP and HTTP.
type RealSender struct {
	Mail   config.MailConfig
	Client *http.Client
}

// NewRealSender builds a RealSender with a bounded HTTP client.
func NewRealSender(mail config.MailConfig) *RealSender {
	return &RealSender{Mail: mail, Client: &http.Client{Timeout: 10 * time.Second}}
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
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\n"+
		"Content-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n",
		from, to, m.Subject, m.Body)
	return smtp.SendMail(addr, auth, from, []string{to}, []byte(msg))
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

package notify

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bfalcher/certguard/internal/config"
	"github.com/bfalcher/certguard/internal/model"
)

func captureServer(t *testing.T, out *[]byte, ct *string) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		*out = b
		*ct = r.Header.Get("Content-Type")
		w.WriteHeader(200)
	}))
	t.Cleanup(s.Close)
	return s
}

func sampleMsg() Message {
	c := &model.Cert{Name: "api.example.com", ExpiresAt: time.Now().UTC().AddDate(0, 0, 2), Host: "api.example.com", Port: 443, SHA256: "abc"}
	return BuildMessage(c, 3, time.Now().UTC())
}

func TestRealSenderGenericWebhook(t *testing.T) {
	var body []byte
	var ct string
	srv := captureServer(t, &body, &ct)
	s := NewRealSender(config.MailConfig{}, true)

	err := s.Send(&model.Channel{Type: model.ChannelWebhook, Target: srv.URL}, sampleMsg())
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if ct != "application/json" {
		t.Errorf("content-type = %q", ct)
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("payload not JSON: %v", err)
	}
	if payload["event"] != "cert_expiry_warning" || payload["name"] != "api.example.com" {
		t.Errorf("unexpected payload: %v", payload)
	}
	if payload["urgency"] != "URGENT" {
		t.Errorf("urgency = %v, want URGENT", payload["urgency"])
	}
}

func TestRealSenderSlackAndDiscordShape(t *testing.T) {
	for _, tc := range []struct {
		typ model.ChannelType
		key string
	}{
		{model.ChannelSlack, "text"},
		{model.ChannelDiscord, "content"},
	} {
		var body []byte
		var ct string
		srv := captureServer(t, &body, &ct)
		s := NewRealSender(config.MailConfig{}, true)
		if err := s.Send(&model.Channel{Type: tc.typ, Target: srv.URL}, sampleMsg()); err != nil {
			t.Fatalf("%s send: %v", tc.typ, err)
		}
		var payload map[string]any
		json.Unmarshal(body, &payload)
		text, _ := payload[tc.key].(string)
		if text == "" {
			t.Errorf("%s: missing %q field in %v", tc.typ, tc.key, payload)
		}
	}
}

func TestRealSenderWebhookErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	s := NewRealSender(config.MailConfig{}, true)
	if err := s.Send(&model.Channel{Type: model.ChannelWebhook, Target: srv.URL}, sampleMsg()); err == nil {
		t.Error("expected error on 500 response")
	}
}

func TestRealSenderEmailUnconfigured(t *testing.T) {
	s := NewRealSender(config.MailConfig{}, true) // no host/user
	if err := s.Send(&model.Channel{Type: model.ChannelEmail, Target: "x@y.com"}, sampleMsg()); err == nil {
		t.Error("expected error when email is unconfigured")
	}
}

func TestHeaderSafeStripsCRLF(t *testing.T) {
	got := headerSafe("Renew soon\r\nBcc: victim@evil.com")
	if got != "Renew soonBcc: victim@evil.com" {
		t.Errorf("headerSafe left a line break in: %q", got)
	}
	if got := headerSafe("normal subject"); got != "normal subject" {
		t.Errorf("headerSafe altered a clean subject: %q", got)
	}
}

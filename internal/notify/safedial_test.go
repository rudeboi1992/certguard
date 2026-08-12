package notify

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"

	"github.com/bfalcher/certguard/internal/config"
	"github.com/bfalcher/certguard/internal/model"
)

func TestIsPublicIPRejectsInternalRanges(t *testing.T) {
	blocked := []string{
		"127.0.0.1",       // loopback
		"::1",             // loopback v6
		"10.1.2.3",        // RFC1918
		"192.168.1.1",     // RFC1918
		"172.16.0.1",      // RFC1918
		"169.254.169.254", // link-local / cloud metadata
		"100.64.0.1",      // CGNAT
		"0.0.0.0",         // unspecified
		"fc00::1",         // ULA
		"fe80::1",         // link-local v6
	}
	for _, s := range blocked {
		if isPublicIP(net.ParseIP(s)) {
			t.Errorf("%s treated as public, want blocked", s)
		}
	}

	public := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"}
	for _, s := range public {
		if !isPublicIP(net.ParseIP(s)) {
			t.Errorf("%s treated as internal, want public", s)
		}
	}
}

func TestSafeControlBlocksInternalDial(t *testing.T) {
	// This is what the Dialer invokes with the concrete post-resolution address,
	// so it is where DNS rebinding would otherwise slip through.
	if err := safeControl("tcp", "169.254.169.254:80", noConn()); err == nil {
		t.Error("safeControl allowed the cloud metadata address")
	} else if !strings.Contains(err.Error(), "blocked") {
		t.Errorf("unexpected error text: %v", err)
	}
	if err := safeControl("tcp", "8.8.8.8:443", noConn()); err != nil {
		t.Errorf("safeControl blocked a public address: %v", err)
	}
}

// noConn is a nil RawConn; safeControl never touches it.
func noConn() syscall.RawConn { return nil }

func TestSenderBlocksLoopbackWebhookByDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	// Default (no private allowed): the loopback test server must be refused,
	// which is the whole point — a user's webhook cannot reach 127.0.0.1.
	blocked := NewRealSender(config.MailConfig{}, false)
	err := blocked.Send(&model.Channel{Type: model.ChannelWebhook, Target: srv.URL}, sampleMsg())
	if err == nil {
		t.Fatal("loopback webhook was delivered; SSRF guard did not fire")
	}
	if !strings.Contains(err.Error(), "blocked") {
		t.Errorf("error should explain the block, got: %v", err)
	}

	// Opt-in: the same target succeeds, for operators who genuinely notify an
	// internal endpoint.
	allowed := NewRealSender(config.MailConfig{}, true)
	if err := allowed.Send(&model.Channel{Type: model.ChannelWebhook, Target: srv.URL}, sampleMsg()); err != nil {
		t.Errorf("with private allowed, delivery failed: %v", err)
	}
}

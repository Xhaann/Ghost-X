package socket

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/websocket"
)

func TestUpgradeRequiresHandshake(t *testing.T) {
	hub := NewHub(testOptions())
	srv := httptest.NewServer(NewHandler(hub, nil))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	if got := hub.Len(); got != 0 {
		t.Errorf("Len() = %d, want 0", got)
	}
}

func TestUpgradeRejectsForeignOrigin(t *testing.T) {
	hub, url := startServer(t, testOptions(), "http://allowed.test")

	header := http.Header{"Origin": {"http://other.test"}}
	_, resp, err := websocket.DefaultDialer.Dial(url, header)
	if err == nil {
		t.Fatal("dial succeeded with foreign origin")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("response = %v, want status %d", resp, http.StatusForbidden)
	}
	resp.Body.Close()
	if got := hub.Len(); got != 0 {
		t.Errorf("Len() = %d, want 0", got)
	}
}

func TestUpgradeAcceptsAllowedOrigin(t *testing.T) {
	hub, url := startServer(t, testOptions(), "http://allowed.test")

	header := http.Header{"Origin": {"http://ALLOWED.test"}}
	conn, resp, err := websocket.DefaultDialer.Dial(url, header)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	resp.Body.Close()
	defer conn.Close()
	onlyClient(t, hub)
}

func TestOriginChecker(t *testing.T) {
	check := originChecker([]string{"https://app.test"})
	tests := []struct {
		origin string
		host   string
		want   bool
	}{
		{"", "api.test", true},
		{"https://api.test", "api.test", true},
		{"https://app.test", "api.test", true},
		{"http://app.test", "api.test", false},
		{"https://evil.test", "api.test", false},
		{"null", "api.test", false},
		{"://bad", "api.test", false},
	}

	for _, tt := range tests {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Host = tt.host
		if tt.origin != "" {
			r.Header.Set("Origin", tt.origin)
		}
		if got := check(r); got != tt.want {
			t.Errorf("origin %q host %q = %v, want %v", tt.origin, tt.host, got, tt.want)
		}
	}
}

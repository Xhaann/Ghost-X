package config

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("SERVER_ADDR", "")
	t.Setenv("SHUTDOWN_TIMEOUT", "")
	t.Setenv("ALLOWED_ORIGINS", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Addr != defaultAddr {
		t.Errorf("Addr = %q, want %q", cfg.Addr, defaultAddr)
	}
	if cfg.ShutdownTimeout != defaultShutdownTimeout {
		t.Errorf("ShutdownTimeout = %v, want %v", cfg.ShutdownTimeout, defaultShutdownTimeout)
	}
	if cfg.AllowedOrigins != nil {
		t.Errorf("AllowedOrigins = %v, want nil", cfg.AllowedOrigins)
	}
}

func TestLoadFromEnv(t *testing.T) {
	t.Setenv("SERVER_ADDR", "127.0.0.1:9000")
	t.Setenv("SHUTDOWN_TIMEOUT", "3s")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Addr != "127.0.0.1:9000" {
		t.Errorf("Addr = %q, want %q", cfg.Addr, "127.0.0.1:9000")
	}
	if cfg.ShutdownTimeout != 3*time.Second {
		t.Errorf("ShutdownTimeout = %v, want %v", cfg.ShutdownTimeout, 3*time.Second)
	}
}

func TestLoadInvalid(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		timeout string
	}{
		{"addr without port", "localhost", ""},
		{"unparseable timeout", "", "soon"},
		{"zero timeout", "", "0s"},
		{"negative timeout", "", "-1s"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("SERVER_ADDR", tt.addr)
			t.Setenv("SHUTDOWN_TIMEOUT", tt.timeout)

			if _, err := Load(); err == nil {
				t.Fatal("Load() error = nil, want error")
			}
		})
	}
}

func TestLoadAllowedOrigins(t *testing.T) {
	t.Setenv("ALLOWED_ORIGINS", " http://localhost:3000 ,https://example.com/,")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := []string{"http://localhost:3000", "https://example.com"}
	if !slices.Equal(cfg.AllowedOrigins, want) {
		t.Errorf("AllowedOrigins = %v, want %v", cfg.AllowedOrigins, want)
	}
}

func TestLoadInvalidOrigins(t *testing.T) {
	for _, v := range []string{"localhost:3000", "ftp://example.com", "https://example.com/path", "https://", "https://a@example.com"} {
		t.Run(v, func(t *testing.T) {
			t.Setenv("ALLOWED_ORIGINS", v)
			if _, err := Load(); err == nil {
				t.Fatal("Load() error = nil, want error")
			}
		})
	}
}

func TestLoadDeviceStore(t *testing.T) {
	t.Setenv("DEVICE_STORE", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	dir, _ := os.UserConfigDir()
	if cfg.DeviceStore != filepath.Join(dir, "ghostx", "devices.json") {
		t.Errorf("DeviceStore = %q", cfg.DeviceStore)
	}
	path := filepath.Join(t.TempDir(), "devices.json")
	t.Setenv("DEVICE_STORE", path)
	if cfg, err := Load(); err != nil || cfg.DeviceStore != path {
		t.Fatalf("DeviceStore = %q, %v", cfg.DeviceStore, err)
	}
	t.Setenv("DEVICE_STORE", "relative/devices.json")
	if _, err := Load(); err == nil {
		t.Fatal("relative device store accepted")
	}
}

func TestLoadLocalSocket(t *testing.T) {
	t.Setenv("LOCAL_SOCKET", "")
	if cfg, err := Load(); err != nil || cfg.LocalSocket != "" {
		t.Fatalf("LocalSocket = %q, %v", cfg.LocalSocket, err)
	}
	path := filepath.Join(t.TempDir(), "ghostx.sock")
	t.Setenv("LOCAL_SOCKET", path)
	if cfg, err := Load(); err != nil || cfg.LocalSocket != path {
		t.Fatalf("LocalSocket = %q, %v", cfg.LocalSocket, err)
	}
	t.Setenv("LOCAL_SOCKET", "relative.sock")
	if _, err := Load(); err == nil {
		t.Fatal("relative local socket accepted")
	}
}

func TestLoadAuthTimeout(t *testing.T) {
	t.Setenv("AUTH_TIMEOUT", "")
	if cfg, err := Load(); err != nil || cfg.AuthTimeout != DefaultAuthTimeout {
		t.Fatalf("AuthTimeout = %v, %v", cfg.AuthTimeout, err)
	}
	t.Setenv("AUTH_TIMEOUT", "15s")
	if cfg, err := Load(); err != nil || cfg.AuthTimeout != 15*time.Second {
		t.Fatalf("AuthTimeout = %v, %v", cfg.AuthTimeout, err)
	}
	for _, v := range []string{"soon", "0s", "-1s", "10"} {
		t.Setenv("AUTH_TIMEOUT", v)
		if _, err := Load(); err == nil {
			t.Fatalf("AUTH_TIMEOUT %q accepted", v)
		}
	}
}

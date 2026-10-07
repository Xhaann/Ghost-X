package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultAddr            = ":8080"
	defaultShutdownTimeout = 10 * time.Second
)

type Config struct {
	Addr            string
	ShutdownTimeout time.Duration
	AllowedOrigins  []string
	DeviceStore     string
}

func Load() (Config, error) {
	cfg := Config{
		Addr:            defaultAddr,
		ShutdownTimeout: defaultShutdownTimeout,
	}

	if v, ok := os.LookupEnv("SERVER_ADDR"); ok && v != "" {
		if _, _, err := net.SplitHostPort(v); err != nil {
			return Config{}, fmt.Errorf("invalid SERVER_ADDR %q: %w", v, err)
		}
		cfg.Addr = v
	}

	if v, ok := os.LookupEnv("SHUTDOWN_TIMEOUT"); ok && v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return Config{}, fmt.Errorf("invalid SHUTDOWN_TIMEOUT %q: %w", v, err)
		}
		if d <= 0 {
			return Config{}, fmt.Errorf("invalid SHUTDOWN_TIMEOUT %q: must be positive", v)
		}
		cfg.ShutdownTimeout = d
	}

	if v, ok := os.LookupEnv("DEVICE_STORE"); ok && v != "" {
		if !filepath.IsAbs(v) {
			return Config{}, fmt.Errorf("invalid DEVICE_STORE %q: must be an absolute path", v)
		}
		cfg.DeviceStore = v
	} else {
		dir, err := os.UserConfigDir()
		if err != nil {
			return Config{}, fmt.Errorf("resolve device store: %w", err)
		}
		cfg.DeviceStore = filepath.Join(dir, "ghostx", "devices.json")
	}

	if v, ok := os.LookupEnv("ALLOWED_ORIGINS"); ok && v != "" {
		origins, err := parseOrigins(v)
		if err != nil {
			return Config{}, fmt.Errorf("invalid ALLOWED_ORIGINS: %w", err)
		}
		cfg.AllowedOrigins = origins
	}

	return cfg, nil
}

func parseOrigins(v string) ([]string, error) {
	var origins []string
	for _, raw := range strings.Split(v, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil {
			return nil, err
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return nil, fmt.Errorf("%q: scheme must be http or https", raw)
		}
		if u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("%q: must be scheme and host only", raw)
		}
		origins = append(origins, u.Scheme+"://"+u.Host)
	}
	return origins, nil
}

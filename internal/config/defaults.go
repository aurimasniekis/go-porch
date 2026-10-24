package config

import "time"

// CloudflareIPRanges are Cloudflare's published edge ranges (https://www.cloudflare.com/ips/, retrieved 2026-10).
// Operators should refresh them; Porch only trusts CF-Connecting-IP from these peers.
var CloudflareIPRanges = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
	"190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
}

// Default returns the default configuration (production mode; public_url and kek.file must still be set).
func Default() *Config {
	return &Config{
		Mode:    ModeProduction,
		DataDir: "/var/lib/porch",
		KEK:     KEKConfig{Source: "file"},
		HTTP: HTTPConfig{
			Listen:            "127.0.0.1:8080",
			ReadHeaderTimeout: Duration(10 * time.Second),
			ReadTimeout:       Duration(30 * time.Second),
			WriteTimeout:      Duration(60 * time.Second),
			IdleTimeout:       Duration(120 * time.Second),
			MaxHeaderBytes:    32 << 10,
			MaxBodyBytes:      1 << 20,
		},
		Management: ManagementConfig{Listen: "127.0.0.1:9464"},
		Proxy:      ProxyConfig{CloudflareRanges: CloudflareIPRanges},
		Log:        LogConfig{Level: "info", Format: "json"},
		Storage:    StorageConfig{PreMigrationSnapshots: 3},
		Session: SessionConfig{
			Idle:            Duration(8 * time.Hour),
			Absolute:        Duration(12 * time.Hour),
			StepUpWindow:    Duration(5 * time.Minute),
			UpstreamRecheck: Duration(time.Hour),
			SetupAbsolute:   Duration(time.Hour),
		},
		Setup: SetupConfig{TokenTTL: Duration(time.Hour)},
	}
}

// Package config loads and validates Porch configuration.
//
// Configuration comes from a YAML file plus PORCH_* environment overrides. Unknown keys are rejected. The runtime mode
// is "production" unless explicitly set to "development"; development-only conveniences are rejected in production.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"go.yaml.in/yaml/v3"
)

// Mode is the runtime mode.
type Mode string

// Runtime modes.
const (
	ModeProduction  Mode = "production"
	ModeDevelopment Mode = "development"
)

// Duration is a time.Duration that unmarshals from Go duration strings ("30s", "15m").
type Duration time.Duration

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return fmt.Errorf("line %d: duration must be a string like \"30s\": %w", n.Line, err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*d = Duration(v)
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

// Config is the complete Porch configuration.
type Config struct {
	Mode        Mode              `yaml:"mode"`
	DataDir     string            `yaml:"data_dir"`
	PublicURL   string            `yaml:"public_url"`
	KEK         KEKConfig         `yaml:"kek"`
	HTTP        HTTPConfig        `yaml:"http"`
	Management  ManagementConfig  `yaml:"management"`
	Proxy       ProxyConfig       `yaml:"proxy"`
	Log         LogConfig         `yaml:"log"`
	Storage     StorageConfig     `yaml:"storage"`
	Session     SessionConfig     `yaml:"session"`
	Setup       SetupConfig       `yaml:"setup"`
	BackupLogin BackupLoginConfig `yaml:"backup_login"`
	Backup      BackupConfig      `yaml:"backup"`
	Events      EventsConfig      `yaml:"events"`
	Outbound    OutboundConfig    `yaml:"outbound"`
	Authz       AuthzConfig       `yaml:"authz"`
	Forward     ForwardAuthConfig `yaml:"forward_auth"`
}

// AuthzConfig configures the authorization engine (ADR-0011).
type AuthzConfig struct {
	// TrustedNetworks are CIDRs reported to policies as context.network == "trusted" (e.g. the home LAN).
	TrustedNetworks []string `yaml:"trusted_networks"`
}

// ForwardAuthConfig configures the forward-auth outpost (ADR-0015).
type ForwardAuthConfig struct {
	// TrustedPeers may call /outpost/auth (the reverse proxies). Empty means proxy.trusted_proxies plus loopback.
	TrustedPeers []string `yaml:"trusted_peers"`
	// SessionTTL bounds a per-application forward-auth session (it also never outlives the Porch session).
	SessionTTL Duration `yaml:"session_ttl"`
}

// EventsConfig configures domain-event delivery (ADR-0019).
type EventsConfig struct {
	Pulse PulseConfig `yaml:"pulse"`
}

// PulseConfig connects the outbox relay to pulse (NATS JetStream).
type PulseConfig struct {
	Enabled bool `yaml:"enabled"`
	// URL of the pulse NATS endpoint, e.g. tls://events.example.com:4222.
	URL string `yaml:"url"`
	// CredsFile is the pulse client .creds file (issued by pulsed for this publisher).
	CredsFile string `yaml:"creds_file"`
	// CAFile trusts an extra CA for the NATS TLS certificate.
	CAFile string `yaml:"ca_file"`
	// Source is the CloudEvents source of published events.
	Source string `yaml:"source"`
}

// BackupConfig configures encrypted backups to S3-compatible storage (ADR-0042).
type BackupConfig struct {
	Enabled bool `yaml:"enabled"`
	// Interval between scheduled backups (also the recovery point objective).
	Interval Duration `yaml:"interval"`
	// Retention is the number of complete backups kept; older ones are deleted after a successful backup.
	Retention int `yaml:"retention"`
	// Recipients are age X25519 public keys (age1…). The matching identities stay offline: Porch can write backups but
	// cannot read them.
	Recipients []string `yaml:"recipients"`
	// ExcludeKEK leaves the KEK out of backups (it must then be kept and restored separately).
	ExcludeKEK bool           `yaml:"exclude_kek"`
	S3         BackupS3Config `yaml:"s3"`
}

// BackupS3Config locates the bucket.
type BackupS3Config struct {
	Endpoint            string `yaml:"endpoint"` // host[:port]
	Bucket              string `yaml:"bucket"`
	Prefix              string `yaml:"prefix"`
	Region              string `yaml:"region"`
	AccessKeyID         string `yaml:"access_key_id"`
	SecretAccessKey     string `yaml:"secret_access_key"` // prefer PORCH_BACKUP_S3_SECRET_ACCESS_KEY or the file
	SecretAccessKeyFile string `yaml:"secret_access_key_file"`
	// Lookup is auto, path or virtual (bucket addressing style).
	Lookup string `yaml:"lookup"`
	CAFile string `yaml:"ca_file"`
	// Insecure uses plain HTTP (development only).
	Insecure     bool `yaml:"insecure"`
	CreateBucket bool `yaml:"create_bucket"`
}

// BackupLoginConfig configures the local backup login (ADR-0008).
type BackupLoginConfig struct {
	// Disabled turns backup login off for everyone. Porch logs a warning at startup when set.
	Disabled        bool     `yaml:"disabled"`
	Threshold       int      `yaml:"threshold"`
	LockDuration    Duration `yaml:"lock_duration"`
	MaxLockDuration Duration `yaml:"max_lock_duration"`
	SourceLimit     int      `yaml:"source_limit"`
	SourceWindow    Duration `yaml:"source_window"`
	CircuitLimit    int      `yaml:"circuit_limit"`
	CircuitWindow   Duration `yaml:"circuit_window"`
	MinPairs        int      `yaml:"min_pairs"`
	MaxPairs        int      `yaml:"max_pairs"`
}

// OutboundConfig controls outbound connections (SSRF guard).
type OutboundConfig struct {
	// AllowCIDRs are internal destinations Porch may connect to (e.g. a LAN identity provider or MinIO).
	AllowCIDRs []string `yaml:"allow_cidrs"`
}

// KEKConfig locates the master key-encryption key (ADR-0003).
type KEKConfig struct {
	// Source is "file" (default) or "env" (reads base64 from PORCH_KEK; discouraged).
	Source string `yaml:"source"`
	File   string `yaml:"file"`
}

// HTTPConfig configures the public listener.
type HTTPConfig struct {
	Listen      string `yaml:"listen"`
	TLSCertFile string `yaml:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file"`
	// ClientCAFile, when set with TLS, requires and verifies client certificates (Cloudflare Authenticated Origin
	// Pulls: the Cloudflare origin-pull CA).
	ClientCAFile      string   `yaml:"client_ca_file"`
	ReadHeaderTimeout Duration `yaml:"read_header_timeout"`
	ReadTimeout       Duration `yaml:"read_timeout"`
	WriteTimeout      Duration `yaml:"write_timeout"`
	IdleTimeout       Duration `yaml:"idle_timeout"`
	MaxHeaderBytes    int      `yaml:"max_header_bytes"`
	MaxBodyBytes      int64    `yaml:"max_body_bytes"`
}

// ManagementConfig configures the private management listener (metrics, health, pprof; ADR-0024).
type ManagementConfig struct {
	Listen string `yaml:"listen"`
	Pprof  bool   `yaml:"pprof"`
}

// ProxyConfig decides which peers may set client-IP headers (ADR-0020).
type ProxyConfig struct {
	// TrustedProxies are CIDRs of reverse proxies whose X-Forwarded-For entries are believed.
	TrustedProxies []string `yaml:"trusted_proxies"`
	// Cloudflare trusts CF-Connecting-IP, but only from CloudflareRanges.
	Cloudflare       bool     `yaml:"cloudflare"`
	CloudflareRanges []string `yaml:"cloudflare_ranges"`
}

// LogConfig configures structured logging.
type LogConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	// AuditFile, if set, receives every committed audit record as one ECS JSON line (mode 0600, append). "-" means stdout.
	AuditFile string `yaml:"audit_file"`
}

// StorageConfig configures storage safety.
type StorageConfig struct {
	// AllowNetworkFS overrides the network-filesystem refusal. Never set in production.
	AllowNetworkFS        bool `yaml:"allow_network_fs"`
	PreMigrationSnapshots int  `yaml:"pre_migration_snapshots"`
}

// SessionConfig configures browser sessions (ADR-0021, ADR-0010).
type SessionConfig struct {
	Idle            Duration `yaml:"idle"`
	Absolute        Duration `yaml:"absolute"`
	StepUpWindow    Duration `yaml:"step_up_window"`
	UpstreamRecheck Duration `yaml:"upstream_recheck"`
	// SetupAbsolute bounds the session created by consuming a setup token (it exists only to enroll a login method).
	SetupAbsolute Duration `yaml:"setup_absolute"`
}

// SetupConfig configures first-run setup tokens.
type SetupConfig struct {
	TokenTTL Duration `yaml:"token_ttl"`
}

// Load reads path (optional) and applies environment overrides from environ, then validates.
func Load(path string, environ []string) (*Config, error) {
	cfg := Default()
	if path != "" {
		f, err := os.Open(path) //nolint:gosec // operator-supplied config path
		if err != nil {
			return nil, fmt.Errorf("open config: %w", err)
		}
		defer f.Close()
		if err := decode(f, cfg); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	if err := applyEnv(cfg, environ); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func decode(r io.Reader, cfg *Config) error {
	data, err := io.ReadAll(io.LimitReader(r, 1<<20))
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("config must contain a single YAML document")
	}
	return nil
}

// IsProduction reports whether the configuration runs in production mode.
func (c *Config) IsProduction() bool { return c.Mode != ModeDevelopment }

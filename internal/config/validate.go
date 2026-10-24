// Adapted from HallPass internal/config/validate.go (Apache-2.0).

package config

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

// ValidationError aggregates every configuration problem found.
type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string {
	return "invalid configuration:\n  - " + strings.Join(e.Problems, "\n  - ")
}

// Validate checks the configuration, including production-mode restrictions.
func (c *Config) Validate() error {
	v := &validator{}
	switch c.Mode {
	case ModeProduction, ModeDevelopment:
	default:
		v.add("mode must be %q or %q, got %q", ModeProduction, ModeDevelopment, c.Mode)
	}
	prod := c.IsProduction()
	if c.DataDir == "" || !filepath.IsAbs(c.DataDir) {
		v.add("data_dir must be an absolute path")
	}
	c.validatePublicURL(v, prod)
	c.validateKEK(v, prod)
	v.listen("http.listen", c.HTTP.Listen)
	if (c.HTTP.TLSCertFile == "") != (c.HTTP.TLSKeyFile == "") {
		v.add("http.tls_cert_file and http.tls_key_file must be set together")
	}
	if c.HTTP.ClientCAFile != "" && c.HTTP.TLSCertFile == "" {
		v.add("http.client_ca_file requires TLS (http.tls_cert_file)")
	}
	v.durationRange("http.read_header_timeout", c.HTTP.ReadHeaderTimeout, time.Second, time.Minute)
	v.durationRange("http.read_timeout", c.HTTP.ReadTimeout, time.Second, 10*time.Minute)
	v.durationRange("http.write_timeout", c.HTTP.WriteTimeout, time.Second, 10*time.Minute)
	v.durationRange("http.idle_timeout", c.HTTP.IdleTimeout, time.Second, 30*time.Minute)
	v.positive("http.max_header_bytes", c.HTTP.MaxHeaderBytes)
	if c.HTTP.MaxBodyBytes <= 0 || c.HTTP.MaxBodyBytes > 64<<20 {
		v.add("http.max_body_bytes must be within 1..%d", 64<<20)
	}
	v.listen("management.listen", c.Management.Listen)
	if host, _, err := net.SplitHostPort(c.Management.Listen); err == nil && !IsLoopbackHost(host) {
		if prod && c.Management.Pprof {
			v.add("management.pprof must not be exposed on a non-loopback management.listen in production")
		}
	}
	for _, p := range c.Proxy.TrustedProxies {
		v.prefix("proxy.trusted_proxies", p)
	}
	for _, p := range c.Proxy.CloudflareRanges {
		v.prefix("proxy.cloudflare_ranges", p)
	}
	if c.Proxy.Cloudflare && len(c.Proxy.CloudflareRanges) == 0 {
		v.add("proxy.cloudflare requires proxy.cloudflare_ranges")
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		v.add("log.level must be debug, info, warn or error")
	}
	switch c.Log.Format {
	case "json", "text":
	default:
		v.add("log.format must be json or text")
	}
	if prod && c.Storage.AllowNetworkFS {
		v.add("storage.allow_network_fs is development-only")
	}
	v.positive("storage.pre_migration_snapshots", c.Storage.PreMigrationSnapshots)
	s := c.Session
	v.durationRange("session.idle", s.Idle, time.Minute, 30*24*time.Hour)
	v.durationRange("session.absolute", s.Absolute, s.Idle.D(), 90*24*time.Hour)
	v.durationRange("session.step_up_window", s.StepUpWindow, 30*time.Second, 30*time.Minute)
	v.durationRange("session.upstream_recheck", s.UpstreamRecheck, time.Minute, 24*time.Hour)
	v.durationRange("session.setup_absolute", s.SetupAbsolute, time.Minute, 24*time.Hour)
	v.durationRange("setup.token_ttl", c.Setup.TokenTTL, time.Minute, 7*24*time.Hour)
	c.validateBackup(v)
	if d := c.Automation.UpstreamMaxAge.D(); d != 0 {
		v.durationRange("automation.upstream_max_age", c.Automation.UpstreamMaxAge, time.Hour, 366*24*time.Hour)
	}
	if p := c.Events.Pulse; p.Enabled {
		if !strings.HasPrefix(p.URL, "tls://") && !strings.HasPrefix(p.URL, "nats://") {
			v.add("events.pulse.url must be a nats:// or tls:// URL")
		}
		if strings.HasPrefix(p.URL, "nats://") && c.IsProduction() {
			v.add("events.pulse.url must use tls:// in production mode")
		}
		if p.CredsFile == "" {
			v.add("events.pulse.creds_file is required")
		}
	}
	b := c.BackupLogin
	if b.Threshold < 1 || b.Threshold > 10 {
		v.add("backup_login.threshold must be within 1..10")
	}
	v.durationRange("backup_login.lock_duration", b.LockDuration, time.Minute, 30*24*time.Hour)
	v.durationRange("backup_login.max_lock_duration", b.MaxLockDuration, b.LockDuration.D(), 90*24*time.Hour)
	v.positive("backup_login.source_limit", b.SourceLimit)
	v.positive("backup_login.circuit_limit", b.CircuitLimit)
	v.durationRange("backup_login.source_window", b.SourceWindow, time.Second, 24*time.Hour)
	v.durationRange("backup_login.circuit_window", b.CircuitWindow, time.Second, 24*time.Hour)
	if b.MinPairs < 3 || b.MaxPairs > 12 || b.MinPairs > b.MaxPairs {
		v.add("backup_login.min_pairs/max_pairs must satisfy 3 <= min <= max <= 12")
	}
	for _, p := range c.Outbound.AllowCIDRs {
		v.prefix("outbound.allow_cidrs", p)
	}
	for _, p := range c.Authz.TrustedNetworks {
		v.prefix("authz.trusted_networks", p)
	}
	for _, p := range c.Forward.TrustedPeers {
		v.prefix("forward_auth.trusted_peers", p)
	}
	v.durationRange("forward_auth.session_ttl", c.Forward.SessionTTL, time.Minute, 7*24*time.Hour)
	return v.err()
}

func (c *Config) validatePublicURL(v *validator, prod bool) {
	if c.PublicURL == "" {
		v.add("public_url is required (the externally reachable https URL; it is also the OIDC issuer)")
		return
	}
	u, err := url.Parse(c.PublicURL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		v.add("public_url must be an absolute URL without credentials, query or fragment")
		return
	}
	if u.Path != "" && u.Path != "/" {
		v.add("public_url must not contain a path (serve Porch at the origin root)")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if prod {
			v.add("public_url must use https in production")
		} else if !IsLoopbackHost(u.Hostname()) {
			v.add("public_url may use http only for localhost in development mode")
		}
	default:
		v.add("public_url scheme must be https")
	}
}

func (c *Config) validateKEK(v *validator, prod bool) {
	switch c.KEK.Source {
	case "file":
		if c.KEK.File == "" {
			if prod {
				v.add("kek.file is required in production (generate one with `porch keys init --out FILE`)")
			}
			return
		}
		if !filepath.IsAbs(c.KEK.File) {
			v.add("kek.file must be an absolute path")
			return
		}
		if prod && isWithin(c.KEK.File, c.DataDir) {
			v.add("kek.file must be stored outside data_dir in production")
		}
	case "env":
	case "credential":
		// systemd LoadCredential=: kek.file names the credential inside $CREDENTIALS_DIRECTORY.
		if c.KEK.File == "" || strings.ContainsAny(c.KEK.File, "/\\") {
			v.add("kek.file must name the systemd credential (e.g. porch-kek) when kek.source is credential")
		}
	default:
		v.add("kek.source must be file, env or credential")
	}
}

// PublicOrigin returns scheme://host of public_url without a trailing slash.
func (c *Config) PublicOrigin() string { return strings.TrimSuffix(c.PublicURL, "/") }

// IsLoopbackHost reports whether host is localhost or a loopback IP.
func IsLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isWithin(path, dir string) bool {
	rel, err := filepath.Rel(filepath.Clean(dir), filepath.Clean(path))
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

type validator struct{ problems []string }

func (v *validator) add(format string, args ...any) {
	v.problems = append(v.problems, fmt.Sprintf(format, args...))
}

func (v *validator) positive(name string, n int) {
	if n <= 0 {
		v.add("%s must be positive", name)
	}
}

func (v *validator) durationRange(name string, d Duration, lo, hi time.Duration) {
	if d.D() < lo || d.D() > hi {
		v.add("%s must be within %s..%s, got %s", name, lo, hi, d.D())
	}
}

func (v *validator) listen(name, addr string) {
	if _, port, err := net.SplitHostPort(addr); err != nil || port == "" {
		v.add("%s must be host:port, got %q", name, addr)
	}
}

func (v *validator) prefix(name, s string) {
	if _, err := netip.ParsePrefix(s); err != nil {
		v.add("%s entry %q is not a CIDR prefix", name, s)
	}
}

func (v *validator) err() error {
	if len(v.problems) == 0 {
		return nil
	}
	return &ValidationError{Problems: v.problems}
}

func (c *Config) validateBackup(v *validator) {
	b := c.Backup
	if !b.Enabled {
		return
	}
	v.durationRange("backup.interval", b.Interval, 15*time.Minute, 7*24*time.Hour)
	if b.Retention < 1 || b.Retention > 1000 {
		v.add("backup.retention must be within 1..1000")
	}
	if len(b.Recipients) == 0 {
		v.add("backup.recipients: at least one age recipient (age1…) is required")
	}
	for _, r := range b.Recipients {
		if !strings.HasPrefix(strings.TrimSpace(r), "age1") {
			v.add("backup.recipients: %q is not an age X25519 recipient", r)
		}
	}
	s := b.S3
	if s.Endpoint == "" || strings.Contains(s.Endpoint, "/") {
		v.add("backup.s3.endpoint must be host[:port]")
	}
	if s.Bucket == "" {
		v.add("backup.s3.bucket is required")
	}
	if s.Prefix != "" && !strings.HasSuffix(s.Prefix, "/") {
		v.add("backup.s3.prefix must end with /")
	}
	if s.AccessKeyID == "" || (s.SecretAccessKey == "" && s.SecretAccessKeyFile == "") {
		v.add("backup.s3: access_key_id and secret_access_key (or secret_access_key_file) are required")
	}
	switch s.Lookup {
	case "", "auto", "path", "virtual":
	default:
		v.add("backup.s3.lookup must be auto, path or virtual")
	}
	if s.Insecure && c.IsProduction() {
		v.add("backup.s3.insecure (plain HTTP) is not allowed in production mode")
	}
}

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "porch.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestProductionRequiresPublicURLAndKEK(t *testing.T) {
	_, err := Load("", nil)
	if err == nil || !strings.Contains(err.Error(), "public_url is required") || !strings.Contains(err.Error(), "kek.file is required") {
		t.Fatalf("got %v", err)
	}
}

func TestDevelopmentMinimal(t *testing.T) {
	p := writeFile(t, "mode: development\ndata_dir: /tmp/porch-dev\npublic_url: http://localhost:8080\n")
	c, err := Load(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.HTTP.Listen != "127.0.0.1:8080" || c.Management.Listen != "127.0.0.1:9464" || c.Session.Idle.D() != 8*time.Hour ||
		c.Session.Absolute.D() != 12*time.Hour {
		t.Fatalf("defaults: %+v", c)
	}
	if c.HTTP.WriteTimeout.D() == 0 {
		t.Fatal("write timeout must be set by default")
	}
}

func TestUnknownKeyRejected(t *testing.T) {
	p := writeFile(t, "mode: development\npublic_url: http://localhost:8080\nhttp:\n  listn: x\n")
	if _, err := Load(p, nil); err == nil || !strings.Contains(err.Error(), "listn") {
		t.Fatalf("got %v", err)
	}
}

func TestEnvOverridesAndUnknownEnv(t *testing.T) {
	env := []string{"PORCH_MODE=development", "PORCH_PUBLIC_URL=http://localhost:9000", "PORCH_DATA_DIR=/tmp/x",
		"PORCH_PROXY_TRUSTED_PROXIES=10.0.0.0/8, 192.168.0.0/16", "PORCH_SESSION_IDLE=1h"}
	c, err := Load("", env)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Proxy.TrustedProxies) != 2 || c.Session.Idle.D() != time.Hour {
		t.Fatalf("%+v", c.Proxy)
	}
	if _, err := Load("", append(env, "PORCH_NOPE=1")); err == nil || !strings.Contains(err.Error(), "PORCH_NOPE") {
		t.Fatalf("unknown env: %v", err)
	}
}

func TestProductionRestrictions(t *testing.T) {
	p := writeFile(t, `public_url: http://auth.example.com
data_dir: /var/lib/porch
kek:
  file: /var/lib/porch/kek
storage:
  allow_network_fs: true
management:
  listen: 0.0.0.0:9464
  pprof: true
proxy:
  trusted_proxies: [not-a-cidr]
`)
	_, err := Load(p, nil)
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, want := range []string{"https in production", "outside data_dir", "allow_network_fs", "pprof", "not-a-cidr"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %v", want, err)
		}
	}
}

func TestEnvKeysDocumented(t *testing.T) {
	keys := EnvKeys()
	if len(keys) < 20 {
		t.Fatalf("too few env keys: %v", keys)
	}
}

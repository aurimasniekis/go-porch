package app_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/aurimasniekis/go-porch/internal/app"
	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/backup"
	"github.com/aurimasniekis/go-porch/internal/config"
	"github.com/aurimasniekis/go-porch/internal/domain"
)

func backupConfig(recipient string) func(*config.Config) {
	return func(c *config.Config) {
		c.Backup.Enabled = true
		c.Backup.Recipients = []string{recipient}
		c.Backup.Retention = 1
		c.Backup.S3 = config.BackupS3Config{Endpoint: "s3.invalid", Bucket: "b", Prefix: "porch/", AccessKeyID: "k", SecretAccessKey: "s", Lookup: "auto"}
	}
}

func openWith(t *testing.T, cfgMutate func(*config.Config), objs backup.ObjectStore) *app.App {
	t.Helper()
	cfg := config.Default()
	cfg.Mode = config.ModeDevelopment
	cfg.DataDir = filepath.Join(t.TempDir(), "data")
	cfg.PublicURL = origin
	cfg.HTTP.Listen, cfg.Management.Listen = "127.0.0.1:0", "127.0.0.1:0"
	cfgMutate(cfg)
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	a, err := app.Open(context.Background(), cfg, slog.New(slog.DiscardHandler), app.Options{Environ: []string{}, RSABits: 2048, BackupObjects: objs})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}

// ADR-0042 restore drill: an encrypted backup restores into a clean data directory; sessions from before the restore
// are invalid, signing keys are new, an alert is raised and the audit chain still verifies.
func TestBackupRestoreDrill(t *testing.T) {
	identity, recipient, err := backup.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	objs := backup.NewMem()
	a := openWith(t, backupConfig(recipient), objs)
	owner := setupOwner(t, a)
	expect(t, owner.do(http.MethodPost, "/api/v1/tenants", map[string]string{"slug": "smith", "name": "Smith family"}, nil), http.StatusCreated)
	expect(t, owner.do(http.MethodPost, "/api/v1/tenants/smith/groups", map[string]string{"slug": "kids", "name": "Kids"}, nil), http.StatusCreated)

	run := decode[map[string]any](t, owner.do(http.MethodPost, "/api/v1/installation/backups", nil, nil))
	if run["ok"] != true || run["kek_included"] != true || run["stored_bytes"].(float64) <= 0 {
		t.Fatalf("run %v", run)
	}
	expect(t, owner.do(http.MethodPost, "/api/v1/tenants/smith/groups", map[string]string{"slug": "teens", "name": "Teens"}, nil), http.StatusCreated)
	run2 := decode[map[string]any](t, owner.do(http.MethodPost, "/api/v1/installation/backups", nil, nil))
	if run2["pruned"].(float64) != 1 { // retention 1
		t.Fatalf("prune %v", run2)
	}
	st := decode[map[string]any](t, owner.do(http.MethodGet, "/api/v1/installation/backups", nil, nil))
	verifyKey := st["verify_key"].(string)
	if len(st["runs"].([]any)) != 2 {
		t.Fatalf("status %v", st)
	}
	h := decode[map[string]any](t, owner.do(http.MethodGet, "/api/v1/installation/health", nil, nil))
	if b := h["backups"].(map[string]any); b["configured"] != true || b["last_ok"] != true {
		t.Fatalf("health backups %v", h["backups"])
	}
	remote, err := backup.List(context.Background(), objs)
	if err != nil || len(remote) != 1 || !remote[0].Complete || remote[0].ID != run2["id"] {
		t.Fatalf("remote %v %v", remote, err)
	}
	// Nothing readable without the identity: objects are age ciphertext.
	for _, o := range remote[0].Manifest.Objects {
		b, _ := objs.Get(context.Background(), o.Key)
		if len(b) < 20 || string(b[:20]) != "age-encryption.org/v" {
			t.Fatalf("%s is not age ciphertext", o.Key)
		}
	}

	ids, err := backup.ParseIdentities(identity)
	if err != nil {
		t.Fatal(err)
	}
	vk, err := backup.ParseVerifyKey(verifyKey)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// Wrong verification key: refused. Wrong identity: cannot decrypt.
	otherPub, _, _ := ed25519.GenerateKey(nil)
	if _, err := backup.Fetch(ctx, objs, backup.FetchOptions{Identities: ids, VerifyKeys: []ed25519.PublicKey{otherPub}}); !errors.Is(err, backup.ErrUnverified) {
		t.Fatalf("forged: %v", err)
	}
	otherID, _, _ := backup.GenerateIdentity()
	oids, _ := backup.ParseIdentities(otherID)
	if _, err := backup.Fetch(ctx, objs, backup.FetchOptions{Identities: oids, VerifyKeys: []ed25519.PublicKey{vk}}); !errors.Is(err, backup.ErrDecrypt) {
		t.Fatalf("wrong identity: %v", err)
	}
	f, err := backup.Fetch(ctx, objs, backup.FetchOptions{Identities: ids, VerifyKeys: []ed25519.PublicKey{vk}})
	if err != nil || !f.Verified || f.KEK == nil {
		t.Fatalf("fetch %v", err)
	}

	// Restore into a clean data directory and start from it.
	dir := filepath.Join(t.TempDir(), "restored")
	kekFile := filepath.Join(t.TempDir(), "kek", "porch.kek")
	if err := backup.Restore(f, backup.RestoreOptions{DataDir: dir, KEKFile: kekFile, InvalidateBackupCredentials: true}); err != nil {
		t.Fatal(err)
	}
	if err := backup.Restore(f, backup.RestoreOptions{DataDir: dir}); err == nil {
		t.Fatal("restore into a non-empty directory")
	}
	b := openWith(t, func(c *config.Config) { c.DataDir, c.KEK.File = dir, kekFile }, nil)
	stale := &client{t: t, h: b.PublicHandler(), cookie: owner.cookie, csrf: owner.csrf, remote: owner.remote}
	expect(t, stale.do(http.MethodGet, "/api/v1/me", nil, nil), http.StatusUnauthorized)
	ts, _, err := b.Tenants.List(ctx, domain.Page{Limit: 50})
	if err != nil || len(ts) != 1 || ts[0].Slug != "smith" {
		t.Fatalf("restored tenants %v %v", ts, err)
	}
	for _, k := range b.OP.Signing.JWKS().Keys {
		for _, old := range a.OP.Signing.JWKS().Keys {
			if k.KeyID == old.KeyID {
				t.Fatalf("signing key %s survived the restore", k.KeyID)
			}
		}
	}
	alerts, err := b.Store.R().ListOpenAlerts(ctx)
	if err != nil || len(alerts) != 1 || alerts[0].Kind != "installation_restored" || alerts[0].Severity != "critical" {
		t.Fatalf("alerts %v %v", alerts, err)
	}
	if res, err := audit.Verify(ctx, b.Store.R()); err != nil || !res.OK {
		t.Fatalf("audit chain after restore %+v %v", res, err)
	}
	if p, _ := backup.ReadPending(dir); p != nil {
		t.Fatal("restore marker left behind")
	}
	// Tampering with a stored object is detected.
	objs.Corrupt(remote[0].Manifest.Objects[0].Key)
	if _, err := backup.Fetch(ctx, objs, backup.FetchOptions{Identities: ids, VerifyKeys: []ed25519.PublicKey{vk}}); err == nil {
		t.Fatal("tampered backup accepted")
	}
}

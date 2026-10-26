package store

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

// subsetFS returns the embedded migrations up to and including version prefix upto (e.g. "0001").
func subsetFS(t *testing.T, upto string) fs.FS {
	t.Helper()
	out := fstest.MapFS{}
	entries, err := fs.ReadDir(EmbeddedMigrations(), ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name()[:4] <= upto {
			b, err := fs.ReadFile(EmbeddedMigrations(), e.Name())
			if err != nil {
				t.Fatal(err)
			}
			out[e.Name()] = &fstest.MapFile{Data: b}
		}
	}
	return out
}

// A database created by an older release (fixture: only migration 0001 applied, with data) migrates forward to the
// latest schema, keeps its data and leaves a pre-migration snapshot.
func TestForwardMigrationFromV1Fixture(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "data")
	old, err := Open(ctx, Options{DataDir: dir, migrations: subsetFS(t, "0001")})
	if err != nil {
		t.Fatal(err)
	}
	if err := old.W().Exec(ctx, "INSERT INTO settings (key, value, updated_at) VALUES ('fixture', 'v1', 1)"); err != nil {
		t.Fatal(err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, Options{DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	row, err := s.R().GetSetting(ctx, "fixture")
	if err != nil || row.Value != "v1" {
		t.Fatalf("data lost: %+v %v", row, err)
	}
	cur, latest, err := SchemaVersions(ctx, s.ReadDB(), EmbeddedMigrations())
	if err != nil || cur != latest {
		t.Fatalf("version %d/%d %v", cur, latest, err)
	}
	snaps, _ := os.ReadDir(filepath.Join(dir, BackupsDir))
	found := false
	for _, e := range snaps {
		found = found || strings.HasPrefix(e.Name(), "pre-migrate-0001-")
	}
	if !found {
		t.Fatal("no pre-migration snapshot")
	}
}

// Migration 0013 rebuilds installation_role_assignments and automation_tokens (ADR-0048): existing rows survive
// unchanged and the new role and issuer column are accepted.
func TestMigration0013KeepsRolesAndTokens(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "data")
	old, err := Open(ctx, Options{DataDir: dir, migrations: subsetFS(t, "0012")})
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"INSERT INTO users (id, public_id, display_name, status, created_at, updated_at) VALUES ('usr_1', 'pub_1', 'Olga', 'active', 1, 1)",
		"INSERT INTO tenants (id, slug, name, status, created_at, updated_at) VALUES ('tnt_1', 'smith', 'Smith', 'active', 1, 1)",
		"INSERT INTO installation_role_assignments (id, user_id, role, source, created_at) VALUES ('opr_1', 'usr_1', 'owner', 'setup', 1)",
		`INSERT INTO automation_tokens (id, mac, hint, name, kind, role, created_by, created_at, expires_at, never_expires)
		 VALUES ('atk_1', x'01', 'abcd', 'terraform', 'installation', 'admin', 'usr_1', 1, 2, 1)`,
		`INSERT INTO automation_tokens (id, mac, hint, name, kind, tenant_id, permissions, created_by, created_at, expires_at, revoked_at)
		 VALUES ('atk_2', x'02', 'efgh', 'apps', 'tenant', 'tnt_1', '["app:manage"]', 'usr_1', 1, 5, 3)`,
	} {
		if err := old.W().Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, Options{DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	roles, err := s.R().ListOperatorRoles(ctx, "usr_1")
	if err != nil || len(roles) != 1 || roles[0] != "owner" {
		t.Fatalf("roles %v %v", roles, err)
	}
	a, err := s.R().GetAutomationToken(ctx, "atk_1")
	if err != nil || a.Name != "terraform" || a.NeverExpires != 1 || a.IssuedBy.Valid || string(a.Mac) != "\x01" {
		t.Fatalf("token %+v %v", a, err)
	}
	b, err := s.R().GetAutomationToken(ctx, "atk_2")
	if err != nil || b.TenantID.String != "tnt_1" || b.Permissions != `["app:manage"]` || b.RevokedAt.Int64 != 3 {
		t.Fatalf("token %+v %v", b, err)
	}
	for _, q := range []string{
		"INSERT INTO installation_role_assignments (id, user_id, role, source, created_at) VALUES ('opr_2', 'usr_1', 'inspector', 'manual', 2)",
		`INSERT INTO automation_tokens (id, mac, hint, name, kind, role, created_by, created_at, expires_at, issued_by)
		 VALUES ('atk_3', x'03', 'ijkl', 'deed', 'installation', 'inspector', 'usr_1', 1, 2, 'atk_1')`,
	} {
		if err := s.W().Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if err := s.W().Exec(ctx, "INSERT INTO installation_role_assignments (id, user_id, role, source, created_at) VALUES ('opr_3', 'usr_1', 'god', 'x', 2)"); err == nil {
		t.Fatal("unknown role accepted")
	}
}

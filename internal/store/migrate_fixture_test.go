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

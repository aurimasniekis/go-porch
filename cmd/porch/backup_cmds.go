package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/aurimasniekis/go-porch/internal/app"
	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/backup"
	"github.com/aurimasniekis/go-porch/internal/keyring"
	"github.com/aurimasniekis/go-porch/internal/store"
)

func runBackupKeygen(_ context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("backup keygen", stderr)
	out := fs.String("out", "", "write the age identity to this file (mode 0600); default: print it")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	id, recipient, err := backup.GenerateIdentity()
	if err != nil {
		return err
	}
	if *out != "" {
		f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		if _, err := f.WriteString(id); err != nil {
			_ = f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	} else if _, err := io.WriteString(stdout, id); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stderr, "recipient (put in backup.recipients): %s\nKeep the identity OFFLINE: it decrypts every backup.\n", recipient)
	return err
}

func runBackupRun(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("backup run", stderr)
	cfgPath := configFlag(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	a, err := openApp(ctx, *cfgPath, stderr)
	if err != nil {
		if errors.Is(err, store.ErrLocked) {
			return errors.New("porch is running: take the backup from Administration → Backups or POST /api/v1/installation/backups")
		}
		return err
	}
	defer a.Close()
	if !a.Cfg.Backup.Enabled {
		return errors.New("backups are not configured (backup.enabled)")
	}
	r, err := a.Backups.Run(ctx, "cli", audit.CLI)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "backup %s complete: %d bytes stored, kek included: %v, pruned: %d\n", r.ID, r.StoredBytes, r.KEKIncluded, r.Pruned)
	return err
}

func runBackupVerifyKey(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("backup verify-key", stderr)
	cfgPath := configFlag(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	a, err := openApp(ctx, *cfgPath, stderr)
	if err != nil {
		return err
	}
	defer a.Close()
	k, err := a.Backups.VerifyKey()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, k)
	return err
}

func objectStore(cfgPath string) (backup.ObjectStore, error) {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return nil, err
	}
	if !cfg.Backup.Enabled {
		return nil, errors.New("backups are not configured (backup.enabled)")
	}
	return app.ObjectStoreFor(cfg)
}

func runBackupList(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("backup list", stderr)
	cfgPath := configFlag(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	objs, err := objectStore(*cfgPath)
	if err != nil {
		return err
	}
	rs, err := backup.List(ctx, objs)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tCREATED\tBYTES\tSTATE\tKEK\tSIGNED BY")
	for _, r := range rs {
		state, kek := "incomplete", "-"
		if r.Complete && r.Manifest != nil {
			state, kek = "complete", fmt.Sprint(r.Manifest.KEKIncluded)
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\t%s\n", r.ID, r.Created.UTC().Format(time.RFC3339), r.Bytes, state, kek, r.KeyID)
	}
	return tw.Flush()
}

type fetchFlags struct {
	cfg, identity, id *string
	keys              *string
	skip              *bool
}

func fetchFlagSet(name string, stderr io.Writer) (*flag.FlagSet, fetchFlags) {
	fs := newFlagSet(name, stderr)
	return fs, fetchFlags{cfg: configFlag(fs), identity: fs.String("identity", "", "age identity file (AGE-SECRET-KEY-1…)"),
		id: fs.String("id", "latest", "backup ID or latest"), keys: fs.String("verify-key", "", "verification key(s) (porch-backup-ed25519:…, comma-separated)"),
		skip: fs.Bool("insecure-skip-verify", false, "restore without verifying the manifest signature (forged backups become possible)")}
}

func (f fetchFlags) fetch(ctx context.Context) (*backup.Fetched, error) {
	if *f.identity == "" {
		return nil, &exitError{code: 2, err: errors.New("--identity is required")}
	}
	if *f.keys == "" && !*f.skip {
		return nil, &exitError{code: 2, err: errors.New("--verify-key is required (shown by `porch backup verify-key`, the server log and the admin UI)")}
	}
	raw, err := os.ReadFile(*f.identity)
	if err != nil {
		return nil, err
	}
	ids, err := backup.ParseIdentities(string(raw))
	if err != nil {
		return nil, err
	}
	var keys []ed25519.PublicKey
	for _, k := range strings.Split(*f.keys, ",") {
		if strings.TrimSpace(k) == "" {
			continue
		}
		pk, err := backup.ParseVerifyKey(k)
		if err != nil {
			return nil, err
		}
		keys = append(keys, pk)
	}
	objs, err := objectStore(*f.cfg)
	if err != nil {
		return nil, err
	}
	return backup.Fetch(ctx, objs, backup.FetchOptions{ID: *f.id, Identities: ids, VerifyKeys: keys, SkipVerify: *f.skip})
}

func runBackupVerify(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs, ff := fetchFlagSet("backup verify", stderr)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	f, err := ff.fetch(ctx)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "porch-verify-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	p := filepath.Join(dir, store.DBFile)
	if err := os.WriteFile(p, f.DB, 0o600); err != nil {
		return err
	}
	d, err := sql.Open("sqlite", "file:"+p+"?mode=ro")
	if err != nil {
		return err
	}
	defer d.Close()
	var res string
	if err := d.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&res); err != nil {
		return err
	}
	if res != "ok" {
		return fmt.Errorf("backup %s: database integrity check: %s", f.Manifest.ID, res)
	}
	if f.KEK != nil {
		if _, err := keyring.ParseKEK(f.KEK); err != nil {
			return fmt.Errorf("backup %s: escrowed KEK: %w", f.Manifest.ID, err)
		}
	}
	_, err = fmt.Fprintf(stdout, "backup %s (%s): signature %s, %d bytes database, integrity ok, kek included: %v, schema %d, porch %s\n",
		f.Manifest.ID, f.Manifest.Created.UTC().Format(time.RFC3339), verifiedWord(f.Verified), len(f.DB), f.KEK != nil, f.Manifest.SchemaVersion,
		f.Manifest.PorchVersion)
	return err
}

func verifiedWord(v bool) string {
	if v {
		return "verified"
	}
	return "NOT VERIFIED"
}

func runRestore(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs, ff := fetchFlagSet("restore", stderr)
	reset := fs.Bool("invalidate-backup-logins", false, "delete every backup-login credential (users re-enrol); recommended after a compromise")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	cfg, err := loadConfig(*ff.cfg)
	if err != nil {
		return err
	}
	kekFile := cfg.KEK.File
	if kekFile == "" && !cfg.IsProduction() {
		kekFile = filepath.Join(cfg.DataDir, keyring.DevKEKFile)
	}
	f, err := ff.fetch(ctx)
	if err != nil {
		return err
	}
	if f.KEK == nil {
		kekFile = "" // the operator keeps the original KEK in place
	}
	if err := backup.Restore(f, backup.RestoreOptions{DataDir: cfg.DataDir, KEKFile: kekFile, InvalidateBackupCredentials: *reset,
		Now: time.Now()}); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "restored backup %s (%s, signature %s) into %s\nThe next `porch serve` invalidates all sessions and refresh tokens, "+
		"replaces the signing keys and raises a critical alert.\n", f.Manifest.ID, f.Manifest.Created.UTC().Format(time.RFC3339), verifiedWord(f.Verified),
		cfg.DataDir)
	return err
}

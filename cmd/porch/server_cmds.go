package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/aurimasniekis/go-porch/internal/app"
	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/config"
	"github.com/aurimasniekis/go-porch/internal/keyring"
	"github.com/aurimasniekis/go-porch/internal/mgmtapi"
	porchlog "github.com/aurimasniekis/go-porch/internal/obs/log"
	"github.com/aurimasniekis/go-porch/internal/store"
)

// configFlag registers -config (default $PORCH_CONFIG).
func configFlag(fs *flag.FlagSet) *string {
	return fs.String("config", os.Getenv("PORCH_CONFIG"), "path to porch.yaml (default $PORCH_CONFIG)")
}

func loadConfig(path string) (*config.Config, error) {
	return config.Load(path, os.Environ())
}

func openApp(ctx context.Context, cfgPath string, stderr io.Writer) (*app.App, error) {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return nil, err
	}
	log := porchlog.New(stderr, cfg.Log.Level, cfg.Log.Format)
	slog.SetDefault(log) // zitadel/oidc logs through the default logger
	return app.Open(ctx, cfg, log, app.Options{})
}

func runServe(ctx context.Context, args []string, _, stderr io.Writer) error {
	fs := newFlagSet("serve", stderr)
	cfgPath := configFlag(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	a, err := openApp(ctx, *cfgPath, stderr)
	if err != nil {
		return err
	}
	defer a.Close()
	ls, err := a.Listen(ctx)
	if err != nil {
		return err
	}
	return a.Serve(ctx, ls)
}

func runMigrate(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("migrate", stderr)
	cfgPath := configFlag(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	s, err := store.Open(ctx, store.Options{DataDir: cfg.DataDir, AllowNetworkFS: cfg.Storage.AllowNetworkFS,
		PreMigrationSnapshots: cfg.Storage.PreMigrationSnapshots, Logger: porchlog.New(stderr, cfg.Log.Level, cfg.Log.Format)})
	if err != nil {
		return err
	}
	defer s.Close()
	cur, latest, err := store.SchemaVersions(ctx, s.ReadDB(), store.EmbeddedMigrations())
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "schema version %d (latest %d)\n", cur, latest)
	return err
}

func runConfigCheck(_ context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("config check", stderr)
	cfgPath := configFlag(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	enc := yaml.NewEncoder(stdout)
	enc.SetIndent(2)
	if err := enc.Encode(cfg); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stderr, "configuration OK")
	return err
}

func runOpenAPI(_ context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("openapi", stderr)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	api := mgmtapi.New(http.NewServeMux(), &mgmtapi.Deps{Version: "v1"}) //nolint:contextcheck // only builds the spec
	b, err := json.MarshalIndent(api.OpenAPI(), "", "  ")
	if err != nil {
		return err
	}
	_, err = stdout.Write(append(b, '\n'))
	return err
}

func runHealthcheck(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("healthcheck", stderr)
	url := fs.String("url", "http://127.0.0.1:9464/readyz", "readiness URL on the management listener")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, *url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return &exitError{code: 1, err: err}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if resp.StatusCode != http.StatusOK {
		return &exitError{code: 1, err: fmt.Errorf("%s: %s", resp.Status, body)}
	}
	_, err = stdout.Write(body)
	return err
}

func runKeysInit(_ context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("keys init", stderr)
	out := fs.String("out", "", "path of the new KEK file (must not exist)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *out == "" {
		return &exitError{code: 2, err: errors.New("--out is required")}
	}
	k, err := keyring.GenerateKEK()
	if err != nil {
		return err
	}
	if err := keyring.WriteKEKFile(*out, k); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "wrote KEK %s (id %s). Store a copy offline: losing it makes the database unreadable.\n", *out, keyring.KEKID(k))
	return err
}

func runKeysStatus(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("keys status", stderr)
	cfgPath := configFlag(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	a, err := openApp(ctx, *cfgPath, stderr)
	if err != nil {
		return err
	}
	defer a.Close()
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]any{"kek_id": a.Keyring.KEKID(), "purposes": a.Keyring.Status()})
}

func runKeysRotate(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("keys rotate", stderr)
	cfgPath := configFlag(fs)
	purpose := fs.String("purpose", "", "purpose to rotate: field, token, signing, backup-meta")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	a, err := openApp(ctx, *cfgPath, stderr)
	if err != nil {
		return err
	}
	defer a.Close()
	v, err := a.Keyring.Rotate(ctx, a.Store, keyring.Purpose(*purpose))
	if err != nil {
		return err
	}
	err = a.Store.W().Tx(ctx, func(tx *store.Tx) error {
		_, err := a.Audit.Append(ctx, tx, audit.Event{Actor: audit.CLI, Action: "keyring.rotated", Target: audit.Target{Type: "keyring", ID: *purpose},
			Details: map[string]any{"version": v}})
		return err
	})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "%s key rotated to v%d; re-sealing of existing values runs in the background while serving\n", *purpose, v)
	return err
}

func runKeysRetire(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("keys retire", stderr)
	cfgPath := configFlag(fs)
	purpose := fs.String("purpose", "", "purpose")
	version := fs.Uint("version", 0, "decrypt-only version to retire")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	a, err := openApp(ctx, *cfgPath, stderr)
	if err != nil {
		return err
	}
	defer a.Close()
	p := keyring.Purpose(*purpose)
	if _, err := a.Keyring.ResealColumns(ctx, a.Store, keyring.Columns, 1<<20); err != nil {
		return err
	}
	inUse, err := keyring.VersionInUse(ctx, a.Store, keyring.Columns, p, uint32(*version)) //nolint:gosec // small version
	if err != nil {
		return err
	}
	if inUse {
		return fmt.Errorf("%s v%d is still used by a sealed column; not retired", p, *version)
	}
	if err := a.Keyring.Retire(ctx, a.Store, p, uint32(*version)); err != nil { //nolint:gosec // small version
		return err
	}
	_, err = fmt.Fprintf(stdout, "%s v%d retired\n", p, *version)
	return err
}

func runSetupToken(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("admin setup-token", stderr)
	cfgPath := configFlag(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	a, err := openApp(ctx, *cfgPath, stderr)
	if err != nil {
		return err
	}
	defer a.Close()
	tok, exp, err := a.Setup.Issue(ctx, a.Cfg.Setup.TokenTTL.D())
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "Setup token (single use, expires %s):\n\n  %s\n\nOpen %s/setup and paste it to create the first owner.\n",
		exp.UTC().Format(time.RFC3339), tok, a.Cfg.PublicOrigin())
	return err
}

func runAuditVerify(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("audit verify", stderr)
	cfgPath := configFlag(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	a, err := openApp(ctx, *cfgPath, stderr)
	if err != nil {
		return err
	}
	defer a.Close()
	res, err := audit.Verify(ctx, a.Store.R())
	if err != nil {
		return err
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(res); err != nil {
		return err
	}
	if !res.OK {
		return &exitError{code: 3, err: errors.New("audit chain verification FAILED")}
	}
	return nil
}

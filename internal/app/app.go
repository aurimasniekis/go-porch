// Package app assembles Porch: configuration, storage, keys, services and the HTTP listeners.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/aurimasniekis/go-porch/internal/apps"
	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/authz"
	"github.com/aurimasniekis/go-porch/internal/buildinfo"
	"github.com/aurimasniekis/go-porch/internal/clock"
	"github.com/aurimasniekis/go-porch/internal/config"
	"github.com/aurimasniekis/go-porch/internal/httpx"
	"github.com/aurimasniekis/go-porch/internal/identity"
	"github.com/aurimasniekis/go-porch/internal/idp"
	"github.com/aurimasniekis/go-porch/internal/idp/upstream"
	"github.com/aurimasniekis/go-porch/internal/installation"
	"github.com/aurimasniekis/go-porch/internal/keyring"
	"github.com/aurimasniekis/go-porch/internal/localauth"
	"github.com/aurimasniekis/go-porch/internal/netguard"
	"github.com/aurimasniekis/go-porch/internal/obs/metrics"
	"github.com/aurimasniekis/go-porch/internal/oidcop"
	"github.com/aurimasniekis/go-porch/internal/session"
	"github.com/aurimasniekis/go-porch/internal/setup"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/tenancy"
)

// App is a running Porch instance's object graph.
type App struct {
	Cfg      *config.Config
	Log      *slog.Logger
	Clock    clock.Clock
	Metrics  *metrics.Metrics
	Store    *store.Store
	Keyring  *keyring.Keyring
	Audit    *audit.Writer
	Users    *identity.Service
	Tenants  *tenancy.Service
	Sessions *session.Manager
	Setup    *setup.Service
	IDP      *idp.Service
	Local    *localauth.Service
	Apps     *apps.Service
	OP       *oidcop.Provider
	ClientIP *httpx.ClientIPResolver

	auditFile io.Closer
}

// Options adjust Open (tests).
type Options struct {
	Clock   clock.Clock
	Environ []string
	// HashParams overrides Argon2id parameters (tests only).
	HashParams *localauth.Params
	// RSABits overrides the RSA signing key size (tests only; default 3072).
	RSABits int
}

// Open opens the data directory (taking its lock), loads the keyring and builds every service.
func Open(ctx context.Context, cfg *config.Config, log *slog.Logger, opts Options) (*App, error) {
	if opts.Clock == nil {
		opts.Clock = clock.System{}
	}
	if opts.Environ == nil {
		opts.Environ = os.Environ()
	}
	a := &App{Cfg: cfg, Log: log, Clock: opts.Clock, Metrics: metrics.New()}
	info := buildinfo.Get()
	a.Metrics.SetBuildInfo(info.Version, info.GoVersion)
	s, err := store.Open(ctx, store.Options{DataDir: cfg.DataDir, AllowNetworkFS: cfg.Storage.AllowNetworkFS,
		PreMigrationSnapshots: cfg.Storage.PreMigrationSnapshots, Logger: log, Clock: opts.Clock, Metrics: a.Metrics})
	if err != nil {
		return nil, err
	}
	a.Store = s
	if err := a.init(ctx, opts); err != nil {
		_ = a.Close()
		return nil, err
	}
	return a, nil
}

func (a *App) init(ctx context.Context, opts Options) error {
	cfg := a.Cfg
	if err := installation.Ensure(ctx, a.Store); err != nil {
		return err
	}
	kek, err := keyring.LoadKEK(keyring.Source{Kind: cfg.KEK.Source, File: cfg.KEK.File, Production: cfg.IsProduction(),
		DataDir: cfg.DataDir, Environ: opts.Environ})
	if err != nil {
		return err
	}
	if a.Keyring, err = keyring.Load(ctx, a.Store, kek); err != nil {
		return err
	}
	a.Audit = audit.NewWriter(a.Keyring)
	if err := a.openAuditSink(); err != nil {
		return err
	}
	a.Users = identity.New(a.Store, a.Audit)
	a.Tenants = tenancy.New(a.Store, a.Audit)
	a.Tenants.OnCreate = authz.EnsureBuiltinsTx
	a.Sessions = session.New(a.Store, a.Keyring, session.Options{Idle: cfg.Session.Idle.D(), Absolute: cfg.Session.Absolute.D(),
		StepUpWindow: cfg.Session.StepUpWindow.D(), UpstreamRecheck: cfg.Session.UpstreamRecheck.D(), SetupAbsolute: cfg.Session.SetupAbsolute.D(),
		Clock: a.Clock})
	a.Setup = setup.New(a.Store, a.Keyring, a.Audit, a.Users, a.Sessions)
	guard, err := netguard.New(cfg.Outbound.AllowCIDRs)
	if err != nil {
		return err
	}
	a.IDP = idp.New(a.Store, a.Keyring, a.Audit, a.Users, a.Tenants, a.Sessions, upstream.New(guard.Client(30*time.Second)), idp.Options{
		PublicURL: cfg.PublicOrigin(), AllowInsecureIssuers: !cfg.IsProduction(), Clock: a.Clock, Metrics: a.Metrics})
	b := cfg.Backup
	pol := localauth.DefaultPolicy()
	pol.Disabled, pol.Threshold, pol.Duration, pol.MaxDuration = b.Disabled, b.Threshold, b.LockDuration.D(), b.MaxLockDuration.D()
	pol.SourceLimit, pol.SourceWindow, pol.CircuitLimit, pol.CircuitWindow = b.SourceLimit, b.SourceWindow.D(), b.CircuitLimit, b.CircuitWindow.D()
	pol.Strength.MinPairs, pol.Strength.MaxPairs = b.MinPairs, b.MaxPairs
	if opts.HashParams != nil {
		pol.Params = *opts.HashParams
	}
	a.Local = localauth.New(a.Store, a.Keyring, a.Audit, a.Sessions, a.Clock, a.Metrics, pol)
	a.Apps = apps.New(a.Store, a.Keyring, a.Audit)
	a.Apps.AllowInsecureRedirects = !cfg.IsProduction()
	keys := oidcop.NewKeys(a.Store, a.Keyring, a.Audit)
	if opts.RSABits > 0 {
		keys.RSABits = opts.RSABits
	}
	if err := keys.Load(ctx); err != nil {
		return fmt.Errorf("oidc signing keys: %w", err)
	}
	a.OP = &oidcop.Provider{Issuer: cfg.PublicOrigin(), Store: a.Store, Keyring: a.Keyring, Audit: a.Audit, Signing: keys, Apps: a.Apps,
		Sessions: a.Sessions, Tenants: a.Tenants, Clock: a.Clock, Metrics: a.Metrics, Log: a.Log}
	if b.Disabled {
		a.Log.Warn("backup_login.disabled is set: the local backup login is OFF for every user; if Google is unavailable nobody can sign in except via `porch admin recover`")
	}
	var cf []string
	if cfg.Proxy.Cloudflare {
		cf = cfg.Proxy.CloudflareRanges
	}
	if a.ClientIP, err = httpx.NewClientIPResolver(cfg.Proxy.TrustedProxies, cf); err != nil {
		return err
	}
	if !cfg.IsProduction() {
		a.Log.Warn("running in development mode: development KEK and http://localhost are allowed; never use this mode in production")
	}
	return nil
}

func (a *App) openAuditSink() error {
	switch a.Cfg.Log.AuditFile {
	case "":
		return nil
	case "-":
		a.Audit.SetSink(audit.NewJSONSink(os.Stdout))
		return nil
	}
	f, err := os.OpenFile(a.Cfg.Log.AuditFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600) //nolint:gosec // operator-configured path
	if err != nil {
		return fmt.Errorf("open audit file: %w", err)
	}
	a.auditFile = f
	a.Audit.SetSink(audit.NewJSONSink(f))
	return nil
}

// Ready reports whether the instance can serve: storage healthy and keyring loaded.
func (a *App) Ready(ctx context.Context) error {
	if a.Keyring == nil {
		return errors.New("keyring not loaded")
	}
	st := a.Store.Health().Status()
	if st.State != store.HealthOK {
		return fmt.Errorf("storage %s: %s", st.State, st.Reason)
	}
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, err := a.Store.R().GetInstallation(cctx)
	return err
}

// Close releases the data directory.
func (a *App) Close() error {
	var errs []error
	if a.Store != nil {
		errs = append(errs, a.Store.Close())
	}
	if a.auditFile != nil {
		errs = append(errs, a.auditFile.Close())
	}
	return errors.Join(errs...)
}

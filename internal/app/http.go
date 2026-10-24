package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/aurimasniekis/go-porch/internal/buildinfo"
	"github.com/aurimasniekis/go-porch/internal/httpx"
	"github.com/aurimasniekis/go-porch/internal/mgmtapi"
	"github.com/aurimasniekis/go-porch/internal/portal"
	"github.com/aurimasniekis/go-porch/internal/session"
	"github.com/aurimasniekis/go-porch/internal/webui"
)

// surface classifies a path for metrics (bounded label values).
func surface(path string) string {
	switch {
	case strings.HasPrefix(path, "/api/"):
		return "api"
	case strings.HasPrefix(path, "/oauth2/"), strings.HasPrefix(path, "/.well-known/"), path == "/jwks":
		return "oidc"
	case strings.HasPrefix(path, "/outpost/"), strings.HasPrefix(path, "/.porch/"):
		return "outpost"
	default:
		return "portal"
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func (a *App) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		d := time.Since(start)
		a.Metrics.HTTPRequest(surface(r.URL.Path), r.Method, sw.status, d)
		lvl := slog.LevelDebug
		if sw.status >= 500 {
			lvl = slog.LevelWarn
		}
		a.Log.Log(r.Context(), lvl, "http", "method", r.Method, "path", r.URL.Path, "status", sw.status,
			"ms", d.Milliseconds(), "client_ip", httpx.ClientIP(r.Context()).String(), "request_id", httpx.GetRequestID(r.Context()))
	})
}

// PublicHandler is the handler for the public listener.
func (a *App) PublicHandler() http.Handler {
	mux := http.NewServeMux()
	mgmtapi.New(mux, a.APIDeps())
	(&portal.Handler{IDP: a.IDP, Sessions: a.Sessions, Log: a.Log, Limiter: httpx.NewLimiter(a.Clock, 30, 10)}).Register(mux)
	op := a.OP.Handler()
	mux.Handle("/.well-known/openid-configuration", op)
	mux.Handle("/jwks", op)
	mux.Handle("/oauth2/", op)
	mux.Handle("GET /oauth2/continue", a.OP.Continue(a.providerSlug))
	a.Outpost.Register(mux)
	mux.Handle("/", webui.Handler(webui.Dist(), a.recheckHook))
	var h http.Handler = mux
	h = httpx.LimitBody(a.Cfg.HTTP.MaxBodyBytes, h)
	h = httpx.SecurityHeaders(strings.HasPrefix(a.Cfg.PublicURL, "https://"), h)
	h = a.accessLog(h)
	h = a.ClientIP.Middleware(h)
	return httpx.RequestID(h)
}

// recheckHook sends page navigations of a federated session that is due for its hourly upstream recheck through the
// silent prompt=none round trip first (ADR-0007). API calls get a 401 upstream_recheck_required instead.
func (a *App) recheckHook(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/login", "/setup", "/recovery":
		return false
	}
	p, err := a.Sessions.Validate(r.Context(), session.TokenFromRequest(r))
	if err != nil || !a.Sessions.NeedsUpstreamRecheck(p) || p.ProviderID == "" {
		return false
	}
	slug := a.providerSlug(r.Context(), p.ProviderID)
	if slug == "" {
		return false
	}
	// The target is a fixed same-origin path; return_to is validated by SafeReturnTo and escaped.
	http.Redirect(w, r, "/login/"+slug+"?intent=recheck&return_to="+url.QueryEscape(httpx.SafeReturnTo(r.URL.RequestURI(), "/")), http.StatusFound) //nolint:gosec // see above
	return true
}

// APIDeps returns the management API dependencies.
func (a *App) APIDeps() *mgmtapi.Deps {
	return &mgmtapi.Deps{Log: a.Log, Version: buildinfo.Get().Version, Origin: a.Cfg.PublicOrigin(), Store: a.Store, Audit: a.Audit,
		Users: a.Users, Tenants: a.Tenants, Sessions: a.Sessions, Setup: a.Setup, IDP: a.IDP, Local: a.Local, Apps: a.Apps, OP: a.OP,
		SAs: a.SAs, Tokens: a.Tokens, Backups: a.Backups, BackupInterval: a.Cfg.Backup.Interval.D(), BackupEnabled: a.Cfg.Backup.Enabled, Engine: a.Engine, Keyring: a.Keyring, Ready: a.Ready, StartedAt: a.Clock.Now(), Clock: a.Clock, Authz: a.Authz, Metrics: a.Metrics,
		SetupRate: httpx.NewLimiter(a.Clock, 10, 5), LoginRate: httpx.NewLimiter(a.Clock, 10, 5)}
}

// ManagementHandler serves metrics, health and (opt-in) pprof on the private listener.
func (a *App) ManagementHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", a.Metrics.Handler())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		err := a.Ready(r.Context())
		a.Metrics.SetReady(err == nil)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprintf(w, "not ready: %v\n", err)
			return
		}
		_, _ = w.Write([]byte("ready\n"))
	})
	if a.Cfg.Management.Pprof {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}
	return mux
}

func (a *App) tlsConfig() (*tls.Config, error) {
	c := a.Cfg.HTTP
	if c.TLSCertFile == "" {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(c.TLSCertFile, c.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS certificate: %w", err)
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	if c.ClientCAFile != "" {
		pem, err := os.ReadFile(c.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("client CA file contains no certificates")
		}
		tc.ClientCAs = pool
		tc.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return tc, nil
}

// Listeners are bound sockets (tests bind :0 and read the addresses).
type Listeners struct {
	Public, Management net.Listener
}

// Listen binds both listeners.
func (a *App) Listen(ctx context.Context) (*Listeners, error) {
	var lc net.ListenConfig
	pub, err := lc.Listen(ctx, "tcp", a.Cfg.HTTP.Listen)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", a.Cfg.HTTP.Listen, err)
	}
	mgmt, err := lc.Listen(ctx, "tcp", a.Cfg.Management.Listen)
	if err != nil {
		_ = pub.Close()
		return nil, fmt.Errorf("listen %s: %w", a.Cfg.Management.Listen, err)
	}
	return &Listeners{Public: pub, Management: mgmt}, nil
}

// Servers builds the public and management servers; every timeout is set (never copy HallPass's missing WriteTimeout).
func (a *App) Servers(ctx context.Context, tc *tls.Config) (public, mgmt *http.Server) {
	c := a.Cfg.HTTP
	handler := a.PublicHandler() //nolint:contextcheck // handlers use each request's context
	public = &http.Server{Handler: handler, ReadHeaderTimeout: c.ReadHeaderTimeout.D(), ReadTimeout: c.ReadTimeout.D(),
		WriteTimeout: c.WriteTimeout.D(), IdleTimeout: c.IdleTimeout.D(), MaxHeaderBytes: c.MaxHeaderBytes, TLSConfig: tc,
		BaseContext: func(net.Listener) context.Context { return ctx }}
	mgmt = &http.Server{Handler: a.ManagementHandler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	return public, mgmt
}

// Serve runs both servers until ctx is canceled, then shuts down gracefully.
func (a *App) Serve(ctx context.Context, ls *Listeners) error {
	tc, err := a.tlsConfig()
	if err != nil {
		return err
	}
	public, mgmt := a.Servers(ctx, tc)
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		var err error
		if tc != nil {
			err = public.ServeTLS(ls.Public, "", "")
		} else {
			err = public.Serve(ls.Public)
		}
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	})
	g.Go(func() error {
		if err := mgmt.Serve(ls.Management); !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	})
	g.Go(func() error {
		a.maintain(gctx)
		return nil
	})
	g.Go(func() error {
		a.backupLoop(gctx)
		return nil
	})
	g.Go(func() error {
		a.relayLoop(gctx)
		return nil
	})
	g.Go(func() error {
		<-gctx.Done()
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		return errors.Join(public.Shutdown(sctx), mgmt.Shutdown(sctx))
	})
	a.Log.Info("porch serving", "public", ls.Public.Addr().String(), "management", ls.Management.Addr().String(),
		"public_url", a.Cfg.PublicURL, "tls", tc != nil, "client_cert_required", tc != nil && tc.ClientAuth == tls.RequireAndVerifyClientCert)
	return g.Wait()
}

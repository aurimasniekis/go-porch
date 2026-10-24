// Command demo-app is a small OpenID Connect relying party that signs users in through Porch and shows what Porch
// issues: the verified ID token, the RFC 9068 access token (decoded and verified against Porch's JWKS), the userinfo
// response and refresh token rotation. It is used for interop testing, the demo Docker stack and the acceptance demo.
//
// It is an example, not a production session layer: sessions live in memory and are lost on restart.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(logger); err != nil {
		logger.Error("demo app stopped", "error", err.Error())
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := loadConfig(os.Getenv)
	if err != nil {
		return err
	}
	client, err := newHTTPClient(cfg.CAFile)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a, err := discoverWithRetry(ctx, cfg, logger, client)
	if err != nil {
		if ctx.Err() != nil {
			logger.Info("interrupted before the issuer was ready")
			return nil
		}
		return err
	}
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           a.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		// Callback and refresh call Porch (client timeout 15s) before responding.
		WriteTimeout:   45 * time.Second,
		IdleTimeout:    2 * time.Minute,
		MaxHeaderBytes: 64 << 10,
		ErrorLog:       slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	logger.Info("demo app listening", "addr", cfg.Listen, "issuer", cfg.Issuer, "client_id", cfg.ClientID,
		"redirect_url", cfg.RedirectURL, "insecure_cookies", cfg.InsecureCookies)

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	if err := <-errc; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// discoverWithRetry builds the app, retrying discovery for a while: in the demo Docker stack the app may start before
// Porch is ready.
func discoverWithRetry(ctx context.Context, cfg config, logger *slog.Logger, client *http.Client) (*app, error) {
	const attempts = 30
	for i := 1; ; i++ {
		a, err := newApp(ctx, cfg, logger, client)
		if err == nil {
			return a, nil
		}
		if i == attempts {
			return nil, err
		}
		logger.Warn("issuer not ready; retrying", "attempt", i, "error", err.Error())
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

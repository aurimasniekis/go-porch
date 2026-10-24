package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	defaultScopes = "openid profile email offline_access groups"
	defaultListen = "127.0.0.1:9090"
	callbackPath  = "/callback"
)

// config is the demo app configuration, read from the environment.
type config struct {
	Issuer          string
	ClientID        string
	ClientSecret    string
	RedirectURL     string
	PostLogoutURL   string
	Resource        string
	Scopes          []string
	Listen          string
	CAFile          string
	InsecureCookies bool
}

// loadConfig reads the configuration through getenv (os.Getenv in production) and reports every problem at once.
func loadConfig(getenv func(string) string) (config, error) {
	get := func(k string) string { return strings.TrimSpace(getenv(k)) }
	cfg := config{
		Issuer:        get("PORCH_ISSUER"),
		ClientID:      get("DEMO_CLIENT_ID"),
		ClientSecret:  get("DEMO_CLIENT_SECRET"),
		RedirectURL:   get("DEMO_REDIRECT_URL"),
		PostLogoutURL: get("DEMO_POST_LOGOUT_URL"),
		Resource:      get("DEMO_RESOURCE"),
		Listen:        get("DEMO_LISTEN"),
		CAFile:        get("DEMO_CA_FILE"),
	}
	scopes := get("DEMO_SCOPES")
	if scopes == "" {
		scopes = defaultScopes
	}
	cfg.Scopes = strings.Fields(scopes)
	if cfg.Listen == "" {
		cfg.Listen = defaultListen
	}
	if cfg.RedirectURL == "" {
		cfg.RedirectURL = "http://localhost:9090" + callbackPath
	}

	var errs []error
	if cfg.Issuer == "" {
		errs = append(errs, errors.New("PORCH_ISSUER is required (e.g. https://porch.example.com)"))
	} else if err := checkAbsURL(cfg.Issuer); err != nil {
		errs = append(errs, fmt.Errorf("PORCH_ISSUER: %w", err))
	}
	if cfg.ClientID == "" {
		errs = append(errs, errors.New("DEMO_CLIENT_ID is required (the client_id of the application registered in Porch)"))
	}
	if cfg.ClientSecret == "" {
		errs = append(errs, errors.New("DEMO_CLIENT_SECRET is required (shown once when the application is registered in Porch)"))
	}
	if err := checkAbsURL(cfg.RedirectURL); err != nil {
		errs = append(errs, fmt.Errorf("DEMO_REDIRECT_URL: %w", err))
	} else if u, _ := url.Parse(cfg.RedirectURL); u.Path != callbackPath {
		errs = append(errs, fmt.Errorf("DEMO_REDIRECT_URL: path must be %s, got %q", callbackPath, u.Path))
	}
	if cfg.PostLogoutURL != "" {
		if err := checkAbsURL(cfg.PostLogoutURL); err != nil {
			errs = append(errs, fmt.Errorf("DEMO_POST_LOGOUT_URL: %w", err))
		}
	}
	if cfg.Resource != "" {
		if u, err := url.Parse(cfg.Resource); err != nil || !u.IsAbs() || u.Fragment != "" {
			errs = append(errs, errors.New("DEMO_RESOURCE must be an absolute URI without a fragment (RFC 8707)"))
		}
	}
	if !slices.Contains(cfg.Scopes, "openid") {
		errs = append(errs, errors.New("DEMO_SCOPES must include openid"))
	}
	if _, _, err := net.SplitHostPort(cfg.Listen); err != nil {
		errs = append(errs, fmt.Errorf("DEMO_LISTEN: %w", err))
	}
	if v := get("DEMO_INSECURE_COOKIES"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("DEMO_INSECURE_COOKIES: %q is not a boolean", v))
		}
		cfg.InsecureCookies = b
	}
	if cfg.CAFile != "" {
		if _, err := os.Stat(cfg.CAFile); err != nil {
			errs = append(errs, fmt.Errorf("DEMO_CA_FILE: %w", err))
		}
	}
	if len(errs) > 0 {
		return config{}, fmt.Errorf("invalid configuration:\n%w", errors.Join(errs...))
	}
	return cfg, nil
}

func checkAbsURL(s string) error {
	u, err := url.Parse(s)
	if err != nil {
		return err
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("%q must be an absolute http(s) URL", s)
	}
	return nil
}

// newHTTPClient returns the client used for every call to Porch. caFile (optional) is a PEM bundle trusted in addition
// to the system roots, for self-signed test setups.
func newHTTPClient(caFile string) (*http.Client, error) {
	tr, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("unexpected default transport")
	}
	tr = tr.Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile) //nolint:gosec // operator-supplied path
		if err != nil {
			return nil, fmt.Errorf("DEMO_CA_FILE: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("DEMO_CA_FILE: no PEM certificates found in %s", caFile)
		}
		tr.TLSClientConfig.RootCAs = pool
	}
	return &http.Client{Transport: tr, Timeout: 15 * time.Second}, nil
}

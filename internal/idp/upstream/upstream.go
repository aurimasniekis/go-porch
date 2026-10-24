// Package upstream talks to upstream OpenID providers (Google, generic OIDC): discovery, the authorization URL with
// PKCE, code exchange and ID token verification (ADR-0007). It performs network I/O and must never be called inside a
// write transaction (enforced by the txscope analyzer).
package upstream

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// GoogleIssuer is Google's OpenID issuer.
const GoogleIssuer = "https://accounts.google.com"

// Config describes one upstream provider.
type Config struct {
	ID          string
	Kind        string // google | oidc
	Issuer      string
	ClientID    string
	Secret      string
	Scopes      []string
	RedirectURL string
}

// AllowedAlgs is the signature allowlist: Google signs with RS256 only; generic providers may use RS256 or ES256.
func (c Config) AllowedAlgs() []string {
	if c.Kind == "google" {
		return []string{oidc.RS256}
	}
	return []string{oidc.RS256, oidc.ES256}
}

// Claims are the verified identity claims Porch uses.
type Claims struct {
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	HD            string
	Name          string
	AuthTime      time.Time
}

// Errors.
var (
	ErrUpstream      = errors.New("upstream provider error")
	ErrLoginRequired = errors.New("upstream login required")
	ErrInvalidToken  = errors.New("upstream ID token invalid")
	ErrMissingNonce  = errors.New("upstream ID token nonce mismatch")
)

// Client caches discovery per provider.
type Client struct {
	http *http.Client
	ttl  time.Duration
	now  func() time.Time

	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	issuer string
	p      *oidc.Provider
	at     time.Time
}

// New returns a client using hc (an SSRF-guarded client in production).
func New(hc *http.Client) *Client {
	return &Client{http: hc, ttl: time.Hour, now: time.Now, cache: map[string]cached{}}
}

func (c *Client) ctx(ctx context.Context) context.Context { return oidc.ClientContext(ctx, c.http) }

func (c *Client) provider(ctx context.Context, cfg Config) (*oidc.Provider, error) {
	c.mu.Lock()
	e, ok := c.cache[cfg.ID]
	c.mu.Unlock()
	if ok && e.issuer == cfg.Issuer && c.now().Sub(e.at) < c.ttl {
		return e.p, nil
	}
	p, err := oidc.NewProvider(c.ctx(ctx), cfg.Issuer) // go-oidc rejects a discovery document whose issuer differs
	if err != nil {
		return nil, fmt.Errorf("%w: discovery: %w", ErrUpstream, err)
	}
	c.mu.Lock()
	c.cache[cfg.ID] = cached{issuer: cfg.Issuer, p: p, at: c.now()}
	c.mu.Unlock()
	return p, nil
}

// Forget drops cached discovery (after a provider is edited).
func (c *Client) Forget(id string) {
	c.mu.Lock()
	delete(c.cache, id)
	c.mu.Unlock()
}

// Secrets are generated per login attempt and stored server-side.
type Secrets struct {
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
}

// NewSecrets returns a fresh nonce and PKCE verifier.
func NewSecrets() (Secrets, error) {
	n, err := random(24)
	if err != nil {
		return Secrets{}, err
	}
	v, err := random(48)
	if err != nil {
		return Secrets{}, err
	}
	return Secrets{Nonce: n, Verifier: v}, nil
}

func random(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// AuthOptions tune the authorization request.
type AuthOptions struct {
	Prompt    string // "", none, login, select_account
	MaxAge0   bool   // require a fresh authentication
	LoginHint string
	HDHint    string // Google hd= UX hint only; never trusted as evidence
}

// AuthURL returns the authorization URL.
func (c *Client) AuthURL(ctx context.Context, cfg Config, state string, s Secrets, o AuthOptions) (string, error) {
	p, err := c.provider(ctx, cfg)
	if err != nil {
		return "", err
	}
	oc := c.oauth(cfg, p)
	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(s.Verifier), oidc.Nonce(s.Nonce)}
	if o.Prompt != "" {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", o.Prompt))
	}
	if o.MaxAge0 {
		opts = append(opts, oauth2.SetAuthURLParam("max_age", "0"))
	}
	if o.LoginHint != "" {
		opts = append(opts, oauth2.SetAuthURLParam("login_hint", o.LoginHint))
	}
	if o.HDHint != "" && cfg.Kind == "google" {
		opts = append(opts, oauth2.SetAuthURLParam("hd", o.HDHint))
	}
	return oc.AuthCodeURL(state, opts...), nil
}

func (c *Client) oauth(cfg Config, p *oidc.Provider) *oauth2.Config {
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "email", "profile"}
	}
	return &oauth2.Config{ClientID: cfg.ClientID, ClientSecret: cfg.Secret, Endpoint: p.Endpoint(), RedirectURL: cfg.RedirectURL, Scopes: scopes}
}

// Exchange trades the code for tokens and verifies the ID token: issuer, audience, signature algorithm, expiry and the
// nonce bound to this login attempt.
func (c *Client) Exchange(ctx context.Context, cfg Config, code string, s Secrets) (Claims, error) {
	p, err := c.provider(ctx, cfg)
	if err != nil {
		return Claims{}, err
	}
	tok, err := c.oauth(cfg, p).Exchange(c.ctx(ctx), code, oauth2.VerifierOption(s.Verifier))
	if err != nil {
		return Claims{}, fmt.Errorf("%w: token exchange: %w", ErrUpstream, err)
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return Claims{}, fmt.Errorf("%w: no id_token in response", ErrInvalidToken)
	}
	v := p.Verifier(&oidc.Config{ClientID: cfg.ClientID, SupportedSigningAlgs: cfg.AllowedAlgs(), Now: c.now})
	idt, err := v.Verify(c.ctx(ctx), raw)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	if idt.Nonce == "" || subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(s.Nonce)) != 1 {
		return Claims{}, ErrMissingNonce
	}
	var cl struct {
		Email         string `json:"email"`
		EmailVerified any    `json:"email_verified"`
		HD            string `json:"hd"`
		Name          string `json:"name"`
		AuthTime      int64  `json:"auth_time"`
		AZP           string `json:"azp"`
	}
	if err := idt.Claims(&cl); err != nil {
		return Claims{}, fmt.Errorf("%w: claims: %w", ErrInvalidToken, err)
	}
	if len(idt.Audience) > 1 && cl.AZP != cfg.ClientID {
		return Claims{}, fmt.Errorf("%w: multiple audiences without matching azp", ErrInvalidToken)
	}
	out := Claims{Issuer: idt.Issuer, Subject: idt.Subject, Email: strings.ToLower(strings.TrimSpace(cl.Email)), HD: strings.ToLower(cl.HD),
		Name: cl.Name, EmailVerified: truthy(cl.EmailVerified)}
	if cl.AuthTime > 0 {
		out.AuthTime = time.Unix(cl.AuthTime, 0).UTC()
	}
	if out.Subject == "" {
		return Claims{}, fmt.Errorf("%w: empty subject", ErrInvalidToken)
	}
	return out, nil
}

// truthy accepts the boolean or the string "true" (some providers send strings).
func truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x == "true"
	}
	return false
}

// PKCEChallenge is exposed for tests.
func PKCEChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

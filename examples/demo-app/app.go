package main

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

//go:embed templates/page.html static/app.css
var assets embed.FS

// app is the demo relying party.
type app struct {
	cfg      config
	log      *slog.Logger
	client   *http.Client
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	// keys is Porch's JWKS, shared by the ID token verifier and the access token inspection.
	keys     *oidc.RemoteKeySet
	oauth    *oauth2.Config
	sessions *sessionStore
	tmpl     *template.Template
	css      []byte
	csp      string
	// origin is this app's own origin (from the redirect URL), checked against the Origin header of POSTs.
	origin string
	// endSession is Porch's end_session_endpoint ("" when not advertised).
	endSession string
	// issParam is true when Porch advertises RFC 9207 (then a missing iss on the callback is an error).
	issParam bool
	now      func() time.Time
}

// newApp runs OpenID Connect discovery against cfg.Issuer and builds the app. client is used for every call to Porch.
func newApp(ctx context.Context, cfg config, logger *slog.Logger, client *http.Client) (*app, error) {
	octx := oidc.ClientContext(ctx, client)
	provider, err := oidc.NewProvider(octx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discovery at %s: %w", cfg.Issuer, err)
	}
	var meta struct {
		JWKSURI          string   `json:"jwks_uri"`
		EndSession       string   `json:"end_session_endpoint"`
		ISSParam         bool     `json:"authorization_response_iss_parameter_supported"`
		ChallengeMethods []string `json:"code_challenge_methods_supported"`
	}
	if err := provider.Claims(&meta); err != nil {
		return nil, fmt.Errorf("discovery document: %w", err)
	}
	if meta.JWKSURI == "" {
		return nil, errors.New("discovery document has no jwks_uri")
	}
	if len(meta.ChallengeMethods) > 0 && !strings.Contains(strings.Join(meta.ChallengeMethods, " "), "S256") {
		logger.Warn("issuer does not advertise PKCE S256; continuing anyway", "methods", meta.ChallengeMethods)
	}
	issuerURL, err := url.Parse(cfg.Issuer)
	if err != nil {
		return nil, err
	}
	redirectURL, err := url.Parse(cfg.RedirectURL)
	if err != nil {
		return nil, err
	}
	css, err := assets.ReadFile("static/app.css")
	if err != nil {
		return nil, err
	}
	tmpl, err := template.New("page.html").Funcs(template.FuncMap{
		"fmtTime": func(t time.Time) string {
			if t.IsZero() {
				return "never"
			}
			return t.UTC().Format(time.RFC3339)
		},
	}).ParseFS(assets, "templates/page.html")
	if err != nil {
		return nil, err
	}

	// The key set's context only configures the HTTP client; it must outlive this call.
	keys := oidc.NewRemoteKeySet(oidc.ClientContext(context.WithoutCancel(ctx), client), meta.JWKSURI)
	endpoint := provider.Endpoint()
	endpoint.AuthStyle = oauth2.AuthStyleInHeader // client_secret_basic
	issuerOrigin := issuerURL.Scheme + "://" + issuerURL.Host
	return &app{
		cfg:      cfg,
		log:      logger,
		client:   client,
		provider: provider,
		verifier: oidc.NewVerifier(cfg.Issuer, keys, &oidc.Config{ClientID: cfg.ClientID, SupportedSigningAlgs: []string{oidc.ES256, oidc.RS256}}),
		keys:     keys,
		oauth: &oauth2.Config{ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, Endpoint: endpoint, RedirectURL: cfg.RedirectURL,
			Scopes: cfg.Scopes},
		sessions:   newSessionStore(!cfg.InsecureCookies),
		tmpl:       tmpl,
		css:        css,
		csp:        "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self' " + issuerOrigin,
		origin:     redirectURL.Scheme + "://" + redirectURL.Host,
		endSession: meta.EndSession,
		issParam:   meta.ISSParam,
		now:        time.Now,
	}, nil
}

// routes returns the app's HTTP handler.
func (a *app) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", a.handleHome)
	mux.HandleFunc("GET /login", a.handleLogin)
	mux.HandleFunc("GET "+callbackPath, a.handleCallback)
	mux.HandleFunc("POST /refresh", a.handleRefresh)
	mux.HandleFunc("POST /logout", a.handleLogout)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /static/app.css", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(a.css)
	})
	return a.secure(mux)
}

// secure sets the security headers on every response and bounds request bodies.
func (a *app) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", a.csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		// same-origin: with no-referrer browsers send "Origin: null" on this app's own form posts.
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Cache-Control", "no-store")
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		next.ServeHTTP(w, r)
	})
}

// pageData feeds templates/page.html.
type pageData struct {
	Error      string
	Status     int
	Issuer     string
	CSRF       string
	Flash      string
	FlashError bool
	User       *signedIn
	Name       string
	Email      string
	Tenant     string
	HasRefresh bool
	ExpiresAt  time.Time
	ExpectAud  string
}

func (a *app) handleHome(w http.ResponseWriter, r *http.Request) {
	d := pageData{Issuer: a.cfg.Issuer, ExpectAud: a.expectedAudience()}
	if sess, ok := a.sessions.get(r); ok {
		d.CSRF = sess.CSRF
		d.Flash, d.FlashError = sess.Flash, sess.FlashError
		if sess.Flash != "" {
			sess.Flash, sess.FlashError = "", false
			a.sessions.put(sess)
		}
		if u := sess.User; u != nil {
			d.User = u
			d.Name = firstString(u.IDClaims, "name", "preferred_username", "email")
			d.Email, _ = u.IDClaims["email"].(string)
			d.Tenant = tenantLabel(u.Access.Porch)
			if d.Tenant == "" {
				porch, _ := u.IDClaims["porch"].(map[string]any)
				d.Tenant = tenantLabel(porch)
			}
			d.HasRefresh = u.Token.RefreshToken != ""
			d.ExpiresAt = u.Token.Expiry
		}
	}
	a.render(w, http.StatusOK, d)
}

func (a *app) handleLogin(w http.ResponseWriter, r *http.Request) {
	if old, ok := a.sessions.get(r); ok {
		a.sessions.drop(old.ID)
	}
	p := &pendingLogin{State: randomToken(), Nonce: randomToken(), Verifier: oauth2.GenerateVerifier(), Expires: a.now().Add(pendingLoginTTL)}
	if _, err := a.sessions.create(w, session{Pending: p}); err != nil {
		a.fail(w, http.StatusServiceUnavailable, "The demo app has too many active sessions; try again later.")
		return
	}
	opts := []oauth2.AuthCodeOption{oidc.Nonce(p.Nonce), oauth2.S256ChallengeOption(p.Verifier)}
	if a.cfg.Resource != "" {
		opts = append(opts, oauth2.SetAuthURLParam("resource", a.cfg.Resource))
	}
	a.log.Info("starting sign-in", "issuer", a.cfg.Issuer)
	http.Redirect(w, r, a.oauth.AuthCodeURL(p.State, opts...), http.StatusFound)
}

func (a *app) handleCallback(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.sessions.get(r)
	if !ok || sess.Pending == nil {
		a.fail(w, http.StatusBadRequest, "No sign-in is in progress (the session cookie is missing or expired). Start again.")
		return
	}
	p := *sess.Pending
	// The pending login is single use, whatever the outcome.
	sess.Pending = nil
	a.sessions.put(sess)

	q := r.URL.Query()
	switch {
	case a.now().After(p.Expires):
		a.fail(w, http.StatusBadRequest, "The sign-in took too long. Start again.")
		return
	case subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(p.State)) != 1:
		a.log.Warn("callback rejected", "reason", "state_mismatch")
		a.fail(w, http.StatusBadRequest, "The state parameter does not match this browser's sign-in request (possible CSRF). Start again.")
		return
	case q.Has("iss") && q.Get("iss") != a.cfg.Issuer:
		a.log.Warn("callback rejected", "reason", "iss_mismatch")
		a.fail(w, http.StatusBadRequest, fmt.Sprintf("The authorization response came from issuer %q, expected %q (RFC 9207 mix-up defence).", q.Get("iss"), a.cfg.Issuer))
		return
	case !q.Has("iss") && a.issParam:
		a.log.Warn("callback rejected", "reason", "iss_missing")
		a.fail(w, http.StatusBadRequest, "The authorization response has no iss parameter although the issuer advertises RFC 9207 support.")
		return
	case q.Get("error") != "":
		a.log.Info("authorization error", "error", q.Get("error"))
		msg := "Porch returned an error: " + q.Get("error")
		if desc := q.Get("error_description"); desc != "" {
			msg += " (" + desc + ")"
		}
		a.fail(w, http.StatusBadRequest, msg)
		return
	case q.Get("code") == "":
		a.fail(w, http.StatusBadRequest, "The authorization response has no code.")
		return
	}

	ctx := context.WithValue(r.Context(), oauth2.HTTPClient, a.client)
	opts := []oauth2.AuthCodeOption{oauth2.VerifierOption(p.Verifier)}
	if a.cfg.Resource != "" {
		opts = append(opts, oauth2.SetAuthURLParam("resource", a.cfg.Resource))
	}
	tok, err := a.oauth.Exchange(ctx, q.Get("code"), opts...)
	if err != nil {
		a.log.Warn("code exchange failed", "error_code", oauthErrorCode(err))
		a.fail(w, http.StatusBadGateway, "Exchanging the authorization code failed: "+oauthErrorText(err))
		return
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		a.fail(w, http.StatusBadGateway, "The token response has no id_token.")
		return
	}
	idt, err := a.verifier.Verify(ctx, rawID)
	if err != nil {
		a.log.Warn("id token rejected", "reason", "verify")
		a.fail(w, http.StatusBadGateway, "The ID token failed verification: "+err.Error())
		return
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(p.Nonce)) != 1 {
		a.log.Warn("id token rejected", "reason", "nonce_mismatch")
		a.fail(w, http.StatusBadRequest, "The ID token nonce does not match this sign-in request (possible replay).")
		return
	}
	if idt.AccessTokenHash != "" {
		if err := idt.VerifyAccessToken(tok.AccessToken); err != nil {
			a.fail(w, http.StatusBadGateway, "The ID token at_hash does not match the access token.")
			return
		}
	}
	u, err := a.describe(ctx, tok, rawID, idt)
	if err != nil {
		a.fail(w, http.StatusBadGateway, err.Error())
		return
	}
	u.SignedInAt = a.now()
	// Rotate the session ID at the privilege change (session fixation defence).
	a.sessions.drop(sess.ID)
	if _, err := a.sessions.create(w, session{User: u, Flash: "Signed in."}); err != nil {
		a.fail(w, http.StatusServiceUnavailable, "The demo app has too many active sessions; try again later.")
		return
	}
	a.log.Info("signed in", "sub", u.Subject)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// describe builds the signed-in view: verified ID token claims, the inspected access token and the userinfo response.
func (a *app) describe(ctx context.Context, tok *oauth2.Token, rawID string, idt *oidc.IDToken) (*signedIn, error) {
	var raw json.RawMessage
	if err := idt.Claims(&raw); err != nil {
		return nil, fmt.Errorf("decoding ID token claims: %w", err)
	}
	claims := map[string]any{}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, fmt.Errorf("decoding ID token claims: %w", err)
	}
	u := &signedIn{Token: tok, RawIDToken: rawID, Subject: idt.Subject, IDClaims: claims, IDClaimsRaw: prettyJSON(raw)}
	a.inspect(ctx, u)
	return u, nil
}

// inspect fills the access token and userinfo views of u from u.Token.
func (a *app) inspect(ctx context.Context, u *signedIn) {
	u.Access = inspectAccessToken(ctx, a.keys, a.cfg.Issuer, a.expectedAudience(), a.now(), u.Token.AccessToken)
	u.UserInfo, u.UserInfoErr = "", ""
	if a.provider.UserInfoEndpoint() == "" {
		u.UserInfoErr = "Porch does not advertise a userinfo_endpoint."
		return
	}
	info, err := a.provider.UserInfo(oidc.ClientContext(ctx, a.client), oauth2.StaticTokenSource(u.Token))
	if err != nil {
		u.UserInfoErr = "UserInfo request failed: " + err.Error()
		return
	}
	var infoRaw json.RawMessage
	switch {
	case info.Claims(&infoRaw) != nil:
		u.UserInfoErr = "UserInfo response is not JSON."
	case info.Subject != u.Subject:
		u.UserInfoErr = "UserInfo sub does not match the ID token sub; response discarded."
	default:
		u.UserInfo = prettyJSON(infoRaw)
	}
}

func (a *app) handleRefresh(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.checkPost(w, r)
	if !ok {
		return
	}
	if sess.User == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	old := sess.User
	if old.Token.RefreshToken == "" {
		sess.Flash, sess.FlashError = "No refresh token: request the offline_access scope (DEMO_SCOPES) to get one.", true
		a.sessions.put(sess)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	ctx := context.WithValue(r.Context(), oauth2.HTTPClient, a.client)
	// A token with no access token is always refreshed.
	tok, err := a.oauth.TokenSource(ctx, &oauth2.Token{RefreshToken: old.Token.RefreshToken}).Token()
	if err != nil {
		a.log.Warn("refresh failed", "error_code", oauthErrorCode(err))
		u := *old
		if oauthErrorCode(err) == "invalid_grant" {
			// Rotated, revoked or expired: the refresh token is dead.
			t := *old.Token
			t.RefreshToken = ""
			u.Token = &t
		}
		sess.User = &u
		sess.Flash, sess.FlashError = "Refreshing failed: "+oauthErrorText(err), true
		a.sessions.put(sess)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	rawID, idt := old.RawIDToken, (*oidc.IDToken)(nil)
	if s, _ := tok.Extra("id_token").(string); s != "" {
		idt, err = a.verifier.Verify(ctx, s)
		if err != nil || idt.Subject != old.Subject || (idt.AccessTokenHash != "" && idt.VerifyAccessToken(tok.AccessToken) != nil) {
			a.log.Warn("refreshed id token rejected", "sub", old.Subject)
			// Keep the previous tokens for display, but the old refresh token was consumed by the rotation.
			u, t := *old, *old.Token
			t.RefreshToken = ""
			u.Token = &t
			sess.User = &u
			sess.Flash, sess.FlashError = "Porch returned a refreshed ID token that failed verification; the new tokens were discarded.", true
			a.sessions.put(sess)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		rawID = s
	}
	var u *signedIn
	if idt != nil {
		if u, err = a.describe(ctx, tok, rawID, idt); err != nil {
			a.fail(w, http.StatusBadGateway, err.Error())
			return
		}
	} else {
		// No new ID token: keep the verified one, re-inspect the new access token.
		cp := *old
		cp.Token = tok
		u = &cp
		a.inspect(ctx, u)
	}
	u.SignedInAt, u.RefreshedAt = old.SignedInAt, a.now()
	sess.User = u
	msg := "Tokens refreshed."
	if tok.RefreshToken != old.Token.RefreshToken {
		msg += " Porch rotated the refresh token; the previous one is now invalid."
	}
	sess.Flash, sess.FlashError = msg, false
	a.sessions.put(sess)
	a.log.Info("tokens refreshed", "sub", u.Subject)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *app) handleLogout(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.checkPost(w, r)
	if !ok {
		return
	}
	a.sessions.destroy(w, sess.ID)
	if sess.User == nil || a.endSession == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	a.log.Info("signed out locally; redirecting to end_session", "sub", sess.User.Subject)
	target, err := url.Parse(a.endSession)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	q := target.Query()
	q.Set("id_token_hint", sess.User.RawIDToken)
	q.Set("client_id", a.cfg.ClientID)
	if a.cfg.PostLogoutURL != "" {
		q.Set("post_logout_redirect_uri", a.cfg.PostLogoutURL)
		q.Set("state", randomToken())
	}
	target.RawQuery = q.Encode()
	http.Redirect(w, r, target.String(), http.StatusSeeOther)
}

// checkPost validates a state-changing form post: same-origin (when the browser says), a live session and its CSRF
// token. It writes the error response itself.
func (a *app) checkPost(w http.ResponseWriter, r *http.Request) (session, bool) {
	// "null" happens for opaque origins; then rely on Fetch Metadata. The per-session CSRF token is checked below either way.
	if o := r.Header.Get("Origin"); o != "" && o != a.origin && (o != "null" || r.Header.Get("Sec-Fetch-Site") != "same-origin") {
		a.fail(w, http.StatusForbidden, "Cross-origin form post refused.")
		return session{}, false
	}
	sess, ok := a.sessions.get(r)
	if !ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return session{}, false
	}
	if err := r.ParseForm(); err != nil || !validCSRF(sess, r.PostForm.Get("csrf")) {
		a.log.Warn("form post rejected", "reason", "csrf")
		a.fail(w, http.StatusForbidden, "The form's CSRF token is missing or wrong. Reload the page and try again.")
		return session{}, false
	}
	return sess, true
}

// expectedAudience is the aud a Porch access token for this app must carry (RFC 8707 resource, else client_id).
func (a *app) expectedAudience() string {
	if a.cfg.Resource != "" {
		return a.cfg.Resource
	}
	return a.cfg.ClientID
}

func (a *app) fail(w http.ResponseWriter, status int, msg string) {
	a.render(w, status, pageData{Error: msg, Status: status, Issuer: a.cfg.Issuer})
}

func (a *app) render(w http.ResponseWriter, status int, d pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := a.tmpl.Execute(w, d); err != nil {
		a.log.Error("rendering page", "error", err)
	}
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func oauthErrorCode(err error) string {
	if re, ok := errors.AsType[*oauth2.RetrieveError](err); ok && re.ErrorCode != "" {
		return re.ErrorCode
	}
	return "transport"
}

// oauthErrorText describes a token endpoint failure without echoing the raw response body.
func oauthErrorText(err error) string {
	if re, ok := errors.AsType[*oauth2.RetrieveError](err); ok {
		if re.ErrorCode == "" {
			return re.Response.Status
		}
		if re.ErrorDescription != "" {
			return re.ErrorCode + " (" + re.ErrorDescription + ")"
		}
		return re.ErrorCode
	}
	return "could not reach the token endpoint"
}

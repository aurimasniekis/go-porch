package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"

	"github.com/aurimasniekis/go-porch/internal/idp/fakeidp"
)

const (
	testClientID = "demo-client"
	testSecret   = "demo-secret"
	testSubject  = "user-ada"
	testResource = "https://api.example.com"
)

// testOP wraps fakeidp with the Porch features fakeidp lacks: userinfo, end_session, RFC 9207 metadata, rotating
// refresh tokens and (optionally) RFC 9068 JWT access tokens signed with an extra ES256 key published in the JWKS.
type testOP struct {
	t   *testing.T
	idp *fakeidp.IdP
	srv *httptest.Server
	key *ecdsa.PrivateKey

	mu         sync.Mutex
	jwtAccess  bool
	access     map[string]string // access token → sub
	refresh    map[string]string // live refresh token → sub
	refreshes  int
	endSession url.Values
}

func newTestOP(t *testing.T, jwtAccess bool) *testOP {
	t.Helper()
	idp, err := fakeidp.New("")
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	op := &testOP{t: t, idp: idp, key: key, jwtAccess: jwtAccess, access: map[string]string{}, refresh: map[string]string{}}
	op.srv = httptest.NewServer(http.HandlerFunc(op.serve))
	t.Cleanup(op.srv.Close)
	idp.SetIssuer(op.srv.URL)
	idp.AddUser(fakeidp.User{Subject: testSubject, Email: "ada@example.com", EmailVerified: true, Name: "Ada Lovelace"})
	idp.AddUser(fakeidp.User{Subject: "user-gone", Email: "gone@example.com", Name: "Gone", Disabled: true})
	idp.Set(func(i *fakeidp.IdP) { i.Current = testSubject })
	return op
}

// forward runs the request against fakeidp and returns the recorded response.
func (op *testOP) forward(r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	op.idp.Handler().ServeHTTP(rec, r)
	return rec
}

func (op *testOP) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		var meta map[string]any
		if err := json.Unmarshal(op.forward(r).Body.Bytes(), &meta); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		meta["userinfo_endpoint"] = op.srv.URL + "/userinfo"
		meta["end_session_endpoint"] = op.srv.URL + "/end_session"
		meta["authorization_response_iss_parameter_supported"] = true
		meta["id_token_signing_alg_values_supported"] = []string{"ES256", "RS256"}
		writeTestJSON(w, http.StatusOK, meta)
	case "/jwks":
		var set jose.JSONWebKeySet
		if err := json.Unmarshal(op.forward(r).Body.Bytes(), &set); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		set.Keys = append(set.Keys, jose.JSONWebKey{Key: &op.key.PublicKey, KeyID: "at-key", Algorithm: "ES256", Use: "sig"})
		writeTestJSON(w, http.StatusOK, set)
	case "/token":
		op.token(w, r)
	case "/userinfo":
		op.mu.Lock()
		sub, ok := op.access[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		op.mu.Unlock()
		if !ok {
			http.Error(w, "invalid_token", http.StatusUnauthorized)
			return
		}
		writeTestJSON(w, http.StatusOK, map[string]any{"sub": sub, "email": "ada@example.com", "porch": map[string]any{"v": 1}})
	case "/end_session":
		op.mu.Lock()
		op.endSession = r.URL.Query()
		op.mu.Unlock()
		if target := r.URL.Query().Get("post_logout_redirect_uri"); target != "" {
			http.Redirect(w, r, target+"?state="+url.QueryEscape(r.URL.Query().Get("state")), http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "signed out")
	default:
		op.idp.Handler().ServeHTTP(w, r)
	}
}

func (op *testOP) token(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if id, secret, ok := r.BasicAuth(); !ok || id != testClientID || secret != testSecret {
		writeTestJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	if form.Get("grant_type") == "refresh_token" {
		op.mu.Lock()
		sub, ok := op.refresh[form.Get("refresh_token")]
		delete(op.refresh, form.Get("refresh_token")) // rotation: single use
		op.refreshes++
		op.mu.Unlock()
		if !ok {
			writeTestJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "refresh token reused"})
			return
		}
		writeTestJSON(w, http.StatusOK, op.mint(sub, map[string]any{"token_type": "Bearer", "expires_in": 600}))
		return
	}
	fr := r.Clone(r.Context())
	fr.Body = io.NopCloser(bytes.NewReader(body))
	rec := op.forward(fr)
	if rec.Code != http.StatusOK {
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
		return
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	idt, _ := resp["id_token"].(string)
	parts := strings.Split(idt, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims struct {
		Sub string `json:"sub"`
	}
	_ = json.Unmarshal(payload, &claims)
	writeTestJSON(w, http.StatusOK, op.mint(claims.Sub, resp))
}

// mint adds a fresh access token (JWT or opaque) and refresh token for sub to resp.
func (op *testOP) mint(sub string, resp map[string]any) map[string]any {
	at := "opaque-at-" + randomToken()
	if op.jwtAccess {
		claims := map[string]any{"iss": op.srv.URL, "sub": sub, "aud": []string{testResource}, "client_id": testClientID,
			"exp": time.Now().Add(10 * time.Minute).Unix(), "iat": time.Now().Unix(), "jti": randomToken(), "scope": "openid profile",
			"porch": map[string]any{"v": 1, "tenant": map[string]any{"id": "tnt_123", "slug": "acme"}, "roles": []string{"admin"}}}
		at = signTestJWT(op.t, op.key, "at-key", "at+jwt", claims)
	}
	rt := "rt-" + randomToken()
	op.mu.Lock()
	op.access[at] = sub
	op.refresh[rt] = sub
	op.mu.Unlock()
	resp["access_token"], resp["refresh_token"] = at, rt
	return resp
}

func signTestJWT(t *testing.T, key *ecdsa.PrivateKey, kid, typ string, claims map[string]any) string {
	t.Helper()
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: key, KeyID: kid}},
		(&jose.SignerOptions{}).WithType(jose.ContentType(typ)))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := s.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	out, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func writeTestJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// lockedBuffer collects logs from concurrent handlers.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type harness struct {
	op       *testOP
	app      *app
	srv      *httptest.Server
	client   *http.Client
	noFollow *http.Client
	logs     *lockedBuffer
}

func newHarness(t *testing.T, jwtAccess bool, mutate func(*config)) *harness {
	t.Helper()
	op := newTestOP(t, jwtAccess)
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	cfg := config{Issuer: op.srv.URL, ClientID: testClientID, ClientSecret: testSecret, RedirectURL: srv.URL + callbackPath,
		PostLogoutURL: srv.URL + "/", Scopes: strings.Fields(defaultScopes), Listen: defaultListen, InsecureCookies: true}
	if jwtAccess {
		cfg.Resource = testResource
	}
	if mutate != nil {
		mutate(&cfg)
	}
	op.idp.AddClient(fakeidp.Client{ID: testClientID, Secret: testSecret, RedirectURIs: []string{cfg.RedirectURL}})
	logs := &lockedBuffer{}
	a, err := newApp(t.Context(), cfg, slog.New(slog.NewJSONHandler(logs, nil)), &http.Client{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle("/", a.routes())
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	noFollow := &http.Client{Jar: jar, Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &harness{op: op, app: a, srv: srv, client: client, noFollow: noFollow, logs: logs}
}

func (h *harness) get(t *testing.T, c *http.Client, u string) (*http.Response, string) {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(b)
}

func (h *harness) post(t *testing.T, c *http.Client, path string, form url.Values) (*http.Response, string) {
	t.Helper()
	resp, err := c.PostForm(h.srv.URL+path, form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(b)
}

// signIn runs the whole flow, following redirects, and returns the landing page.
func (h *harness) signIn(t *testing.T) string {
	t.Helper()
	resp, body := h.get(t, h.client, h.srv.URL+"/login")
	if resp.StatusCode != http.StatusOK || resp.Request.URL.Path != "/" {
		t.Fatalf("sign-in landed on %s with %d:\n%s", resp.Request.URL, resp.StatusCode, body)
	}
	return body
}

// callbackURL starts a login and lets the OP answer, returning the (not yet visited) callback URL.
func (h *harness) callbackURL(t *testing.T) *url.URL {
	t.Helper()
	resp, _ := h.get(t, h.noFollow, h.srv.URL+"/login")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("/login = %d", resp.StatusCode)
	}
	resp, body := h.get(t, h.noFollow, resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize = %d: %s", resp.StatusCode, body)
	}
	u, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

var csrfRE = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func csrfFrom(t *testing.T, page string) string {
	t.Helper()
	m := csrfRE.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no CSRF token in page:\n%s", page)
	}
	return m[1]
}

func mustContain(t *testing.T, body string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(body, w) {
			t.Errorf("page does not contain %q", w)
		}
	}
	if t.Failed() {
		t.Logf("page:\n%s", body)
	}
}

func assertSignedOut(t *testing.T, h *harness) {
	t.Helper()
	_, body := h.get(t, h.client, h.srv.URL+"/")
	mustContain(t, body, "You are signed out", "Sign in with Porch")
}

func TestSignInShowsVerifiedTokens(t *testing.T) {
	h := newHarness(t, true, nil)
	body := h.signIn(t)
	mustContain(t, body,
		"Signed in as Ada Lovelace",
		`<code id="subject">`+testSubject+`</code>`,
		"ada@example.com",
		"acme (tnt_123)",
		"ID token claims",
		`&#34;email_verified&#34;: true`,
		"decoded, verified by signature against Porch JWKS",
		`&#34;typ&#34;: &#34;at&#43;jwt&#34;`,
		`&#34;roles&#34;: [`,
		"UserInfo response",
		`&#34;sub&#34;: &#34;`+testSubject+`&#34;`,
		"present (opaque, rotating; not shown)",
	)
	if strings.Contains(body, "FAIL") {
		t.Errorf("a check failed:\n%s", body)
	}

	var q url.Values
	h.op.idp.Set(func(i *fakeidp.IdP) { q = i.LastAuthorize })
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("nonce") == "" || q.Get("state") == "" {
		t.Errorf("authorization request lacks PKCE/nonce/state: %v", q)
	}
	if q.Get("resource") != testResource {
		t.Errorf("resource = %q, want %q", q.Get("resource"), testResource)
	}
	if q.Get("scope") != defaultScopes {
		t.Errorf("scope = %q", q.Get("scope"))
	}

	// Tokens are never logged.
	h.op.mu.Lock()
	var secrets []string
	for at := range h.op.access {
		secrets = append(secrets, at)
	}
	for rt := range h.op.refresh {
		secrets = append(secrets, rt)
	}
	h.op.mu.Unlock()
	logs := h.logs.String()
	for _, s := range secrets {
		if strings.Contains(logs, s) {
			t.Errorf("a token appears in the logs")
		}
	}
	if !strings.Contains(logs, `"msg":"signed in"`) {
		t.Errorf("expected a signed-in log line, got:\n%s", logs)
	}
}

func TestOpaqueAccessTokenIsShownAsOpaque(t *testing.T) {
	h := newHarness(t, false, nil)
	body := h.signIn(t)
	mustContain(t, body, `<code id="subject">`+testSubject+`</code>`, "Opaque access token", "not a JWT")
	if strings.Contains(body, "verified by signature against Porch JWKS") {
		t.Error("an opaque token must not be labelled as verified")
	}
}

func TestStateMismatchIsRejected(t *testing.T) {
	h := newHarness(t, false, nil)
	cb := h.callbackURL(t)
	q := cb.Query()
	q.Set("state", "attacker-state")
	cb.RawQuery = q.Encode()
	resp, body := h.get(t, h.client, cb.String())
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	mustContain(t, body, "state parameter does not match")
	assertSignedOut(t, h)
}

func TestCallbackIsSingleUse(t *testing.T) {
	h := newHarness(t, false, nil)
	cb := h.callbackURL(t)
	if resp, body := h.get(t, h.noFollow, cb.String()); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("first callback = %d: %s", resp.StatusCode, body)
	}
	resp, body := h.get(t, h.noFollow, cb.String())
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("replayed callback = %d, want 400", resp.StatusCode)
	}
	mustContain(t, body, "No sign-in is in progress")
}

func TestIssuerMismatchIsRejected(t *testing.T) {
	h := newHarness(t, false, nil)
	for name, tc := range map[string]struct {
		edit func(url.Values)
		want string
	}{
		"wrong": {func(q url.Values) { q.Set("iss", "https://evil.example") }, "came from issuer &#34;https://evil.example&#34;"},
		// Discovery advertises RFC 9207, so a missing iss is also refused.
		"missing": {func(q url.Values) { q.Del("iss") }, "has no iss parameter"},
	} {
		t.Run(name, func(t *testing.T) {
			cb := h.callbackURL(t)
			q := cb.Query()
			tc.edit(q)
			cb.RawQuery = q.Encode()
			resp, body := h.get(t, h.client, cb.String())
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", resp.StatusCode)
			}
			mustContain(t, body, tc.want)
			assertSignedOut(t, h)
		})
	}
}

func TestNonceMismatchIsRejected(t *testing.T) {
	h := newHarness(t, false, nil)
	h.op.idp.Set(func(i *fakeidp.IdP) { i.Mutate = func(c map[string]any) { c["nonce"] = "replayed-nonce" } })
	resp, body := h.get(t, h.client, h.srv.URL+"/login")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	mustContain(t, body, "nonce does not match")
	assertSignedOut(t, h)
}

func TestIDTokenForOtherAudienceIsRejected(t *testing.T) {
	h := newHarness(t, false, nil)
	h.op.idp.Set(func(i *fakeidp.IdP) { i.Mutate = func(c map[string]any) { c["aud"] = "someone-else" } })
	resp, body := h.get(t, h.client, h.srv.URL+"/login")
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	mustContain(t, body, "ID token failed verification")
	assertSignedOut(t, h)
}

func TestAuthorizationErrorIsShown(t *testing.T) {
	h := newHarness(t, false, nil)
	h.op.idp.Set(func(i *fakeidp.IdP) { i.Current = "user-gone" })
	resp, body := h.get(t, h.client, h.srv.URL+"/login")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	// fakeidp's error redirect carries no iss; discovery advertises RFC 9207, so the response is refused before the error
	// is trusted. Without RFC 9207 metadata the error itself is shown.
	mustContain(t, body, "no iss parameter")

	h2 := newHarness(t, false, nil)
	h2.app.issParam = false
	h2.op.idp.Set(func(i *fakeidp.IdP) { i.Current = "user-gone" })
	resp, body = h2.get(t, h2.client, h2.srv.URL+"/login")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	mustContain(t, body, "Porch returned an error: access_denied")
}

func TestRefreshRotatesTokens(t *testing.T) {
	h := newHarness(t, true, nil)
	page := h.signIn(t)
	csrf := csrfFrom(t, page)

	// Without (or with a wrong) CSRF token the form post is refused.
	for _, bad := range []url.Values{{}, {"csrf": {"wrong"}}} {
		resp, _ := h.post(t, h.client, "/refresh", bad)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("refresh with csrf=%q: status %d, want 403", bad.Get("csrf"), resp.StatusCode)
		}
	}
	// A cross-origin post is refused even with the right token.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, h.srv.URL+"/refresh", strings.NewReader(url.Values{"csrf": {csrf}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example")
	resp, err := h.noFollow.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin refresh: status %d, want 403", resp.StatusCode)
	}

	h.op.mu.Lock()
	before := len(h.op.access)
	h.op.mu.Unlock()
	resp, body := h.post(t, h.client, "/refresh", url.Values{"csrf": {csrf}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh: status %d", resp.StatusCode)
	}
	mustContain(t, body, "Tokens refreshed.", "Porch rotated the refresh token", "verified by signature against Porch JWKS",
		`<code id="subject">`+testSubject+`</code>`)
	h.op.mu.Lock()
	refreshes, after, live := h.op.refreshes, len(h.op.access), len(h.op.refresh)
	h.op.mu.Unlock()
	if refreshes != 1 || after != before+1 || live != 1 {
		t.Errorf("refreshes=%d access tokens %d→%d live refresh tokens=%d", refreshes, before, after, live)
	}

	// The OP now rejects the current refresh token: the app reports it and drops it.
	h.op.mu.Lock()
	clear(h.op.refresh)
	h.op.mu.Unlock()
	_, body = h.post(t, h.client, "/refresh", url.Values{"csrf": {csrf}})
	mustContain(t, body, "Refreshing failed: invalid_grant (refresh token reused)", `<dd id="refresh-token">none</dd>`)
}

func TestLogoutClearsSessionAndEndsPorchSession(t *testing.T) {
	h := newHarness(t, false, nil)
	page := h.signIn(t)
	csrf := csrfFrom(t, page)

	if resp, _ := h.post(t, h.noFollow, "/logout", url.Values{"csrf": {"wrong"}}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("logout with a wrong CSRF token: status %d, want 403", resp.StatusCode)
	}
	resp, body := h.post(t, h.client, "/logout", url.Values{"csrf": {csrf}})
	if resp.StatusCode != http.StatusOK || resp.Request.URL.Path != "/" {
		t.Fatalf("logout landed on %s (%d)", resp.Request.URL, resp.StatusCode)
	}
	mustContain(t, body, "You are signed out")

	h.op.mu.Lock()
	es := h.op.endSession
	h.op.mu.Unlock()
	if es.Get("id_token_hint") == "" || es.Get("post_logout_redirect_uri") != h.srv.URL+"/" || es.Get("state") == "" ||
		es.Get("client_id") != testClientID {
		t.Errorf("end_session query = %v", es)
	}
	assertSignedOut(t, h)
	// The old session is gone server-side too.
	h.app.sessions.mu.Lock()
	n := len(h.app.sessions.m)
	h.app.sessions.mu.Unlock()
	if n != 0 {
		t.Errorf("%d sessions remain after logout", n)
	}
}

func TestSecurityHeadersStaticAndHealth(t *testing.T) {
	h := newHarness(t, false, nil)
	resp, body := h.get(t, h.client, h.srv.URL+"/")
	csp := resp.Header.Get("Content-Security-Policy")
	want := "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self' " + h.op.srv.URL
	if csp != want {
		t.Errorf("CSP = %q, want %q", csp, want)
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" || resp.Header.Get("Referrer-Policy") != "same-origin" {
		t.Errorf("missing security headers: %v", resp.Header)
	}
	mustContain(t, body, `<html lang="en">`, `<link rel="stylesheet" href="/static/app.css">`)
	if strings.Contains(body, "<style") || strings.Contains(body, "<script") || strings.Contains(body, "style=") {
		t.Error("page has inline style or script, which the CSP forbids")
	}

	resp, body = h.get(t, h.client, h.srv.URL+"/static/app.css")
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/css") || !strings.Contains(body, "body") {
		t.Errorf("app.css: %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	resp, body = h.get(t, h.client, h.srv.URL+"/healthz")
	if resp.StatusCode != http.StatusOK || body != "ok\n" {
		t.Errorf("healthz: %d %q", resp.StatusCode, body)
	}
	if resp, _ := h.get(t, h.client, h.srv.URL+"/nope"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown path: %d", resp.StatusCode)
	}
}

func TestSecureCookies(t *testing.T) {
	h := newHarness(t, false, func(c *config) { c.InsecureCookies = false })
	resp, _ := h.get(t, h.noFollow, h.srv.URL+"/login")
	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %v", cookies)
	}
	c := cookies[0]
	if c.Name != "__Host-porch_demo" || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" {
		t.Errorf("cookie = %+v", c)
	}
}

func TestInspectAccessToken(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, http.StatusOK, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "ES256", Use: "sig"}}})
	}))
	defer jwks.Close()
	keys := oidc.NewRemoteKeySet(t.Context(), jwks.URL)
	const iss, aud = "https://porch.example", "https://api.example.com"
	now := time.Now()
	claims := func(edit func(map[string]any)) map[string]any {
		c := map[string]any{"iss": iss, "aud": aud, "sub": "s", "exp": now.Add(time.Minute).Unix(),
			"porch": map[string]any{"v": 1, "tenant": map[string]any{"id": "t1", "slug": "acme"}}}
		if edit != nil {
			edit(c)
		}
		return c
	}
	hs256 := func() string {
		s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("0123456789abcdef0123456789abcdef")},
			(&jose.SignerOptions{}).WithType("at+jwt"))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(claims(nil))
		obj, err := s.Sign(b)
		if err != nil {
			t.Fatal(err)
		}
		out, _ := obj.CompactSerialize()
		return out
	}

	tests := []struct {
		name               string
		raw                string
		wantJWT, wantValid bool
		failing            string
	}{
		{"valid", signTestJWT(t, key, "k1", "at+jwt", claims(nil)), true, true, ""},
		{"application typ", signTestJWT(t, key, "k1", "application/at+jwt", claims(nil)), true, true, ""},
		{"aud array", signTestJWT(t, key, "k1", "at+jwt", claims(func(c map[string]any) { c["aud"] = []string{"x", aud} })), true, true, ""},
		{"id token typ", signTestJWT(t, key, "k1", "JWT", claims(nil)), true, false, "typ"},
		{"foreign key", signTestJWT(t, other, "k1", "at+jwt", claims(nil)), true, false, "Signature"},
		{"hmac", hs256(), true, false, "Signature"},
		{"wrong aud", signTestJWT(t, key, "k1", "at+jwt", claims(func(c map[string]any) { c["aud"] = "client" })), true, false, "aud"},
		{"wrong iss", signTestJWT(t, key, "k1", "at+jwt", claims(func(c map[string]any) { c["iss"] = "https://evil" })), true, false, "iss"},
		{"expired", signTestJWT(t, key, "k1", "at+jwt", claims(func(c map[string]any) { c["exp"] = now.Add(-time.Minute).Unix() })), true, false, "expired"},
		{"opaque", "fake-at-abc", false, false, ""},
		{"three dots but not a JWT", "a.b.c", false, false, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := inspectAccessToken(context.Background(), keys, iss, aud, now, tc.raw)
			if v.JWT != tc.wantJWT || v.Verified != tc.wantValid {
				t.Fatalf("JWT=%v Verified=%v, want %v/%v; checks %+v", v.JWT, v.Verified, tc.wantJWT, tc.wantValid, v.Checks)
			}
			if v.Length != len(tc.raw) {
				t.Errorf("Length = %d", v.Length)
			}
			if tc.wantValid && tenantLabel(v.Porch) != "acme (t1)" {
				t.Errorf("tenant = %q", tenantLabel(v.Porch))
			}
			if !tc.wantValid && v.Porch != nil {
				t.Error("porch claim of an unverified token must not be used")
			}
			if tc.failing != "" {
				found := false
				for _, c := range v.Checks {
					if !c.OK && strings.Contains(c.Name, tc.failing) {
						found = true
					}
				}
				if !found {
					t.Errorf("no failing check mentioning %q: %+v", tc.failing, v.Checks)
				}
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	base := map[string]string{"PORCH_ISSUER": "https://porch.example", "DEMO_CLIENT_ID": "id", "DEMO_CLIENT_SECRET": "secret"}

	cfg, err := loadConfig(env(base))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != defaultListen || strings.Join(cfg.Scopes, " ") != defaultScopes || cfg.RedirectURL != "http://localhost:9090/callback" ||
		cfg.InsecureCookies {
		t.Errorf("defaults: %+v", cfg)
	}

	_, err = loadConfig(env(map[string]string{}))
	if err == nil || !strings.Contains(err.Error(), "PORCH_ISSUER is required") || !strings.Contains(err.Error(), "DEMO_CLIENT_ID is required") {
		t.Errorf("empty env: %v", err)
	}

	for k, v := range map[string]string{
		"PORCH_ISSUER":          "porch.example",
		"DEMO_REDIRECT_URL":     "http://localhost:9090/cb",
		"DEMO_POST_LOGOUT_URL":  "/",
		"DEMO_RESOURCE":         "api",
		"DEMO_SCOPES":           "profile email",
		"DEMO_LISTEN":           "9090",
		"DEMO_INSECURE_COOKIES": "maybe",
		"DEMO_CA_FILE":          "/does/not/exist.pem",
	} {
		m := map[string]string{}
		for bk, bv := range base {
			m[bk] = bv
		}
		m[k] = v
		if _, err := loadConfig(env(m)); err == nil || !strings.Contains(err.Error(), k) {
			t.Errorf("%s=%q: error %v should name the variable", k, v, err)
		}
	}
}

func TestCustomCAFile(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "hi") }))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	plain, err := newHTTPClient("")
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := plain.Get(srv.URL); err == nil {
		resp.Body.Close()
		t.Fatal("a self-signed server must not be trusted without DEMO_CA_FILE")
	}
	trusted, err := newHTTPClient(path)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := trusted.Get(srv.URL)
	if err != nil {
		t.Fatalf("with DEMO_CA_FILE: %v", err)
	}
	resp.Body.Close()

	bad := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(bad, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newHTTPClient(bad); err == nil {
		t.Error("a file without certificates must be refused")
	}
}

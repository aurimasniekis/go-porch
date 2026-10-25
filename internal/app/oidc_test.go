package app_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"

	"github.com/aurimasniekis/go-porch/internal/apps"
	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/authz"
	"github.com/aurimasniekis/go-porch/internal/domain"
	"github.com/aurimasniekis/go-porch/internal/idp"
	"github.com/aurimasniekis/go-porch/internal/idp/fakeidp"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/tenancy"
)

const rpRedirect = "https://rp.example/cb"

// rp is a test relying party registered in a tenant.
type rp struct {
	st       *stack
	clientID string
	secret   string
	app      apps.Application
}

func (st *stack) newRP(t *testing.T, tn tenancy.Tenant, slug string, cp apps.ClientParams) *rp {
	t.Helper()
	sc, _ := st.a.Tenants.SystemScope(context.Background(), tn.ID)
	if cp.Type == "" {
		cp.Type = "confidential"
	}
	if cp.RedirectURIs == nil {
		cp.RedirectURIs = []string{rpRedirect}
	}
	if cp.GrantTypes == nil {
		cp.GrantTypes = []string{"authorization_code", "refresh_token"}
	}
	cr, err := st.a.Apps.Create(context.Background(), domain.SystemChange, sc, apps.CreateParams{Slug: slug, Name: slug, Kind: apps.KindOIDC,
		Disclosure: &apps.Disclosure{Email: true, Groups: true, Roles: true}, Client: &cp})
	if err != nil {
		t.Fatal(err)
	}
	return &rp{st: st, clientID: cr.Client.ID, secret: cr.Secret, app: cr.App}
}

func pkce() (verifier, challenge string) {
	verifier = strings.Repeat("v", 43) + randSuffix()
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

var counter int

func randSuffix() string {
	counter++
	return strings.Repeat("x", counter%5) + string(rune('a'+counter%26))
}

// authorize drives the browser through /oauth2/authorize until the redirect to the RP and returns that URL's query.
func (b *browser) authorize(t *testing.T, params url.Values) url.Values {
	t.Helper()
	var final *url.URL
	c := *b.c
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Host == "rp.example" {
			final = req.URL
			return http.ErrUseLastResponse
		}
		return nil
	}
	resp, err := c.Get(b.st.origin() + "/oauth2/authorize?" + params.Encode()) //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if final == nil {
		return url.Values{"_status": {resp.Status}, "_body": {string(body)}, "_url": {resp.Request.URL.String()}}
	}
	return final.Query()
}

func (r *rp) authParams(challenge string, extra map[string]string) url.Values {
	v := url.Values{"client_id": {r.clientID}, "redirect_uri": {rpRedirect}, "response_type": {"code"}, "scope": {"openid profile email offline_access groups"},
		"state": {"st-123"}, "nonce": {"n-456"}}
	if challenge != "" {
		v.Set("code_challenge", challenge)
		v.Set("code_challenge_method", "S256")
	}
	for k, x := range extra {
		if x == "" {
			v.Del(k)
		} else {
			v.Set(k, x)
		}
	}
	return v
}

type tokenResp struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int    `json:"expires_in"`
	Error        string `json:"error"`
	Scope        string `json:"scope"`
}

func (r *rp) post(t *testing.T, path string, form url.Values, auth bool) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, r.st.origin()+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if auth {
		req.SetBasicAuth(url.QueryEscape(r.clientID), url.QueryEscape(r.secret))
	}
	resp, err := r.st.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (r *rp) token(t *testing.T, form url.Values) (int, tokenResp) {
	t.Helper()
	code, raw := r.post(t, "/oauth2/token", form, true)
	b, _ := json.Marshal(raw)
	var tr tokenResp
	_ = json.Unmarshal(b, &tr)
	return code, tr
}

func (r *rp) exchange(t *testing.T, code, verifier string) (int, tokenResp) {
	return r.token(t, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {rpRedirect}, "code_verifier": {verifier}})
}

// jwtParts decodes header and claims without verification (tests only).
func jwtParts(t *testing.T, tok string) (map[string]any, map[string]any) {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWS: %q", tok)
	}
	var h, c map[string]any
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(hb, &h)
	_ = json.Unmarshal(cb, &c)
	return h, c
}

// oidcStack: Porch + fake Google + tenant smith with a JIT rule and a logged-in browser for ada.
func oidcStack(t *testing.T) (*stack, tenancy.Tenant, *browser) {
	t.Helper()
	st := newStack(t)
	tn := st.setupGoogle(nil, idp.RuleParams{Domain: "smith.example", EvidenceKind: idp.EvidenceWorkspaceHD, Mode: idp.ModeJIT})
	st.google.AddUser(workspaceUser("g-ada", "ada@smith.example", "smith.example"))
	b := st.browser()
	st.loginAs(b, "g-ada")
	return st, tn, b
}

func TestOIDCCodeFlowEndToEnd(t *testing.T) {
	st, tn, b := oidcStack(t)
	r := st.newRP(t, tn, "grafana", apps.ClientParams{Audiences: []string{"https://api.smith.example"}})
	ctx := oidc.ClientContext(context.Background(), st.srv.Client())

	// Discovery through go-oidc (validates issuer consistency).
	prov, err := oidc.NewProvider(ctx, st.origin())
	if err != nil {
		t.Fatal(err)
	}
	var disc map[string]any
	_ = prov.Claims(&disc)
	if disc["authorization_response_iss_parameter_supported"] != true || len(disc["code_challenge_methods_supported"].([]any)) != 1 {
		t.Fatalf("discovery %v", disc)
	}
	verifier, challenge := pkce()
	q := b.authorize(t, r.authParams(challenge, map[string]string{"resource": "https://api.smith.example"}))
	if q.Get("code") == "" || q.Get("state") != "st-123" || q.Get("iss") != st.origin() {
		t.Fatalf("callback %v", q)
	}
	code, tr := r.exchange(t, q.Get("code"), verifier)
	if code != http.StatusOK || tr.AccessToken == "" || tr.IDToken == "" || tr.RefreshToken == "" {
		t.Fatalf("token %d %+v", code, tr)
	}
	// ID token: verified by go-oidc for this client; nonce, auth_time, at_hash, porch claim.
	idt, err := prov.Verifier(&oidc.Config{ClientID: r.clientID, SupportedSigningAlgs: []string{"ES256"}}).Verify(ctx, tr.IDToken)
	if err != nil {
		t.Fatal(err)
	}
	var ic map[string]any
	_ = idt.Claims(&ic)
	porch := ic["porch"].(map[string]any)
	if idt.Nonce != "n-456" || ic["email"] != "ada@smith.example" || ic["email_verified"] != true || porch["tenant"].(map[string]any)["slug"] != "smith" ||
		ic["at_hash"] == nil || !strings.HasPrefix(idt.Subject, "u_") {
		t.Fatalf("id token claims %v", ic)
	}
	if err := idt.VerifyAccessToken(tr.AccessToken); err != nil {
		t.Fatalf("at_hash: %v", err)
	}
	// Access token: RFC 9068 (typ at+jwt, aud = resource, not the client), verifiable against the JWKS.
	h, ac := jwtParts(t, tr.AccessToken)
	if h["typ"] != "at+jwt" || ac["aud"].([]any)[0] != "https://api.smith.example" || ac["client_id"] != r.clientID || ac["sub"] != idt.Subject ||
		ac["jti"] == nil || !strings.Contains(ac["scope"].(string), "openid") {
		t.Fatalf("access token %v %v", h, ac)
	}
	ks := oidc.NewRemoteKeySet(ctx, st.origin()+"/jwks")
	if _, err := ks.VerifySignature(ctx, tr.AccessToken); err != nil {
		t.Fatalf("access token signature: %v", err)
	}
	// UserInfo with the access token.
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, st.origin()+"/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tr.AccessToken)
	resp, err := st.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var ui map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&ui)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || ui["sub"] != idt.Subject || ui["email"] != "ada@smith.example" {
		t.Fatalf("userinfo %d %v", resp.StatusCode, ui)
	}
	// Introspection by the confidential client.
	code, in := r.post(t, "/oauth2/introspect", url.Values{"token": {tr.AccessToken}}, true)
	if code != 200 || in["active"] != true || in["token_type"] != "access_token" {
		t.Fatalf("introspect %d %v", code, in)
	}
	code, in = r.post(t, "/oauth2/introspect", url.Values{"token": {tr.RefreshToken}}, true)
	if code != 200 || in["active"] != true || in["token_type"] != "refresh_token" {
		t.Fatalf("introspect refresh %d %v", code, in)
	}
	// Refresh rotation keeps working and returns a new refresh token.
	code, tr2 := r.token(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tr.RefreshToken}})
	if code != 200 || tr2.RefreshToken == "" || tr2.RefreshToken == tr.RefreshToken || tr2.IDToken == "" {
		t.Fatalf("refresh %d %+v", code, tr2)
	}
	// Audit chain stays valid through the whole flow.
	if res, err := audit.Verify(context.Background(), st.a.Store.R()); err != nil || !res.OK {
		t.Fatalf("audit %+v %v", res, err)
	}
}

// M3 acceptance: exact redirect URI matching; mismatches never redirect.
func TestRedirectURIExactMatch(t *testing.T) {
	st, tn, b := oidcStack(t)
	r := st.newRP(t, tn, "app", apps.ClientParams{})
	_, challenge := pkce()
	for _, bad := range []string{"https://rp.example/cb/", "https://rp.example/cb?x=1", "http://rp.example/cb", "https://rp.example/CB",
		"https://evil.example/cb", "https://rp.example.evil.example/cb", "https://rp.example/cb#frag", ""} {
		q := b.authorize(t, r.authParams(challenge, map[string]string{"redirect_uri": bad}))
		if q.Get("code") != "" || q.Get("_status") == "" || strings.HasPrefix(q.Get("_status"), "3") {
			t.Errorf("%q: redirected or issued a code: %v", bad, q)
		}
	}
}

func TestPKCEEnforced(t *testing.T) {
	st, tn, b := oidcStack(t)
	r := st.newRP(t, tn, "app", apps.ClientParams{})
	q := b.authorize(t, r.authParams("", nil))
	if q.Get("error") != "invalid_request" || q.Get("state") != "st-123" {
		t.Fatalf("missing challenge: %v", q)
	}
	v, c := pkce()
	q = b.authorize(t, r.authParams(c, map[string]string{"code_challenge_method": "plain"}))
	if q.Get("error") != "invalid_request" {
		t.Fatalf("plain: %v", q)
	}
	q = b.authorize(t, r.authParams(c, nil))
	if code, tr := r.exchange(t, q.Get("code"), v+"x"); code != 400 || tr.Error != "invalid_grant" {
		t.Fatalf("wrong verifier: %d %+v", code, tr)
	}
	q = b.authorize(t, r.authParams(c, nil))
	if code, tr := r.exchange(t, q.Get("code"), ""); code != 400 || tr.Error != "invalid_grant" {
		t.Fatalf("missing verifier: %d %+v", code, tr)
	}
	// Public clients can never opt out of PKCE.
	sc, _ := st.a.Tenants.SystemScope(context.Background(), tn.ID)
	f := false
	if _, err := st.a.Apps.Create(context.Background(), domain.SystemChange, sc, apps.CreateParams{Slug: "spa", Name: "spa", Kind: apps.KindOIDC,
		Client: &apps.ClientParams{Type: "public", RedirectURIs: []string{rpRedirect}, RequirePKCE: &f}}); err == nil {
		t.Fatal("public client without PKCE accepted")
	}
}

// M3 acceptance: code replay is refused and revokes what the first exchange issued.
func TestCodeReplayRevokes(t *testing.T) {
	st, tn, b := oidcStack(t)
	r := st.newRP(t, tn, "app", apps.ClientParams{})
	v, c := pkce()
	q := b.authorize(t, r.authParams(c, nil))
	code, tr := r.exchange(t, q.Get("code"), v)
	if code != 200 {
		t.Fatal(code)
	}
	code, tr2 := r.exchange(t, q.Get("code"), v)
	if code != 400 || tr2.Error != "invalid_grant" {
		t.Fatalf("replay: %d %+v", code, tr2)
	}
	if _, in := r.post(t, "/oauth2/introspect", url.Values{"token": {tr.AccessToken}}, true); in["active"] != false {
		t.Fatalf("access token still active after replay: %v", in)
	}
	if code, tr3 := r.token(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tr.RefreshToken}}); code != 400 || tr3.Error != "invalid_grant" {
		t.Fatalf("refresh after replay: %d %+v", code, tr3)
	}
}

// M3 acceptance: a rotated refresh token reused → the whole family is revoked.
func TestRefreshReuseRevokesFamily(t *testing.T) {
	st, tn, b := oidcStack(t)
	r := st.newRP(t, tn, "app", apps.ClientParams{})
	v, c := pkce()
	q := b.authorize(t, r.authParams(c, nil))
	_, t1 := r.exchange(t, q.Get("code"), v)
	_, t2 := r.token(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {t1.RefreshToken}})
	if t2.RefreshToken == "" {
		t.Fatal("no rotated token")
	}
	if code, x := r.token(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {t1.RefreshToken}}); code != 400 || x.Error != "invalid_grant" {
		t.Fatalf("reuse accepted: %d %+v", code, x)
	}
	if code, x := r.token(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {t2.RefreshToken}}); code != 400 || x.Error != "invalid_grant" {
		t.Fatalf("family not revoked: %d %+v", code, x)
	}
	// Scope cannot be widened on refresh.
	q = b.authorize(t, r.authParams(c, map[string]string{"scope": "openid offline_access"}))
	_, t3 := r.exchange(t, q.Get("code"), v)
	if code, x := r.token(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {t3.RefreshToken}, "scope": {"openid email"}}); code != 400 || x.Error != "invalid_scope" {
		t.Fatalf("scope widened: %d %+v", code, x)
	}
}

// M3 acceptance: tokens signed before a rotation keep verifying during the overlap; the old key leaves the JWKS after.
func TestSigningKeyRotationOverlap(t *testing.T) {
	st, tn, b := oidcStack(t)
	r := st.newRP(t, tn, "app", apps.ClientParams{})
	v, c := pkce()
	q := b.authorize(t, r.authParams(c, nil))
	_, tr := r.exchange(t, q.Get("code"), v)
	h, _ := jwtParts(t, tr.IDToken)
	oldKid := h["kid"].(string)
	ctx := context.Background()
	newKid, err := st.a.OP.Signing.Rotate(ctx, audit.CLI, "ES256", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	jwks := func() []string {
		resp, err := st.srv.Client().Get(st.origin() + "/jwks") //nolint:noctx // test
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var set jose.JSONWebKeySet
		_ = json.NewDecoder(resp.Body).Decode(&set)
		var kids []string
		for _, k := range set.Keys {
			kids = append(kids, k.KeyID)
		}
		return kids
	}
	if kids := jwks(); !contains(kids, oldKid) || !contains(kids, newKid) {
		t.Fatalf("overlap JWKS %v", kids)
	}
	oc := oidc.ClientContext(ctx, st.srv.Client())
	prov, _ := oidc.NewProvider(oc, st.origin())
	if _, err := prov.Verifier(&oidc.Config{ClientID: r.clientID, SupportedSigningAlgs: []string{"ES256"}, SkipExpiryCheck: true}).Verify(oc, tr.IDToken); err != nil {
		t.Fatalf("old token during overlap: %v", err)
	}
	q = b.authorize(t, r.authParams(c, nil))
	_, tr2 := r.exchange(t, q.Get("code"), v)
	if h2, _ := jwtParts(t, tr2.IDToken); h2["kid"] != newKid {
		t.Fatalf("new tokens not signed with the new key: %v", h2)
	}
	st.clk.Advance(2 * time.Hour)
	st.a.RunMaintenance(ctx)
	if kids := jwks(); contains(kids, oldKid) || !contains(kids, newKid) {
		t.Fatalf("after overlap JWKS %v", kids)
	}
}

func contains(s []string, x string) bool {
	for _, v := range s {
		if v == x {
			return true
		}
	}
	return false
}

// Cross-tenant: an app of tenant B refuses a user who is only a member of tenant A.
func TestCrossTenantAccessDenied(t *testing.T) {
	st, _, b := oidcStack(t)
	other, err := st.a.Tenants.Create(context.Background(), domain.SystemChange, tenancy.CreateParams{Slug: "jones", Name: "Jones"})
	if err != nil {
		t.Fatal(err)
	}
	r := st.newRP(t, other, "jones-app", apps.ClientParams{})
	_, c := pkce()
	q := b.authorize(t, r.authParams(c, nil))
	if q.Get("error") != "access_denied" || q.Get("code") != "" {
		t.Fatalf("cross-tenant: %v", q)
	}
}

func TestPromptAndMaxAge(t *testing.T) {
	st, tn, b := oidcStack(t)
	r := st.newRP(t, tn, "app", apps.ClientParams{})
	_, c := pkce()
	anon := st.browser()
	if q := anon.authorize(t, r.authParams(c, map[string]string{"prompt": "none"})); q.Get("error") != "login_required" {
		t.Fatalf("prompt=none anon: %v", q)
	}
	if q := b.authorize(t, r.authParams(c, map[string]string{"prompt": "none"})); q.Get("code") == "" {
		t.Fatalf("prompt=none with session: %v", q)
	}
	// prompt=login sends the user through an interactive upstream sign-in before the code (for Google, which cannot be
	// forced to re-authenticate, prompt=select_account; ADR-0047). Time moves on between the original login and this
	// request, as it does for real (the conformance suite caught a max_age=0 loop here).
	st.clk.Advance(3 * time.Second)
	st.google.Set(func(i *fakeidp.IdP) { i.Now = st.clk.Now })
	q := b.authorize(t, r.authParams(c, map[string]string{"prompt": "login"}))
	if q.Get("code") == "" {
		t.Fatalf("prompt=login: %v", q)
	}
	if gq := st.google.LastAuthorize; gq.Get("prompt") != "select_account" {
		t.Fatalf("upstream sign-in not interactive: %v", gq)
	}
	st.clk.Advance(10 * time.Minute)
	if q := b.authorize(t, r.authParams(c, map[string]string{"prompt": "none", "max_age": "60"})); q.Get("error") != "login_required" {
		t.Fatalf("max_age with prompt=none: %v", q)
	}
}

func TestClientAuthAndClientCredentials(t *testing.T) {
	st, tn, _ := oidcStack(t)
	svc := st.newRP(t, tn, "backup-job", apps.ClientParams{GrantTypes: []string{"client_credentials"}, RedirectURIs: []string{},
		Audiences: []string{"https://api.smith.example"}})
	code, tr := svc.token(t, url.Values{"grant_type": {"client_credentials"}})
	if code != 200 || tr.AccessToken == "" || tr.RefreshToken != "" || tr.IDToken != "" {
		t.Fatalf("client credentials %d %+v", code, tr)
	}
	// Scopes the client is not registered for are refused, never signed into the token (review M10).
	if code, x := svc.token(t, url.Values{"grant_type": {"client_credentials"}, "scope": {"orders:delete"}}); code != 400 || x.Error != "invalid_scope" {
		t.Fatalf("unregistered scope %d %+v", code, x)
	}
	_, ac := jwtParts(t, tr.AccessToken)
	if ac["sub"] != svc.clientID || ac["aud"].([]any)[0] != "https://api.smith.example" {
		t.Fatalf("cc claims %v", ac)
	}
	bad := *svc
	bad.secret = "porch_cs_wrong"
	if code, x := bad.token(t, url.Values{"grant_type": {"client_credentials"}}); code != 401 || x.Error != "invalid_client" {
		t.Fatalf("wrong secret %d %+v", code, x)
	}
	if code, x := svc.token(t, url.Values{"grant_type": {"client_credentials"}, "scope": {"openid"}}); code != 400 || x.Error != "invalid_scope" {
		t.Fatalf("openid via cc %d %+v", code, x)
	}
	// A public client may not introspect and may not send a secret.
	pub := st.newRP(t, tn, "spa", apps.ClientParams{Type: "public"})
	pub.secret = ""
	if code, _ := pub.post(t, "/oauth2/introspect", url.Values{"token": {tr.AccessToken}, "client_id": {pub.clientID}}, false); code < 400 {
		t.Fatalf("public client introspected: %d", code)
	}
	pub.secret = "x"
	if code, x := pub.token(t, url.Values{"grant_type": {"authorization_code"}, "code": {"x"}}); code != 401 || x.Error != "invalid_client" {
		t.Fatalf("public client with secret %d %+v", code, x)
	}
}

func TestRevocationAndEndSession(t *testing.T) {
	st, tn, b := oidcStack(t)
	r := st.newRP(t, tn, "app", apps.ClientParams{PostLogoutURIs: []string{"https://rp.example/bye"}})
	v, c := pkce()
	q := b.authorize(t, r.authParams(c, nil))
	_, tr := r.exchange(t, q.Get("code"), v)
	if code, _ := r.post(t, "/oauth2/revoke", url.Values{"token": {tr.AccessToken}}, true); code != 200 {
		t.Fatalf("revoke %d", code)
	}
	if _, in := r.post(t, "/oauth2/introspect", url.Values{"token": {tr.AccessToken}}, true); in["active"] != false {
		t.Fatal("revoked access token still active")
	}
	q = b.authorize(t, r.authParams(c, nil))
	_, tr = r.exchange(t, q.Get("code"), v)
	// RP-initiated logout with an unregistered target is refused.
	cl := *b.c
	cl.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := cl.Get(st.origin() + "/oauth2/end_session?" + url.Values{"id_token_hint": {tr.IDToken}, "post_logout_redirect_uri": {"https://evil.example/"}}.Encode()) //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusFound {
		t.Fatalf("redirected to unregistered post-logout URI: %s", resp.Header.Get("Location"))
	}
	resp, err = cl.Get(st.origin() + "/oauth2/end_session?" + url.Values{"id_token_hint": {tr.IDToken}, "post_logout_redirect_uri": {"https://rp.example/bye"},
		"state": {"s1"}}.Encode()) //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusFound || loc != "https://rp.example/bye?state=s1" {
		t.Fatalf("end_session %d %s", resp.StatusCode, loc)
	}
	if b.me() != nil {
		t.Fatal("Porch session survived RP-initiated logout")
	}
	if code, x := r.token(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tr.RefreshToken}}); code != 400 || x.Error != "invalid_grant" {
		t.Fatalf("refresh after logout %d %+v", code, x)
	}
}

func TestDisabledUserLosesTokens(t *testing.T) {
	st, tn, b := oidcStack(t)
	r := st.newRP(t, tn, "app", apps.ClientParams{})
	v, c := pkce()
	q := b.authorize(t, r.authParams(c, nil))
	_, tr := r.exchange(t, q.Get("code"), v)
	me := b.me()
	disabled := "disabled"
	if _, err := st.a.Users.Update(context.Background(), domain.SystemChange, me["user_id"].(string), userStatus(disabled)); err != nil {
		t.Fatal(err)
	}
	if code, x := r.token(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tr.RefreshToken}}); code != 400 || x.Error != "invalid_grant" {
		t.Fatalf("refresh for disabled user %d %+v", code, x)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, st.origin()+"/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tr.AccessToken)
	resp, err := st.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("userinfo for disabled user %d", resp.StatusCode)
	}
}

// max_age=0 (what zitadel derives from prompt=login) is satisfied by an authentication made after the request.
func TestMaxAgeZeroNoLoop(t *testing.T) {
	st, tn, b := oidcStack(t)
	r := st.newRP(t, tn, "app", apps.ClientParams{})
	_, c := pkce()
	st.clk.Advance(30 * time.Second)
	// The upstream's clock runs 2 s behind Porch's: its auth_time predates the authorization request.
	st.google.Set(func(i *fakeidp.IdP) { i.Now = func() time.Time { return st.clk.Now().Add(-2 * time.Second) } })
	q := b.authorize(t, r.authParams(c, map[string]string{"max_age": "0"}))
	if q.Get("code") == "" {
		t.Fatalf("max_age=0 did not complete: %v", q)
	}
}

// Security review M11: deny policies on the sign-in method also apply at refresh (the method travels with the token).
func TestDenyPolicyOnAuthMethodAtRefresh(t *testing.T) {
	st, tn, b := oidcStack(t)
	r := st.newRP(t, tn, "app-m11", apps.ClientParams{})
	v, c := pkce()
	q := b.authorize(t, r.authParams(c, nil))
	code, tr := r.exchange(t, q.Get("code"), v)
	if code != 200 || tr.RefreshToken == "" {
		t.Fatalf("exchange %d %+v", code, tr)
	}
	sc, _ := st.a.Tenants.SystemScope(context.Background(), tn.ID)
	if _, err := st.a.Authz.CreatePolicy(context.Background(), domain.SystemChange, sc, authz.PolicyParams{Slug: "no-google", Name: "x", Effect: "deny",
		Expression: `principal.auth_method == "google"`, Actions: []string{"app:access"}}); err != nil {
		t.Fatal(err)
	}
	if code, x := r.token(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tr.RefreshToken}}); code < 400 {
		t.Fatalf("refresh allowed after deny on the sign-in method: %d %+v", code, x)
	}
}

// Security review L9 (code-replay race): a replay that lands while the first exchange is still issuing marks the code;
// the first exchange then revokes what it issued instead of returning it.
func TestConcurrentCodeReplayRevokes(t *testing.T) {
	st, tn, b := oidcStack(t)
	r := st.newRP(t, tn, "app-race", apps.ClientParams{})
	v, c := pkce()
	q := b.authorize(t, r.authParams(c, nil))
	// Simulate the concurrent replay having marked the code after the first exchange burned it.
	if err := st.a.Store.W().Tx(context.Background(), func(tx *store.Tx) error {
		_, err := tx.SQL.ExecContext(context.Background(), "UPDATE auth_codes SET replayed_at = ?", tx.NowMicros())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if code, tr := r.exchange(t, q.Get("code"), v); code != 400 || tr.Error != "invalid_grant" || tr.AccessToken != "" {
		t.Fatalf("exchange of a replayed code: %d %+v", code, tr)
	}
}

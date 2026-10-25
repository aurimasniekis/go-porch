package app_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aurimasniekis/go-porch/internal/app"
	"github.com/aurimasniekis/go-porch/internal/authz"
	"github.com/aurimasniekis/go-porch/internal/clock"
	"github.com/aurimasniekis/go-porch/internal/config"
	"github.com/aurimasniekis/go-porch/internal/domain"
	"github.com/aurimasniekis/go-porch/internal/identity"
	"github.com/aurimasniekis/go-porch/internal/idp"
	"github.com/aurimasniekis/go-porch/internal/idp/fakeidp"
	"github.com/aurimasniekis/go-porch/internal/localauth"
	"github.com/aurimasniekis/go-porch/internal/session"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/tenancy"
)

var fastHash = localauth.Params{Memory: 1024, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16}

// stack is Porch on TLS (so __Host- cookies flow) plus a fake Google.
type stack struct {
	t       *testing.T
	a       *app.App
	srv     *httptest.Server
	google  *fakeidp.IdP
	gsrv    *httptest.Server
	clk     *clock.Fake
	prov    idp.Provider
	dataDir string
}

func newStack(t *testing.T, mutate ...func(*config.Config)) *stack {
	t.Helper()
	st := &stack{t: t, clk: clock.NewFake(time.Now().UTC().Truncate(time.Second))}
	g, err := fakeidp.New("http://placeholder")
	if err != nil {
		t.Fatal(err)
	}
	g.Now = st.clk.Now
	st.google, st.gsrv = g, httptest.NewServer(g.Handler())
	t.Cleanup(st.gsrv.Close)
	g.SetIssuer(st.gsrv.URL)
	st.srv = httptest.NewUnstartedServer(nil)
	st.dataDir = filepath.Join(t.TempDir(), "data")
	st.open(mutate...)
	st.srv.StartTLS()
	t.Cleanup(st.srv.Close)
	g.AddClient(fakeidp.Client{ID: "porch-client", Secret: "porch-secret", RedirectURIs: []string{st.origin() + "/login/google/callback"}})
	return st
}

func (st *stack) origin() string { return "https://" + st.srv.Listener.Addr().String() }

func (st *stack) open(mutate ...func(*config.Config)) {
	cfg := config.Default()
	cfg.Mode = config.ModeDevelopment
	cfg.DataDir = st.dataDir
	cfg.PublicURL = st.origin()
	cfg.Outbound.AllowCIDRs = []string{"127.0.0.0/8"}
	for _, m := range mutate {
		m(cfg)
	}
	if err := cfg.Validate(); err != nil {
		st.t.Fatal(err)
	}
	a, err := app.Open(context.Background(), cfg, slog.New(slog.DiscardHandler), app.Options{Environ: []string{}, Clock: st.clk, HashParams: &fastHash, RSABits: 2048})
	if err != nil {
		st.t.Fatal(err)
	}
	st.a = a
	st.srv.Config.Handler = a.PublicHandler()
	st.t.Cleanup(func() { _ = a.Close() })
}

// restart closes and reopens the app on the same data directory (persistence tests).
func (st *stack) restart() {
	_ = st.a.Close()
	st.open()
}

type browser struct {
	t    *testing.T
	st   *stack
	c    *http.Client
	csrf string
}

func (st *stack) browser() *browser {
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Transport: st.srv.Client().Transport, Jar: jar, Timeout: 10 * time.Second} // own jar per browser
	return &browser{t: st.t, st: st, c: c}
}

// visit follows redirects across Porch and the fake IdP and returns the final URL.
func (b *browser) visit(path string) *url.URL {
	b.t.Helper()
	u := path
	if strings.HasPrefix(path, "/") {
		u = b.st.origin() + path
	}
	resp, err := b.c.Get(u) //nolint:noctx // test
	if err != nil {
		b.t.Fatal(err)
	}
	resp.Body.Close()
	return resp.Request.URL
}

func (b *browser) api(method, path string, body any) (int, map[string]any) {
	b.t.Helper()
	var r io.Reader
	if body != nil {
		buf, _ := json.Marshal(body)
		r = bytes.NewReader(buf)
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, b.st.origin()+path, r)
	req.Header.Set("Content-Type", "application/json")
	if method != http.MethodGet {
		req.Header.Set("Origin", b.st.origin())
		req.Header.Set("X-Porch-CSRF", b.csrf)
	}
	resp, err := b.c.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &out)
	if out == nil {
		out = map[string]any{"_raw": string(raw)}
	}
	return resp.StatusCode, out
}

func (b *browser) me() map[string]any {
	code, me := b.api(http.MethodGet, "/api/v1/me", nil)
	if code != http.StatusOK {
		return nil
	}
	b.csrf, _ = me["csrf_token"].(string)
	return me
}

// setupGoogle creates the provider, a tenant and a domain rule directly through services.
func (st *stack) setupGoogle(allowedHDs []string, rules ...idp.RuleParams) tenancy.Tenant {
	st.t.Helper()
	ctx := context.Background()
	p, err := st.a.IDP.CreateProvider(ctx, domain.SystemChange, idp.ProviderParams{Slug: "google", Kind: idp.KindGoogle, Name: "Google",
		Issuer: st.gsrv.URL, ClientID: "porch-client", Secret: "porch-secret", AllowedHDs: allowedHDs})
	if err != nil {
		st.t.Fatal(err)
	}
	st.prov = p
	tn, err := st.a.Tenants.Create(ctx, domain.SystemChange, tenancy.CreateParams{Slug: "smith", Name: "Smith family"})
	if err != nil {
		st.t.Fatal(err)
	}
	sc, _ := st.a.Tenants.SystemScope(ctx, tn.ID)
	for _, r := range rules {
		r.ProviderID = p.ID
		if _, err := st.a.IDP.CreateRule(ctx, domain.SystemChange, sc, r); err != nil {
			st.t.Fatal(err)
		}
	}
	return tn
}

func (st *stack) members(tn tenancy.Tenant) []tenancy.Membership {
	sc, _ := st.a.Tenants.SystemScope(context.Background(), tn.ID)
	pg, _ := domain.ParsePage(200, "")
	ms, _, err := st.a.Tenants.ListMembers(context.Background(), sc, pg)
	if err != nil {
		st.t.Fatal(err)
	}
	return ms
}

func workspaceUser(sub, email, hd string) fakeidp.User {
	return fakeidp.User{Subject: sub, Email: email, EmailVerified: true, Name: strings.Split(email, "@")[0], HD: hd}
}

func (st *stack) loginAs(b *browser, sub string) *url.URL {
	st.google.Set(func(i *fakeidp.IdP) { i.Current = sub })
	return b.visit("/login/google?return_to=/apps")
}

func TestGoogleWorkspaceJITEnrollment(t *testing.T) {
	st := newStack(t)
	tn := st.setupGoogle(nil, idp.RuleParams{Domain: "smith.example", EvidenceKind: idp.EvidenceWorkspaceHD, Mode: idp.ModeJIT})
	st.google.AddUser(workspaceUser("g-ada", "ada@smith.example", "smith.example"))
	b := st.browser()
	final := st.loginAs(b, "g-ada")
	if final.Path != "/apps" {
		t.Fatalf("landed on %s", final)
	}
	me := b.me()
	if me == nil || me["session"].(map[string]any)["method"] != "google" {
		t.Fatalf("me %v", me)
	}
	ms := st.members(tn)
	if len(ms) != 1 || !strings.HasPrefix(ms[0].Source, "domain_rule:") {
		t.Fatalf("members %+v", ms)
	}
	// PKCE + nonce + hd hint were sent; the hint is UX only.
	q := st.google.LastAuthorize
	if q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" || q.Get("state") == "" {
		t.Fatalf("authorize params %v", q)
	}
	// Second login reuses the identity: still one user.
	b2 := st.browser()
	st.loginAs(b2, "g-ada")
	if n := len(st.members(tn)); n != 1 {
		t.Fatalf("members after relogin %d", n)
	}
}

// M2 acceptance: the hd claim is the only Workspace evidence.
func TestHDValidation(t *testing.T) {
	cases := map[string]struct {
		user    fakeidp.User
		mutate  func(map[string]any)
		allowed []string
		want    string
	}{
		"missing hd (consumer account)": {user: workspaceUser("g1", "ada@smith.example", ""), want: "not_enrolled"},
		"mismatched hd":                 {user: workspaceUser("g2", "ada@smith.example", "other.example"), want: "not_enrolled"},
		"hd only in email suffix":       {user: fakeidp.User{Subject: "g3", Email: "eve@smith.example", EmailVerified: true}, want: "not_enrolled"},
		"provider allowlist rejects":    {user: workspaceUser("g4", "x@other.example", "other.example"), allowed: []string{"smith.example"}, want: "domain_not_allowed"},
		"provider allowlist missing hd": {user: workspaceUser("g5", "x@gmail.example", ""), allowed: []string{"smith.example"}, want: "domain_not_allowed"},
		"forged hd with wrong audience": {user: workspaceUser("g6", "x@smith.example", "smith.example"), mutate: func(c map[string]any) { c["aud"] = "other-client" }, want: "expired"},
		"forged hd with wrong nonce":    {user: workspaceUser("g7", "x@smith.example", "smith.example"), mutate: func(c map[string]any) { c["nonce"] = "x" }, want: "expired"},
		"token from another issuer":     {user: workspaceUser("g8", "x@smith.example", "smith.example"), mutate: func(c map[string]any) { c["iss"] = "https://evil.example" }, want: "expired"},
		"expired token":                 {user: workspaceUser("g9", "x@smith.example", "smith.example"), mutate: func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }, want: "expired"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			st := newStack(t)
			tn := st.setupGoogle(c.allowed, idp.RuleParams{Domain: "smith.example", EvidenceKind: idp.EvidenceWorkspaceHD, Mode: idp.ModeJIT})
			st.google.AddUser(c.user)
			st.google.Set(func(i *fakeidp.IdP) { i.Mutate = c.mutate })
			b := st.browser()
			final := st.loginAs(b, c.user.Subject)
			if final.Path != "/login" || final.Query().Get("error") != c.want {
				t.Fatalf("landed on %s, want error %s", final, c.want)
			}
			if b.me() != nil || len(st.members(tn)) != 0 {
				t.Fatal("enrolled or signed in")
			}
		})
	}
	// The hd= authorization hint is sent for single-domain providers but never trusted (covered by "missing hd").
	st := newStack(t)
	st.setupGoogle([]string{"smith.example"})
	st.google.AddUser(workspaceUser("g10", "a@smith.example", "smith.example"))
	st.loginAs(st.browser(), "g10")
	if st.google.LastAuthorize.Get("hd") != "smith.example" {
		t.Fatal("hd hint not sent")
	}
}

// T-B3-4 / M2 acceptance: an upstream account with the same email as an existing user is never linked to it.
func TestEmailLinkAttack(t *testing.T) {
	st := newStack(t)
	tn := st.setupGoogle(nil, idp.RuleParams{Domain: "smith.example", EvidenceKind: idp.EvidenceVerifiedEmail, Mode: idp.ModeJIT})
	ctx := context.Background()
	victim, err := st.a.Users.Create(ctx, domain.SystemChange, identityParams("Victim", "victim@smith.example"))
	if err != nil {
		t.Fatal(err)
	}
	// Attacker controls an upstream account claiming the victim's (verified) email.
	st.google.AddUser(fakeidp.User{Subject: "attacker-sub", Email: "victim@smith.example", EmailVerified: true, Name: "Attacker"})
	b := st.browser()
	st.loginAs(b, "attacker-sub")
	me := b.me()
	if me == nil {
		t.Fatal("expected JIT enrollment of a separate user")
	}
	if me["user_id"] == victim.ID {
		t.Fatal("attacker was linked to the victim's account by email")
	}
	if n := len(st.members(tn)); n != 1 {
		t.Fatalf("members %d", n)
	}
	// Without any rule or invite the same login is refused outright.
	st2 := newStack(t)
	st2.setupGoogle(nil)
	_, _ = st2.a.Users.Create(ctx, domain.SystemChange, identityParams("Victim", "victim@smith.example"))
	st2.google.AddUser(fakeidp.User{Subject: "attacker-sub", Email: "victim@smith.example", EmailVerified: true})
	if f := st2.loginAs(st2.browser(), "attacker-sub"); f.Query().Get("error") != "not_enrolled" {
		t.Fatalf("got %s", f)
	}
}

func TestInviteOnlyAndVerifiedEmail(t *testing.T) {
	st := newStack(t)
	tn := st.setupGoogle(nil, idp.RuleParams{Domain: "smith.example", EvidenceKind: idp.EvidenceWorkspaceHD, Mode: idp.ModeInviteOnly})
	st.google.AddUser(workspaceUser("g-bob", "bob@smith.example", "smith.example"))
	if f := st.loginAs(st.browser(), "g-bob"); f.Query().Get("error") != "not_enrolled" {
		t.Fatalf("uninvited: %s", f)
	}
	sc, _ := st.a.Tenants.SystemScope(context.Background(), tn.ID)
	if _, err := st.a.IDP.CreateInvite(context.Background(), domain.SystemChange, sc, "bob@smith.example", time.Hour); err != nil {
		t.Fatal(err)
	}
	// An unverified email cannot use the invite.
	st.google.AddUser(fakeidp.User{Subject: "g-bob2", Email: "bob@smith.example", EmailVerified: false, HD: "smith.example"})
	if f := st.loginAs(st.browser(), "g-bob2"); f.Query().Get("error") != "not_enrolled" {
		t.Fatalf("unverified: %s", f)
	}
	if f := st.loginAs(st.browser(), "g-bob"); f.Path != "/apps" {
		t.Fatalf("invited: %s", f)
	}
	if ms := st.members(tn); len(ms) != 1 || !strings.HasPrefix(ms[0].Source, "domain_rule:") {
		t.Fatalf("members %+v", ms)
	}
}

// State, nonce and the browser binding: a callback without the state cookie or replayed later is refused.
func TestLoginCSRFAndReplay(t *testing.T) {
	st := newStack(t)
	st.setupGoogle(nil, idp.RuleParams{Domain: "smith.example", EvidenceKind: idp.EvidenceWorkspaceHD, Mode: idp.ModeJIT})
	st.google.AddUser(workspaceUser("g-ada", "ada@smith.example", "smith.example"))
	st.google.Set(func(i *fakeidp.IdP) { i.Current = "g-ada" })
	// Attacker starts a login, captures the callback URL, and makes the victim's browser open it.
	attacker := st.browser()
	attacker.c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if strings.Contains(req.URL.Path, "/callback") {
			return http.ErrUseLastResponse
		}
		return nil
	}
	resp, err := attacker.c.Get(st.origin() + "/login/google") //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	callback := resp.Header.Get("Location")
	victim := st.browser()
	if f := victim.visit(callback); f.Query().Get("error") != "expired" || victim.me() != nil {
		t.Fatalf("login CSRF accepted: %s", f)
	}
	// The browser that started the login completes it once; replaying the same callback afterwards fails (state burned,
	// code single-use).
	attacker.c.CheckRedirect = nil
	if f := attacker.visit(callback); f.Path != "/" || attacker.me() == nil {
		t.Fatalf("legitimate completion failed: %s", f)
	}
	if f := attacker.visit(callback); f.Query().Get("error") != "expired" {
		t.Fatalf("replay accepted: %s", f)
	}
}

// ADR-0007: hourly prompt=none recheck; a removed Workspace user loses the session.
func TestUpstreamRecheck(t *testing.T) {
	st := newStack(t)
	tn := st.setupGoogle(nil, idp.RuleParams{Domain: "smith.example", EvidenceKind: idp.EvidenceWorkspaceHD, Mode: idp.ModeJIT})
	st.google.AddUser(workspaceUser("g-ada", "ada@smith.example", "smith.example"))
	b := st.browser()
	st.loginAs(b, "g-ada")
	if b.me() == nil {
		t.Fatal("not logged in")
	}
	st.clk.Advance(61 * time.Minute)
	code, p := b.api(http.MethodGet, "/api/v1/installation", nil)
	if code != http.StatusUnauthorized || p["code"] != "upstream_recheck_required" || p["action"] != "/login/google?intent=recheck" {
		t.Fatalf("recheck not enforced: %d %v", code, p)
	}
	// Silent recheck succeeds while the account is fine.
	if f := b.visit("/login/google?intent=recheck&return_to=/apps"); f.Path != "/apps" {
		t.Fatalf("recheck: %s", f)
	}
	if st.google.LastAuthorize.Get("prompt") != "none" {
		t.Fatal("recheck must use prompt=none")
	}
	code, _ = b.api(http.MethodGet, "/api/v1/me/identities", nil)
	if code != http.StatusOK {
		t.Fatalf("after recheck: %d", code)
	}
	// The hd changes (account moved out of the Workspace): the derived membership goes at the next recheck.
	st.google.UpdateUser("g-ada", func(u *fakeidp.User) { u.HD = "elsewhere.example" })
	st.clk.Advance(61 * time.Minute)
	b.visit("/login/google?intent=recheck&return_to=/apps")
	if n := len(st.members(tn)); n != 0 {
		t.Fatalf("evidence lost but %d memberships remain", n)
	}
	// Removed from the Workspace: prompt=none fails → session ends.
	st.google.UpdateUser("g-ada", func(u *fakeidp.User) { u.Disabled = true })
	st.clk.Advance(61 * time.Minute)
	if f := b.visit("/login/google?intent=recheck&return_to=/apps"); f.Query().Get("error") != "session_ended" {
		t.Fatalf("got %s", f)
	}
	if b.me() != nil {
		t.Fatal("session survived failed recheck")
	}
}

func TestGoogleStepUp(t *testing.T) {
	st := newStack(t)
	st.setupGoogle(nil, idp.RuleParams{Domain: "smith.example", EvidenceKind: idp.EvidenceWorkspaceHD, Mode: idp.ModeJIT})
	st.google.AddUser(workspaceUser("g-ada", "ada@smith.example", "smith.example"))
	b := st.browser()
	st.loginAs(b, "g-ada")
	b.me()
	st.clk.Advance(10 * time.Minute)
	code, p := b.api(http.MethodPut, "/api/v1/me/backup-handle", map[string]string{"handle": "ada-backup"})
	if code != http.StatusForbidden || p["code"] != "reauth_required" || p["action"] != "/login/google?intent=stepup" {
		t.Fatalf("%d %v", code, p)
	}
	b.visit("/login/google?intent=stepup&return_to=/account")
	if q := st.google.LastAuthorize; q.Get("prompt") != "login" || q.Get("max_age") != "0" {
		t.Fatalf("step-up params %v", q)
	}
	b.me()
	if code, p := b.api(http.MethodPut, "/api/v1/me/backup-handle", map[string]string{"handle": "ada-backup"}); code != http.StatusNoContent {
		t.Fatalf("after step-up %d %v", code, p)
	}
}

// Enroll the backup credential through the API, then exercise the two-step login, lockout and the DoS property:
// Google login keeps working while backup login is locked (M2 acceptance).
func TestBackupLoginAndDoSIsolation(t *testing.T) {
	st := newStack(t)
	st.setupGoogle(nil, idp.RuleParams{Domain: "smith.example", EvidenceKind: idp.EvidenceWorkspaceHD, Mode: idp.ModeJIT})
	st.google.AddUser(workspaceUser("g-ada", "ada@smith.example", "smith.example"))
	b := st.browser()
	st.loginAs(b, "g-ada")
	b.me()
	pairs := []map[string]string{{"title": "Street of the summer house", "answer": "Vaivorykštės gatvė 14"},
		{"title": "First concert I paid for", "answer": "Massive Attack in Riga, 2004"}, {"title": "Grandmother's dog", "answer": "Kudlius the third"}}
	code, p := b.api(http.MethodPut, "/api/v1/me/backup-credential", map[string]any{"password": "correct-Horse-battery-79!", "pairs": pairs,
		"confirm": []string{"vaivorykštės gatvė 14", "massive attack in riga 2004", "kudlius the third"}})
	if code != http.StatusOK {
		t.Fatalf("enroll %d %v", code, p)
	}
	code, p = b.api(http.MethodGet, "/api/v1/me/backup-credential", nil)
	if code != http.StatusOK || p["enrolled"] != true || len(p["titles"].([]any)) != 3 {
		t.Fatalf("status %v", p)
	}
	// Anonymous browser: step 1 wrong password → generic 401, account locks (threshold 1).
	anon := st.browser()
	code, p = anon.api(http.MethodPost, "/api/v1/auth/backup/start", map[string]string{"identifier": "ada@smith.example", "password": "nope-nope-nope"})
	if code != http.StatusUnauthorized || p["code"] != "unauthorized" {
		t.Fatalf("%d %v", code, p)
	}
	code, p2 := anon.api(http.MethodPost, "/api/v1/auth/backup/start", map[string]string{"identifier": "nobody@smith.example", "password": "nope-nope-nope"})
	if code != http.StatusUnauthorized || p2["detail"] != p["detail"] {
		t.Fatalf("unknown user distinguishable: %v vs %v", p2, p)
	}
	code, _ = anon.api(http.MethodPost, "/api/v1/auth/backup/start", map[string]string{"identifier": "ada@smith.example", "password": "correct-Horse-battery-79!"})
	if code != http.StatusUnauthorized {
		t.Fatalf("locked account accepted correct password: %d", code)
	}
	// DoS isolation: Google login still works for the locked user.
	g := st.browser()
	if f := st.loginAs(g, "g-ada"); f.Path != "/apps" || g.me() == nil {
		t.Fatalf("Google login blocked by backup lockout: %s", f)
	}
	// Restart persistence: the lock survives a restart.
	st.restart()
	code, _ = anon.api(http.MethodPost, "/api/v1/auth/backup/start", map[string]string{"identifier": "ada@smith.example", "password": "correct-Horse-battery-79!"})
	if code != http.StatusUnauthorized {
		t.Fatalf("lock lost across restart: %d", code)
	}
	// After the lock expires the two-step login succeeds.
	st.clk.Advance(6*time.Hour + time.Minute)
	code, p = anon.api(http.MethodPost, "/api/v1/auth/backup/start", map[string]string{"identifier": "ada@smith.example", "password": "correct-Horse-battery-79!"})
	if code != http.StatusOK || len(p["titles"].([]any)) != 3 {
		t.Fatalf("start %d %v", code, p)
	}
	code, p = anon.api(http.MethodPost, "/api/v1/auth/backup/finish", map[string]any{"answers": []string{"Vaivorykštės gatvė 14", "massive attack in riga 2004", "Kudlius the third"}})
	if code != http.StatusOK || p["session"].(map[string]any)["method"] != "backup" {
		t.Fatalf("finish %d %v", code, p)
	}
	// Login POSTs from another origin are refused (login CSRF).
	other := st.browser()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, st.origin()+"/api/v1/auth/backup/start",
		strings.NewReader(`{"identifier":"ada@smith.example","password":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.example")
	resp, err := other.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin login POST: %d", resp.StatusCode)
	}
	// Operators see the lockout state and can lift it (step-up) without seeing the credential.
	adaID := b.me()["user_id"].(string)
	code, _ = anon.api(http.MethodPost, "/api/v1/auth/backup/start", map[string]string{"identifier": "ada@smith.example", "password": "nope-nope-nope"})
	if code != http.StatusUnauthorized {
		t.Fatalf("relock: %d", code)
	}
	tok, _, err := st.a.Setup.Issue(context.Background(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	owner := st.browser()
	if code, p := owner.api(http.MethodPost, "/api/v1/setup", map[string]string{"token": tok, "display_name": "Olga Owner"}); code != http.StatusCreated {
		t.Fatalf("setup %d %v", code, p)
	}
	owner.me()
	code, u := owner.api(http.MethodGet, "/api/v1/users/"+adaID, nil)
	bl, _ := u["backup_login"].(map[string]any)
	if code != http.StatusOK || bl["enrolled"] != true || bl["locked_until"] == nil {
		t.Fatalf("lockout status %d %v", code, u)
	}
	if code, p := owner.api(http.MethodPost, "/api/v1/users/"+adaID+"/backup-lockout/unlock", nil); code != http.StatusNoContent {
		t.Fatalf("unlock %d %v", code, p)
	}
	if _, u = owner.api(http.MethodGet, "/api/v1/users/"+adaID, nil); u["backup_login"].(map[string]any)["locked_until"] != nil {
		t.Fatalf("still locked %v", u)
	}
	code, _ = anon.api(http.MethodPost, "/api/v1/auth/backup/start", map[string]string{"identifier": "ada@smith.example", "password": "correct-Horse-battery-79!"})
	if code != http.StatusOK {
		t.Fatalf("after unlock: %d", code)
	}
}

// Sessions and recovery survive a restart; the first owner can link Google after setup via a step-up.
func TestSessionSurvivesRestart(t *testing.T) {
	st := newStack(t)
	st.setupGoogle(nil, idp.RuleParams{Domain: "smith.example", EvidenceKind: idp.EvidenceWorkspaceHD, Mode: idp.ModeJIT})
	st.google.AddUser(workspaceUser("g-ada", "ada@smith.example", "smith.example"))
	b := st.browser()
	st.loginAs(b, "g-ada")
	st.restart()
	if b.me() == nil {
		t.Fatal("session lost across restart")
	}
}

func identityParams(name, email string) identityCreate {
	return identityCreate{DisplayName: name, PrimaryEmail: email}
}

var _ = store.ErrNotFound
var _ = session.CookieName

// Security review L3: automation tokens of a Google user stop working when Google has not confirmed the user for
// longer than automation.upstream_max_age, and work again after the next sign-in.
func TestFederatedTokenNeedsUpstreamConfirmation(t *testing.T) {
	st := newStack(t)
	tn := st.setupGoogle(nil, idp.RuleParams{Domain: "smith.example", EvidenceKind: idp.EvidenceWorkspaceHD, Mode: idp.ModeJIT})
	st.google.AddUser(workspaceUser("g-ada", "ada@smith.example", "smith.example"))
	ada := st.browser()
	st.loginAs(ada, "g-ada")
	adaID := ada.me()["user_id"].(string)
	// Make Ada a tenant administrator so she can issue a tenant token.
	sc, _ := st.a.Tenants.SystemScope(context.Background(), tn.ID)
	roles, _ := st.a.Authz.Roles(context.Background(), sc)
	var admin string
	for _, r := range roles {
		if r.Slug == "admin" {
			admin = r.ID
		}
	}
	if _, err := st.a.Authz.Assign(context.Background(), domain.SystemChange, sc, authz.AssignmentParams{SubjectType: "user", SubjectID: adaID,
		RoleID: admin, ScopeType: "tenant"}); err != nil {
		t.Fatal(err)
	}
	code, tok := ada.api(http.MethodPost, "/api/v1/tenants/"+tn.Slug+"/automation-tokens", map[string]any{"name": "tf", "permissions": []string{"group:manage"},
		"expires_in_days": 90})
	if code != http.StatusCreated {
		t.Fatalf("token %d %v", code, tok)
	}
	call := func() int {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, st.origin()+"/api/v1/tenants/"+tn.Slug+"/groups", nil)
		req.Header.Set("Authorization", "Bearer "+tok["token"].(string))
		resp, err := st.browser().c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := call(); c != http.StatusOK {
		t.Fatalf("fresh token %d", c)
	}
	st.clk.Advance(31 * 24 * time.Hour)
	if c := call(); c != http.StatusUnauthorized {
		t.Fatalf("token without upstream confirmation for 31 days: %d", c)
	}
	st.loginAs(st.browser(), "g-ada")
	if c := call(); c != http.StatusOK {
		t.Fatalf("token after a new Google sign-in: %d", c)
	}
}

// Security review L9: anonymous callback floods are throttled before they reach the audit log.
func TestLoginCallbackThrottled(t *testing.T) {
	st := newStack(t)
	st.setupGoogle(nil)
	b := st.browser()
	throttled := 0
	for range 100 {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, st.origin()+"/login/google/callback?state=x&code=y", nil)
		resp, err := b.c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			throttled++
		}
	}
	n, err := st.a.Store.R().CountAuditEvents(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if throttled == 0 || n > 60 {
		t.Fatalf("callback flood: %d throttled, %d audit events", throttled, n)
	}
}

// An installation owner who signs in with Google can issue an installation token that never expires (ADR-0046): it
// works years later and without the provider confirming the owner, so automation survives a provider outage. Only
// installation tokens qualify; an expiry and never_expires exclude each other.
func TestOwnerTokenWithoutExpiry(t *testing.T) {
	st := newStack(t)
	tn := st.setupGoogle(nil, idp.RuleParams{Domain: "smith.example", EvidenceKind: idp.EvidenceWorkspaceHD, Mode: idp.ModeJIT})
	st.google.AddUser(workspaceUser("g-olga", "olga@smith.example", "smith.example"))
	olga := st.browser()
	st.loginAs(olga, "g-olga")
	olgaID := olga.me()["user_id"].(string)
	if err := st.a.Store.W().Tx(context.Background(), func(tx *store.Tx) error {
		return st.a.Users.GrantOperatorRoleTx(context.Background(), tx, domain.SystemChange, olgaID, identity.RoleOwner, "manual")
	}); err != nil {
		t.Fatal(err)
	}
	st.loginAs(olga, "g-olga") // fresh sign-in: issuing tokens needs step-up
	olga.me()                  // the new session's CSRF token
	code, out := olga.api(http.MethodPost, "/api/v1/installation/automation-tokens", map[string]any{"name": "terraform", "role": "admin",
		"never_expires": true, "expires_in_days": 30})
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("expiry together with never_expires: %d %v", code, out)
	}
	code, tok := olga.api(http.MethodPost, "/api/v1/installation/automation-tokens", map[string]any{"name": "terraform", "role": "admin",
		"never_expires": true})
	if code != http.StatusCreated || tok["never_expires"] != true || tok["expires_at"] != nil {
		t.Fatalf("token without expiry: %d %v", code, tok)
	}
	code, out = olga.api(http.MethodPost, "/api/v1/tenants/"+tn.Slug+"/automation-tokens", map[string]any{"name": "x", "permissions": []string{"group:manage"},
		"never_expires": true})
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("tenant token with never_expires: %d %v", code, out)
	}
	call := func() int {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, st.origin()+"/api/v1/tenants", nil)
		req.Header.Set("Authorization", "Bearer "+tok["token"].(string))
		resp, err := st.browser().c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	// Two years later, with no Google sign-in since: still valid (a 366-day token or the 30-day upstream rule would stop it).
	st.clk.Advance(2 * 366 * 24 * time.Hour)
	if c := call(); c != http.StatusOK {
		t.Fatalf("token without expiry after two years without a Google sign-in: %d", c)
	}
	// Revocation still ends it at once (Olga's browser session itself expired long ago, so revoke through the service).
	if err := st.a.Tokens.Revoke(context.Background(), domain.SystemChange, tok["id"].(string)); err != nil {
		t.Fatal(err)
	}
	if c := call(); c != http.StatusUnauthorized {
		t.Fatalf("revoked token: %d", c)
	}
}

package app_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aurimasniekis/go-porch/internal/app"
	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/clock"
	"github.com/aurimasniekis/go-porch/internal/config"
	"github.com/aurimasniekis/go-porch/internal/session"
	"github.com/aurimasniekis/go-porch/internal/store"
)

const origin = "http://localhost:8080"

func newApp(t *testing.T, mutate ...func(*config.Config)) *app.App {
	t.Helper()
	return newAppWithClock(t, nil, mutate...)
}

func newAppWithClock(t *testing.T, clk clock.Clock, mutate ...func(*config.Config)) *app.App {
	t.Helper()
	cfg := config.Default()
	cfg.Mode = config.ModeDevelopment
	cfg.DataDir = filepath.Join(t.TempDir(), "data")
	cfg.PublicURL = origin
	cfg.HTTP.Listen = "127.0.0.1:0"
	cfg.Management.Listen = "127.0.0.1:0"
	for _, m := range mutate {
		m(cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	a, err := app.Open(context.Background(), cfg, slog.New(slog.DiscardHandler), app.Options{Environ: []string{}, Clock: clk, RSABits: 2048})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}

// client drives the public handler like a browser on the Porch origin.
type client struct {
	t      *testing.T
	h      http.Handler
	cookie string
	csrf   string
	remote string
}

func (c *client) do(method, path string, body any, hdr map[string]string) *httptest.ResponseRecorder {
	c.t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, r)
	req.RemoteAddr = c.remote
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet {
		req.Header.Set("Origin", origin)
		if c.csrf != "" {
			req.Header.Set("X-Porch-CSRF", c.csrf)
		}
	}
	if c.cookie != "" {
		req.AddCookie(&http.Cookie{Name: session.CookieName, Value: c.cookie})
	}
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, req)
	return rec
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %d %s: %v", rec.Code, rec.Body.String(), err)
	}
	return v
}

func expect(t *testing.T, rec *httptest.ResponseRecorder, code int) {
	t.Helper()
	if rec.Code != code {
		t.Fatalf("status %d, want %d: %s", rec.Code, code, rec.Body.String())
	}
}

func setupOwner(t *testing.T, a *app.App) *client {
	t.Helper()
	tok, _, err := a.Setup.Issue(context.Background(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c := &client{t: t, h: a.PublicHandler(), remote: "198.51.100.7:4444"}
	rec := c.do(http.MethodPost, "/api/v1/setup", map[string]string{"token": tok, "display_name": "Olga Owner", "email": "olga@example.com"}, nil)
	expect(t, rec, http.StatusCreated)
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == session.CookieName {
			if !ck.Secure || !ck.HttpOnly || ck.SameSite != http.SameSiteLaxMode || ck.Domain != "" || ck.Path != "/" {
				t.Fatalf("cookie attributes: %+v", ck)
			}
			c.cookie = ck.Value
		}
	}
	me := decode[map[string]any](t, rec)
	c.csrf, _ = me["csrf_token"].(string)
	if c.cookie == "" || c.csrf == "" {
		t.Fatalf("no session: %s", rec.Body.String())
	}
	return c
}

func TestManagementFlow(t *testing.T) {
	a := newApp(t)
	c := setupOwner(t, a)
	// Setup cannot run twice.
	tok2 := "porch_setup_x"
	expect(t, c.do(http.MethodPost, "/api/v1/setup", map[string]string{"token": tok2, "display_name": "x"}, nil), http.StatusConflict)

	me := decode[map[string]any](t, c.do(http.MethodGet, "/api/v1/me", nil, nil))
	if roles := me["operator_roles"].([]any); len(roles) != 1 || roles[0] != "owner" {
		t.Fatalf("roles %v", roles)
	}

	rec := c.do(http.MethodPost, "/api/v1/tenants", map[string]string{"slug": "smith", "name": "Smith family"}, map[string]string{"X-Porch-Managed-By": "terraform"})
	expect(t, rec, http.StatusCreated)
	if rec.Header().Get("ETag") != `"1"` {
		t.Fatalf("etag %q", rec.Header().Get("ETag"))
	}
	tn := decode[map[string]any](t, rec)
	if tn["managed_by"] != "terraform" || !strings.HasPrefix(tn["last_changed_by"].(string), "user:usr_") {
		t.Fatalf("provenance: %v", tn)
	}
	// Duplicate slug → 409 with stable code.
	rec = c.do(http.MethodPost, "/api/v1/tenants", map[string]string{"slug": "smith", "name": "x"}, nil)
	expect(t, rec, http.StatusConflict)
	if p := decode[map[string]any](t, rec); p["code"] != "already_exists" || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/problem+json") {
		t.Fatalf("problem: %v %s", p, rec.Header().Get("Content-Type"))
	}
	// Schema validation → 422 validation_failed.
	rec = c.do(http.MethodPost, "/api/v1/tenants", map[string]string{"slug": "Bad Slug", "name": "x"}, nil)
	expect(t, rec, http.StatusUnprocessableEntity)
	if p := decode[map[string]any](t, rec); p["code"] != "validation_failed" {
		t.Fatalf("problem: %v", p)
	}

	u := decode[map[string]any](t, c.do(http.MethodPost, "/api/v1/users", map[string]string{"display_name": "Alice", "primary_email": "Alice@Example.com"}, nil))
	if u["primary_email"] != "alice@example.com" {
		t.Fatalf("email not normalised: %v", u)
	}
	rec = c.do(http.MethodPost, "/api/v1/tenants/smith/members", map[string]string{"user_id": u["id"].(string)}, nil)
	expect(t, rec, http.StatusCreated)
	m := decode[map[string]any](t, rec)
	list := decode[map[string]any](t, c.do(http.MethodGet, "/api/v1/tenants/smith/members", nil, nil))
	if items := list["items"].([]any); len(items) != 1 {
		t.Fatalf("members %v", list)
	}
	// Optimistic concurrency.
	path := "/api/v1/tenants/smith/members/" + m["id"].(string)
	expect(t, c.do(http.MethodPatch, path, map[string]string{"status": "suspended"}, map[string]string{"If-Match": `"1"`}), http.StatusOK)
	rec = c.do(http.MethodPatch, path, map[string]string{"status": "active"}, map[string]string{"If-Match": `"1"`})
	expect(t, rec, http.StatusPreconditionFailed)
	if p := decode[map[string]any](t, rec); p["code"] != "precondition_failed" {
		t.Fatalf("problem %v", p)
	}
	expect(t, c.do(http.MethodDelete, path, nil, map[string]string{"If-Match": `"2"`}), http.StatusNoContent)
	// Pagination.
	for i := range 3 {
		expect(t, c.do(http.MethodPost, "/api/v1/tenants", map[string]string{"slug": "t" + string(rune('a'+i)) + "x", "name": "x"}, nil), http.StatusCreated)
	}
	p1 := decode[map[string]any](t, c.do(http.MethodGet, "/api/v1/tenants?limit=2", nil, nil))
	if len(p1["items"].([]any)) != 2 || p1["next_cursor"] == nil {
		t.Fatalf("page1 %v", p1)
	}
	p2 := decode[map[string]any](t, c.do(http.MethodGet, "/api/v1/tenants?limit=2&cursor="+p1["next_cursor"].(string), nil, nil))
	if len(p2["items"].([]any)) != 2 {
		t.Fatalf("page2 %v", p2)
	}
	expect(t, c.do(http.MethodGet, "/api/v1/tenants?cursor=!!!", nil, nil), http.StatusUnprocessableEntity)

	// Audit chain verifies through the API and records the trusted client IP.
	v := decode[map[string]any](t, c.do(http.MethodGet, "/api/v1/installation/audit/verify", nil, nil))
	if v["ok"] != true {
		t.Fatalf("audit %v", v)
	}
	// Logout ends the session.
	expect(t, c.do(http.MethodPost, "/api/v1/logout", nil, nil), http.StatusNoContent)
	expect(t, c.do(http.MethodGet, "/api/v1/me", nil, nil), http.StatusUnauthorized)
}

// T-B2-3: state-changing cookie requests need the same Origin and the session's CSRF token.
func TestCSRFAndOrigin(t *testing.T) {
	a := newApp(t)
	c := setupOwner(t, a)
	body := map[string]string{"slug": "smith", "name": "x"}
	expect(t, c.do(http.MethodPost, "/api/v1/tenants", body, map[string]string{"X-Porch-CSRF": ""}), http.StatusForbidden)
	expect(t, c.do(http.MethodPost, "/api/v1/tenants", body, map[string]string{"X-Porch-CSRF": "forged"}), http.StatusForbidden)
	expect(t, c.do(http.MethodPost, "/api/v1/tenants", body, map[string]string{"Origin": "https://evil.example.com"}), http.StatusForbidden)
	expect(t, c.do(http.MethodPost, "/api/v1/tenants", body, map[string]string{"Origin": ""}), http.StatusForbidden)
	expect(t, c.do(http.MethodPost, "/api/v1/tenants", body, map[string]string{"Origin": "", "Sec-Fetch-Site": "same-origin"}), http.StatusCreated)
	// No session at all.
	anon := &client{t: t, h: c.h, remote: c.remote}
	expect(t, anon.do(http.MethodGet, "/api/v1/tenants", nil, nil), http.StatusUnauthorized)
}

// Non-operators cannot use installation endpoints, and cannot reach tenants they do not administer.
func TestNonOperatorForbidden(t *testing.T) {
	a := newApp(t)
	owner := setupOwner(t, a)
	expect(t, owner.do(http.MethodPost, "/api/v1/tenants", map[string]string{"slug": "smith", "name": "x"}, nil), http.StatusCreated)
	u := decode[map[string]any](t, owner.do(http.MethodPost, "/api/v1/users", map[string]string{"display_name": "Mallory"}, nil))
	var sc session.Created
	err := a.Store.W().Tx(context.Background(), func(tx *store.Tx) error {
		var err error
		sc, err = a.Sessions.CreateTx(context.Background(), tx, session.NewParams{UserID: u["id"].(string), Method: session.MethodGoogle})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := a.Sessions.Validate(context.Background(), sc.Token)
	if err != nil {
		t.Fatal(err)
	}
	m := &client{t: t, h: owner.h, cookie: sc.Token, csrf: p.CSRFToken, remote: "203.0.113.5:1"}
	expect(t, m.do(http.MethodGet, "/api/v1/me", nil, nil), http.StatusOK)
	for _, path := range []string{"/api/v1/tenants", "/api/v1/users", "/api/v1/installation", "/api/v1/sessions", "/api/v1/audit", "/api/v1/installation/health"} {
		expect(t, m.do(http.MethodGet, path, nil, nil), http.StatusForbidden)
	}
	// Tenant administration is delegated (ADR-0038): a non-member cannot tell a forbidden tenant from a missing one.
	for _, path := range []string{"/api/v1/tenants/smith", "/api/v1/tenants/smith/members", "/api/v1/tenants/smith/roles", "/api/v1/tenants/nope/roles"} {
		expect(t, m.do(http.MethodGet, path, nil, nil), http.StatusNotFound)
	}
	expect(t, m.do(http.MethodPost, "/api/v1/tenants", map[string]string{"slug": "evil", "name": "x"}, nil), http.StatusForbidden)
}

// T-B2-1: a forged X-Forwarded-For from an untrusted peer never reaches the audit log.
func TestAuditRecordsTrustedClientIP(t *testing.T) {
	var buf bytes.Buffer
	a := newApp(t)
	a.Audit.SetSink(audit.NewJSONSink(&buf))
	c := setupOwner(t, a)
	expect(t, c.do(http.MethodPost, "/api/v1/tenants", map[string]string{"slug": "smith", "name": "x"},
		map[string]string{"X-Forwarded-For": "1.2.3.4", "CF-Connecting-IP": "5.6.7.8"}), http.StatusCreated)
	if !strings.Contains(buf.String(), `"ip":"198.51.100.7"`) || strings.Contains(buf.String(), "1.2.3.4") || strings.Contains(buf.String(), "5.6.7.8") {
		t.Fatalf("audit IPs: %s", buf.String())
	}
	// With the peer configured as a trusted proxy, the forwarded client is used.
	b := newApp(t, func(c *config.Config) { c.Proxy.TrustedProxies = []string{"198.51.100.0/24"} })
	buf.Reset()
	b.Audit.SetSink(audit.NewJSONSink(&buf))
	cb := setupOwner(t, b)
	expect(t, cb.do(http.MethodPost, "/api/v1/tenants", map[string]string{"slug": "smith", "name": "x"},
		map[string]string{"X-Forwarded-For": "203.0.113.77"}), http.StatusCreated)
	if !strings.Contains(buf.String(), `"ip":"203.0.113.77"`) {
		t.Fatalf("trusted proxy IP not used: %s", buf.String())
	}
}

func TestHeadersAndListenerSeparation(t *testing.T) {
	a := newApp(t)
	pub := a.PublicHandler()
	rec := httptest.NewRecorder()
	pub.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/setup/status", nil))
	expect(t, rec, http.StatusOK)
	for _, h := range []string{"Content-Security-Policy", "X-Frame-Options", "X-Request-ID"} {
		if rec.Header().Get(h) == "" {
			t.Errorf("missing %s", h)
		}
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("API response cacheable")
	}
	// /metrics, health and pprof are not on the public listener (unknown paths get the SPA shell at most).
	for _, p := range []string{"/metrics", "/healthz", "/readyz", "/debug/pprof/"} {
		rec := httptest.NewRecorder()
		pub.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		b := rec.Body.String()
		if strings.Contains(b, "porch_") || strings.Contains(b, "ready") || strings.Contains(b, "goroutine") || rec.Header().Get("Content-Type") == "text/plain; version=0.0.4" {
			t.Errorf("public %s exposes management content: %d %q", p, rec.Code, b[:min(len(b), 80)])
		}
	}
	mg := a.ManagementHandler()
	for p, want := range map[string]int{"/metrics": 200, "/healthz": 200, "/readyz": 200, "/debug/pprof/": 404} {
		rec := httptest.NewRecorder()
		mg.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != want {
			t.Errorf("mgmt %s → %d want %d", p, rec.Code, want)
		}
		if p == "/metrics" && !strings.Contains(rec.Body.String(), "porch_store_tx_duration_seconds") {
			t.Error("metrics missing store histogram")
		}
	}
	// Oversized bodies are refused.
	big := strings.Repeat("x", 2<<20)
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/setup", strings.NewReader(big))
	req.Header.Set("Content-Type", "application/json")
	pub.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("big body → %d", rec.Code)
	}
}

// Real listeners: both bind, serve and shut down when the context ends.
func TestServeAndShutdown(t *testing.T) {
	a := newApp(t)
	ls, err := a.Listen(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Serve(ctx, ls) }()
	resp, err := http.Get("http://" + ls.Management.Addr().String() + "/readyz") //nolint:noctx // test
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("readyz %v %v", resp, err)
	}
	resp.Body.Close()
	resp, err = http.Get("http://" + ls.Public.Addr().String() + "/api/v1/setup/status") //nolint:noctx // test
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("public %v %v", resp, err)
	}
	resp.Body.Close()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("shutdown timed out")
	}
}

// A second process cannot open the same data directory.
func TestDataDirLock(t *testing.T) {
	a := newApp(t)
	_, err := app.Open(context.Background(), a.Cfg, slog.New(slog.DiscardHandler), app.Options{Environ: []string{}})
	if err == nil {
		t.Fatal("second open succeeded")
	}
}

func TestServerTimeoutsSet(t *testing.T) {
	a := newApp(t)
	for _, s := range func() []*http.Server { p, m := a.Servers(context.Background(), nil); return []*http.Server{p, m} }() {
		if s.ReadHeaderTimeout == 0 || s.ReadTimeout == 0 || s.WriteTimeout == 0 || s.IdleTimeout == 0 || s.MaxHeaderBytes == 0 {
			t.Fatalf("server timeouts not set: %+v", s)
		}
	}
}

// Applications through the API: the client secret is shown exactly once; rotation needs a recent sign-in.
func TestApplicationsAPI(t *testing.T) {
	clk := clock.NewFake(time.Now())
	a := newAppWithClock(t, clk)
	c := setupOwner(t, a)
	expect(t, c.do(http.MethodPost, "/api/v1/tenants", map[string]string{"slug": "smith", "name": "Smith"}, nil), http.StatusCreated)
	rec := c.do(http.MethodPost, "/api/v1/tenants/smith/applications", map[string]any{"slug": "grafana", "name": "Grafana", "kind": "oidc",
		"client": map[string]any{"redirect_uris": []string{"https://grafana.smith.example/login/generic_oauth"}, "audiences": []string{"https://grafana.smith.example"}}}, nil)
	expect(t, rec, http.StatusCreated)
	created := decode[map[string]any](t, rec)
	secret, _ := created["client_secret"].(string)
	cl := created["client"].(map[string]any)
	if !strings.HasPrefix(secret, "porch_cs_") || cl["client_id"] == "" || cl["require_pkce"] != true || cl["signing_alg"] != "ES256" ||
		cl["discovery_url"] != origin+"/.well-known/openid-configuration" {
		t.Fatalf("created %v", created)
	}
	got := c.do(http.MethodGet, "/api/v1/tenants/smith/applications/"+created["id"].(string), nil, nil)
	if strings.Contains(got.Body.String(), secret) || strings.Contains(got.Body.String(), "client_secret\"") {
		t.Fatal("secret returned again")
	}
	// Wildcard redirect URIs are always refused.
	rec = c.do(http.MethodPost, "/api/v1/tenants/smith/applications", map[string]any{"slug": "x", "name": "x", "kind": "oidc",
		"client": map[string]any{"redirect_uris": []string{"https://*.smith.example/cb"}}}, nil)
	expect(t, rec, http.StatusUnprocessableEntity)
	// Rotation needs a step-up: the setup session is fresh now, stale after 10 minutes.
	clk.Advance(10 * time.Minute)
	rec = c.do(http.MethodPost, "/api/v1/tenants/smith/applications/"+created["id"].(string)+"/rotate-secret", nil, nil)
	expect(t, rec, http.StatusForbidden)
	if p := decode[map[string]any](t, rec); p["code"] != "reauth_required" {
		t.Fatalf("problem %v", p)
	}
	// Signing keys are listed for operators.
	keys := c.do(http.MethodGet, "/api/v1/installation/signing-keys", nil, nil)
	expect(t, keys, http.StatusOK)
	if !strings.Contains(keys.Body.String(), "ES256") || !strings.Contains(keys.Body.String(), "RS256") {
		t.Fatalf("keys %s", keys.Body.String())
	}
}

// The authorization decision API explains decisions; shares grant cross-tenant access explicitly.
func TestAuthzCheckAndSharesAPI(t *testing.T) {
	a := newApp(t)
	c := setupOwner(t, a)
	for _, slug := range []string{"smith", "jones"} {
		expect(t, c.do(http.MethodPost, "/api/v1/tenants", map[string]string{"slug": slug, "name": slug}, nil), http.StatusCreated)
	}
	u := decode[map[string]any](t, c.do(http.MethodPost, "/api/v1/users", map[string]string{"display_name": "Carol"}, nil))
	expect(t, c.do(http.MethodPost, "/api/v1/tenants/jones/members", map[string]string{"user_id": u["id"].(string)}, nil), http.StatusCreated)
	app := decode[map[string]any](t, c.do(http.MethodPost, "/api/v1/tenants/smith/applications", map[string]any{"slug": "jellyfin", "name": "Jellyfin",
		"kind": "forward_auth", "hosts": []string{"jellyfin.smith.example"}}, nil))
	req := map[string]any{"user_id": u["id"], "action": "app:access", "resource": map[string]string{"type": "app", "id": app["id"].(string)}}
	d := decode[map[string]any](t, c.do(http.MethodPost, "/api/v1/tenants/smith/authz/check", req, nil))
	if d["allowed"] != false || d["reason"] != "tenant_gate" {
		t.Fatalf("before share %v", d)
	}
	expect(t, c.do(http.MethodPost, "/api/v1/tenants/smith/applications/"+app["id"].(string)+"/shares", map[string]string{"tenant": "jones"}, nil),
		http.StatusNoContent)
	rec0 := c.do(http.MethodPost, "/api/v1/tenants/smith/authz/check", req, nil)
	d = decode[map[string]any](t, rec0)
	trace, ok := d["trace"].(map[string]any)
	if !ok {
		t.Fatalf("no trace: %s", rec0.Body.String())
	}
	if d["allowed"] != true || trace["tenant_gate"].(map[string]any)["via"] != "share:jones" {
		t.Fatalf("after share %v", d)
	}
	// Simulated context is flagged.
	req["context"] = map[string]any{"ip": "10.0.0.1", "network": "trusted", "hour": 3}
	rec1 := c.do(http.MethodPost, "/api/v1/tenants/smith/authz/check", req, nil)
	d = decode[map[string]any](t, rec1)
	if tr, _ := d["trace"].(map[string]any); tr == nil || tr["simulated"] != true {
		t.Fatalf("simulation not flagged %v", d)
	}
	// Hosts are unique installation-wide.
	rec := c.do(http.MethodPost, "/api/v1/tenants/jones/applications", map[string]any{"slug": "x", "name": "x", "kind": "forward_auth",
		"hosts": []string{"jellyfin.smith.example"}}, nil)
	expect(t, rec, http.StatusConflict)
}

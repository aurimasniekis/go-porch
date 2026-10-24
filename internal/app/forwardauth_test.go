package app_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aurimasniekis/go-porch/internal/apps"
	"github.com/aurimasniekis/go-porch/internal/domain"
	"github.com/aurimasniekis/go-porch/internal/idp"
	"github.com/aurimasniekis/go-porch/internal/tenancy"
)

// caddyLike emulates Caddy: strip client X-Porch-*, route /.porch/* to Porch with the app Host, else forward_auth.
type caddyLike struct {
	porch   *url.URL
	client  *http.Client
	backend http.Handler
	noStrip bool // simulate a misconfigured proxy
}

func (c *caddyLike) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !c.noStrip {
		for k := range r.Header {
			if strings.HasPrefix(strings.ToLower(k), "x-porch-") || strings.HasPrefix(strings.ToLower(k), "remote-") {
				r.Header.Del(k)
			}
		}
	}
	if strings.HasPrefix(r.URL.Path, "/.porch/") {
		rp := &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(c.porch)
			pr.Out.Host = pr.In.Host // preserve the application host
		}, Transport: c.client.Transport}
		rp.ServeHTTP(w, r)
		return
	}
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, c.porch.String()+"/outpost/auth", nil)
	// Like Caddy's forward_auth: client headers are copied into the subrequest, then X-Forwarded-* are overwritten.
	for k, v := range r.Header {
		req.Header[k] = v
	}
	req.Header.Set("X-Forwarded-Method", r.Method)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", r.Host)
	req.Header.Set("X-Forwarded-Uri", r.URL.RequestURI())
	resp, err := c.client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 == 2 {
		for k, v := range resp.Header {
			if strings.HasPrefix(strings.ToLower(k), "x-porch-") {
				r.Header[k] = v
			}
		}
		c.backend.ServeHTTP(w, r)
		return
	}
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// whoami echoes the request line and headers.
var whoami = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	var keys []string
	for k := range r.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	_, _ = fmt.Fprintf(w, "%s %s\n", r.Method, r.URL.RequestURI())
	for _, k := range keys {
		_, _ = fmt.Fprintf(w, "%s: %s\n", k, strings.Join(r.Header[k], ","))
	}
})

type faFixture struct {
	st    *stack
	tn    tenancy.Tenant
	b     *browser
	proxy *httptest.Server
	caddy *caddyLike
	appID string
}

// faStack starts Porch, fake Google, a forward_auth app for whoami.test behind caddyLike, and a browser that resolves
// *.test to the proxy.
func faStack(t *testing.T, mode string) *faFixture {
	t.Helper()
	st := newStack(t)
	tn := st.setupGoogle(nil, idp.RuleParams{Domain: "smith.example", EvidenceKind: idp.EvidenceWorkspaceHD, Mode: idp.ModeJIT})
	st.google.AddUser(workspaceUser("g-ada", "ada@smith.example", "smith.example"))
	sc, _ := st.a.Tenants.SystemScope(context.Background(), tn.ID)
	cr, err := st.a.Apps.Create(context.Background(), domain.SystemChange, sc, apps.CreateParams{Slug: "whoami", Name: "Whoami", Kind: apps.KindForwardAuth,
		AccessMode: mode, Hosts: []string{"whoami.test"}})
	if err != nil {
		t.Fatal(err)
	}
	pu, _ := url.Parse(st.origin())
	noFollow := &http.Client{Transport: st.srv.Client().Transport, Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }} // a proxy relays redirects
	caddy := &caddyLike{porch: pu, client: noFollow, backend: whoami}
	proxy := httptest.NewTLSServer(caddy)
	t.Cleanup(proxy.Close)
	b := st.browser()
	base := st.srv.Client().Transport.(*http.Transport).Clone()
	base.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test servers
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	base.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if host, _, _ := net.SplitHostPort(addr); strings.HasSuffix(host, ".test") {
			addr = proxy.Listener.Addr().String()
		}
		return dialer.DialContext(ctx, network, addr)
	}
	jar, _ := cookiejar.New(nil)
	b.c = &http.Client{Transport: base, Jar: jar, Timeout: 10 * time.Second}
	return &faFixture{st: st, tn: tn, b: b, proxy: proxy, caddy: caddy, appID: cr.App.ID}
}

func (f *faFixture) get(t *testing.T, u string, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, u, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := f.b.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(body)
}

func TestForwardAuthFlow(t *testing.T) {
	f := faStack(t, apps.AccessAllMembers)
	f.st.loginAs(f.b, "g-ada")
	resp, body := f.get(t, "https://whoami.test/hello?x=1", map[string]string{"X-Porch-User": "attacker", "Remote-User": "admin"})
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "GET /hello?x=1") {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	for _, want := range []string{"X-Porch-Email: ada@smith.example", "X-Porch-Tenant: smith", "X-Porch-User: u_"} {
		if !strings.Contains(body, want) {
			t.Errorf("backend missing %q in:\n%s", want, body)
		}
	}
	if strings.Contains(body, "attacker") || strings.Contains(body, "Remote-User") {
		t.Fatalf("spoofed identity reached the backend:\n%s", body)
	}
	// The forward-auth cookie is host-only on the application host and never on Porch's host.
	appURL, _ := url.Parse("https://whoami.test/")
	var fa *http.Cookie
	for _, c := range f.b.c.Jar.Cookies(appURL) {
		if c.Name == "__Host-porch_fa" {
			fa = c
		}
	}
	if fa == nil {
		t.Fatal("no forward-auth cookie on the app host")
	}
	porchURL, _ := url.Parse(f.st.origin())
	for _, c := range f.b.c.Jar.Cookies(porchURL) {
		if c.Name == "__Host-porch_fa" {
			t.Fatal("forward-auth cookie leaked to the Porch host")
		}
	}
	// Second request: no redirect needed.
	resp, _ = f.get(t, "https://whoami.test/again", nil)
	if resp.StatusCode != http.StatusOK || resp.Request.URL.Host != "whoami.test" {
		t.Fatalf("second request %d %s", resp.StatusCode, resp.Request.URL)
	}
	// Signing out of Porch invalidates the app session too.
	f.b.me()
	if code, _ := f.b.api(http.MethodPost, "/api/v1/logout", nil); code != http.StatusNoContent {
		t.Fatal(code)
	}
	nr := *f.b.c
	nr.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	r2, err := nr.Get("https://whoami.test/after-logout") //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	r2.Body.Close()
	if r2.StatusCode != http.StatusFound || !strings.Contains(r2.Header.Get("Location"), "/outpost/start") {
		t.Fatalf("after Porch logout: %d %s", r2.StatusCode, r2.Header.Get("Location"))
	}
}

// T-B2-2: a proxy that forgets to strip client headers still cannot make Porch vouch for them; Porch overwrites the
// identity headers it controls. (Headers Porch does not set are the proxy's responsibility — documented.)
func TestForwardAuthMisconfiguredProxyOverwrite(t *testing.T) {
	f := faStack(t, apps.AccessAllMembers)
	f.caddy.noStrip = true
	f.st.loginAs(f.b, "g-ada")
	_, body := f.get(t, "https://whoami.test/", map[string]string{"X-Porch-Email": "attacker@evil.example"})
	if strings.Contains(body, "attacker@evil.example") {
		t.Fatalf("spoofed X-Porch-Email survived:\n%s", body)
	}
}

func TestForwardAuthAccessDeniedAndOpenRedirect(t *testing.T) {
	f := faStack(t, apps.AccessAssigned)
	f.st.loginAs(f.b, "g-ada")
	resp, body := f.get(t, "https://whoami.test/", nil)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "No access") {
		t.Fatalf("assigned app without grant: %d %q", resp.StatusCode, body)
	}
	for _, rd := range []string{"https://evil.example/", "https://whoami.test@evil.example/", "javascript:alert(1)", "//whoami.test/", "/relative",
		"https://unknown.test/"} {
		resp, _ := f.get(t, f.st.origin()+"/outpost/start?rd="+url.QueryEscape(rd), nil)
		if resp.StatusCode != http.StatusBadRequest || resp.Request.URL.Host != strings.TrimPrefix(f.st.origin(), "https://") {
			t.Errorf("rd %q: %d → %s", rd, resp.StatusCode, resp.Request.URL)
		}
	}
}

func TestForwardAuthOutpostHardening(t *testing.T) {
	f := faStack(t, apps.AccessAllMembers)
	h := f.st.a.PublicHandler()
	// Untrusted peer calling /outpost/auth directly.
	req := httptest.NewRequest(http.MethodGet, "/outpost/auth", nil)
	req.RemoteAddr = "203.0.113.10:1234"
	req.Header.Set("X-Forwarded-Host", "whoami.test")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("untrusted peer: %d", rec.Code)
	}
	// Unknown host.
	req = httptest.NewRequest(http.MethodGet, "/outpost/auth", nil)
	req.RemoteAddr = "127.0.0.1:1"
	req.Header.Set("X-Forwarded-Host", "nope.test")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unknown host: %d", rec.Code)
	}
	// A code minted for whoami.test cannot be redeemed on another host.
	f.st.loginAs(f.b, "g-ada")
	nr := *f.b.c
	nr.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Path == "/.porch/callback" {
			return http.ErrUseLastResponse
		}
		return nil
	}
	resp, err := nr.Get(f.st.origin() + "/outpost/start?rd=" + url.QueryEscape("https://whoami.test/x")) //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Host != "whoami.test" {
		t.Fatalf("callback location %s", loc)
	}
	other, _ := f.get(t, "https://other.test/.porch/callback?"+loc.RawQuery, nil)
	if other.StatusCode != http.StatusBadRequest {
		t.Fatalf("code redeemed on another host: %d", other.StatusCode)
	}
	again, _ := f.get(t, "https://whoami.test/.porch/callback?"+loc.RawQuery, nil)
	if again.StatusCode != http.StatusBadRequest {
		t.Fatalf("burned code reused: %d", again.StatusCode)
	}
}

// Security review H1: proxies such as Caddy and Traefik copy client headers into the auth subrequest, so a client-set
// X-Original-URL must never select the application (a cookie for one app must not open another).
func TestForwardAuthIgnoresClientOriginalURL(t *testing.T) {
	f := faStack(t, apps.AccessAssigned) // whoami.test: assigned only, ada has no grant
	sc, _ := f.st.a.Tenants.SystemScope(context.Background(), f.tn.ID)
	if _, err := f.st.a.Apps.Create(context.Background(), domain.SystemChange, sc, apps.CreateParams{Slug: "pub", Name: "Pub", Kind: apps.KindForwardAuth,
		AccessMode: apps.AccessAllMembers, Hosts: []string{"public.test"}}); err != nil {
		t.Fatal(err)
	}
	f.st.loginAs(f.b, "g-ada")
	if resp, _ := f.get(t, "https://public.test/", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("public %d", resp.StatusCode)
	}
	var fa string
	pu, _ := url.Parse("https://public.test/")
	for _, c := range f.b.c.Jar.Cookies(pu) {
		if c.Name == "__Host-porch_fa" {
			fa = c.Value
		}
	}
	if fa == "" {
		t.Fatal("no forward-auth cookie for public.test")
	}
	resp, body := f.get(t, "https://whoami.test/secret", map[string]string{"X-Original-URL": "https://public.test/", "Cookie": "__Host-porch_fa=" + fa})
	if resp.StatusCode == http.StatusOK || strings.Contains(body, "GET /secret") {
		t.Fatalf("X-Original-URL selected another application: %d %s", resp.StatusCode, body)
	}
}

// Security review L8: a sign-in link captured by an attacker (the callback with their first code, or the finish link
// with their second code) never signs another browser into the attacker's identity.
func TestForwardAuthLoginBoundToBrowser(t *testing.T) {
	f := faStack(t, apps.AccessAllMembers)
	f.st.loginAs(f.b, "g-ada") // the attacker
	stopAt := func(path string) string {
		c := *f.b.c
		c.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
			if req.URL.Path == path {
				return http.ErrUseLastResponse
			}
			return nil
		}
		resp, err := c.Get(f.st.origin() + "/outpost/start?rd=" + url.QueryEscape("https://whoami.test/x")) //nolint:noctx // test
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.Header.Get("Location")
	}
	for _, link := range []string{stopAt("/.porch/callback"), stopAt("/.porch/finish")} {
		if link == "" {
			t.Fatal("no sign-in link")
		}
		jar, _ := cookiejar.New(nil)
		victim := &http.Client{Transport: f.b.c.Transport, Jar: jar}
		r1, err := victim.Get(link) //nolint:noctx // test
		if err != nil {
			t.Fatal(err)
		}
		r1.Body.Close()
		r2, err := victim.Get("https://whoami.test/profile") //nolint:noctx // test
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(r2.Body)
		r2.Body.Close()
		if strings.Contains(string(body), "ada@smith.example") {
			t.Fatalf("victim signed in as the attacker via %s", link)
		}
	}
	// The attacker's own browser still completes the flow.
	if resp, body := f.get(t, "https://whoami.test/x", nil); resp.StatusCode != http.StatusOK || !strings.Contains(body, "ada@smith.example") {
		t.Fatalf("own sign-in: %d", resp.StatusCode)
	}
}

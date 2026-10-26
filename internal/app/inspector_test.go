package app_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aurimasniekis/go-porch/internal/clock"
)

// tenantReads are the configuration reads an inspector may make in a tenant (ADR-0048).
func tenantReads(app, sa string) []string {
	base := "/api/v1/tenants/smith"
	return []string{base, base + "/applications", base + "/applications/" + app, base + "/applications/" + app + "/shares",
		base + "/service-accounts", base + "/service-accounts/" + sa, base + "/members", base + "/groups", base + "/roles",
		base + "/roles/admin", base + "/permissions", base + "/assignments", base + "/resources", base + "/policies", base + "/invites",
		base + "/domain-rules", "/api/v1/tenants", "/api/v1/identity-providers"}
}

// inspectorFixture is a tenant with an application and a service account.
func inspectorFixture(t *testing.T, owner *client) (app, sa string) {
	t.Helper()
	smithWith(t, owner)
	app = decode[map[string]any](t, owner.do(http.MethodPost, "/api/v1/tenants/smith/applications", map[string]any{"slug": "wiki", "name": "Wiki",
		"kind": "forward_auth", "hosts": []string{"wiki.smith.example"}}, nil))["id"].(string)
	sa = decode[map[string]any](t, owner.do(http.MethodPost, "/api/v1/tenants/smith/service-accounts", map[string]any{"slug": "ci", "name": "CI",
		"audiences": []string{"https://api.smith.example"}}, nil))["id"].(string)
	return app, sa
}

// writesAreRefused sends every mutating operation of the management API, and a set of valid writes, as caller: none
// may succeed.
func writesAreRefused(t *testing.T, who string, do func(method, path string, body any) *httptest.ResponseRecorder, app string) {
	t.Helper()
	raw, err := os.ReadFile("../../api/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	param := regexp.MustCompile(`\{[a-z_]+\}`)
	n := 0
	for path, ops := range spec.Paths {
		if strings.HasPrefix(path, "/me") || path == "/logout" || strings.HasPrefix(path, "/setup") {
			continue // the caller's own account, not configuration
		}
		concrete := param.ReplaceAllStringFunc(strings.Replace(path, "{tenant}", "smith", 1), func(p string) string {
			if p == "{app}" {
				return app
			}
			return "x"
		})
		for method := range ops {
			m := strings.ToUpper(method)
			if m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions {
				continue
			}
			n++
			if rec := do(m, "/api/v1"+concrete, map[string]any{}); rec.Code < 300 {
				t.Errorf("%s: %s %s = %d", who, m, path, rec.Code)
			}
		}
	}
	if n < 50 {
		t.Fatalf("only %d mutating operations found", n)
	}
	for _, w := range []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, "/api/v1/tenants", map[string]string{"slug": "doe", "name": "Doe"}},
		{http.MethodPatch, "/api/v1/tenants/smith", map[string]any{"name": "Smiths"}},
		{http.MethodPost, "/api/v1/tenants/smith/applications", map[string]any{"slug": "x", "name": "X", "kind": "forward_auth",
			"hosts": []string{"x.smith.example"}}},
		{http.MethodPost, "/api/v1/tenants/smith/groups", map[string]string{"slug": "kids", "name": "Kids"}},
		{http.MethodPost, "/api/v1/tenants/smith/roles", map[string]any{"slug": "r", "name": "R", "permissions": []string{"app:read"}}},
		{http.MethodPost, "/api/v1/tenants/smith/service-accounts", map[string]any{"slug": "x", "name": "X"}},
		{http.MethodPost, "/api/v1/tenants/smith/automation-tokens", map[string]any{"name": "x", "permissions": []string{"app:read"},
			"expires_in_days": 1}},
		{http.MethodPost, "/api/v1/installation/automation-tokens", map[string]any{"name": "x", "role": "inspector", "expires_in_days": 1}},
		{http.MethodDelete, "/api/v1/tenants/smith/applications/" + app, nil},
	} {
		if rec := do(w.method, w.path, w.body); rec.Code < 300 || rec.Code == http.StatusUnprocessableEntity {
			t.Errorf("%s: %s %s = %d %s, want 403/404", who, w.method, w.path, rec.Code, rec.Body.String())
		}
	}
}

// ADR-0048: the installation inspector (a person or a token) reads the configuration of every tenant and changes
// nothing.
func TestInspectorReadsEveryTenant(t *testing.T) {
	a := newApp(t)
	owner := setupOwner(t, a)
	app, sa := inspectorFixture(t, owner)
	ivy, ivyID := memberClient(t, a, owner, "", "Ivy")
	for _, p := range tenantReads(app, sa) {
		if rec := ivy.do(http.MethodGet, p, nil, nil); rec.Code < 400 {
			t.Fatalf("GET %s before the role = %d", p, rec.Code)
		}
	}
	expect(t, owner.do(http.MethodPost, "/api/v1/installation/operators", map[string]string{"user_id": ivyID, "role": "inspector"}, nil),
		http.StatusNoContent)
	for _, p := range tenantReads(app, sa) {
		expect(t, ivy.do(http.MethodGet, p, nil, nil), http.StatusOK)
	}
	caps := decode[map[string]any](t, ivy.do(http.MethodGet, "/api/v1/me/admin", nil, nil))
	tn := caps["tenants"].([]any)
	if caps["inspector"] != true || caps["installation"] != false || caps["auditor"] != false || len(tn) != 1 ||
		tn[0].(map[string]any)["via"] != "inspector" {
		t.Fatalf("capabilities %v", caps)
	}
	// Installation business other than reading tenants stays closed.
	for _, p := range []string{"/api/v1/users", "/api/v1/audit", "/api/v1/installation/health", "/api/v1/sessions",
		"/api/v1/tenants/smith/audit", "/api/v1/tenants/smith/automation-tokens"} {
		if rec := ivy.do(http.MethodGet, p, nil, nil); rec.Code < 400 {
			t.Errorf("GET %s = %d", p, rec.Code)
		}
	}
	writesAreRefused(t, "inspector", func(method, path string, body any) *httptest.ResponseRecorder {
		return ivy.do(method, path, body, nil)
	}, app)

	// An inspector token reads the same, and only while its creator holds an installation role.
	tok := decode[map[string]any](t, owner.do(http.MethodPost, "/api/v1/installation/automation-tokens",
		map[string]any{"name": "deed", "role": "inspector", "expires_in_days": 30}, nil))
	if tok["role"] != "inspector" {
		t.Fatalf("token %v", tok)
	}
	deed := bearer(owner, tok["token"].(string))
	for _, p := range tenantReads(app, sa) {
		expect(t, deed(http.MethodGet, p, nil), http.StatusOK)
	}
	writesAreRefused(t, "inspector token", func(method, path string, body any) *httptest.ResponseRecorder {
		return deed(method, path, body)
	}, app)
	// No secrets in what it reads.
	for _, p := range []string{"/api/v1/tenants/smith/applications/" + app, "/api/v1/tenants/smith/service-accounts/" + sa} {
		if body := deed(http.MethodGet, p, nil).Body.String(); strings.Contains(body, "client_secret") {
			t.Fatalf("%s leaks a secret: %s", p, body)
		}
	}

	// The auditor role is unchanged: installation health, but nothing inside a tenant.
	aud := decode[map[string]any](t, owner.do(http.MethodPost, "/api/v1/installation/automation-tokens",
		map[string]any{"name": "grafana", "role": "auditor", "expires_in_days": 30}, nil))
	ro := bearer(owner, aud["token"].(string))
	expect(t, ro(http.MethodGet, "/api/v1/installation/health", nil), http.StatusOK)
	expect(t, ro(http.MethodGet, "/api/v1/tenants/smith/applications", nil), http.StatusNotFound)

	// Removing the role ends the person's access at once.
	expect(t, owner.do(http.MethodDelete, "/api/v1/installation/operators/"+ivyID+"/inspector", nil, nil), http.StatusNoContent)
	expect(t, ivy.do(http.MethodGet, "/api/v1/tenants/smith/applications", nil, nil), http.StatusNotFound)
}

// ADR-0048: tenant :read permissions allow the matching reads and no writes.
func TestTenantReadPermissions(t *testing.T) {
	a := newApp(t)
	owner := setupOwner(t, a)
	app, sa := inspectorFixture(t, owner)
	dana, danaID := memberClient(t, a, owner, "smith", "Dana")
	give(t, owner, danaID, roleWith(t, owner, "viewer", "app:read", "service_account:read", "member:read"), nil)
	for _, p := range []string{"/api/v1/tenants/smith/applications", "/api/v1/tenants/smith/applications/" + app,
		"/api/v1/tenants/smith/service-accounts", "/api/v1/tenants/smith/service-accounts/" + sa, "/api/v1/tenants/smith/members"} {
		expect(t, dana.do(http.MethodGet, p, nil, nil), http.StatusOK)
	}
	// Reads not granted, shares and domain rules (operators and inspectors only), and every write stay closed.
	expect(t, dana.do(http.MethodGet, "/api/v1/tenants/smith/groups", nil, nil), http.StatusNotFound)
	expect(t, dana.do(http.MethodGet, "/api/v1/tenants/smith/applications/"+app+"/shares", nil, nil), http.StatusForbidden)
	expect(t, dana.do(http.MethodPost, "/api/v1/tenants/smith/applications", map[string]any{"slug": "x", "name": "X", "kind": "forward_auth",
		"hosts": []string{"x.smith.example"}}, nil), http.StatusNotFound)
	expect(t, dana.do(http.MethodPatch, "/api/v1/tenants/smith/service-accounts/"+sa, map[string]any{"name": "Y"}, nil), http.StatusNotFound)
	expect(t, dana.do(http.MethodPost, "/api/v1/tenants/smith/members", map[string]string{"user_id": danaID}, nil), http.StatusNotFound)
	caps := decode[map[string]any](t, dana.do(http.MethodGet, "/api/v1/me/admin", nil, nil))
	if got := caps["tenants"].([]any)[0].(map[string]any)["permissions"]; len(got.([]any)) != 3 {
		t.Fatalf("permissions %v", got)
	}
	// A read-only tenant token works the same way.
	tok := decode[map[string]any](t, dana.do(http.MethodPost, "/api/v1/tenants/smith/automation-tokens",
		map[string]any{"name": "deed", "permissions": []string{"app:read"}, "expires_in_days": 7}, nil))
	ro := bearer(owner, tok["token"].(string))
	expect(t, ro(http.MethodGet, "/api/v1/tenants/smith/applications", nil), http.StatusOK)
	expect(t, ro(http.MethodGet, "/api/v1/tenants/smith/service-accounts", nil), http.StatusNotFound)
	expect(t, ro(http.MethodDelete, "/api/v1/tenants/smith/applications/"+app, nil), http.StatusNotFound)
	// A :manage permission still allows the reads.
	expect(t, owner.do(http.MethodGet, "/api/v1/tenants/smith/applications", nil, nil), http.StatusOK)
}

// ADR-0048: an installation token whose creator is an owner issues tokens no broader than itself; other tokens issue
// only narrower tokens of their own tenant; no token outlives its issuer; revoking a token revokes what it issued.
func TestTokensIssueTokens(t *testing.T) {
	clk := clock.NewFake(time.Now().UTC().Truncate(time.Second))
	a := newAppWithClock(t, clk)
	owner := setupOwner(t, a)
	smithWith(t, owner)
	expect(t, owner.do(http.MethodPost, "/api/v1/tenants", map[string]string{"slug": "jones", "name": "Jones"}, nil), http.StatusCreated)
	root := decode[map[string]any](t, owner.do(http.MethodPost, "/api/v1/installation/automation-tokens",
		map[string]any{"name": "terraform", "role": "admin", "never_expires": true}, nil))
	tf := bearer(owner, root["token"].(string))
	issue := func(c func(method, path string, body any, hdr ...map[string]string) *httptest.ResponseRecorder, path string, body map[string]any,
		want int) map[string]any {
		t.Helper()
		rec := c(http.MethodPost, path, body)
		expect(t, rec, want)
		if want != http.StatusCreated {
			return nil
		}
		return decode[map[string]any](t, rec)
	}
	const inst, smith = "/api/v1/installation/automation-tokens", "/api/v1/tenants/smith/automation-tokens"

	// The owner's token issues an inspector token and a tenant token, both recording their issuer.
	insp := issue(tf, inst, map[string]any{"name": "deed", "role": "inspector", "expires_in_days": 30}, http.StatusCreated)
	if insp["issued_by"] != root["id"] || insp["never_expires"] != false {
		t.Fatalf("issued %v", insp)
	}
	expect(t, bearer(owner, insp["token"].(string))(http.MethodGet, "/api/v1/tenants/smith/applications", nil), http.StatusOK)
	never := issue(tf, inst, map[string]any{"name": "deed-forever", "role": "inspector", "never_expires": true}, http.StatusCreated)
	ten := issue(tf, smith, map[string]any{"name": "apps", "permissions": []string{"app:read", "app:manage"}, "expires_in_days": 2},
		http.StatusCreated)
	apps := bearer(owner, ten["token"].(string))
	// The issuer reads and revokes what it issued; an unrelated token cannot.
	if got := decode[map[string]any](t, tf(http.MethodGet, inst+"/"+insp["id"].(string), nil)); got["name"] != "deed" || got["token"] != nil {
		t.Fatalf("get %v", got)
	}
	expect(t, tf(http.MethodGet, smith+"/"+ten["id"].(string), nil), http.StatusOK)
	other := decode[map[string]any](t, owner.do(http.MethodPost, inst, map[string]any{"name": "other", "role": "inspector", "expires_in_days": 30}, nil))
	otherTok := bearer(owner, other["token"].(string))
	expect(t, otherTok(http.MethodGet, inst+"/"+insp["id"].(string), nil), http.StatusNotFound)
	expect(t, otherTok(http.MethodDelete, inst+"/"+never["id"].(string), nil), http.StatusNotFound)
	expect(t, tf(http.MethodDelete, inst+"/"+never["id"].(string), nil), http.StatusNoContent)

	// Read-only tokens never issue broader tokens; tenant tokens issue only within their own tenant and grant.
	inspTok := bearer(owner, insp["token"].(string))
	issue(inspTok, inst, map[string]any{"name": "x", "role": "admin", "expires_in_days": 1}, http.StatusForbidden)
	issue(inspTok, inst, map[string]any{"name": "x", "role": "inspector", "expires_in_days": 1}, http.StatusForbidden)
	issue(inspTok, smith, map[string]any{"name": "x", "permissions": []string{"app:read"}, "expires_in_days": 1}, http.StatusForbidden)
	issue(apps, inst, map[string]any{"name": "x", "role": "inspector", "expires_in_days": 1}, http.StatusForbidden)
	issue(apps, "/api/v1/tenants/jones/automation-tokens", map[string]any{"name": "x", "permissions": []string{"app:read"}, "expires_in_days": 1},
		http.StatusNotFound)
	issue(apps, smith, map[string]any{"name": "x", "permissions": []string{"group:manage"}, "expires_in_days": 1}, http.StatusNotFound)
	// ...and never outlive their issuer, or skip expiry unless the issuer never expires.
	issue(apps, smith, map[string]any{"name": "x", "permissions": []string{"app:read"}, "expires_in_days": 3}, http.StatusUnprocessableEntity)
	limited := issue(tf, inst, map[string]any{"name": "limited", "role": "admin", "expires_in_days": 5}, http.StatusCreated)
	issue(bearer(owner, limited["token"].(string)), inst, map[string]any{"name": "x", "role": "inspector", "never_expires": true},
		http.StatusUnprocessableEntity)
	child := issue(apps, smith, map[string]any{"name": "child", "permissions": []string{"app:read"}, "expires_in_days": 1}, http.StatusCreated)
	childTok := bearer(owner, child["token"].(string))
	expect(t, childTok(http.MethodGet, "/api/v1/tenants/smith/applications", nil), http.StatusOK)
	// A read-only token issues nothing, not even a copy of itself.
	issue(childTok, smith, map[string]any{"name": "x", "permissions": []string{"app:read"}, "expires_in_days": 1}, http.StatusForbidden)
	expect(t, childTok(http.MethodPost, "/api/v1/tenants/smith/applications", map[string]any{"slug": "x", "name": "X", "kind": "forward_auth",
		"hosts": []string{"x.smith.example"}}), http.StatusNotFound)
	// The tenant token reads its child without tenant:manage.
	expect(t, apps(http.MethodGet, smith+"/"+child["id"].(string), nil), http.StatusOK)
	expect(t, apps(http.MethodGet, smith+"/"+ten["id"].(string), nil), http.StatusNotFound)

	// Interactive people still need a recent sign-in; tokens never do (they were issued under one).
	ev := decode[map[string]any](t, owner.do(http.MethodGet, "/api/v1/audit?action=automation_token.created&limit=1", nil, nil))["items"].([]any)[0]
	if d := ev.(map[string]any)["details"].(map[string]any); d["issued_by"] != ten["id"] {
		t.Fatalf("audit details %v", d)
	}

	// Revoking the root revokes everything it issued, transitively.
	expect(t, owner.do(http.MethodDelete, inst+"/"+root["id"].(string), nil, nil), http.StatusNoContent)
	for name, c := range map[string]func(method, path string, body any, hdr ...map[string]string) *httptest.ResponseRecorder{
		"root": tf, "inspector": inspTok, "tenant": apps, "child": childTok} {
		if rec := c(http.MethodGet, "/api/v1/me", nil); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s token still works: %d", name, rec.Code)
		}
	}
	expect(t, otherTok(http.MethodGet, "/api/v1/tenants", nil), http.StatusOK)
}

// ADR-0048: an installation token issues tokens only while its creator is an installation owner.
func TestTokenIssuanceFollowsCreatorOwnership(t *testing.T) {
	a := newApp(t)
	owner := setupOwner(t, a)
	bob, bobID := memberClient(t, a, owner, "", "Bob")
	for _, role := range []string{"owner", "admin"} {
		expect(t, owner.do(http.MethodPost, "/api/v1/installation/operators", map[string]string{"user_id": bobID, "role": role}, nil),
			http.StatusNoContent)
	}
	tok := decode[map[string]any](t, bob.do(http.MethodPost, "/api/v1/installation/automation-tokens",
		map[string]any{"name": "bob-tf", "role": "admin", "expires_in_days": 30}, nil))
	tf := bearer(owner, tok["token"].(string))
	body := map[string]any{"name": "deed", "role": "inspector", "expires_in_days": 1}
	expect(t, tf(http.MethodPost, "/api/v1/installation/automation-tokens", body), http.StatusCreated)
	expect(t, owner.do(http.MethodDelete, "/api/v1/installation/operators/"+bobID+"/owner", nil, nil), http.StatusNoContent)
	expect(t, tf(http.MethodGet, "/api/v1/tenants", nil), http.StatusOK) // still an admin token
	expect(t, tf(http.MethodPost, "/api/v1/installation/automation-tokens", body), http.StatusForbidden)
}

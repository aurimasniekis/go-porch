package app_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/aurimasniekis/go-porch/internal/app"
	"github.com/aurimasniekis/go-porch/internal/authz"
	"github.com/aurimasniekis/go-porch/internal/session"
	"github.com/aurimasniekis/go-porch/internal/store"
)

// memberClient creates a user, adds them to tenant and returns a browser client with a fresh session.
func memberClient(t *testing.T, a *app.App, owner *client, tenant, name string) (*client, string) {
	t.Helper()
	u := decode[map[string]any](t, owner.do(http.MethodPost, "/api/v1/users", map[string]string{"display_name": name}, nil))
	id := u["id"].(string)
	if tenant != "" {
		expect(t, owner.do(http.MethodPost, "/api/v1/tenants/"+tenant+"/members", map[string]string{"user_id": id}, nil), http.StatusCreated)
	}
	var sc session.Created
	err := a.Store.W().Tx(context.Background(), func(tx *store.Tx) error {
		var err error
		sc, err = a.Sessions.CreateTx(context.Background(), tx, session.NewParams{UserID: id, Method: session.MethodBackup})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := a.Sessions.Validate(context.Background(), sc.Token)
	if err != nil {
		t.Fatal(err)
	}
	return &client{t: t, h: owner.h, cookie: sc.Token, csrf: p.CSRFToken, remote: "203.0.113.9:1"}, id
}

func problemCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	return decode[map[string]any](t, rec)["code"].(string)
}

func roleID(t *testing.T, c *client, tenant, slug string) string {
	t.Helper()
	return decode[map[string]any](t, c.do(http.MethodGet, "/api/v1/tenants/"+tenant+"/roles/"+slug, nil, nil))["id"].(string)
}

func assign(c *client, tenant string, body map[string]any) *httptest.ResponseRecorder {
	if body["scope_type"] == nil {
		body["scope_type"] = "tenant"
	}
	return c.do(http.MethodPost, "/api/v1/tenants/"+tenant+"/assignments", body, nil)
}

// ADR-0038: tenant members administer a tenant through permissions, and can never grant more than they hold.
func TestDelegatedTenantAdministration(t *testing.T) {
	a := newApp(t)
	owner := setupOwner(t, a)
	for _, slug := range []string{"smith", "jones"} {
		expect(t, owner.do(http.MethodPost, "/api/v1/tenants", map[string]string{"slug": slug, "name": slug}, nil), http.StatusCreated)
	}
	dave, daveID := memberClient(t, a, owner, "smith", "Dave")
	_, bobID := memberClient(t, a, owner, "smith", "Bob")

	// Without permissions a member cannot tell the tenant exists.
	expect(t, dave.do(http.MethodGet, "/api/v1/tenants/smith/roles", nil, nil), http.StatusNotFound)
	if caps := decode[map[string]any](t, dave.do(http.MethodGet, "/api/v1/me/admin", nil, nil)); len(caps["tenants"].([]any)) != 0 {
		t.Fatalf("caps without roles: %v", caps)
	}

	helpdesk := decode[map[string]any](t, owner.do(http.MethodPost, "/api/v1/tenants/smith/roles", map[string]any{"slug": "helpdesk", "name": "Helpdesk",
		"permissions": []string{"group:manage", "role:manage", "member:manage", "app:access"}}, nil))
	expect(t, assign(owner, "smith", map[string]any{"subject_type": "user", "subject_id": daveID, "role_id": helpdesk["id"]}), http.StatusCreated)

	expect(t, dave.do(http.MethodGet, "/api/v1/tenants/smith/roles", nil, nil), http.StatusOK)
	expect(t, dave.do(http.MethodGet, "/api/v1/tenants/smith/members", nil, nil), http.StatusOK)
	grp, grpID := memberClient(t, a, owner, "smith", "Gina")
	gm := decode[map[string]any](t, owner.do(http.MethodPost, "/api/v1/tenants/smith/roles", map[string]any{"slug": "groups-only", "name": "Groups",
		"permissions": []string{"group:manage"}}, nil))
	expect(t, assign(owner, "smith", map[string]any{"subject_type": "user", "subject_id": grpID, "role_id": gm["id"]}), http.StatusCreated)
	expect(t, grp.do(http.MethodGet, "/api/v1/tenants/smith/members", nil, nil), http.StatusOK)
	expect(t, grp.do(http.MethodPost, "/api/v1/tenants/smith/members", map[string]string{"user_id": bobID}, nil), http.StatusNotFound)
	expect(t, dave.do(http.MethodGet, "/api/v1/tenants/jones/roles", nil, nil), http.StatusNotFound)
	expect(t, dave.do(http.MethodGet, "/api/v1/tenants/smith/policies", nil, nil), http.StatusNotFound)
	expect(t, dave.do(http.MethodGet, "/api/v1/tenants/smith/applications", nil, nil), http.StatusNotFound)
	expect(t, dave.do(http.MethodDelete, "/api/v1/tenants/smith", nil, nil), http.StatusForbidden)
	caps := decode[map[string]any](t, dave.do(http.MethodGet, "/api/v1/me/admin", nil, nil))
	ts := caps["tenants"].([]any)
	if len(ts) != 1 || ts[0].(map[string]any)["slug"] != "smith" || ts[0].(map[string]any)["via"] != "delegated" || caps["installation"] != false {
		t.Fatalf("caps: %v", caps)
	}
	if perms := ts[0].(map[string]any)["permissions"].([]any); len(perms) != 3 {
		t.Fatalf("delegated perms: %v", perms)
	}

	// Escalation: the built-in admin role grants *:*, which Dave does not hold.
	adminRole := roleID(t, owner, "smith", "admin")
	rec := assign(dave, "smith", map[string]any{"subject_type": "user", "subject_id": bobID, "role_id": adminRole})
	expect(t, rec, http.StatusForbidden)
	if code := problemCode(t, rec); code != "privilege_escalation" {
		t.Fatalf("code %q", code)
	}
	if as := decode[[]map[string]any](t, owner.do(http.MethodGet, "/api/v1/tenants/smith/assignments?subject_id="+bobID, nil, nil)); len(as) != 0 {
		t.Fatalf("assignment created despite escalation: %v", as)
	}
	// Roles: may only contain (directly or via bundles) what Dave holds.
	expect(t, dave.do(http.MethodPost, "/api/v1/tenants/smith/roles", map[string]any{"slug": "viewer", "name": "Viewer", "permissions": []string{"app:access"}}, nil),
		http.StatusCreated)
	expect(t, dave.do(http.MethodPost, "/api/v1/tenants/smith/roles", map[string]any{"slug": "pol", "name": "Pol", "permissions": []string{"policy:manage"}}, nil),
		http.StatusForbidden)
	expect(t, dave.do(http.MethodPost, "/api/v1/tenants/smith/roles", map[string]any{"slug": "sneaky", "name": "Sneaky", "permissions": []string{},
		"includes": []string{adminRole}}, nil), http.StatusForbidden)
	expect(t, dave.do(http.MethodPut, "/api/v1/tenants/smith/roles/viewer", map[string]any{"name": "Viewer", "permissions": []string{"*:*"}}, nil),
		http.StatusForbidden)
	expect(t, dave.do(http.MethodPost, "/api/v1/tenants/smith/roles", map[string]any{"slug": "wild", "name": "Wild", "permissions": []string{"group:*"}}, nil),
		http.StatusForbidden)
	// Granting what he holds works.
	expect(t, assign(dave, "smith", map[string]any{"subject_type": "user", "subject_id": bobID, "role_id": helpdesk["id"]}), http.StatusCreated)

	// Groups confer their assignments: Dave cannot put Bob into a group that grants admin, nor nest under it.
	admins := decode[map[string]any](t, owner.do(http.MethodPost, "/api/v1/tenants/smith/groups", map[string]string{"slug": "admins", "name": "Admins"}, nil))
	adminsAsg := decode[map[string]any](t, assign(owner, "smith", map[string]any{"subject_type": "group", "subject_id": admins["id"], "role_id": adminRole}))
	expect(t, dave.do(http.MethodPut, "/api/v1/tenants/smith/groups/admins/members/"+bobID, nil, nil), http.StatusForbidden)
	expect(t, dave.do(http.MethodPost, "/api/v1/tenants/smith/groups", map[string]string{"slug": "family", "name": "Family"}, nil), http.StatusCreated)
	expect(t, dave.do(http.MethodPut, "/api/v1/tenants/smith/groups/family/members/"+bobID, nil, nil), http.StatusNoContent)
	expect(t, dave.do(http.MethodPut, "/api/v1/tenants/smith/groups/family/parents/admins", nil, nil), http.StatusForbidden)
	// Nor demote administrators above him.
	expect(t, dave.do(http.MethodDelete, "/api/v1/tenants/smith/assignments/"+adminsAsg["id"].(string), nil, nil), http.StatusForbidden)
	expect(t, dave.do(http.MethodDelete, "/api/v1/tenants/smith/groups/admins", nil, nil), http.StatusForbidden)

	// Conditional grants do not count as held.
	cond := decode[map[string]any](t, owner.do(http.MethodPost, "/api/v1/tenants/smith/policies", map[string]any{"slug": "office", "name": "Office",
		"effect": "condition", "expression": `context.network == "trusted"`}, nil))
	pm := decode[map[string]any](t, owner.do(http.MethodPost, "/api/v1/tenants/smith/roles", map[string]any{"slug": "policy-admin", "name": "Policy admin",
		"permissions": []string{"policy:manage"}}, nil))
	expect(t, assign(owner, "smith", map[string]any{"subject_type": "user", "subject_id": daveID, "role_id": pm["id"], "condition_policy_id": cond["id"]}),
		http.StatusCreated)
	expect(t, dave.do(http.MethodPost, "/api/v1/tenants/smith/roles", map[string]any{"slug": "pol2", "name": "Pol", "permissions": []string{"policy:manage"}}, nil),
		http.StatusForbidden)

	// Operators are exempt from escalation checks; removing Dave's role ends his access immediately (epoch bump).
	expect(t, assign(owner, "smith", map[string]any{"subject_type": "user", "subject_id": bobID, "role_id": adminRole}), http.StatusCreated)
	for _, x := range decode[[]map[string]any](t, owner.do(http.MethodGet, "/api/v1/tenants/smith/assignments?subject_id="+daveID, nil, nil)) {
		expect(t, owner.do(http.MethodDelete, "/api/v1/tenants/smith/assignments/"+x["id"].(string), nil, nil), http.StatusNoContent)
	}
	expect(t, dave.do(http.MethodGet, "/api/v1/tenants/smith/roles", nil, nil), http.StatusNotFound)
}

// Tenant status is installation business even for a tenant:manage holder.
func TestDelegatedTenantSettings(t *testing.T) {
	a := newApp(t)
	owner := setupOwner(t, a)
	expect(t, owner.do(http.MethodPost, "/api/v1/tenants", map[string]string{"slug": "smith", "name": "Smith"}, nil), http.StatusCreated)
	eve, eveID := memberClient(t, a, owner, "smith", "Eve")
	expect(t, assign(owner, "smith", map[string]any{"subject_type": "user", "subject_id": eveID, "role_id": roleID(t, owner, "smith", "admin")}),
		http.StatusCreated)
	expect(t, eve.do(http.MethodPatch, "/api/v1/tenants/smith", map[string]any{"name": "Smith family"}, nil), http.StatusOK)
	expect(t, eve.do(http.MethodPatch, "/api/v1/tenants/smith", map[string]any{"status": "disabled"}, nil), http.StatusForbidden)
	expect(t, eve.do(http.MethodDelete, "/api/v1/tenants/smith", nil, nil), http.StatusForbidden)
	// Shares and domain rules stay with installation operators.
	app := decode[map[string]any](t, eve.do(http.MethodPost, "/api/v1/tenants/smith/applications", map[string]any{"slug": "wiki", "name": "Wiki",
		"kind": "forward_auth", "hosts": []string{"wiki.smith.example"}}, nil))
	expect(t, eve.do(http.MethodGet, "/api/v1/tenants/smith/applications/"+app["id"].(string)+"/shares", nil, nil), http.StatusForbidden)
	expect(t, eve.do(http.MethodGet, "/api/v1/tenants/smith/domain-rules", nil, nil), http.StatusForbidden)
}

func tokenRequest(t *testing.T, h http.Handler, clientID, secret string, form url.Values) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(clientID)+":"+url.QueryEscape(secret))))
	req.RemoteAddr = "192.0.2.10:1"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

func claimsOf(t *testing.T, jwt string) map[string]any {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", jwt)
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// ADR-0037: service accounts authenticate with client credentials and hold role assignments like users.
func TestServiceAccounts(t *testing.T) {
	a := newApp(t)
	owner := setupOwner(t, a)
	for _, slug := range []string{"smith", "jones"} {
		expect(t, owner.do(http.MethodPost, "/api/v1/tenants", map[string]string{"slug": slug, "name": slug}, nil), http.StatusCreated)
	}
	rec := owner.do(http.MethodPost, "/api/v1/tenants/smith/service-accounts", map[string]any{"slug": "backup-job", "name": "Backup job",
		"audiences": []string{"https://api.smith.example"}, "access_token_ttl_seconds": 300}, nil)
	expect(t, rec, http.StatusCreated)
	sa := decode[map[string]any](t, rec)
	id, secret := sa["id"].(string), sa["client_secret"].(string)
	if !strings.HasPrefix(id, "sva_") || !strings.HasPrefix(secret, "porch_sa_") || sa["token_endpoint"] != origin+"/oauth2/token" {
		t.Fatalf("created %v", sa)
	}
	if got := decode[map[string]any](t, owner.do(http.MethodGet, "/api/v1/tenants/smith/service-accounts/backup-job", nil, nil)); got["client_secret"] != nil {
		t.Fatal("secret returned after creation")
	}
	h := a.PublicHandler()
	form := url.Values{"grant_type": {"client_credentials"}, "resource": {"https://api.smith.example"}}
	code, tr := tokenRequest(t, h, id, secret, form)
	if code != 200 || tr["access_token"] == nil || tr["id_token"] != nil || tr["refresh_token"] != nil {
		t.Fatalf("token %d %v", code, tr)
	}
	cl := claimsOf(t, tr["access_token"].(string))
	if cl["sub"] != id || cl["client_id"] != id || cl["aud"].([]any)[0] != "https://api.smith.example" || cl["exp"].(float64)-cl["iat"].(float64) != 300 {
		t.Fatalf("claims %v", cl)
	}
	if code, _ := tokenRequest(t, h, id, secret+"x", form); code != 401 {
		t.Fatalf("wrong secret: %d", code)
	}
	if code, _ := tokenRequest(t, h, id, secret, url.Values{"grant_type": {"client_credentials"}, "resource": {"https://evil.example"}}); code != 400 {
		t.Fatalf("unregistered resource: %d", code)
	}
	if code, _ := tokenRequest(t, h, id, secret, url.Values{"grant_type": {"authorization_code"}, "code": {"x"}}); code < 400 {
		t.Fatalf("code grant: %d", code)
	}
	if got := decode[map[string]any](t, owner.do(http.MethodGet, "/api/v1/tenants/smith/service-accounts/backup-job", nil, nil)); got["last_used_at"] == nil {
		t.Fatal("last_used_at not recorded")
	}

	// Roles apply to service accounts; tenant isolation holds; the implicit all-members grant does not.
	role := decode[map[string]any](t, owner.do(http.MethodPost, "/api/v1/tenants/smith/roles", map[string]any{"slug": "backup", "name": "Backup",
		"permissions": []string{"backup:run"}}, nil))
	expect(t, assign(owner, "smith", map[string]any{"subject_type": "service_account", "subject_id": id, "role_id": role["id"]}), http.StatusCreated)
	ctx := context.Background()
	check := func(tenant, action string) authz.Decision {
		tn := decode[map[string]any](t, owner.do(http.MethodGet, "/api/v1/tenants/"+tenant, nil, nil))
		d, err := a.Engine.Check(ctx, authz.Request{TenantID: tn["id"].(string), Subject: authz.Subject{Type: "service_account", ID: id}, Action: action,
			Resource: authz.Resource{Type: "tenant"}})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	if d := check("smith", "backup:run"); !d.Allowed || d.Trace.TenantGate.Via != "service_account" {
		t.Fatalf("sa allowed: %+v", d)
	}
	if d := check("smith", "backup:delete"); d.Allowed {
		t.Fatal("ungranted action allowed")
	}
	if d := check("jones", "backup:run"); d.Allowed || d.Reason != "tenant_gate" {
		t.Fatalf("cross-tenant: %+v", d)
	}
	eff := decode[[]map[string]any](t, owner.do(http.MethodGet, "/api/v1/tenants/smith/authz/effective?subject_type=service_account&subject_id="+id, nil, nil))
	if len(eff) != 1 || eff[0]["permission"] != "backup:run" || eff[0]["via"] != "service_account" {
		t.Fatalf("effective %v", eff)
	}
	// Service accounts of one tenant cannot be assigned roles in another.
	jonesRole := roleID(t, owner, "jones", "member")
	expect(t, assign(owner, "jones", map[string]any{"subject_type": "service_account", "subject_id": id, "role_id": jonesRole}), http.StatusUnprocessableEntity)

	// Rotation: the old secret stops working at once.
	rot := decode[map[string]any](t, owner.do(http.MethodPost, "/api/v1/tenants/smith/service-accounts/backup-job/rotate-secret", nil, nil))
	if code, _ := tokenRequest(t, h, id, secret, form); code != 401 {
		t.Fatalf("old secret after rotation: %d", code)
	}
	if code, _ := tokenRequest(t, h, id, rot["client_secret"].(string), form); code != 200 {
		t.Fatalf("new secret: %d", code)
	}
	// Disabled accounts cannot get tokens and fail the tenant gate.
	expect(t, owner.do(http.MethodPatch, "/api/v1/tenants/smith/service-accounts/backup-job", map[string]any{"enabled": false}, nil), http.StatusOK)
	if code, _ := tokenRequest(t, h, id, rot["client_secret"].(string), form); code != 401 {
		t.Fatalf("disabled: %d", code)
	}
	if d := check("smith", "backup:run"); d.Allowed {
		t.Fatal("disabled service account allowed")
	}
	// Delete removes its assignments.
	expect(t, owner.do(http.MethodDelete, "/api/v1/tenants/smith/service-accounts/backup-job", nil, nil), http.StatusNoContent)
	if as := decode[[]map[string]any](t, owner.do(http.MethodGet, "/api/v1/tenants/smith/assignments?subject_id="+id, nil, nil)); len(as) != 0 {
		t.Fatalf("assignments survive deletion: %v", as)
	}
	// Delegation: managing service accounts needs service_account:manage.
	mem, _ := memberClient(t, a, owner, "smith", "Mia")
	expect(t, mem.do(http.MethodGet, "/api/v1/tenants/smith/service-accounts", nil, nil), http.StatusNotFound)
	expect(t, mem.do(http.MethodGet, "/api/v1/tenants/smith/members", nil, nil), http.StatusNotFound)
}

func TestAuditExplorerSessionsAndHealth(t *testing.T) {
	a := newApp(t)
	owner := setupOwner(t, a)
	for _, slug := range []string{"smith", "jones"} {
		expect(t, owner.do(http.MethodPost, "/api/v1/tenants", map[string]string{"slug": slug, "name": slug}, nil), http.StatusCreated)
	}
	expect(t, owner.do(http.MethodPost, "/api/v1/tenants/jones/groups", map[string]string{"slug": "kids", "name": "Kids"}, nil), http.StatusCreated)
	expect(t, owner.do(http.MethodPost, "/api/v1/tenants/smith/groups", map[string]string{"slug": "kids", "name": "Kids"}, nil), http.StatusCreated)

	page := decode[map[string]any](t, owner.do(http.MethodGet, "/api/v1/audit?action=tenant.&limit=1", nil, nil))
	items := page["items"].([]any)
	if len(items) != 1 || page["next_cursor"] == nil || !strings.HasPrefix(items[0].(map[string]any)["action"].(string), "tenant.") {
		t.Fatalf("page 1: %v", page)
	}
	first := items[0].(map[string]any)
	page2 := decode[map[string]any](t, owner.do(http.MethodGet, "/api/v1/audit?action=tenant.&limit=1&cursor="+page["next_cursor"].(string), nil, nil))
	second := page2["items"].([]any)[0].(map[string]any)
	if second["seq"].(float64) >= first["seq"].(float64) || first["actor_name"] != "Olga Owner" {
		t.Fatalf("pagination %v %v", first, second)
	}
	expect(t, owner.do(http.MethodGet, "/api/v1/audit?action=x%25", nil, nil), http.StatusUnprocessableEntity)

	// A tenant auditor sees only their tenant's events.
	aud, audID := memberClient(t, a, owner, "smith", "Audrey")
	r := decode[map[string]any](t, owner.do(http.MethodPost, "/api/v1/tenants/smith/roles", map[string]any{"slug": "auditor", "name": "Auditor",
		"permissions": []string{"audit:read"}}, nil))
	expect(t, assign(owner, "smith", map[string]any{"subject_type": "user", "subject_id": audID, "role_id": r["id"]}), http.StatusCreated)
	smith := decode[map[string]any](t, owner.do(http.MethodGet, "/api/v1/tenants/smith", nil, nil))
	tp := decode[map[string]any](t, aud.do(http.MethodGet, "/api/v1/tenants/smith/audit?action=group.", nil, nil))
	evs := tp["items"].([]any)
	if len(evs) != 1 {
		t.Fatalf("tenant audit: %v", tp)
	}
	for _, e := range evs {
		if e.(map[string]any)["tenant_id"] != smith["id"] {
			t.Fatalf("foreign event %v", e)
		}
	}
	expect(t, aud.do(http.MethodGet, "/api/v1/tenants/jones/audit", nil, nil), http.StatusNotFound)
	expect(t, aud.do(http.MethodGet, "/api/v1/audit", nil, nil), http.StatusForbidden)

	// Sessions: the owner sees and ends other sessions.
	sessions := decode[[]map[string]any](t, owner.do(http.MethodGet, "/api/v1/sessions?user="+audID, nil, nil))
	if len(sessions) != 1 || sessions[0]["current"] != false || sessions[0]["user_name"] != "Audrey" {
		t.Fatalf("sessions %v", sessions)
	}
	all := decode[[]map[string]any](t, owner.do(http.MethodGet, "/api/v1/sessions", nil, nil))
	current := 0
	for _, s := range all {
		if s["current"] == true {
			current++
		}
	}
	if current != 1 {
		t.Fatalf("current flag: %v", all)
	}
	expect(t, owner.do(http.MethodDelete, "/api/v1/sessions/"+sessions[0]["id"].(string), nil, nil), http.StatusNoContent)
	expect(t, aud.do(http.MethodGet, "/api/v1/me", nil, nil), http.StatusUnauthorized)
	expect(t, owner.do(http.MethodDelete, "/api/v1/sessions/"+sessions[0]["id"].(string), nil, nil), http.StatusNotFound)
	aud2, _ := memberClient(t, a, owner, "", "Zed")
	zed := decode[map[string]any](t, aud2.do(http.MethodGet, "/api/v1/me", nil, nil))
	expect(t, owner.do(http.MethodPost, "/api/v1/users/"+zed["user_id"].(string)+"/revoke-sessions", nil, nil), http.StatusNoContent)
	expect(t, aud2.do(http.MethodGet, "/api/v1/me", nil, nil), http.StatusUnauthorized)
	ev := decode[map[string]any](t, owner.do(http.MethodGet, "/api/v1/audit?action=session.", nil, nil))
	if n := len(ev["items"].([]any)); n != 2 {
		t.Fatalf("session audit events: %d", n)
	}

	h := decode[map[string]any](t, owner.do(http.MethodGet, "/api/v1/installation/health", nil, nil))
	if h["ready"] != true || h["tenants"].(float64) != 2 || h["users"].(float64) < 3 || len(h["keyring"].([]any)) == 0 {
		t.Fatalf("health %v", h)
	}
	checks := map[string]string{}
	for _, c := range h["checks"].([]any) {
		m := c.(map[string]any)
		checks[m["name"].(string)] = m["status"].(string)
	}
	if checks["storage"] != "ok" || checks["readiness"] != "ok" || checks["backups"] != "warning" {
		t.Fatalf("checks %v", checks)
	}
}

// Installation roles are granted and revoked by owners only; the last owner cannot be removed.
func TestOperatorRoleManagement(t *testing.T) {
	a := newApp(t)
	owner := setupOwner(t, a)
	me := decode[map[string]any](t, owner.do(http.MethodGet, "/api/v1/me", nil, nil))
	ivy, ivyID := memberClient(t, a, owner, "", "Ivy")
	_, _ = memberClient(t, a, owner, "", "Ivan 100%_off")
	if us := decode[map[string]any](t, owner.do(http.MethodGet, "/api/v1/users?q=IV", nil, nil))["items"].([]any); len(us) != 2 {
		t.Fatalf("search IV: %v", us)
	}
	if us := decode[map[string]any](t, owner.do(http.MethodGet, "/api/v1/users?q=%25_", nil, nil))["items"].([]any); len(us) != 1 {
		t.Fatalf("search is not literal: %v", us)
	}
	expect(t, ivy.do(http.MethodGet, "/api/v1/tenants", nil, nil), http.StatusForbidden)
	expect(t, owner.do(http.MethodPost, "/api/v1/installation/operators", map[string]string{"user_id": ivyID, "role": "admin"}, nil), http.StatusNoContent)
	expect(t, owner.do(http.MethodPost, "/api/v1/installation/operators", map[string]string{"user_id": ivyID, "role": "admin"}, nil), http.StatusConflict)
	expect(t, ivy.do(http.MethodGet, "/api/v1/tenants", nil, nil), http.StatusOK)
	// Admins are not owners: they cannot hand out installation roles.
	expect(t, ivy.do(http.MethodPost, "/api/v1/installation/operators", map[string]string{"user_id": ivyID, "role": "owner"}, nil), http.StatusForbidden)
	expect(t, owner.do(http.MethodDelete, "/api/v1/installation/operators/"+ivyID+"/admin", nil, nil), http.StatusNoContent)
	expect(t, ivy.do(http.MethodGet, "/api/v1/tenants", nil, nil), http.StatusForbidden)
	expect(t, owner.do(http.MethodDelete, "/api/v1/installation/operators/"+me["user_id"].(string)+"/owner", nil, nil), http.StatusConflict)
	ops := decode[[]map[string]any](t, owner.do(http.MethodGet, "/api/v1/installation/operators", nil, nil))
	if len(ops) != 1 || ops[0]["role"] != "owner" {
		t.Fatalf("operators %v", ops)
	}
	ev := decode[map[string]any](t, owner.do(http.MethodGet, "/api/v1/audit?action=installation.role_", nil, nil))
	if n := len(ev["items"].([]any)); n != 3 { // setup grant + grant + revoke
		t.Fatalf("role audit events: %d", n)
	}
}

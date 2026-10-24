package app_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aurimasniekis/go-porch/internal/clock"
)

// bearer is a client authenticating with an automation token: no cookie, no CSRF token, no Origin header.
func bearer(c *client, token string) func(method, path string, body any, hdr ...map[string]string) *httptest.ResponseRecorder {
	return func(method, path string, body any, hdr ...map[string]string) *httptest.ResponseRecorder {
		h := map[string]string{"Authorization": "Bearer " + token, "Origin": ""}
		for _, x := range hdr {
			for k, v := range x {
				h[k] = v
			}
		}
		anon := &client{t: c.t, h: c.h, remote: "192.0.2.50:1"}
		return anon.do(method, path, body, h)
	}
}

// ADR-0041: automation tokens act for their creator within the token's grant, never for interactive-only operations.
func TestAutomationTokens(t *testing.T) {
	clk := clock.NewFake(time.Now().UTC().Truncate(time.Second))
	a := newAppWithClock(t, clk)
	owner := setupOwner(t, a)
	for _, slug := range []string{"smith", "jones"} {
		expect(t, owner.do(http.MethodPost, "/api/v1/tenants", map[string]string{"slug": slug, "name": slug}, nil), http.StatusCreated)
	}

	// Installation token (admin): manages tenants without CSRF or Origin.
	rec := owner.do(http.MethodPost, "/api/v1/installation/automation-tokens", map[string]any{"name": "terraform", "role": "admin", "expires_in_days": 30}, nil)
	expect(t, rec, http.StatusCreated)
	tok := decode[map[string]any](t, rec)
	secret := tok["token"].(string)
	if !strings.HasPrefix(secret, "porch_at_") || tok["kind"] != "installation" || tok["hint"] != secret[len(secret)-4:] {
		t.Fatalf("token %v", tok)
	}
	tf := bearer(owner, secret)
	expect(t, tf(http.MethodGet, "/api/v1/tenants", nil), http.StatusOK)
	expect(t, tf(http.MethodPost, "/api/v1/tenants", map[string]string{"slug": "doe", "name": "Doe"}, map[string]string{"X-Porch-Managed-By": "terraform"}),
		http.StatusCreated)
	doe := decode[map[string]any](t, tf(http.MethodGet, "/api/v1/tenants/doe", nil))
	if doe["managed_by"] != "terraform" || doe["last_changed_by"] != "automation:"+tok["id"].(string) {
		t.Fatalf("provenance %v", doe)
	}
	ev := decode[map[string]any](t, owner.do(http.MethodGet, "/api/v1/audit?action=tenant.created&limit=1", nil, nil))["items"].([]any)[0].(map[string]any)
	if ev["actor_type"] != "automation" || ev["actor_id"] != tok["id"] || ev["auth_method"] != "automation" {
		t.Fatalf("audit %v", ev)
	}
	// Step-up protected configuration works; interactive-only operations do not.
	expect(t, tf(http.MethodPost, "/api/v1/tenants/doe/policies", map[string]any{"slug": "p", "name": "p", "effect": "condition", "expression": "true"}),
		http.StatusCreated)
	for _, x := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/installation/automation-tokens"},
		{http.MethodPost, "/api/v1/installation/operators"},
		{http.MethodPost, "/api/v1/installation/signing-keys/rotate"},
		{http.MethodPut, "/api/v1/me/backup-handle"},
	} {
		expect(t, tf(x.method, x.path, map[string]any{"name": "x", "role": "admin", "expires_in_days": 1, "user_id": "x", "handle": "x", "alg": "ES256"}),
			http.StatusForbidden)
	}
	expect(t, tf(http.MethodGet, "/api/v1/tenants", nil, map[string]string{"Authorization": "Bearer porch_at_nope"}), http.StatusUnauthorized)

	// Auditor tokens read but never write.
	aud := decode[map[string]any](t, owner.do(http.MethodPost, "/api/v1/installation/automation-tokens",
		map[string]any{"name": "grafana", "role": "auditor", "expires_in_days": 1}, nil))
	ro := bearer(owner, aud["token"].(string))
	expect(t, ro(http.MethodGet, "/api/v1/installation/health", nil), http.StatusOK)
	expect(t, ro(http.MethodPost, "/api/v1/tenants", map[string]string{"slug": "nope", "name": "x"}), http.StatusForbidden)

	// Tenant token issued by an operator: limited to its tenant and permissions.
	tt := decode[map[string]any](t, owner.do(http.MethodPost, "/api/v1/tenants/smith/automation-tokens",
		map[string]any{"name": "apps", "permissions": []string{"app:manage"}, "expires_in_days": 1}, nil))
	apps := bearer(owner, tt["token"].(string))
	expect(t, apps(http.MethodPost, "/api/v1/tenants/smith/applications", map[string]any{"slug": "wiki", "name": "Wiki", "kind": "forward_auth",
		"hosts": []string{"wiki.smith.example"}}), http.StatusCreated)
	expect(t, apps(http.MethodGet, "/api/v1/tenants/smith/roles", nil), http.StatusNotFound)
	expect(t, apps(http.MethodGet, "/api/v1/tenants/jones/applications", nil), http.StatusNotFound)
	expect(t, apps(http.MethodGet, "/api/v1/tenants", nil), http.StatusForbidden)

	// Tenant token issued by a delegated admin: only permissions they hold; follows their current rights.
	dave, daveID := memberClient(t, a, owner, "smith", "Dave")
	role := decode[map[string]any](t, owner.do(http.MethodPost, "/api/v1/tenants/smith/roles", map[string]any{"slug": "groups", "name": "Groups",
		"permissions": []string{"group:manage"}}, nil))
	asg := decode[map[string]any](t, assign(owner, "smith", map[string]any{"subject_type": "user", "subject_id": daveID, "role_id": role["id"]}))
	rec = dave.do(http.MethodPost, "/api/v1/tenants/smith/automation-tokens", map[string]any{"name": "x", "permissions": []string{"group:manage", "policy:manage"},
		"expires_in_days": 1}, nil)
	expect(t, rec, http.StatusForbidden)
	if problemCode(t, rec) != "privilege_escalation" {
		t.Fatal(rec.Body.String())
	}
	expect(t, dave.do(http.MethodPost, "/api/v1/tenants/smith/automation-tokens", map[string]any{"name": "x", "permissions": []string{"policy:manage"},
		"expires_in_days": 1}, nil), http.StatusNotFound)
	dt := decode[map[string]any](t, dave.do(http.MethodPost, "/api/v1/tenants/smith/automation-tokens",
		map[string]any{"name": "groups", "permissions": []string{"group:manage"}, "expires_in_days": 1}, nil))
	daveTok := bearer(owner, dt["token"].(string))
	expect(t, daveTok(http.MethodPost, "/api/v1/tenants/smith/groups", map[string]string{"slug": "kids", "name": "Kids"}), http.StatusCreated)
	expect(t, daveTok(http.MethodGet, "/api/v1/tenants/smith/members", nil), http.StatusOK) // group:manage may read members
	expect(t, daveTok(http.MethodPost, "/api/v1/tenants/smith/members", map[string]string{"user_id": daveID}), http.StatusNotFound)
	expect(t, owner.do(http.MethodDelete, "/api/v1/tenants/smith/assignments/"+asg["id"].(string), nil, nil), http.StatusNoContent)
	expect(t, daveTok(http.MethodGet, "/api/v1/tenants/smith/groups", nil), http.StatusNotFound)

	// Listing never shows secrets; revocation and expiry end a token at once.
	list := decode[[]map[string]any](t, owner.do(http.MethodGet, "/api/v1/installation/automation-tokens", nil, nil))
	if len(list) != 2 || list[0]["token"] != nil {
		t.Fatalf("list %v", list)
	}
	expect(t, owner.do(http.MethodDelete, "/api/v1/installation/automation-tokens/"+aud["id"].(string), nil, nil), http.StatusNoContent)
	expect(t, ro(http.MethodGet, "/api/v1/installation/health", nil), http.StatusUnauthorized)
	expect(t, owner.do(http.MethodPost, "/api/v1/installation/automation-tokens", map[string]any{"name": "x", "role": "admin", "expires_in_days": 400}, nil),
		http.StatusUnprocessableEntity)
	// Disabled creators lose their tokens.
	expect(t, daveTok(http.MethodGet, "/api/v1/me", nil), http.StatusOK)
	expect(t, owner.do(http.MethodPatch, "/api/v1/users/"+daveID, map[string]any{"status": "disabled"}, nil), http.StatusOK)
	expect(t, daveTok(http.MethodGet, "/api/v1/me", nil), http.StatusUnauthorized)
	clk.Advance(25 * time.Hour)
	expect(t, apps(http.MethodGet, "/api/v1/tenants/smith/applications", nil), http.StatusUnauthorized)
	expect(t, tf(http.MethodGet, "/api/v1/tenants", nil), http.StatusOK)
	me := decode[map[string]any](t, tf(http.MethodGet, "/api/v1/me", nil))
	if me["user_id"] == nil || me["session"].(map[string]any)["method"] != "automation" {
		t.Fatalf("me via token %v", me)
	}
}

func TestIdempotencyKeys(t *testing.T) {
	a := newApp(t)
	owner := setupOwner(t, a)
	expect(t, owner.do(http.MethodPost, "/api/v1/tenants", map[string]string{"slug": "smith", "name": "Smith"}, nil), http.StatusCreated)
	tok := decode[map[string]any](t, owner.do(http.MethodPost, "/api/v1/installation/automation-tokens",
		map[string]any{"name": "tf", "role": "admin", "expires_in_days": 1}, nil))
	tf := bearer(owner, tok["token"].(string))
	key := map[string]string{"Idempotency-Key": "create-kids-1"}
	first := tf(http.MethodPost, "/api/v1/tenants/smith/groups", map[string]string{"slug": "kids", "name": "Kids"}, key)
	expect(t, first, http.StatusCreated)
	again := tf(http.MethodPost, "/api/v1/tenants/smith/groups", map[string]string{"slug": "kids", "name": "Kids"}, key)
	expect(t, again, http.StatusCreated)
	if again.Header().Get("Idempotent-Replayed") != "true" || again.Body.String() != first.Body.String() {
		t.Fatalf("replay %v %s", again.Header(), again.Body.String())
	}
	if gs := decode[[]map[string]any](t, tf(http.MethodGet, "/api/v1/tenants/smith/groups", nil)); len(gs) != 1 {
		t.Fatalf("created twice: %v", gs)
	}
	rec := tf(http.MethodPost, "/api/v1/tenants/smith/groups", map[string]string{"slug": "teens", "name": "Teens"}, key)
	expect(t, rec, http.StatusUnprocessableEntity)
	if problemCode(t, rec) != "idempotency_key_reused" {
		t.Fatal(rec.Body.String())
	}
	// The same key from another credential is a different key.
	expect(t, owner.do(http.MethodPost, "/api/v1/tenants/smith/groups", map[string]string{"slug": "kids", "name": "Kids"}, key), http.StatusConflict)

	// Secrets are never replayed.
	skey := map[string]string{"Idempotency-Key": "sa-1"}
	sa := tf(http.MethodPost, "/api/v1/tenants/smith/service-accounts", map[string]any{"slug": "job", "name": "Job"}, skey)
	expect(t, sa, http.StatusCreated)
	rec = tf(http.MethodPost, "/api/v1/tenants/smith/service-accounts", map[string]any{"slug": "job", "name": "Job"}, skey)
	expect(t, rec, http.StatusConflict)
	if problemCode(t, rec) != "idempotent_secret_withheld" || !strings.HasSuffix(rec.Header().Get("Location"), "/service-accounts/"+decode[map[string]any](t, sa)["id"].(string)) ||
		strings.Contains(rec.Body.String(), "porch_sa_") {
		t.Fatalf("withheld %v %s", rec.Header(), rec.Body.String())
	}
	// Failures are not stored: the same key retries the request.
	fkey := map[string]string{"Idempotency-Key": "bad-1"}
	expect(t, tf(http.MethodPost, "/api/v1/tenants/smith/groups", map[string]string{"slug": "Bad Slug", "name": "x"}, fkey), http.StatusUnprocessableEntity)
	rec = tf(http.MethodPost, "/api/v1/tenants/smith/groups", map[string]string{"slug": "Bad Slug", "name": "x"}, fkey)
	expect(t, rec, http.StatusUnprocessableEntity)
	if rec.Header().Get("Idempotent-Replayed") != "" {
		t.Fatal("failure replayed")
	}
	expect(t, tf(http.MethodPost, "/api/v1/tenants/smith/groups", map[string]string{"slug": "x", "name": "x"}, map[string]string{"Idempotency-Key": "bad key"}),
		http.StatusBadRequest)
}

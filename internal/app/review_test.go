package app_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/aurimasniekis/go-porch/internal/clock"
)

// Regression tests for the M7 security review (findings H2–H3, M1–M6, M9, L1, L2, L6). Each asserts the safe
// behaviour; the review's repro showed the opposite.

func smithWith(t *testing.T, owner *client) {
	t.Helper()
	expect(t, owner.do(http.MethodPost, "/api/v1/tenants", map[string]string{"slug": "smith", "name": "Smith"}, nil), http.StatusCreated)
}

func roleWith(t *testing.T, owner *client, slug string, perms ...string) string {
	t.Helper()
	return decode[map[string]any](t, owner.do(http.MethodPost, "/api/v1/tenants/smith/roles", map[string]any{"slug": slug, "name": slug,
		"permissions": perms}, nil))["id"].(string)
}

func give(t *testing.T, owner *client, userID, roleID string, extra map[string]any) {
	t.Helper()
	body := map[string]any{"subject_type": "user", "subject_id": userID, "role_id": roleID}
	for k, v := range extra {
		body[k] = v
	}
	expect(t, assign(owner, "smith", body), http.StatusCreated)
}

func expectEscalation(t *testing.T, rec *httptest.ResponseRecorder, what string) {
	t.Helper()
	if rec.Code != http.StatusForbidden || problemCode(t, rec) != "privilege_escalation" {
		t.Fatalf("%s: %d %s, want 403 privilege_escalation", what, rec.Code, rec.Body.String())
	}
}

// H3: an operator's tenant token is limited to its own permissions when granting.
func TestReviewOperatorTenantTokenLimited(t *testing.T) {
	a := newApp(t)
	owner := setupOwner(t, a)
	smithWith(t, owner)
	_, mallory := memberClient(t, a, owner, "smith", "Mallory")
	tt := decode[map[string]any](t, owner.do(http.MethodPost, "/api/v1/tenants/smith/automation-tokens",
		map[string]any{"name": "roles", "permissions": []string{"role:manage"}, "expires_in_days": 1}, nil))
	tok := bearer(owner, tt["token"].(string))
	expectEscalation(t, tok(http.MethodPost, "/api/v1/tenants/smith/assignments", map[string]any{"subject_type": "user", "subject_id": mallory,
		"role_id": roleID(t, owner, "smith", "admin"), "scope_type": "tenant"}), "assign admin")
	expectEscalation(t, tok(http.MethodPost, "/api/v1/tenants/smith/roles", map[string]any{"slug": "x", "name": "x", "permissions": []string{"*:*"}}),
		"define *:*")
	expect(t, tok(http.MethodPost, "/api/v1/tenants/smith/roles", map[string]any{"slug": "rm", "name": "rm", "permissions": []string{"role:manage"}}),
		http.StatusCreated)
}

// M2: expiring grants do not count as held.
func TestReviewExpiringGrantNotHeld(t *testing.T) {
	clk := clock.NewFake(time.Now().UTC().Truncate(time.Second))
	a := newAppWithClock(t, clk)
	owner := setupOwner(t, a)
	smithWith(t, owner)
	temp, tempID := memberClient(t, a, owner, "smith", "Temp")
	give(t, owner, tempID, roleID(t, owner, "smith", "admin"), map[string]any{"expires_at": clk.Now().Add(time.Hour)})
	expectEscalation(t, assign(temp, "smith", map[string]any{"subject_type": "user", "subject_id": tempID, "role_id": roleID(t, owner, "smith", "admin")}),
		"permanent copy of an expiring admin grant")
}

// H2: rotating, re-enabling or retargeting a service account needs its permissions.
func TestReviewServiceAccountControl(t *testing.T) {
	a := newApp(t)
	owner := setupOwner(t, a)
	smithWith(t, owner)
	sam, samID := memberClient(t, a, owner, "smith", "Sam")
	give(t, owner, samID, roleWith(t, owner, "sa", "service_account:manage"), nil)
	sa := decode[map[string]any](t, owner.do(http.MethodPost, "/api/v1/tenants/smith/service-accounts", map[string]any{"slug": "ci", "name": "CI"}, nil))
	expect(t, assign(owner, "smith", map[string]any{"subject_type": "service_account", "subject_id": sa["id"], "role_id": roleID(t, owner, "smith", "admin")}),
		http.StatusCreated)
	expectEscalation(t, sam.do(http.MethodPost, "/api/v1/tenants/smith/service-accounts/ci/rotate-secret", nil, nil), "rotate admin SA")
	expectEscalation(t, sam.do(http.MethodPatch, "/api/v1/tenants/smith/service-accounts/ci", map[string]any{"enabled": false}, nil), "update admin SA")
	expectEscalation(t, sam.do(http.MethodDelete, "/api/v1/tenants/smith/service-accounts/ci", nil, nil), "delete admin SA")
}

// M4: an administrator denied a permission can neither remove the deny nor grant the permission.
func TestReviewDenyPolicyBindsAdmin(t *testing.T) {
	a := newApp(t)
	owner := setupOwner(t, a)
	smithWith(t, owner)
	bob, bobID := memberClient(t, a, owner, "smith", "Bob")
	_, carolID := memberClient(t, a, owner, "smith", "Carol")
	give(t, owner, bobID, roleID(t, owner, "smith", "admin"), nil)
	expect(t, owner.do(http.MethodPost, "/api/v1/tenants/smith/policies", map[string]any{"slug": "no-apps-for-bob", "name": "x", "effect": "deny",
		"actions": []string{"app:*"}, "expression": `principal.id == "` + decode[map[string]any](t, bob.do(http.MethodGet, "/api/v1/me", nil, nil))["public_id"].(string) + `"`},
		nil), http.StatusCreated)
	expect(t, bob.do(http.MethodGet, "/api/v1/tenants/smith/applications", nil, nil), http.StatusNotFound) // wildcard deny applies
	expectEscalation(t, bob.do(http.MethodDelete, "/api/v1/tenants/smith/policies/no-apps-for-bob", nil, nil), "delete own deny")
	expectEscalation(t, assign(bob, "smith", map[string]any{"subject_type": "user", "subject_id": carolID,
		"role_id": roleWith(t, owner, "apps", "app:manage")}), "grant denied permission")
}

// M5: joining a group that a condition keys on needs what the condition unlocks.
func TestReviewGroupConditionGuarded(t *testing.T) {
	a := newApp(t)
	owner := setupOwner(t, a)
	smithWith(t, owner)
	gina, ginaID := memberClient(t, a, owner, "smith", "Gina")
	give(t, owner, ginaID, roleWith(t, owner, "gm", "group:manage"), nil)
	cond := decode[map[string]any](t, owner.do(http.MethodPost, "/api/v1/tenants/smith/policies", map[string]any{"slug": "oncall-only", "name": "x",
		"effect": "condition", "expression": `"oncall" in principal.groups`}, nil))
	give(t, owner, ginaID, roleWith(t, owner, "pm", "app:manage"), map[string]any{"condition_policy_id": cond["id"]})
	expect(t, owner.do(http.MethodPost, "/api/v1/tenants/smith/groups", map[string]string{"slug": "oncall", "name": "On call"}, nil), http.StatusCreated)
	expectEscalation(t, gina.do(http.MethodPut, "/api/v1/tenants/smith/groups/oncall/members/"+ginaID, nil, nil), "join oncall")
	expect(t, gina.do(http.MethodGet, "/api/v1/tenants/smith/applications", nil, nil), http.StatusNotFound)
}

// L1: stripping a role needs what it held.
func TestReviewRoleStripGuarded(t *testing.T) {
	a := newApp(t)
	owner := setupOwner(t, a)
	smithWith(t, owner)
	dave, daveID := memberClient(t, a, owner, "smith", "Dave")
	give(t, owner, daveID, roleWith(t, owner, "rm", "role:manage"), nil)
	roleWith(t, owner, "ops", "policy:manage", "app:manage")
	expectEscalation(t, dave.do(http.MethodPut, "/api/v1/tenants/smith/roles/ops", map[string]any{"name": "ops", "permissions": []string{}}, nil), "strip ops")
}

// M3: member:manage cannot suspend an admin, and removal deletes assignments so re-adding does not resurrect them.
func TestReviewMembershipCleanup(t *testing.T) {
	a := newApp(t)
	owner := setupOwner(t, a)
	smithWith(t, owner)
	mm, mmID := memberClient(t, a, owner, "smith", "MM")
	alice, aliceID := memberClient(t, a, owner, "smith", "Alice")
	give(t, owner, mmID, roleWith(t, owner, "mm", "member:manage"), nil)
	give(t, owner, aliceID, roleID(t, owner, "smith", "admin"), nil)
	var aliceMem string
	for _, m := range decode[map[string]any](t, owner.do(http.MethodGet, "/api/v1/tenants/smith/members", nil, nil))["items"].([]any) {
		if m.(map[string]any)["user_id"] == aliceID {
			aliceMem = m.(map[string]any)["id"].(string)
		}
	}
	expectEscalation(t, mm.do(http.MethodPatch, "/api/v1/tenants/smith/members/"+aliceMem, map[string]any{"status": "suspended"}, nil), "suspend admin")
	expect(t, owner.do(http.MethodDelete, "/api/v1/tenants/smith/members/"+aliceMem, nil, nil), http.StatusNoContent)
	expect(t, mm.do(http.MethodPost, "/api/v1/tenants/smith/members", map[string]string{"user_id": aliceID}, nil), http.StatusCreated)
	expect(t, alice.do(http.MethodGet, "/api/v1/tenants/smith/roles", nil, nil), http.StatusNotFound)
}

// M6: admins cannot disable owners; tokens cannot disable operators; the last owner stays.
func TestReviewOwnerProtection(t *testing.T) {
	a := newApp(t)
	owner := setupOwner(t, a)
	ownerID := decode[map[string]any](t, owner.do(http.MethodGet, "/api/v1/me", nil, nil))["user_id"].(string)
	adm, admID := memberClient(t, a, owner, "", "Adm")
	expect(t, owner.do(http.MethodPost, "/api/v1/installation/operators", map[string]any{"user_id": admID, "role": "admin"}, nil), http.StatusNoContent)
	expect(t, adm.do(http.MethodPatch, "/api/v1/users/"+ownerID, map[string]any{"status": "disabled"}, nil), http.StatusForbidden)
	expect(t, owner.do(http.MethodPatch, "/api/v1/users/"+ownerID, map[string]any{"status": "disabled"}, nil), http.StatusConflict)
	tok := decode[map[string]any](t, owner.do(http.MethodPost, "/api/v1/installation/automation-tokens",
		map[string]any{"name": "tf", "role": "admin", "expires_in_days": 1}, nil))
	expect(t, bearer(owner, tok["token"].(string))(http.MethodDelete, "/api/v1/users/"+admID, nil), http.StatusForbidden)
	expect(t, owner.do(http.MethodGet, "/api/v1/me", nil, nil), http.StatusOK)
}

// L2: a revoked credential gets no idempotent replay.
func TestReviewIdempotencyNeedsAuthentication(t *testing.T) {
	a := newApp(t)
	owner := setupOwner(t, a)
	tok := decode[map[string]any](t, owner.do(http.MethodPost, "/api/v1/installation/automation-tokens",
		map[string]any{"name": "tf", "role": "admin", "expires_in_days": 1}, nil))
	tf := bearer(owner, tok["token"].(string))
	body := map[string]string{"slug": "doe", "name": "Doe"}
	expect(t, tf(http.MethodPost, "/api/v1/tenants", body, map[string]string{"Idempotency-Key": "k1"}), http.StatusCreated)
	expect(t, owner.do(http.MethodDelete, "/api/v1/installation/automation-tokens/"+tok["id"].(string), nil, nil), http.StatusNoContent)
	expect(t, tf(http.MethodPost, "/api/v1/tenants", body, map[string]string{"Idempotency-Key": "k1"}), http.StatusUnauthorized)
}

// M1: audiences are owned by one tenant and never look like client IDs; M9: disabled tenants get no tokens;
// L6: launch URLs are validated on update.
func TestReviewAudiencesTenantsAndLaunchURL(t *testing.T) {
	a := newApp(t)
	owner := setupOwner(t, a)
	for _, slug := range []string{"smith", "jones"} {
		expect(t, owner.do(http.MethodPost, "/api/v1/tenants", map[string]string{"slug": slug, "name": slug}, nil), http.StatusCreated)
	}
	sa := decode[map[string]any](t, owner.do(http.MethodPost, "/api/v1/tenants/smith/service-accounts", map[string]any{"slug": "api", "name": "API",
		"audiences": []string{"https://api.smith.example"}}, nil))
	expect(t, owner.do(http.MethodPost, "/api/v1/tenants/jones/service-accounts", map[string]any{"slug": "squat", "name": "S",
		"audiences": []string{"https://api.smith.example"}}, nil), http.StatusConflict)
	expect(t, owner.do(http.MethodPost, "/api/v1/tenants/jones/service-accounts", map[string]any{"slug": "squat2", "name": "S",
		"audiences": []string{sa["id"].(string)}}, nil), http.StatusUnprocessableEntity)
	expect(t, owner.do(http.MethodPatch, "/api/v1/tenants/smith", map[string]any{"status": "disabled"}, nil), http.StatusOK)
	if code, _ := tokenRequest(t, a.PublicHandler(), sa["id"].(string), sa["client_secret"].(string),
		url.Values{"grant_type": {"client_credentials"}, "resource": {"https://api.smith.example"}}); code != http.StatusUnauthorized {
		t.Fatalf("disabled tenant token: %d", code)
	}
	app := decode[map[string]any](t, owner.do(http.MethodPost, "/api/v1/tenants/jones/applications", map[string]any{"slug": "wiki", "name": "Wiki",
		"kind": "forward_auth", "hosts": []string{"wiki.jones.example"}}, nil))
	if hs := app["hosts"].([]any); len(hs) != 1 {
		t.Fatalf("create response hosts %v", hs)
	}
	expect(t, owner.do(http.MethodPatch, "/api/v1/tenants/jones/applications/"+app["id"].(string), map[string]any{"launch_url": "javascript:alert(1)"}, nil),
		http.StatusUnprocessableEntity)
}

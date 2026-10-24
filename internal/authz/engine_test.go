package authz_test

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"

	"github.com/aurimasniekis/go-porch/internal/apps"
	"github.com/aurimasniekis/go-porch/internal/authz"
	"github.com/aurimasniekis/go-porch/internal/domain"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/tenancy"
	"github.com/aurimasniekis/go-porch/internal/testenv"
)

type fx struct {
	e     *testenv.Env
	tn    tenancy.Tenant
	sc    tenancy.Scope
	alice string // member
	bob   string // member
	carol string // not a member
	app   string // all_members app
	vault string // assigned-only app
	apps  *apps.Service
}

func setup(t *testing.T) *fx {
	t.Helper()
	e := testenv.New(t)
	ctx := context.Background()
	tn := e.Tenant(t, "smith")
	sc, _ := e.Tenants.SystemScope(ctx, tn.ID)
	f := &fx{e: e, tn: tn, sc: sc, apps: apps.New(e.Store, e.Keyring, e.Audit)}
	f.alice = e.User(t, "Alice", "alice@smith.example").ID
	f.bob = e.User(t, "Bob", "bob@smith.example").ID
	f.carol = e.User(t, "Carol", "carol@jones.example").ID
	e.Member(t, tn, f.alice)
	e.Member(t, tn, f.bob)
	mk := func(slug, mode string) string {
		c, err := f.apps.Create(ctx, domain.SystemChange, sc, apps.CreateParams{Slug: slug, Name: slug, Kind: apps.KindForwardAuth, AccessMode: mode,
			Hosts: []string{slug + ".smith.example"}})
		if err != nil {
			t.Fatal(err)
		}
		return c.App.ID
	}
	f.app, f.vault = mk("jellyfin", apps.AccessAllMembers), mk("vault", apps.AccessAssigned)
	return f
}

func (f *fx) check(t *testing.T, user, action, app string) authz.Decision {
	t.Helper()
	d, err := f.e.Engine.Check(context.Background(), authz.Request{TenantID: f.tn.ID, Subject: authz.Subject{Type: "user", ID: user, AuthMethod: "google",
		AuthTime: f.e.Clock.Now()}, Action: action, Resource: authz.Resource{Type: "app", ID: app}, ClientIP: netip.MustParseAddr("10.0.0.5")})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func (f *fx) role(t *testing.T, slug string, perms []string, includes ...string) string {
	t.Helper()
	r, err := f.e.Authz.CreateRole(context.Background(), domain.SystemChange, f.sc, authz.RoleParams{Slug: slug, Name: slug, Permissions: perms, Includes: includes})
	if err != nil {
		t.Fatal(err)
	}
	return r.ID
}

func (f *fx) group(t *testing.T, slug string) string {
	t.Helper()
	g, err := f.e.Authz.CreateGroup(context.Background(), domain.SystemChange, f.sc, slug, slug, "")
	if err != nil {
		t.Fatal(err)
	}
	return g.ID
}

func TestTenantGateAndAccessModes(t *testing.T) {
	f := setup(t)
	if d := f.check(t, f.alice, authz.PermAppAccess, f.app); !d.Allowed || d.Trace.Candidates[0].Via != "implicit:all_members" {
		t.Fatalf("member → all_members app: %+v", d)
	}
	if d := f.check(t, f.carol, authz.PermAppAccess, f.app); d.Allowed || d.Reason != "tenant_gate" {
		t.Fatalf("non-member: %+v", d)
	}
	if d := f.check(t, f.alice, authz.PermAppAccess, f.vault); d.Allowed || d.Reason != "default_deny" {
		t.Fatalf("assigned app without grant: %+v", d)
	}
	if d := f.check(t, f.alice, "app:manage", f.app); d.Allowed {
		t.Fatal("app:manage granted to a plain member")
	}
}

// Nested groups and role bundles (ADR-0011): Alice ∈ kids ⊂ family; family holds "viewer" which bundles "vault-user".
func TestNestedGroupsAndBundles(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	vaultUser := f.role(t, "vault-user", []string{authz.PermAppAccess})
	viewer := f.role(t, "viewer", nil, vaultUser)
	family, kids := f.group(t, "family"), f.group(t, "kids")
	if err := f.e.Authz.NestGroup(ctx, domain.SystemChange, f.sc, family, kids); err != nil {
		t.Fatal(err)
	}
	if err := f.e.Authz.AddGroupMember(ctx, domain.SystemChange, f.sc, kids, f.alice, ""); err != nil {
		t.Fatal(err)
	}
	as, err := f.e.Authz.Assign(ctx, domain.SystemChange, f.sc, authz.AssignmentParams{SubjectType: "group", SubjectID: family, RoleID: viewer,
		ScopeType: "resource", ScopeResourceType: "app", ScopeResourceID: f.vault})
	if err != nil {
		t.Fatal(err)
	}
	d := f.check(t, f.alice, authz.PermAppAccess, f.vault)
	if !d.Allowed || d.Trace.Candidates[0].Via != "group:family" || d.Trace.Candidates[0].Role != "vault-user" {
		t.Fatalf("nested grant: %+v", d)
	}
	if d := f.check(t, f.bob, authz.PermAppAccess, f.vault); d.Allowed {
		t.Fatal("bob is in no group")
	}
	// A grant scoped to vault does not leak to other apps or actions.
	if d := f.check(t, f.alice, "app:manage", f.vault); d.Allowed {
		t.Fatal("permission leaked")
	}
	// Revocation takes effect immediately (epoch bump invalidates the cached model).
	if err := f.e.Authz.Unassign(ctx, domain.SystemChange, f.sc, as.ID); err != nil {
		t.Fatal(err)
	}
	if d := f.check(t, f.alice, authz.PermAppAccess, f.vault); d.Allowed {
		t.Fatal("revoked grant still applies")
	}
}

func TestDenyOverridesAndConditions(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	admin, _ := f.e.Authz.GetRole(ctx, f.sc, authz.RoleAdmin)
	if _, err := f.e.Authz.Assign(ctx, domain.SystemChange, f.sc, authz.AssignmentParams{SubjectType: "user", SubjectID: f.alice, RoleID: admin.ID,
		ScopeType: "tenant"}); err != nil {
		t.Fatal(err)
	}
	if d := f.check(t, f.alice, authz.PermAppAccess, f.vault); !d.Allowed {
		t.Fatalf("admin *:*: %+v", d)
	}
	if _, err := f.e.Authz.CreatePolicy(ctx, domain.SystemChange, f.sc, authz.PolicyParams{Slug: "lan-only", Name: "LAN only", Effect: "deny",
		Actions: []string{authz.PermAppAccess}, Expression: `context.network != "trusted"`}); err != nil {
		t.Fatal(err)
	}
	if d := f.check(t, f.alice, authz.PermAppAccess, f.vault); !d.Allowed {
		t.Fatalf("trusted network: %+v", d) // 10.0.0.5 is in testenv's trusted 10.0.0.0/8
	}
	d, _ := f.e.Engine.Check(ctx, authz.Request{TenantID: f.tn.ID, Subject: authz.Subject{Type: "user", ID: f.alice}, Action: authz.PermAppAccess,
		Resource: authz.Resource{Type: "app", ID: f.vault}, ClientIP: netip.MustParseAddr("203.0.113.9")})
	if d.Allowed || d.Reason != "denied_by_policy" {
		t.Fatalf("deny must override *:*: %+v", d)
	}
	// Conditional grant: Bob may use the vault only with a Google session.
	cond, err := f.e.Authz.CreatePolicy(ctx, domain.SystemChange, f.sc, authz.PolicyParams{Slug: "google-only", Name: "Google", Effect: "condition",
		Expression: `principal.auth_method == "google"`})
	if err != nil {
		t.Fatal(err)
	}
	user := f.role(t, "vault-user", []string{authz.PermAppAccess})
	if _, err := f.e.Authz.Assign(ctx, domain.SystemChange, f.sc, authz.AssignmentParams{SubjectType: "user", SubjectID: f.bob, RoleID: user,
		ScopeType: "resource_type", ScopeResourceType: "app", ConditionPolicyID: cond.ID}); err != nil {
		t.Fatal(err)
	}
	if d := f.check(t, f.bob, authz.PermAppAccess, f.vault); !d.Allowed {
		t.Fatalf("google session: %+v", d)
	}
	d, _ = f.e.Engine.Check(ctx, authz.Request{TenantID: f.tn.ID, Subject: authz.Subject{Type: "user", ID: f.bob, AuthMethod: "backup"},
		Action: authz.PermAppAccess, Resource: authz.Resource{Type: "app", ID: f.vault}, ClientIP: netip.MustParseAddr("10.1.1.1")})
	if d.Allowed || d.Trace.Candidates[0].Condition == nil || d.Trace.Candidates[0].Condition.Result {
		t.Fatalf("backup session must fail the condition: %+v", d)
	}
}

// A policy whose stored hash no longer matches (e.g. the environment changed) fails closed.
func TestStalePolicyFailsClosed(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if _, err := f.e.Authz.CreatePolicy(ctx, domain.SystemChange, f.sc, authz.PolicyParams{Slug: "never", Name: "never", Effect: "deny",
		Actions: []string{"*"}, Expression: `false`}); err != nil {
		t.Fatal(err)
	}
	if d := f.check(t, f.alice, authz.PermAppAccess, f.app); !d.Allowed {
		t.Fatalf("valid deny=false policy: %+v", d)
	}
	err := f.e.Store.W().Tx(ctx, func(tx *store.Tx) error {
		if _, err := tx.SQL.ExecContext(ctx, "UPDATE policies SET compiled_hash = 'tampered'"); err != nil {
			return err
		}
		return tx.Q.BumpAuthzEpoch(ctx, f.tn.ID)
	})
	if err != nil {
		t.Fatal(err)
	}
	if d := f.check(t, f.alice, authz.PermAppAccess, f.app); d.Allowed || d.Trace.DenyPolicies[0].Error == "" {
		t.Fatalf("stale policy did not fail closed: %+v", d)
	}
}

func TestAssignmentExpiry(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	user := f.role(t, "vault-user", []string{authz.PermAppAccess})
	exp := f.e.Clock.Now().Add(time.Hour)
	if _, err := f.e.Authz.Assign(ctx, domain.SystemChange, f.sc, authz.AssignmentParams{SubjectType: "user", SubjectID: f.alice, RoleID: user,
		ScopeType: "resource", ScopeResourceType: "app", ScopeResourceID: f.vault, ExpiresAt: &exp}); err != nil {
		t.Fatal(err)
	}
	if d := f.check(t, f.alice, authz.PermAppAccess, f.vault); !d.Allowed {
		t.Fatal("before expiry")
	}
	f.e.Clock.Advance(2 * time.Hour)
	if d := f.check(t, f.alice, authz.PermAppAccess, f.vault); d.Allowed {
		t.Fatal("expired grant applies")
	}
}

// Cross-tenant access only through an explicit share; assignments cannot reference another tenant's role or a non-member.
func TestSharesAndCrossTenantIsolation(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	jones := f.e.Tenant(t, "jones")
	f.e.Member(t, jones, f.carol)
	if d := f.check(t, f.carol, authz.PermAppAccess, f.app); d.Allowed {
		t.Fatal("carol before share")
	}
	if err := f.apps.ShareWith(ctx, domain.SystemChange, f.sc, f.app, jones.ID); err != nil {
		t.Fatal(err)
	}
	if d := f.check(t, f.carol, authz.PermAppAccess, f.app); !d.Allowed || d.Trace.TenantGate.Via != "share:jones" {
		t.Fatalf("shared: %+v", d)
	}
	if d := f.check(t, f.carol, authz.PermAppAccess, f.vault); d.Allowed {
		t.Fatal("share leaked to another app")
	}
	if err := f.apps.Unshare(ctx, domain.SystemChange, f.sc, f.app, jones.ID); err != nil {
		t.Fatal(err)
	}
	if d := f.check(t, f.carol, authz.PermAppAccess, f.app); d.Allowed {
		t.Fatal("unshared app still accessible")
	}
	jsc, _ := f.e.Tenants.SystemScope(ctx, jones.ID)
	jrole, err := f.e.Authz.CreateRole(ctx, domain.SystemChange, jsc, authz.RoleParams{Slug: "r", Name: "r", Permissions: []string{"*:*"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.e.Authz.Assign(ctx, domain.SystemChange, f.sc, authz.AssignmentParams{SubjectType: "user", SubjectID: f.alice, RoleID: jrole.ID,
		ScopeType: "tenant"}); err == nil {
		t.Fatal("assignment referenced another tenant's role")
	}
	if _, err := f.e.Authz.Assign(ctx, domain.SystemChange, f.sc, authz.AssignmentParams{SubjectType: "user", SubjectID: f.carol,
		RoleID: f.role(t, "x", []string{"*:*"}), ScopeType: "tenant"}); err == nil {
		t.Fatal("assignment to a non-member")
	}
}

func TestCycleAndDepthLimits(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	var chain []string
	for i := range 6 {
		chain = append(chain, f.group(t, fmt.Sprintf("g%d", i)))
	}
	for i := range 5 {
		if err := f.e.Authz.NestGroup(ctx, domain.SystemChange, f.sc, chain[i], chain[i+1]); err != nil {
			t.Fatalf("edge %d: %v", i, err)
		}
	}
	extra := f.group(t, "g6")
	if err := f.e.Authz.NestGroup(ctx, domain.SystemChange, f.sc, chain[5], extra); err == nil {
		t.Fatal("depth 6 accepted")
	}
	if err := f.e.Authz.NestGroup(ctx, domain.SystemChange, f.sc, chain[3], chain[0]); err == nil {
		t.Fatal("group cycle accepted")
	}
	r1 := f.role(t, "r1", nil)
	r2 := f.role(t, "r2", nil, r1)
	if _, err := f.e.Authz.UpdateRole(ctx, domain.SystemChange, f.sc, r1, authz.RoleParams{Name: "r1", Includes: []string{r2}}); err == nil {
		t.Fatal("role bundle cycle accepted")
	}
}

// Property: whatever sequence of nesting edges is attempted, the accepted graph stays acyclic with depth ≤ 5.
func TestNestingPropertyRandom(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	const n = 12
	gs := make([]string, n)
	for i := range n {
		gs[i] = f.group(t, fmt.Sprintf("p%d", i))
	}
	rng := rand.New(rand.NewPCG(42, 7)) //nolint:gosec // deterministic test data
	children := map[string][]string{}
	for range 150 {
		a, b := gs[rng.IntN(n)], gs[rng.IntN(n)]
		if err := f.e.Authz.NestGroup(ctx, domain.SystemChange, f.sc, a, b); err == nil {
			children[a] = append(children[a], b)
		}
	}
	var depth func(string, map[string]bool) int
	depth = func(g string, onPath map[string]bool) int {
		if onPath[g] {
			t.Fatalf("cycle through %s", g)
		}
		onPath[g] = true
		defer delete(onPath, g)
		best := 0
		for _, c := range children[g] {
			best = max(best, 1+depth(c, onPath))
		}
		return best
	}
	for _, g := range gs {
		if d := depth(g, map[string]bool{}); d > authz.MaxDepth {
			t.Fatalf("depth %d from %s", d, g)
		}
	}
}

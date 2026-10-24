package tenancy_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aurimasniekis/go-porch/internal/apperr"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/tenancy"
	"github.com/aurimasniekis/go-porch/internal/testenv"
)

// M1 acceptance / T-B5-3: the schema itself refuses cross-tenant references.
func TestCompositeForeignKeysRefuseCrossTenantReferences(t *testing.T) {
	e := testenv.New(t)
	ctx := context.Background()
	a, b := e.Tenant(t, "smith"), e.Tenant(t, "jones")
	alice, bob := e.User(t, "Alice", ""), e.User(t, "Bob", "")
	e.Member(t, a, alice.ID)
	e.Member(t, b, bob.ID)
	exec := func(q string, args ...any) error {
		return e.Store.W().Tx(ctx, func(tx *store.Tx) error { _, err := tx.SQL.ExecContext(ctx, q, args...); return err })
	}
	ins := "INSERT INTO groups (id, tenant_id, slug, name, created_at, updated_at) VALUES (?, ?, ?, ?, 0, 0)"
	if err := exec(ins, "grp_a", a.ID, "kids", "Kids"); err != nil {
		t.Fatal(err)
	}
	gm := "INSERT INTO group_members (tenant_id, group_id, user_id, source, created_at) VALUES (?, ?, ?, 'manual', 0)"
	cases := map[string][]any{
		"tenant B row pointing at tenant A group":   {b.ID, "grp_a", bob.ID},
		"tenant A group with a non-member of A":     {a.ID, "grp_a", bob.ID},
		"tenant A group, member of A, wrong tenant": {b.ID, "grp_a", alice.ID},
		"unknown tenant": {"ten_nope", "grp_a", alice.ID},
	}
	for name, args := range cases {
		if err := exec(gm, args...); !store.IsConstraint(err) {
			t.Errorf("%s: expected constraint violation, got %v", name, err)
		}
	}
	if err := exec(gm, a.ID, "grp_a", alice.ID); err != nil {
		t.Fatalf("valid insert: %v", err)
	}
	// Removing Alice's membership cascades to her group memberships in that tenant.
	sc, _ := e.Tenants.SystemScope(ctx, a.ID)
	ms, _, _ := e.Tenants.ListMembers(ctx, sc, mustPage(t))
	if err := e.Tenants.RemoveMember(ctx, testenv.Admin, sc, ms[0].ID, 0); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := e.Store.ReadDB().QueryRowContext(ctx, "SELECT count(*) FROM group_members").Scan(&n); err != nil || n != 0 {
		t.Fatalf("group members left: %d %v", n, err)
	}
}

func TestScopeResolution(t *testing.T) {
	e := testenv.New(t)
	ctx := context.Background()
	a, b := e.Tenant(t, "smith"), e.Tenant(t, "jones")
	alice := e.User(t, "Alice", "")
	owner := e.Owner(t, "Olga")
	m := e.Member(t, a, alice.ID)

	if sc, err := e.Tenants.ResolveForMember(ctx, alice.ID, "smith"); err != nil || sc.TenantID() != a.ID || sc.Via() != tenancy.ViaMembership {
		t.Fatalf("member by slug: %+v %v", sc, err)
	}
	if sc, err := e.Tenants.ResolveForMember(ctx, alice.ID, a.ID); err != nil || sc.TenantID() != a.ID {
		t.Fatalf("member by id: %v", err)
	}
	// Not a member of B: indistinguishable from a missing tenant.
	_, errB := e.Tenants.ResolveForMember(ctx, alice.ID, b.ID)
	_, errX := e.Tenants.ResolveForMember(ctx, alice.ID, "does-not-exist")
	if errB == nil || errX == nil || errB.Error() != errX.Error() {
		t.Fatalf("errors differ: %v / %v", errB, errX)
	}
	// Alice is not an operator.
	if _, err := e.Tenants.ResolveForOperator(ctx, alice.ID, b.ID); err == nil {
		t.Fatal("non-operator got operator scope")
	}
	if sc, err := e.Tenants.ResolveForOperator(ctx, owner.ID, b.ID); err != nil || sc.Via() != tenancy.ViaOperator {
		t.Fatalf("operator: %v", err)
	}
	// Suspended membership loses access.
	sc, _ := e.Tenants.SystemScope(ctx, a.ID)
	if _, err := e.Tenants.SetMemberStatus(ctx, testenv.Admin, sc, m.ID, tenancy.StatusSuspended, m.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Tenants.ResolveForMember(ctx, alice.ID, a.ID); err == nil {
		t.Fatal("suspended member still resolves")
	}
	// The zero Scope is useless.
	if _, err := e.Tenants.Get(ctx, tenancy.Scope{}); err == nil {
		t.Fatal("zero scope accepted")
	}
	if _, _, err := e.Tenants.ListMembers(ctx, tenancy.Scope{}, mustPage(t)); err == nil {
		t.Fatal("zero scope accepted for members")
	}
}

func TestTenantValidationAndConcurrency(t *testing.T) {
	e := testenv.New(t)
	ctx := context.Background()
	for _, slug := range []string{"", "A", "UPPER", "-x", "x-", strings.Repeat("a", 64), "a_b"} {
		if _, err := e.Tenants.Create(ctx, testenv.Admin, tenancy.CreateParams{Slug: slug, Name: "x"}); apperr.CodeOf(err) != apperr.CodeInvalid {
			t.Errorf("slug %q: %v", slug, err)
		}
	}
	tn := e.Tenant(t, "smith")
	if _, err := e.Tenants.Create(ctx, testenv.Admin, tenancy.CreateParams{Slug: "smith", Name: "x"}); apperr.CodeOf(err) != apperr.CodeAlreadyExists {
		t.Fatalf("dup: %v", err)
	}
	sc, _ := e.Tenants.SystemScope(ctx, tn.ID)
	name := "Smith family"
	up, err := e.Tenants.Update(ctx, testenv.Admin, sc, tenancy.UpdateParams{Name: &name, IfVersion: tn.Version})
	if err != nil || up.Version != tn.Version+1 {
		t.Fatalf("%+v %v", up, err)
	}
	// Stale If-Match.
	if _, err := e.Tenants.Update(ctx, testenv.Admin, sc, tenancy.UpdateParams{Name: &name, IfVersion: tn.Version}); apperr.CodeOf(err) != apperr.CodePrecondition {
		t.Fatalf("stale: %v", err)
	}
	if err := e.Tenants.Delete(ctx, testenv.Admin, sc, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Tenants.Get(ctx, sc); !errors.Is(err, tenancy.ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
}

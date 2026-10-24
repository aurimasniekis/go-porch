package mgmtapi

import (
	"context"
	"net/http"
	"slices"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/aurimasniekis/go-porch/internal/apperr"
	"github.com/aurimasniekis/go-porch/internal/authz"
	"github.com/aurimasniekis/go-porch/internal/httpx"
	"github.com/aurimasniekis/go-porch/internal/identity"
	"github.com/aurimasniekis/go-porch/internal/session"
	"github.com/aurimasniekis/go-porch/internal/tenancy"
)

// CodeEscalation is returned when a delegated administrator tries to grant more than they hold (ADR-0038).
const CodeEscalation apperr.Code = "privilege_escalation"

// tenantAdmin resolves a tenant scope for a management operation that needs perm. Installation owners and admins act
// as operators. Any other caller must be an active member whose permissions in that tenant allow perm at tenant scope
// (delegated administration, ADR-0038). Callers without access cannot tell a missing tenant from a forbidden one.
func (d *Deps) tenantAdmin(ctx context.Context, ref, perm string) (tenancy.Scope, error) {
	return d.tenantAdminAny(ctx, ref, perm)
}

// tenantAdminAny is tenantAdmin for read operations that any of several permissions may use (for example the member
// list, which group and role managers need to pick subjects).
func (d *Deps) tenantAdminAny(ctx context.Context, ref string, perms ...string) (tenancy.Scope, error) {
	p := Principal(ctx)
	if p == nil {
		return tenancy.Scope{}, huma.Error401Unauthorized("authentication required")
	}
	if p.IsOperator(identity.RoleOwner, identity.RoleAdmin) {
		return d.operatorScope(ctx, ref)
	}
	if p.Token != nil && p.Token.CreatorOperator && p.Token.TenantID != "" {
		sc, err := d.Tenants.ResolveForOperator(ctx, p.UserID, ref)
		if err != nil || !slices.ContainsFunc(perms, func(perm string) bool { return tokenCovers(p.Token, sc.TenantID(), perm) }) {
			return tenancy.Scope{}, d.fail("tenant-admin", tenancy.ErrNoAccess)
		}
		return sc, nil
	}
	sc, err := d.Tenants.ResolveDelegated(ctx, p.UserID, ref, func(tenantID string) error {
		for _, perm := range perms {
			ok, err := d.holds(ctx, tenantID, perm)
			if err != nil {
				return err
			}
			if ok {
				return nil
			}
		}
		return tenancy.ErrNoAccess
	})
	if err != nil {
		return sc, d.fail("tenant-admin", err)
	}
	return sc, nil
}

// tokenCovers reports whether an automation token's grant allows perm in tenantID (tenant tokens only).
func tokenCovers(g *session.TokenGrant, tenantID, perm string) bool {
	if g == nil {
		return true
	}
	if g.TenantID == "" || g.TenantID != tenantID {
		return false
	}
	return slices.ContainsFunc(g.Permissions, func(have string) bool { return authz.Grants(have, perm) })
}

// holds asks the engine whether the caller may perform perm on the tenant itself. Automation tokens additionally
// need the permission in their own grant.
func (d *Deps) holds(ctx context.Context, tenantID, perm string) (bool, error) {
	p := Principal(ctx)
	if !tokenCovers(p.Token, tenantID, perm) {
		return false, nil
	}
	dec, err := d.Engine.Check(ctx, authz.Request{TenantID: tenantID, Subject: authz.Subject{Type: "user", ID: p.UserID, AuthMethod: p.Method,
		AuthTime: p.AuthTime}, Action: perm, Resource: authz.Resource{Type: "tenant"}, ClientIP: httpx.ClientIP(ctx)})
	return dec.Allowed, err
}

// mayGrant refuses a delegated change that would confer permissions the caller does not hold unconditionally at
// tenant scope. Operators are exempt (installation administrators can always grant).
func (d *Deps) mayGrant(ctx context.Context, sc tenancy.Scope, perms []string) error {
	if sc.Via() == tenancy.ViaOperator || len(perms) == 0 {
		return nil
	}
	p := Principal(ctx)
	missing, err := d.Engine.Missing(ctx, sc.TenantID(), p.UserID, perms)
	if err != nil {
		return d.fail("escalation", err)
	}
	for _, w := range perms {
		if !tokenCovers(p.Token, sc.TenantID(), w) && !slices.Contains(missing, w) {
			missing = append(missing, w)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	slices.Sort(missing)
	return problem(http.StatusForbidden, CodeEscalation, "you cannot grant permissions you do not hold: "+strings.Join(missing, ", "),
		[]apperr.FieldError{{Field: "permissions", Message: "not held: " + strings.Join(missing, ", ")}})
}

// mayGrantRole checks mayGrant for every permission a role (with its bundled roles) confers.
func (d *Deps) mayGrantRole(ctx context.Context, sc tenancy.Scope, roleID string) error {
	if sc.Via() == tenancy.ViaOperator {
		return nil
	}
	perms, err := d.Engine.RolePermissions(ctx, sc.TenantID(), roleID)
	if err != nil {
		return d.fail("escalation", err)
	}
	return d.mayGrant(ctx, sc, perms)
}

// mayGrantGroup checks mayGrant for everything membership of a group (and its ancestors) confers.
func (d *Deps) mayGrantGroup(ctx context.Context, sc tenancy.Scope, groupID string) error {
	if sc.Via() == tenancy.ViaOperator {
		return nil
	}
	perms, err := d.Engine.GroupPermissions(ctx, sc.TenantID(), groupID)
	if err != nil {
		return d.fail("escalation", err)
	}
	return d.mayGrant(ctx, sc, perms)
}

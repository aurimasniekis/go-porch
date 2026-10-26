package mgmtapi

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/aurimasniekis/go-porch/internal/apperr"
	"github.com/aurimasniekis/go-porch/internal/authz"
	"github.com/aurimasniekis/go-porch/internal/httpx"
	"github.com/aurimasniekis/go-porch/internal/identity"
	"github.com/aurimasniekis/go-porch/internal/ids"
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

// tenantReader resolves a tenant scope for a read operation. Installation owners and admins act as operators;
// inspectors (people and inspector tokens, ADR-0048) read every tenant; anyone else needs one of perms, as for
// tenantAdminAny. Pass the read permission together with the management permissions that also allow the read. With
// no perms, only operators and inspectors may read.
func (d *Deps) tenantReader(ctx context.Context, ref string, perms ...string) (tenancy.Scope, error) {
	p := Principal(ctx)
	if p == nil {
		return tenancy.Scope{}, huma.Error401Unauthorized("authentication required")
	}
	if p.IsOperator(identity.RoleOwner, identity.RoleAdmin) {
		return d.operatorScope(ctx, ref)
	}
	if p.IsOperator(identity.RoleInspector) {
		sc, err := d.Tenants.ResolveForInspector(ctx, p.UserID, ref)
		if err != nil {
			return sc, d.fail("tenant-reader", err)
		}
		return sc, nil
	}
	if len(perms) == 0 {
		_, err := requireOperator(ctx, identity.RoleOwner, identity.RoleAdmin, identity.RoleInspector)
		return tenancy.Scope{}, err
	}
	return d.tenantAdminAny(ctx, ref, perms...)
}

// tokenCovers reports whether an automation token's grant allows perm in tenantID. Installation admin tokens act as
// operators; tenant tokens cover their own tenant and permissions only.
func tokenCovers(g *session.TokenGrant, tenantID, perm string) bool {
	if g == nil || g.Role == identity.RoleAdmin {
		return true
	}
	if g.TenantID == "" || g.TenantID != tenantID {
		return false
	}
	return slices.ContainsFunc(g.Permissions, func(have string) bool { return authz.Grants(have, perm) })
}

// subject is the caller as an engine subject (the creator for automation tokens).
func subject(ctx context.Context, tenantID string) authz.Request {
	p := Principal(ctx)
	return authz.Request{TenantID: tenantID, Subject: authz.Subject{Type: "user", ID: p.UserID, AuthMethod: p.Method, AuthTime: p.AuthTime},
		Resource: authz.Resource{Type: "tenant"}, ClientIP: httpx.ClientIP(ctx)}
}

// holds asks the engine whether the caller may perform perm on the tenant itself. Automation tokens additionally
// need the permission in their own grant.
func (d *Deps) holds(ctx context.Context, tenantID, perm string) (bool, error) {
	if !tokenCovers(Principal(ctx).Token, tenantID, perm) {
		return false, nil
	}
	req := subject(ctx, tenantID)
	req.Action = perm
	dec, err := d.Engine.Check(ctx, req)
	return dec.Allowed, err
}

// mayGrant refuses a change that would confer (or remove) permissions the caller does not hold unconditionally at
// tenant scope, or that a deny policy blocks for them (ADR-0038). Interactive installation operators are exempt; an
// automation token never confers more than its own grant, whoever created it.
func (d *Deps) mayGrant(ctx context.Context, sc tenancy.Scope, perms []string) error {
	if len(perms) == 0 {
		return nil
	}
	p := Principal(ctx)
	var missing []string
	if sc.Via() != tenancy.ViaOperator {
		var err error
		if missing, err = d.Engine.Missing(ctx, subject(ctx, sc.TenantID()), perms); err != nil {
			return d.fail("escalation", err)
		}
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
	missing = slices.Compact(missing)
	return problem(http.StatusForbidden, CodeEscalation, "you cannot grant permissions you do not hold: "+strings.Join(missing, ", "),
		[]apperr.FieldError{{Field: "permissions", Message: "not held: " + strings.Join(missing, ", ")}})
}

// exempt reports whether escalation checks can be skipped entirely (interactive operators).
func exempt(ctx context.Context, sc tenancy.Scope) bool {
	return sc.Via() == tenancy.ViaOperator && Principal(ctx).Token == nil
}

// mayGrantRole checks mayGrant for every permission a role (with its bundled roles) confers.
func (d *Deps) mayGrantRole(ctx context.Context, sc tenancy.Scope, roleID string) error {
	if exempt(ctx, sc) {
		return nil
	}
	perms, err := d.Engine.RolePermissions(ctx, sc.TenantID(), roleID)
	if err != nil {
		return d.fail("escalation", err)
	}
	return d.mayGrant(ctx, sc, perms)
}

// mayGrantGroup checks mayGrant for everything membership of a group confers: the permissions assigned to it and its
// ancestors, plus whatever policies keyed on the group's slug unlock or block (joining a group can satisfy a condition
// such as "oncall" in principal.groups, leaving one can escape a deny).
func (d *Deps) mayGrantGroup(ctx context.Context, sc tenancy.Scope, groupID string) error {
	if exempt(ctx, sc) {
		return nil
	}
	perms, err := d.Engine.GroupPermissions(ctx, sc.TenantID(), groupID)
	if err != nil {
		return d.fail("escalation", err)
	}
	g, err := d.Authz.GetGroup(ctx, sc, groupID)
	if err != nil {
		return d.fail("escalation", err)
	}
	more, err := d.policyPerms(ctx, sc, func(pol authz.PolicyDef) bool {
		return strings.Contains(pol.Expression, `"`+g.Slug+`"`) || strings.Contains(pol.Expression, "'"+g.Slug+"'")
	})
	if err != nil {
		return err
	}
	return d.mayGrant(ctx, sc, append(perms, more...))
}

// policyPerms returns what the matching policies affect: the actions of deny policies and every permission of the
// roles whose assignments a condition policy gates.
func (d *Deps) policyPerms(ctx context.Context, sc tenancy.Scope, match func(authz.PolicyDef) bool) ([]string, error) {
	pols, err := d.Authz.Policies(ctx, sc)
	if err != nil {
		return nil, d.fail("escalation", err)
	}
	var as []authz.Assignment
	var perms []string
	for _, pol := range pols {
		if !match(pol) {
			continue
		}
		if pol.Effect == "deny" {
			perms = append(perms, denyPerms(pol.Effect, pol.Actions)...)
			continue
		}
		if as == nil {
			if as, err = d.Authz.Assignments(ctx, sc); err != nil {
				return nil, d.fail("escalation", err)
			}
		}
		for _, a := range as {
			if a.ConditionPolicyID != pol.ID {
				continue
			}
			ps, err := d.Engine.RolePermissions(ctx, sc.TenantID(), a.RoleID)
			if err != nil {
				return nil, d.fail("escalation", err)
			}
			perms = append(perms, ps...)
		}
	}
	return perms, nil
}

// audiencesFree refuses API audiences that another tenant already registered or that name a client or service account:
// a token for another tenant's API (or one that looks issued to a client) must not be mintable here (review M1).
func (d *Deps) audiencesFree(ctx context.Context, sc tenancy.Scope, auds []string) error {
	if len(auds) == 0 {
		return nil
	}
	rows, err := d.Store.R().ListAudienceOwners(ctx)
	if err != nil {
		return d.fail("audiences", err)
	}
	for _, a := range auds {
		if strings.HasPrefix(a, ids.OAuthClient+"_") || strings.HasPrefix(a, ids.ServiceAccount+"_") {
			return problem(http.StatusUnprocessableEntity, apperr.CodeInvalid, "audiences: "+a+" looks like a client ID", nil)
		}
		for _, r := range rows {
			if r.TenantID == sc.TenantID() {
				continue
			}
			var theirs []string
			_ = json.Unmarshal([]byte(r.Audiences), &theirs)
			if slices.Contains(theirs, a) {
				return problem(http.StatusConflict, apperr.CodeConflict, "audiences: "+a+" belongs to another tenant", nil)
			}
		}
	}
	return nil
}

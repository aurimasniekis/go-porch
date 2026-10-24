package authz

import (
	"context"
	"slices"
	"strings"

	"github.com/aurimasniekis/go-porch/internal/store/db"
)

// EffectiveGrant is one permission a principal holds and how.
type EffectiveGrant struct {
	Permission  string `json:"permission"`
	Scope       string `json:"scope"` // tenant | type:<t> | <type>:<id>
	Role        string `json:"role"`
	Via         string `json:"via"` // user | group:<slug> | service_account
	Conditional bool   `json:"conditional"`
	Expires     bool   `json:"expires"`
}

// Effective lists every grant reaching the subject in a tenant (conditions are reported, not evaluated).
func (e *Engine) Effective(ctx context.Context, tenantID, subjectType, subjectID string) ([]EffectiveGrant, error) {
	m, err := e.model(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	via := map[string]string{subjectType + ":" + subjectID: subjectType}
	if subjectType == "user" {
		direct, err := e.s.R().ListUserGroupIDs(ctx, db.ListUserGroupIDsParams{TenantID: tenantID, UserID: subjectID})
		if err != nil {
			return nil, err
		}
		for _, g := range m.groupClosure(direct) {
			via["group:"+g] = "group:" + m.groups[g].Slug
		}
	}
	now := e.clock.Now()
	var out []EffectiveGrant
	for _, a := range m.assignments {
		v, ok := via[a.SubjectType+":"+a.SubjectID]
		if !ok || expired(a, now) {
			continue
		}
		scope := "tenant"
		switch a.ScopeType {
		case "resource_type":
			scope = "type:" + a.ScopeResourceType
		case "resource":
			scope = a.ScopeResourceType + ":" + a.ScopeResourceID
		}
		for _, rid := range m.expandRoles(a.RoleID) {
			for _, perm := range m.rolePerms[rid] {
				out = append(out, EffectiveGrant{Permission: perm, Scope: scope, Role: m.roles[rid].Slug, Via: v,
					Conditional: a.ConditionPolicyID.Valid, Expires: a.ExpiresAt.Valid})
			}
		}
	}
	slices.SortFunc(out, func(a, b EffectiveGrant) int {
		return strings.Compare(a.Permission+a.Scope+a.Via, b.Permission+b.Scope+b.Via)
	})
	return out, nil
}

// Missing returns the permissions in want that subject does not hold unconditionally at tenant scope (escalation
// checks for delegated administration: a tenant admin may only grant what they hold).
func (e *Engine) Missing(ctx context.Context, tenantID, userID string, want []string) ([]string, error) {
	grants, err := e.Effective(ctx, tenantID, "user", userID)
	if err != nil {
		return nil, err
	}
	var missing []string
	for _, w := range want {
		held := false
		for _, g := range grants {
			if g.Scope == "tenant" && !g.Conditional && (g.Permission == w || Grants(g.Permission, w) || g.Permission == "*:*") {
				held = true
				break
			}
		}
		if !held {
			missing = append(missing, w)
		}
	}
	return missing, nil
}

// RolePermissions returns every permission a role grants including bundled roles.
func (e *Engine) RolePermissions(ctx context.Context, tenantID, roleID string) ([]string, error) {
	m, err := e.model(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, rid := range m.expandRoles(roleID) {
		for _, p := range m.rolePerms[rid] {
			if !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
	}
	return out, nil
}

// GroupPermissions returns every permission granted to the group or its ancestors (what joining it confers).
func (e *Engine) GroupPermissions(ctx context.Context, tenantID, groupID string) ([]string, error) {
	m, err := e.model(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, g := range m.groupClosure([]string{groupID}) {
		for _, a := range m.assignments {
			if a.SubjectType != "group" || a.SubjectID != g {
				continue
			}
			for _, rid := range m.expandRoles(a.RoleID) {
				for _, p := range m.rolePerms[rid] {
					if !slices.Contains(out, p) {
						out = append(out, p)
					}
				}
			}
		}
	}
	return out, nil
}

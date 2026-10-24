package authz

import (
	"context"
	"encoding/json"
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

// Missing returns the permissions in want that the subject of req does not hold for escalation purposes (ADR-0038): a
// permission counts as held only through an unconditional, non-expiring grant at tenant scope, and only while no deny
// policy blocks it for the subject (a denied administrator cannot grant, or remove a deny on, what they are denied).
// req.TenantID and req.Subject identify the caller; req.Action and req.Resource are ignored.
func (e *Engine) Missing(ctx context.Context, req Request, want []string) ([]string, error) {
	grants, err := e.Effective(ctx, req.TenantID, req.Subject.Type, req.Subject.ID)
	if err != nil {
		return nil, err
	}
	m, err := e.model(ctx, req.TenantID)
	if err != nil {
		return nil, err
	}
	var missing []string
	for _, w := range want {
		held := false
		for _, g := range grants {
			if g.Scope == "tenant" && !g.Conditional && !g.Expires && Grants(g.Permission, w) {
				held = true
				break
			}
		}
		if held {
			denied, err := e.deniedFor(ctx, m, req, w)
			if err != nil {
				return nil, err
			}
			held = !denied
		}
		if !held {
			missing = append(missing, w)
		}
	}
	return missing, nil
}

// deniedFor reports whether a deny policy of the tenant blocks the subject for want (or, for a wildcard, for any
// action it covers that a deny policy names). Each overlapping deny is evaluated with a representative action.
func (e *Engine) deniedFor(ctx context.Context, m *model, req Request, want string) (bool, error) {
	reps := map[string]bool{}
	for _, pid := range m.denies {
		var acts []string
		_ = json.Unmarshal([]byte(m.policies[pid].Actions), &acts)
		for _, a := range acts {
			switch {
			case a == "*" || Grants(a, want):
				reps[concrete(want)] = true
			case Grants(want, a):
				reps[concrete(a)] = true
			}
		}
	}
	for act := range reps {
		r := req
		r.Action, r.Resource, r.SimulatedContext = act, Resource{Type: "tenant"}, nil
		d, err := e.check(ctx, r)
		if err != nil {
			return false, err
		}
		if d.Reason == "denied_by_policy" {
			return true, nil
		}
	}
	return false, nil
}

// concrete turns a wildcard permission into a representative concrete action ("app:*" → "app:any").
func concrete(p string) string {
	t, a, _ := strings.Cut(p, ":")
	if t == "*" {
		t = "any"
	}
	if a == "*" {
		a = "any"
	}
	return t + ":" + a
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

package authz

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/aurimasniekis/go-porch/internal/apperr"
	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/domain"
	"github.com/aurimasniekis/go-porch/internal/ids"
	"github.com/aurimasniekis/go-porch/internal/outbox"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/store/db"
	"github.com/aurimasniekis/go-porch/internal/tenancy"
)

// Admin manages the authorization model of tenants. Every change bumps the tenant's authz epoch in the same
// transaction, which invalidates cached models (ADR-0011).
type Admin struct {
	s     *store.Store
	audit *audit.Writer
}

// NewAdmin returns the admin service.
func NewAdmin(s *store.Store, a *audit.Writer) *Admin { return &Admin{s: s, audit: a} }

// change runs fn in a transaction that also bumps the epoch, audits and emits an event.
func (a *Admin) change(ctx context.Context, name string, ch domain.Change, sc tenancy.Scope, ev audit.Event, fn func(tx *store.Tx) error) error {
	if !sc.Valid() {
		return tenancy.ErrNoAccess
	}
	return a.s.W().TxNamed(ctx, name, func(tx *store.Tx) error {
		if err := fn(tx); err != nil {
			return err
		}
		if err := tx.Q.BumpAuthzEpoch(ctx, sc.TenantID()); err != nil {
			return err
		}
		ev.Actor, ev.TenantID = ch.Actor, sc.TenantID()
		if _, err := a.audit.Append(ctx, tx, ev); err != nil {
			return err
		}
		area, action, _ := strings.Cut(ev.Action, ".")
		_, err := outbox.Enqueue(ctx, tx, outbox.Event{Area: "authz", Entity: area, Action: action, TenantID: sc.TenantID(),
			Payload: map[string]any{"target_id": ev.Target.ID}})
		return err
	})
}

// EnsureBuiltinsTx creates the built-in roles of a new tenant (hooked into tenant creation).
func EnsureBuiltinsTx(ctx context.Context, tx *store.Tx, tenantID string) error {
	for _, r := range []struct {
		slug, name, desc string
		perms            []string
	}{
		{RoleAdmin, "Administrator", "Manages this tenant (applications, members, groups, roles and policies).", []string{"*:*"}},
		{RoleMember, "Member", "Every active member. Grants access to applications whose access mode is 'all members'.", nil},
	} {
		if _, err := tx.Q.GetRoleBySlug(ctx, db.GetRoleBySlugParams{TenantID: tenantID, Slug: r.slug}); err == nil {
			continue
		}
		id := ids.New(ids.Role)
		if err := tx.Q.InsertRole(ctx, db.InsertRoleParams{ID: id, TenantID: tenantID, Slug: r.slug, Name: r.name, Description: r.desc, BuiltIn: 1,
			ManagedBy: domain.ManagedSystem, CreatedAt: tx.NowMicros(), UpdatedAt: tx.NowMicros()}); err != nil {
			return err
		}
		for _, p := range r.perms {
			if err := tx.Q.InsertRolePermission(ctx, db.InsertRolePermissionParams{TenantID: tenantID, RoleID: id, Permission: p}); err != nil {
				return err
			}
		}
	}
	return tx.Q.BumpAuthzEpoch(ctx, tenantID)
}

// Role is a role with its permissions and included roles.
type Role struct {
	ID          string    `json:"id"`
	Slug        string    `json:"slug"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	BuiltIn     bool      `json:"built_in"`
	Permissions []string  `json:"permissions"`
	Includes    []string  `json:"includes"` // role IDs bundled into this one
	Version     int64     `json:"version"`
	ManagedBy   string    `json:"managed_by"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// RoleParams create or replace a role's definition.
type RoleParams struct {
	Slug, Name, Description string
	Permissions             []string
	Includes                []string
	IfVersion               int64
}

// ErrNotFound is the generic not-found error of this package.
var ErrNotFound = apperr.New(apperr.CodeNotFound, "not found")

func validatePerms(perms []string, v *apperr.Validation) {
	for _, p := range perms {
		if !ValidPermission(p) {
			v.Add("permissions", "%q is not <resource_type>:<action>", p)
		}
	}
}

func (a *Admin) setIncludesTx(ctx context.Context, tx *store.Tx, tenantID, roleID string, includes []string) error {
	if err := tx.Q.DeleteRoleEdges(ctx, db.DeleteRoleEdgesParams{TenantID: tenantID, ParentID: roleID}); err != nil {
		return err
	}
	edges, err := tx.Q.ListRoleEdges(ctx, tenantID)
	if err != nil {
		return err
	}
	children := map[string][]string{}
	for _, e := range edges {
		children[e.ParentID] = append(children[e.ParentID], e.ChildID)
	}
	for _, c := range includes {
		if err := checkDAG(children, roleID, c); err != nil {
			return apperr.New(apperr.CodeInvalid, "includes: %s", err)
		}
		if err := tx.Q.InsertRoleEdge(ctx, db.InsertRoleEdgeParams{TenantID: tenantID, ParentID: roleID, ChildID: c}); err != nil {
			if store.IsConstraint(err) {
				return apperr.New(apperr.CodeInvalid, "includes: unknown role %s in this tenant", c)
			}
			return err
		}
		children[roleID] = append(children[roleID], c)
	}
	return nil
}

// CreateRole adds a custom role.
func (a *Admin) CreateRole(ctx context.Context, ch domain.Change, sc tenancy.Scope, p RoleParams) (Role, error) {
	var v apperr.Validation
	if !domain.ValidSlug(p.Slug) {
		v.Add("slug", "must be lowercase letters, digits or inner hyphens")
	}
	p.Name = domain.CleanName("name", p.Name, &v)
	validatePerms(p.Permissions, &v)
	if err := v.Err(); err != nil {
		return Role{}, err
	}
	id := ids.New(ids.Role)
	err := a.change(ctx, "authz.create_role", ch, sc, audit.Event{Action: "role.created", Target: audit.Target{Type: "role", ID: id},
		Details: map[string]any{"slug": p.Slug, "permissions": p.Permissions, "includes": p.Includes}}, func(tx *store.Tx) error {
		err := tx.Q.InsertRole(ctx, db.InsertRoleParams{ID: id, TenantID: sc.TenantID(), Slug: p.Slug, Name: p.Name, Description: p.Description,
			ManagedBy: ch.Managed(), LastChangedBy: domain.NullStr(ch.ChangedBy()), CreatedAt: tx.NowMicros(), UpdatedAt: tx.NowMicros()})
		if store.IsConstraint(err) {
			return apperr.New(apperr.CodeAlreadyExists, "role %q exists", p.Slug)
		}
		if err != nil {
			return err
		}
		for _, perm := range p.Permissions {
			if err := tx.Q.InsertRolePermission(ctx, db.InsertRolePermissionParams{TenantID: sc.TenantID(), RoleID: id, Permission: perm}); err != nil {
				return err
			}
		}
		return a.setIncludesTx(ctx, tx, sc.TenantID(), id, p.Includes)
	})
	if err != nil {
		return Role{}, err
	}
	return a.GetRole(ctx, sc, id)
}

// UpdateRole replaces a role's name, description, permissions and includes (built-in roles keep their permissions).
func (a *Admin) UpdateRole(ctx context.Context, ch domain.Change, sc tenancy.Scope, id string, p RoleParams) (Role, error) {
	var v apperr.Validation
	p.Name = domain.CleanName("name", p.Name, &v)
	validatePerms(p.Permissions, &v)
	if err := v.Err(); err != nil {
		return Role{}, err
	}
	err := a.change(ctx, "authz.update_role", ch, sc, audit.Event{Action: "role.updated", Target: audit.Target{Type: "role", ID: id},
		Details: map[string]any{"permissions": p.Permissions, "includes": p.Includes}}, func(tx *store.Tx) error {
		r, err := tx.Q.GetRole(ctx, db.GetRoleParams{TenantID: sc.TenantID(), ID: id})
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if err := domain.IfMatch(p.IfVersion, r.Version); err != nil {
			return err
		}
		if _, err := tx.Q.UpdateRole(ctx, db.UpdateRoleParams{Name: p.Name, Description: p.Description, ManagedBy: ch.Managed(),
			LastChangedBy: domain.NullStr(ch.ChangedBy()), UpdatedAt: tx.NowMicros(), TenantID: sc.TenantID(), ID: id, Version: r.Version}); err != nil {
			return err
		}
		if r.BuiltIn == 0 {
			if err := tx.Q.DeleteRolePermissions(ctx, db.DeleteRolePermissionsParams{TenantID: sc.TenantID(), RoleID: id}); err != nil {
				return err
			}
			for _, perm := range p.Permissions {
				if err := tx.Q.InsertRolePermission(ctx, db.InsertRolePermissionParams{TenantID: sc.TenantID(), RoleID: id, Permission: perm}); err != nil {
					return err
				}
			}
		}
		return a.setIncludesTx(ctx, tx, sc.TenantID(), id, p.Includes)
	})
	if err != nil {
		return Role{}, err
	}
	return a.GetRole(ctx, sc, id)
}

// DeleteRole removes a custom role and its assignments.
func (a *Admin) DeleteRole(ctx context.Context, ch domain.Change, sc tenancy.Scope, id string) error {
	return a.change(ctx, "authz.delete_role", ch, sc, audit.Event{Action: "role.deleted", Target: audit.Target{Type: "role", ID: id}},
		func(tx *store.Tx) error {
			n, err := tx.Q.DeleteRole(ctx, db.DeleteRoleParams{TenantID: sc.TenantID(), ID: id})
			if err != nil {
				return err
			}
			if n == 0 {
				return apperr.New(apperr.CodeNotFound, "role not found (built-in roles cannot be deleted)")
			}
			return nil
		})
}

// GetRole returns one role.
func (a *Admin) GetRole(ctx context.Context, sc tenancy.Scope, id string) (Role, error) {
	rs, err := a.Roles(ctx, sc)
	if err != nil {
		return Role{}, err
	}
	for _, r := range rs {
		if r.ID == id || r.Slug == id {
			return r, nil
		}
	}
	return Role{}, ErrNotFound
}

// Roles lists the tenant's roles.
func (a *Admin) Roles(ctx context.Context, sc tenancy.Scope) ([]Role, error) {
	if !sc.Valid() {
		return nil, tenancy.ErrNoAccess
	}
	rows, err := a.s.R().ListRoles(ctx, sc.TenantID())
	if err != nil {
		return nil, err
	}
	perms, err := a.s.R().ListTenantRolePermissions(ctx, sc.TenantID())
	if err != nil {
		return nil, err
	}
	edges, err := a.s.R().ListRoleEdges(ctx, sc.TenantID())
	if err != nil {
		return nil, err
	}
	out := make([]Role, 0, len(rows))
	for _, r := range rows {
		ro := Role{ID: r.ID, Slug: r.Slug, Name: r.Name, Description: r.Description, BuiltIn: r.BuiltIn == 1, Permissions: []string{}, Includes: []string{},
			Version: r.Version, ManagedBy: r.ManagedBy, UpdatedAt: domain.FromMicros(r.UpdatedAt)}
		for _, p := range perms {
			if p.RoleID == r.ID {
				ro.Permissions = append(ro.Permissions, p.Permission)
			}
		}
		for _, e := range edges {
			if e.ParentID == r.ID {
				ro.Includes = append(ro.Includes, e.ChildID)
			}
		}
		out = append(out, ro)
	}
	return out, nil
}

// Group is a tenant group.
type Group struct {
	ID          string    `json:"id"`
	Slug        string    `json:"slug"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Parents     []string  `json:"parents"`
	Members     []string  `json:"members"` // user IDs (direct)
	Version     int64     `json:"version"`
	ManagedBy   string    `json:"managed_by"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// CreateGroup adds a group.
func (a *Admin) CreateGroup(ctx context.Context, ch domain.Change, sc tenancy.Scope, slug, name, description string) (Group, error) {
	var v apperr.Validation
	if !domain.ValidSlug(slug) {
		v.Add("slug", "must be lowercase letters, digits or inner hyphens")
	}
	name = domain.CleanName("name", name, &v)
	if err := v.Err(); err != nil {
		return Group{}, err
	}
	id := ids.New(ids.Group)
	err := a.change(ctx, "authz.create_group", ch, sc, audit.Event{Action: "group.created", Target: audit.Target{Type: "group", ID: id},
		Details: map[string]any{"slug": slug}}, func(tx *store.Tx) error {
		err := tx.Q.InsertGroup(ctx, db.InsertGroupParams{ID: id, TenantID: sc.TenantID(), Slug: slug, Name: name, Description: description,
			ManagedBy: ch.Managed(), LastChangedBy: domain.NullStr(ch.ChangedBy()), CreatedAt: tx.NowMicros(), UpdatedAt: tx.NowMicros()})
		if store.IsConstraint(err) {
			return apperr.New(apperr.CodeAlreadyExists, "group %q exists", slug)
		}
		return err
	})
	if err != nil {
		return Group{}, err
	}
	return a.GetGroup(ctx, sc, id)
}

// UpdateGroup changes a group's name and description.
func (a *Admin) UpdateGroup(ctx context.Context, ch domain.Change, sc tenancy.Scope, id, name, description string, ifVersion int64) (Group, error) {
	var v apperr.Validation
	name = domain.CleanName("name", name, &v)
	if len(description) > 2000 {
		v.Add("description", "at most 2000 characters")
	}
	if err := v.Err(); err != nil {
		return Group{}, err
	}
	g, err := a.GetGroup(ctx, sc, id)
	if err != nil {
		return Group{}, err
	}
	err = a.change(ctx, "authz.update_group", ch, sc, audit.Event{Action: "group.updated", Target: audit.Target{Type: "group", ID: g.ID}},
		func(tx *store.Tx) error {
			if err := domain.IfMatch(ifVersion, g.Version); err != nil {
				return err
			}
			n, err := tx.Q.UpdateGroup(ctx, db.UpdateGroupParams{Name: name, Description: description, ManagedBy: ch.Managed(),
				LastChangedBy: domain.NullStr(ch.ChangedBy()), UpdatedAt: tx.NowMicros(), TenantID: sc.TenantID(), ID: g.ID, Version: g.Version})
			if err == nil && n != 1 {
				return apperr.New(apperr.CodePrecondition, "group changed concurrently")
			}
			return err
		})
	if err != nil {
		return Group{}, err
	}
	return a.GetGroup(ctx, sc, g.ID)
}

// DeleteGroup removes a group (memberships, nesting edges and its assignments).
func (a *Admin) DeleteGroup(ctx context.Context, ch domain.Change, sc tenancy.Scope, id string) error {
	return a.change(ctx, "authz.delete_group", ch, sc, audit.Event{Action: "group.deleted", Target: audit.Target{Type: "group", ID: id}},
		func(tx *store.Tx) error {
			n, err := tx.Q.DeleteGroup(ctx, db.DeleteGroupParams{TenantID: sc.TenantID(), ID: id})
			if err != nil {
				return err
			}
			if n == 0 {
				return ErrNotFound
			}
			// Assignments to a deleted group would never match; remove them for clarity.
			_, err = tx.SQL.ExecContext(ctx, "DELETE FROM role_assignments WHERE tenant_id = ? AND subject_type = 'group' AND subject_id = ?", sc.TenantID(), id)
			return err
		})
}

// AddGroupMember adds a tenant member to a group (the composite FK rejects non-members).
func (a *Admin) AddGroupMember(ctx context.Context, ch domain.Change, sc tenancy.Scope, groupID, userID, source string) error {
	if source == "" {
		source = "manual"
	}
	return a.change(ctx, "authz.add_group_member", ch, sc, audit.Event{Action: "group.member_added", Target: audit.Target{Type: "group", ID: groupID},
		Details: map[string]any{"user_id": userID, "source": source}}, func(tx *store.Tx) error {
		err := tx.Q.InsertGroupMember(ctx, db.InsertGroupMemberParams{TenantID: sc.TenantID(), GroupID: groupID, UserID: userID, Source: source, CreatedAt: tx.NowMicros()})
		if store.IsConstraint(err) {
			return apperr.New(apperr.CodeInvalid, "user must be a member of this tenant and the group must exist (or the user is already in it)")
		}
		return err
	})
}

// RemoveGroupMember removes a user from a group.
func (a *Admin) RemoveGroupMember(ctx context.Context, ch domain.Change, sc tenancy.Scope, groupID, userID string) error {
	return a.change(ctx, "authz.remove_group_member", ch, sc, audit.Event{Action: "group.member_removed", Target: audit.Target{Type: "group", ID: groupID},
		Details: map[string]any{"user_id": userID}}, func(tx *store.Tx) error {
		n, err := tx.Q.DeleteGroupMember(ctx, db.DeleteGroupMemberParams{TenantID: sc.TenantID(), GroupID: groupID, UserID: userID})
		if err == nil && n == 0 {
			return ErrNotFound
		}
		return err
	})
}

// NestGroup makes child a member group of parent (DAG, depth ≤ 5).
func (a *Admin) NestGroup(ctx context.Context, ch domain.Change, sc tenancy.Scope, parentID, childID string) error {
	return a.change(ctx, "authz.nest_group", ch, sc, audit.Event{Action: "group.nested", Target: audit.Target{Type: "group", ID: parentID},
		Details: map[string]any{"child": childID}}, func(tx *store.Tx) error {
		edges, err := tx.Q.ListGroupEdges(ctx, sc.TenantID())
		if err != nil {
			return err
		}
		children := map[string][]string{}
		for _, e := range edges {
			children[e.ParentID] = append(children[e.ParentID], e.ChildID)
		}
		if err := checkDAG(children, parentID, childID); err != nil {
			return apperr.New(apperr.CodeInvalid, "%s", err)
		}
		err = tx.Q.InsertGroupEdge(ctx, db.InsertGroupEdgeParams{TenantID: sc.TenantID(), ParentID: parentID, ChildID: childID})
		if store.IsConstraint(err) {
			return apperr.New(apperr.CodeInvalid, "both groups must exist in this tenant (and not already be nested)")
		}
		return err
	})
}

// UnnestGroup removes a nesting edge.
func (a *Admin) UnnestGroup(ctx context.Context, ch domain.Change, sc tenancy.Scope, parentID, childID string) error {
	return a.change(ctx, "authz.unnest_group", ch, sc, audit.Event{Action: "group.unnested", Target: audit.Target{Type: "group", ID: parentID},
		Details: map[string]any{"child": childID}}, func(tx *store.Tx) error {
		n, err := tx.Q.DeleteGroupEdge(ctx, db.DeleteGroupEdgeParams{TenantID: sc.TenantID(), ParentID: parentID, ChildID: childID})
		if err == nil && n == 0 {
			return ErrNotFound
		}
		return err
	})
}

// Groups lists groups with their direct members and parents.
func (a *Admin) Groups(ctx context.Context, sc tenancy.Scope) ([]Group, error) {
	if !sc.Valid() {
		return nil, tenancy.ErrNoAccess
	}
	rows, err := a.s.R().ListGroups(ctx, sc.TenantID())
	if err != nil {
		return nil, err
	}
	edges, err := a.s.R().ListGroupEdges(ctx, sc.TenantID())
	if err != nil {
		return nil, err
	}
	out := make([]Group, 0, len(rows))
	for _, g := range rows {
		grp := Group{ID: g.ID, Slug: g.Slug, Name: g.Name, Description: g.Description, Parents: []string{}, Members: []string{}, Version: g.Version,
			ManagedBy: g.ManagedBy, UpdatedAt: domain.FromMicros(g.UpdatedAt)}
		for _, e := range edges {
			if e.ChildID == g.ID {
				grp.Parents = append(grp.Parents, e.ParentID)
			}
		}
		ms, err := a.s.R().ListGroupMembers(ctx, db.ListGroupMembersParams{TenantID: sc.TenantID(), GroupID: g.ID})
		if err != nil {
			return nil, err
		}
		for _, m := range ms {
			grp.Members = append(grp.Members, m.UserID)
		}
		out = append(out, grp)
	}
	return out, nil
}

// GetGroup returns one group by ID or slug.
func (a *Admin) GetGroup(ctx context.Context, sc tenancy.Scope, id string) (Group, error) {
	gs, err := a.Groups(ctx, sc)
	if err != nil {
		return Group{}, err
	}
	for _, g := range gs {
		if g.ID == id || g.Slug == id {
			return g, nil
		}
	}
	return Group{}, ErrNotFound
}

// PolicyDef is a stored policy.
type PolicyDef struct {
	ID         string    `json:"id"`
	Slug       string    `json:"slug"`
	Name       string    `json:"name"`
	Effect     string    `json:"effect"`
	Actions    []string  `json:"actions"`
	Expression string    `json:"expression"`
	EnvVersion int64     `json:"env_version"`
	Version    int64     `json:"version"`
	ManagedBy  string    `json:"managed_by"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// PolicyParams create or update a policy.
type PolicyParams struct {
	Slug, Name, Effect, Expression string
	Actions                        []string
	IfVersion                      int64
}

func validatePolicy(p *PolicyParams, v *apperr.Validation) *Policy {
	if p.Effect != "condition" && p.Effect != "deny" {
		v.Add("effect", "must be condition or deny")
	}
	if p.Effect == "deny" && len(p.Actions) == 0 {
		v.Add("actions", "deny policies list the actions they apply to (\"*\" for all)")
	}
	if p.Effect == "condition" && len(p.Actions) > 0 {
		v.Add("actions", "condition policies apply to the assignments that reference them; leave actions empty")
	}
	for _, act := range p.Actions {
		if act != "*" && !ValidPermission(act) {
			v.Add("actions", "%q is not <resource_type>:<action>", act)
		}
	}
	prog, err := Compile(p.Expression)
	if err != nil {
		v.Add("expression", "%s", strings.TrimPrefix(err.Error(), ErrPolicy.Error()+": "))
	}
	if p.Actions == nil {
		p.Actions = []string{}
	}
	return prog
}

// CreatePolicy adds a policy after compiling it against the current environment.
func (a *Admin) CreatePolicy(ctx context.Context, ch domain.Change, sc tenancy.Scope, p PolicyParams) (PolicyDef, error) {
	var v apperr.Validation
	if !domain.ValidSlug(p.Slug) {
		v.Add("slug", "must be lowercase letters, digits or inner hyphens")
	}
	p.Name = domain.CleanName("name", p.Name, &v)
	prog := validatePolicy(&p, &v)
	if err := v.Err(); err != nil {
		return PolicyDef{}, err
	}
	id := ids.New(ids.Policy)
	acts, _ := json.Marshal(p.Actions)
	err := a.change(ctx, "authz.create_policy", ch, sc, audit.Event{Action: "policy.created", Target: audit.Target{Type: "policy", ID: id},
		Details: map[string]any{"slug": p.Slug, "effect": p.Effect, "hash": prog.Hash}}, func(tx *store.Tx) error {
		err := tx.Q.InsertPolicy(ctx, db.InsertPolicyParams{ID: id, TenantID: sc.TenantID(), Slug: p.Slug, Name: p.Name, Effect: p.Effect,
			Actions: string(acts), Expression: p.Expression, EnvVersion: EnvVersion, CompiledHash: prog.Hash, ManagedBy: ch.Managed(),
			LastChangedBy: domain.NullStr(ch.ChangedBy()), CreatedAt: tx.NowMicros(), UpdatedAt: tx.NowMicros()})
		if store.IsConstraint(err) {
			return apperr.New(apperr.CodeAlreadyExists, "policy %q exists", p.Slug)
		}
		return err
	})
	if err != nil {
		return PolicyDef{}, err
	}
	return a.GetPolicy(ctx, sc, id)
}

// UpdatePolicy replaces a policy's name, actions and expression (its effect cannot change).
func (a *Admin) UpdatePolicy(ctx context.Context, ch domain.Change, sc tenancy.Scope, id string, p PolicyParams) (PolicyDef, error) {
	cur, err := a.GetPolicy(ctx, sc, id)
	if err != nil {
		return PolicyDef{}, err
	}
	p.Effect = cur.Effect
	var v apperr.Validation
	p.Name = domain.CleanName("name", p.Name, &v)
	prog := validatePolicy(&p, &v)
	if err := v.Err(); err != nil {
		return PolicyDef{}, err
	}
	acts, _ := json.Marshal(p.Actions)
	err = a.change(ctx, "authz.update_policy", ch, sc, audit.Event{Action: "policy.updated", Target: audit.Target{Type: "policy", ID: id},
		Details: map[string]any{"hash": prog.Hash}}, func(tx *store.Tx) error {
		n, err := tx.Q.UpdatePolicy(ctx, db.UpdatePolicyParams{Name: p.Name, Actions: string(acts), Expression: p.Expression, CompiledHash: prog.Hash,
			ManagedBy: ch.Managed(), LastChangedBy: domain.NullStr(ch.ChangedBy()), UpdatedAt: tx.NowMicros(), TenantID: sc.TenantID(), ID: cur.ID,
			Version: max(p.IfVersion, cur.Version)})
		if err == nil && n == 0 {
			return apperr.New(apperr.CodePrecondition, "policy was changed; reload and retry")
		}
		return err
	})
	if err != nil {
		return PolicyDef{}, err
	}
	return a.GetPolicy(ctx, sc, cur.ID)
}

// DeletePolicy removes a policy (and assignments conditioned on it).
func (a *Admin) DeletePolicy(ctx context.Context, ch domain.Change, sc tenancy.Scope, id string) error {
	return a.change(ctx, "authz.delete_policy", ch, sc, audit.Event{Action: "policy.deleted", Target: audit.Target{Type: "policy", ID: id}},
		func(tx *store.Tx) error {
			n, err := tx.Q.DeletePolicy(ctx, db.DeletePolicyParams{TenantID: sc.TenantID(), ID: id})
			if err == nil && n == 0 {
				return ErrNotFound
			}
			return err
		})
}

// Policies lists policies.
func (a *Admin) Policies(ctx context.Context, sc tenancy.Scope) ([]PolicyDef, error) {
	if !sc.Valid() {
		return nil, tenancy.ErrNoAccess
	}
	rows, err := a.s.R().ListPolicies(ctx, sc.TenantID())
	if err != nil {
		return nil, err
	}
	out := make([]PolicyDef, 0, len(rows))
	for _, r := range rows {
		var acts []string
		_ = json.Unmarshal([]byte(r.Actions), &acts)
		if acts == nil {
			acts = []string{}
		}
		out = append(out, PolicyDef{ID: r.ID, Slug: r.Slug, Name: r.Name, Effect: r.Effect, Actions: acts, Expression: r.Expression,
			EnvVersion: r.EnvVersion, Version: r.Version, ManagedBy: r.ManagedBy, UpdatedAt: domain.FromMicros(r.UpdatedAt)})
	}
	return out, nil
}

// GetPolicy returns one policy by ID or slug.
func (a *Admin) GetPolicy(ctx context.Context, sc tenancy.Scope, id string) (PolicyDef, error) {
	ps, err := a.Policies(ctx, sc)
	if err != nil {
		return PolicyDef{}, err
	}
	for _, p := range ps {
		if p.ID == id || p.Slug == id {
			return p, nil
		}
	}
	return PolicyDef{}, ErrNotFound
}

// Assignment binds a subject to a role at a scope.
type Assignment struct {
	ID                string     `json:"id"`
	SubjectType       string     `json:"subject_type"`
	SubjectID         string     `json:"subject_id"`
	RoleID            string     `json:"role_id"`
	ScopeType         string     `json:"scope_type"`
	ScopeResourceType string     `json:"scope_resource_type,omitempty"`
	ScopeResourceID   string     `json:"scope_resource_id,omitempty"`
	ConditionPolicyID string     `json:"condition_policy_id,omitempty"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`
	Source            string     `json:"source"`
	CreatedAt         time.Time  `json:"created_at"`
}

// AssignmentParams describe an assignment.
type AssignmentParams struct {
	SubjectType, SubjectID, RoleID                string
	ScopeType, ScopeResourceType, ScopeResourceID string
	ConditionPolicyID                             string
	ExpiresAt                                     *time.Time
	Source                                        string
}

// Assign creates an assignment after validating subject, scope and condition within the tenant.
func (a *Admin) Assign(ctx context.Context, ch domain.Change, sc tenancy.Scope, p AssignmentParams) (Assignment, error) {
	var v apperr.Validation
	switch p.ScopeType {
	case "tenant":
		p.ScopeResourceType, p.ScopeResourceID = "", ""
	case "resource_type":
		p.ScopeResourceID = ""
		if !regexpType(p.ScopeResourceType) {
			v.Add("scope_resource_type", "required")
		}
	case "resource":
		if !regexpType(p.ScopeResourceType) || p.ScopeResourceID == "" {
			v.Add("scope_resource_id", "resource scope needs scope_resource_type and scope_resource_id")
		}
	default:
		v.Add("scope_type", "must be tenant, resource_type or resource")
	}
	if p.Source == "" {
		p.Source = "manual"
	}
	if err := v.Err(); err != nil {
		return Assignment{}, err
	}
	id := ids.New(ids.Assignment)
	err := a.change(ctx, "authz.assign", ch, sc, audit.Event{Action: "assignment.created", Target: audit.Target{Type: "assignment", ID: id},
		Details: map[string]any{"subject_type": p.SubjectType, "subject_id": p.SubjectID, "role_id": p.RoleID, "scope": p.ScopeType,
			"resource": p.ScopeResourceType + ":" + p.ScopeResourceID, "condition": p.ConditionPolicyID}}, func(tx *store.Tx) error {
		switch p.SubjectType {
		case "user":
			if _, err := tx.Q.GetMembershipByUser(ctx, db.GetMembershipByUserParams{TenantID: sc.TenantID(), UserID: p.SubjectID}); err != nil {
				return apperr.New(apperr.CodeInvalid, "subject_id: user is not a member of this tenant")
			}
		case "group":
			if _, err := tx.Q.GetGroup(ctx, db.GetGroupParams{TenantID: sc.TenantID(), ID: p.SubjectID}); err != nil {
				return apperr.New(apperr.CodeInvalid, "subject_id: unknown group in this tenant")
			}
		case "service_account":
			if sa, err := tx.Q.GetServiceAccountByID(ctx, p.SubjectID); err != nil || sa.TenantID != sc.TenantID() {
				return apperr.New(apperr.CodeInvalid, "subject_id: unknown service account in this tenant")
			}
		default:
			return apperr.New(apperr.CodeInvalid, "subject_type must be user, group or service_account")
		}
		if p.ScopeType == "resource" {
			if p.ScopeResourceType == "app" {
				if _, err := tx.Q.GetApplication(ctx, db.GetApplicationParams{TenantID: sc.TenantID(), ID: p.ScopeResourceID}); err != nil {
					return apperr.New(apperr.CodeInvalid, "scope_resource_id: unknown application in this tenant")
				}
			} else if r, err := tx.Q.GetResource(ctx, db.GetResourceParams{TenantID: sc.TenantID(), ID: p.ScopeResourceID}); err != nil || r.Type != p.ScopeResourceType {
				return apperr.New(apperr.CodeInvalid, "scope_resource_id: unknown resource of that type in this tenant")
			}
		}
		if p.ConditionPolicyID != "" {
			pol, err := tx.Q.GetPolicy(ctx, db.GetPolicyParams{TenantID: sc.TenantID(), ID: p.ConditionPolicyID})
			if err != nil || pol.Effect != "condition" {
				return apperr.New(apperr.CodeInvalid, "condition_policy_id: unknown condition policy in this tenant")
			}
		}
		var exp sql.NullInt64
		if p.ExpiresAt != nil {
			if !p.ExpiresAt.After(tx.Now) {
				return apperr.New(apperr.CodeInvalid, "expires_at must be in the future")
			}
			exp = sql.NullInt64{Int64: p.ExpiresAt.UnixMicro(), Valid: true}
		}
		err := tx.Q.InsertAssignment(ctx, db.InsertAssignmentParams{ID: id, TenantID: sc.TenantID(), SubjectType: p.SubjectType, SubjectID: p.SubjectID,
			RoleID: p.RoleID, ScopeType: p.ScopeType, ScopeResourceType: p.ScopeResourceType, ScopeResourceID: p.ScopeResourceID,
			ConditionPolicyID: domain.NullStr(p.ConditionPolicyID), ExpiresAt: exp, Source: p.Source, CreatedAt: tx.NowMicros(),
			CreatedBy: domain.NullStr(ch.ChangedBy())})
		if store.IsConstraint(err) {
			return apperr.New(apperr.CodeInvalid, "role_id: unknown role in this tenant")
		}
		return err
	})
	if err != nil {
		return Assignment{}, err
	}
	return a.GetAssignment(ctx, sc, id)
}

func regexpType(t string) bool {
	return t != "" && ValidPermission(t+":x") && !strings.Contains(t, "*")
}

// Unassign removes an assignment.
func (a *Admin) Unassign(ctx context.Context, ch domain.Change, sc tenancy.Scope, id string) error {
	return a.change(ctx, "authz.unassign", ch, sc, audit.Event{Action: "assignment.deleted", Target: audit.Target{Type: "assignment", ID: id}},
		func(tx *store.Tx) error {
			n, err := tx.Q.DeleteAssignment(ctx, db.DeleteAssignmentParams{TenantID: sc.TenantID(), ID: id})
			if err == nil && n == 0 {
				return ErrNotFound
			}
			return err
		})
}

// Assignments lists assignments.
func (a *Admin) Assignments(ctx context.Context, sc tenancy.Scope) ([]Assignment, error) {
	if !sc.Valid() {
		return nil, tenancy.ErrNoAccess
	}
	rows, err := a.s.R().ListAssignments(ctx, sc.TenantID())
	if err != nil {
		return nil, err
	}
	out := make([]Assignment, 0, len(rows))
	for _, r := range rows {
		out = append(out, Assignment{ID: r.ID, SubjectType: r.SubjectType, SubjectID: r.SubjectID, RoleID: r.RoleID, ScopeType: r.ScopeType,
			ScopeResourceType: r.ScopeResourceType, ScopeResourceID: r.ScopeResourceID, ConditionPolicyID: r.ConditionPolicyID.String,
			ExpiresAt: domain.OptMicros(r.ExpiresAt), Source: r.Source, CreatedAt: domain.FromMicros(r.CreatedAt)})
	}
	return out, nil
}

// GetAssignment returns one assignment.
func (a *Admin) GetAssignment(ctx context.Context, sc tenancy.Scope, id string) (Assignment, error) {
	as, err := a.Assignments(ctx, sc)
	if err != nil {
		return Assignment{}, err
	}
	if i := slices.IndexFunc(as, func(x Assignment) bool { return x.ID == id }); i >= 0 {
		return as[i], nil
	}
	return Assignment{}, ErrNotFound
}

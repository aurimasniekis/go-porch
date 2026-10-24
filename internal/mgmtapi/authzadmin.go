package mgmtapi

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/aurimasniekis/go-porch/internal/authz"
	"github.com/aurimasniekis/go-porch/internal/tenancy"
)

// withETag is an output carrying the resource version.
type withETag[T any] struct {
	ETag string `header:"ETag"`
	Body T
}

func tagged[T any](version int64, body T) *withETag[T] {
	return &withETag[T]{ETag: etag(version), Body: body}
}

// RoleRequest creates or replaces a role.
type RoleRequest struct {
	Slug        string   `json:"slug,omitempty" maxLength:"63" doc:"Create only."`
	Name        string   `json:"name" minLength:"1" maxLength:"200"`
	Description string   `json:"description,omitempty" maxLength:"2000"`
	Permissions []string `json:"permissions" maxItems:"100" doc:"<resource_type>:<action>; either side may be *. Built-in roles keep their permissions."`
	Includes    []string `json:"includes,omitempty" maxItems:"20" doc:"IDs of roles bundled into this one (DAG, depth ≤ 5)."`
}

// GroupRequest creates a group.
type GroupRequest struct {
	Slug        string `json:"slug" minLength:"1" maxLength:"63"`
	Name        string `json:"name" minLength:"1" maxLength:"200"`
	Description string `json:"description,omitempty" maxLength:"2000"`
}

// GroupUpdate edits a group.
type GroupUpdate struct {
	Name        string `json:"name" minLength:"1" maxLength:"200"`
	Description string `json:"description" maxLength:"2000"`
}

// ResourceRequest creates a resource.
type ResourceRequest struct {
	Type       string            `json:"type" minLength:"1" maxLength:"32" doc:"Lowercase identifier; app and tenant are reserved."`
	Slug       string            `json:"slug" minLength:"1" maxLength:"63"`
	Name       string            `json:"name" minLength:"1" maxLength:"200"`
	ParentID   string            `json:"parent_id,omitempty" maxLength:"64"`
	Attributes map[string]string `json:"attributes,omitempty" doc:"Visible to policies as resource.attributes."`
}

// ResourceUpdate edits a resource.
type ResourceUpdate struct {
	Name       string            `json:"name" minLength:"1" maxLength:"200"`
	Attributes map[string]string `json:"attributes"`
}

// PolicyRequest creates or replaces a policy.
type PolicyRequest struct {
	Slug       string   `json:"slug,omitempty" maxLength:"63" doc:"Create only."`
	Name       string   `json:"name" minLength:"1" maxLength:"200"`
	Effect     string   `json:"effect" enum:"condition,deny" doc:"condition: referenced by assignments, must be true for them to apply; deny: overrides grants for its actions."`
	Actions    []string `json:"actions,omitempty" maxItems:"50" doc:"Deny policies only: permissions it applies to (* for all)."`
	Expression string   `json:"expression" minLength:"1" maxLength:"4096" doc:"expr-lang boolean expression over principal, resource, action, context, now (environment v1)."`
}

// PolicyValidateRequest is an expression to compile.
type PolicyValidateRequest struct {
	Expression string `json:"expression" maxLength:"4096"`
}

// PolicyValidation is the result of compiling an expression.
type PolicyValidation struct {
	Valid bool   `json:"valid"`
	Error string `json:"error,omitempty"`
}

// AssignmentRequest grants a role.
type AssignmentRequest struct {
	SubjectType       string     `json:"subject_type" enum:"user,group,service_account"`
	SubjectID         string     `json:"subject_id" minLength:"1" maxLength:"64"`
	RoleID            string     `json:"role_id" minLength:"1" maxLength:"64"`
	ScopeType         string     `json:"scope_type" enum:"tenant,resource_type,resource"`
	ScopeResourceType string     `json:"scope_resource_type,omitempty" maxLength:"32"`
	ScopeResourceID   string     `json:"scope_resource_id,omitempty" maxLength:"64"`
	ConditionPolicyID string     `json:"condition_policy_id,omitempty" maxLength:"64"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`
}

// PermissionCatalogue lists known permissions.
type PermissionCatalogue struct {
	System []string `json:"system"`
	Custom []string `json:"custom" doc:"Permissions used by this tenant's roles that are not system permissions."`
}

// RoleRef addresses a role.
type RoleRef struct {
	TenantRef
	Role string `path:"role" maxLength:"64" doc:"Role ID or slug."`
}

// GroupRef addresses a group.
type GroupRef struct {
	TenantRef
	Group string `path:"group" maxLength:"64" doc:"Group ID or slug."`
}

// GroupMemberRef addresses a group member.
type GroupMemberRef struct {
	GroupRef
	User string `path:"user" maxLength:"64" doc:"User ID."`
}

// ParentRef addresses a group nesting edge.
type ParentRef struct {
	GroupRef
	Parent string `path:"parent" maxLength:"64" doc:"Parent group ID or slug."`
}

// ResourceRef addresses a resource.
type ResourceRef struct {
	TenantRef
	Resource string `path:"resource" maxLength:"64"`
}

// PolicyRef addresses a policy.
type PolicyRef struct {
	TenantRef
	Policy string `path:"policy" maxLength:"64" doc:"Policy ID or slug."`
}

func registerAuthzAdmin(api huma.API, d *Deps) {
	registerRoles(api, d)
	registerGroups(api, d)
	registerResources(api, d)
	registerPolicies(api, d)
	registerAssignments(api, d)
}

func registerRoles(api huma.API, d *Deps) {
	tags := []string{"authz"}
	huma.Register(api, huma.Operation{OperationID: "list-permissions", Method: http.MethodGet, Path: "/tenants/{tenant}/permissions",
		Summary: "Known permissions (system catalogue and custom ones in use)", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *TenantRef) (*struct{ Body PermissionCatalogue }, error) {
			sc, err := d.tenantAdmin(ctx, in.Tenant, authz.PermRoleManage)
			if err != nil {
				return nil, err
			}
			rs, err := d.Authz.Roles(ctx, sc)
			if err != nil {
				return nil, d.fail("permissions", err)
			}
			out := PermissionCatalogue{System: slices.Clone(authz.SystemPermissions), Custom: []string{}}
			for _, r := range rs {
				for _, p := range r.Permissions {
					if !slices.Contains(out.System, p) && !slices.Contains(out.Custom, p) {
						out.Custom = append(out.Custom, p)
					}
				}
			}
			slices.Sort(out.Custom)
			return &struct{ Body PermissionCatalogue }{Body: out}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "list-roles", Method: http.MethodGet, Path: "/tenants/{tenant}/roles",
		Summary: "Roles of a tenant", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *TenantRef) (*struct{ Body []authz.Role }, error) {
			sc, err := d.tenantAdmin(ctx, in.Tenant, authz.PermRoleManage)
			if err != nil {
				return nil, err
			}
			rs, err := d.Authz.Roles(ctx, sc)
			if err != nil {
				return nil, d.fail("list-roles", err)
			}
			return &struct{ Body []authz.Role }{Body: rs}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "create-role", Method: http.MethodPost, Path: "/tenants/{tenant}/roles", DefaultStatus: http.StatusCreated,
		Summary: "Create a role (delegated administrators may only include permissions they hold)", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			TenantRef
			ManagedBy
			Body RoleRequest
		}) (*withETag[authz.Role], error) {
			sc, err := d.tenantAdmin(ctx, in.Tenant, authz.PermRoleManage)
			if err != nil {
				return nil, err
			}
			if err := d.mayDefineRole(ctx, sc, in.Body.Permissions, in.Body.Includes); err != nil {
				return nil, err
			}
			r, err := d.Authz.CreateRole(ctx, change(ctx, in.ManagedBy.ManagedBy), sc, authz.RoleParams{Slug: in.Body.Slug, Name: in.Body.Name,
				Description: in.Body.Description, Permissions: nonNilStrings(in.Body.Permissions), Includes: in.Body.Includes})
			if err != nil {
				return nil, d.fail("create-role", err)
			}
			return tagged(r.Version, r), nil
		})
	huma.Register(api, huma.Operation{OperationID: "get-role", Method: http.MethodGet, Path: "/tenants/{tenant}/roles/{role}",
		Summary: "Get a role", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *RoleRef) (*withETag[authz.Role], error) {
			sc, err := d.tenantAdmin(ctx, in.Tenant, authz.PermRoleManage)
			if err != nil {
				return nil, err
			}
			r, err := d.Authz.GetRole(ctx, sc, in.Role)
			if err != nil {
				return nil, d.fail("get-role", err)
			}
			return tagged(r.Version, r), nil
		})
	huma.Register(api, huma.Operation{OperationID: "update-role", Method: http.MethodPut, Path: "/tenants/{tenant}/roles/{role}",
		Summary: "Replace a role's definition", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			RoleRef
			ManagedBy
			IfMatch
			Body RoleRequest
		}) (*withETag[authz.Role], error) {
			sc, err := d.tenantAdmin(ctx, in.Tenant, authz.PermRoleManage)
			if err != nil {
				return nil, err
			}
			v, err := in.Version()
			if err != nil {
				return nil, err
			}
			cur, err := d.Authz.GetRole(ctx, sc, in.Role)
			if err != nil {
				return nil, d.fail("update-role", err)
			}
			// Both the new definition and what it removes: stripping permissions demotes everyone holding the role.
			if err := d.mayDefineRole(ctx, sc, in.Body.Permissions, in.Body.Includes); err != nil {
				return nil, err
			}
			if err := d.mayGrantRole(ctx, sc, cur.ID); err != nil {
				return nil, err
			}
			r, err := d.Authz.UpdateRole(ctx, change(ctx, in.ManagedBy.ManagedBy), sc, cur.ID, authz.RoleParams{Name: in.Body.Name,
				Description: in.Body.Description, Permissions: nonNilStrings(in.Body.Permissions), Includes: in.Body.Includes, IfVersion: v})
			if err != nil {
				return nil, d.fail("update-role", err)
			}
			return tagged(r.Version, r), nil
		})
	huma.Register(api, huma.Operation{OperationID: "delete-role", Method: http.MethodDelete, Path: "/tenants/{tenant}/roles/{role}",
		DefaultStatus: http.StatusNoContent, Summary: "Delete a custom role and its assignments", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			RoleRef
			ManagedBy
			IfMatch
		}) (*struct{}, error) {
			v, err := in.Version()
			if err != nil {
				return nil, err
			}
			sc, err := d.tenantAdmin(ctx, in.Tenant, authz.PermRoleManage)
			if err != nil {
				return nil, err
			}
			cur, err := d.Authz.GetRole(ctx, sc, in.Role)
			if err != nil {
				return nil, d.fail("delete-role", err)
			}
			if err := d.mayGrantRole(ctx, sc, cur.ID); err != nil {
				return nil, err
			}
			if err := d.Authz.DeleteRole(ctx, change(ctx, in.ManagedBy.ManagedBy), sc, cur.ID, v); err != nil {
				return nil, d.fail("delete-role", err)
			}
			return &struct{}{}, nil
		})
}

// mayDefineRole checks a role definition (its permissions plus everything bundled roles grant) against the caller.
func (d *Deps) mayDefineRole(ctx context.Context, sc tenancy.Scope, perms, includes []string) error {
	if exempt(ctx, sc) {
		return nil
	}
	all := slices.Clone(perms)
	for _, inc := range includes {
		ps, err := d.Engine.RolePermissions(ctx, sc.TenantID(), inc)
		if err != nil {
			return d.fail("escalation", err)
		}
		all = append(all, ps...)
	}
	return d.mayGrant(ctx, sc, all)
}

func registerGroups(api huma.API, d *Deps) {
	tags := []string{"authz"}
	huma.Register(api, huma.Operation{OperationID: "list-groups", Method: http.MethodGet, Path: "/tenants/{tenant}/groups",
		Summary: "Groups of a tenant (direct members and parents)", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *TenantRef) (*struct{ Body []authz.Group }, error) {
			sc, err := d.tenantAdmin(ctx, in.Tenant, authz.PermGroupManage)
			if err != nil {
				return nil, err
			}
			gs, err := d.Authz.Groups(ctx, sc)
			if err != nil {
				return nil, d.fail("list-groups", err)
			}
			return &struct{ Body []authz.Group }{Body: gs}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "create-group", Method: http.MethodPost, Path: "/tenants/{tenant}/groups", DefaultStatus: http.StatusCreated,
		Summary: "Create a group", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			TenantRef
			ManagedBy
			Body GroupRequest
		}) (*withETag[authz.Group], error) {
			sc, err := d.tenantAdmin(ctx, in.Tenant, authz.PermGroupManage)
			if err != nil {
				return nil, err
			}
			g, err := d.Authz.CreateGroup(ctx, change(ctx, in.ManagedBy.ManagedBy), sc, in.Body.Slug, in.Body.Name, in.Body.Description)
			if err != nil {
				return nil, d.fail("create-group", err)
			}
			return tagged(g.Version, g), nil
		})
	huma.Register(api, huma.Operation{OperationID: "get-group", Method: http.MethodGet, Path: "/tenants/{tenant}/groups/{group}",
		Summary: "Get a group", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *GroupRef) (*withETag[authz.Group], error) {
			sc, err := d.tenantAdmin(ctx, in.Tenant, authz.PermGroupManage)
			if err != nil {
				return nil, err
			}
			g, err := d.Authz.GetGroup(ctx, sc, in.Group)
			if err != nil {
				return nil, d.fail("get-group", err)
			}
			return tagged(g.Version, g), nil
		})
	huma.Register(api, huma.Operation{OperationID: "update-group", Method: http.MethodPatch, Path: "/tenants/{tenant}/groups/{group}",
		Summary: "Rename or describe a group", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			GroupRef
			ManagedBy
			IfMatch
			Body GroupUpdate
		}) (*withETag[authz.Group], error) {
			sc, err := d.tenantAdmin(ctx, in.Tenant, authz.PermGroupManage)
			if err != nil {
				return nil, err
			}
			v, err := in.Version()
			if err != nil {
				return nil, err
			}
			g, err := d.Authz.UpdateGroup(ctx, change(ctx, in.ManagedBy.ManagedBy), sc, in.Group, in.Body.Name, in.Body.Description, v)
			if err != nil {
				return nil, d.fail("update-group", err)
			}
			return tagged(g.Version, g), nil
		})
	huma.Register(api, huma.Operation{OperationID: "delete-group", Method: http.MethodDelete, Path: "/tenants/{tenant}/groups/{group}",
		DefaultStatus: http.StatusNoContent, Summary: "Delete a group (memberships, nesting and its assignments)", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			GroupRef
			ManagedBy
			IfMatch
		}) (*struct{}, error) {
			v, err := in.Version()
			if err != nil {
				return nil, err
			}
			sc, g, err := d.groupFor(ctx, in.Tenant, in.Group)
			if err != nil {
				return nil, err
			}
			if err := d.mayGrantGroup(ctx, sc, g.ID); err != nil {
				return nil, err
			}
			if err := d.Authz.DeleteGroup(ctx, change(ctx, in.ManagedBy.ManagedBy), sc, g.ID, v); err != nil {
				return nil, d.fail("delete-group", err)
			}
			return &struct{}{}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "add-group-member", Method: http.MethodPut, Path: "/tenants/{tenant}/groups/{group}/members/{user}",
		DefaultStatus: http.StatusNoContent, Summary: "Add a tenant member to a group (delegated administrators may only confer what they hold)",
		Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *GroupMemberRef) (*struct{}, error) {
			sc, g, err := d.groupFor(ctx, in.Tenant, in.Group)
			if err != nil {
				return nil, err
			}
			if err := d.mayGrantGroup(ctx, sc, g.ID); err != nil {
				return nil, err
			}
			if err := d.Authz.AddGroupMember(ctx, change(ctx, ""), sc, g.ID, in.User, ""); err != nil {
				return nil, d.fail("add-group-member", err)
			}
			return &struct{}{}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "remove-group-member", Method: http.MethodDelete, Path: "/tenants/{tenant}/groups/{group}/members/{user}",
		DefaultStatus: http.StatusNoContent, Summary: "Remove a user from a group", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *GroupMemberRef) (*struct{}, error) {
			sc, g, err := d.groupFor(ctx, in.Tenant, in.Group)
			if err != nil {
				return nil, err
			}
			if err := d.mayGrantGroup(ctx, sc, g.ID); err != nil {
				return nil, err
			}
			if err := d.Authz.RemoveGroupMember(ctx, change(ctx, ""), sc, g.ID, in.User); err != nil {
				return nil, d.fail("remove-group-member", err)
			}
			return &struct{}{}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "nest-group", Method: http.MethodPut, Path: "/tenants/{tenant}/groups/{group}/parents/{parent}",
		DefaultStatus: http.StatusNoContent, Summary: "Make a group a member of a parent group (DAG, depth ≤ 5)", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *ParentRef) (*struct{}, error) {
			sc, child, err := d.groupFor(ctx, in.Tenant, in.Group)
			if err != nil {
				return nil, err
			}
			parent, err := d.Authz.GetGroup(ctx, sc, in.Parent)
			if err != nil {
				return nil, d.fail("nest-group", err)
			}
			if err := d.mayGrantGroup(ctx, sc, parent.ID); err != nil {
				return nil, err
			}
			if err := d.Authz.NestGroup(ctx, change(ctx, ""), sc, parent.ID, child.ID); err != nil {
				return nil, d.fail("nest-group", err)
			}
			return &struct{}{}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "unnest-group", Method: http.MethodDelete, Path: "/tenants/{tenant}/groups/{group}/parents/{parent}",
		DefaultStatus: http.StatusNoContent, Summary: "Remove a group from a parent group", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *ParentRef) (*struct{}, error) {
			sc, child, err := d.groupFor(ctx, in.Tenant, in.Group)
			if err != nil {
				return nil, err
			}
			parent, err := d.Authz.GetGroup(ctx, sc, in.Parent)
			if err != nil {
				return nil, d.fail("unnest-group", err)
			}
			if err := d.mayGrantGroup(ctx, sc, parent.ID); err != nil {
				return nil, err
			}
			if err := d.Authz.UnnestGroup(ctx, change(ctx, ""), sc, parent.ID, child.ID); err != nil {
				return nil, d.fail("unnest-group", err)
			}
			return &struct{}{}, nil
		})
}

func (d *Deps) groupFor(ctx context.Context, tenant, ref string) (tenancy.Scope, authz.Group, error) {
	sc, err := d.tenantAdmin(ctx, tenant, authz.PermGroupManage)
	if err != nil {
		return sc, authz.Group{}, err
	}
	g, err := d.Authz.GetGroup(ctx, sc, ref)
	if err != nil {
		return sc, g, d.fail("group", err)
	}
	return sc, g, nil
}

func registerResources(api huma.API, d *Deps) {
	tags := []string{"authz"}
	huma.Register(api, huma.Operation{OperationID: "list-resources", Method: http.MethodGet, Path: "/tenants/{tenant}/resources",
		Summary: "Resources of a tenant (assignment scopes; parents form a hierarchy)", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *TenantRef) (*struct{ Body []authz.ResourceDef }, error) {
			sc, err := d.tenantAdmin(ctx, in.Tenant, authz.PermResourceManage)
			if err != nil {
				return nil, err
			}
			rs, err := d.Authz.Resources(ctx, sc)
			if err != nil {
				return nil, d.fail("list-resources", err)
			}
			return &struct{ Body []authz.ResourceDef }{Body: rs}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "create-resource", Method: http.MethodPost, Path: "/tenants/{tenant}/resources",
		DefaultStatus: http.StatusCreated, Summary: "Create a resource", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			TenantRef
			ManagedBy
			Body ResourceRequest
		}) (*withETag[authz.ResourceDef], error) {
			sc, err := d.tenantAdmin(ctx, in.Tenant, authz.PermResourceManage)
			if err != nil {
				return nil, err
			}
			b := in.Body
			r, err := d.Authz.CreateResource(ctx, change(ctx, in.ManagedBy.ManagedBy), sc, authz.ResourceParams{Type: b.Type, Slug: b.Slug, Name: b.Name,
				ParentID: b.ParentID, Attributes: b.Attributes})
			if err != nil {
				return nil, d.fail("create-resource", err)
			}
			return tagged(r.Version, r), nil
		})
	huma.Register(api, huma.Operation{OperationID: "get-resource", Method: http.MethodGet, Path: "/tenants/{tenant}/resources/{resource}",
		Summary: "Get a resource", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *ResourceRef) (*withETag[authz.ResourceDef], error) {
			sc, err := d.tenantAdmin(ctx, in.Tenant, authz.PermResourceManage)
			if err != nil {
				return nil, err
			}
			r, err := d.Authz.GetResource(ctx, sc, in.Resource)
			if err != nil {
				return nil, d.fail("get-resource", err)
			}
			return tagged(r.Version, r), nil
		})
	huma.Register(api, huma.Operation{OperationID: "update-resource", Method: http.MethodPatch, Path: "/tenants/{tenant}/resources/{resource}",
		Summary: "Rename a resource or replace its attributes", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			ResourceRef
			ManagedBy
			IfMatch
			Body ResourceUpdate
		}) (*withETag[authz.ResourceDef], error) {
			sc, err := d.tenantAdmin(ctx, in.Tenant, authz.PermResourceManage)
			if err != nil {
				return nil, err
			}
			v, err := in.Version()
			if err != nil {
				return nil, err
			}
			r, err := d.Authz.UpdateResource(ctx, change(ctx, in.ManagedBy.ManagedBy), sc, in.Resource, authz.ResourceParams{Name: in.Body.Name,
				Attributes: in.Body.Attributes, IfVersion: v})
			if err != nil {
				return nil, d.fail("update-resource", err)
			}
			return tagged(r.Version, r), nil
		})
	huma.Register(api, huma.Operation{OperationID: "delete-resource", Method: http.MethodDelete, Path: "/tenants/{tenant}/resources/{resource}",
		DefaultStatus: http.StatusNoContent, Summary: "Delete a resource, its children and assignments scoped to it", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			ResourceRef
			ManagedBy
			IfMatch
		}) (*struct{}, error) {
			v, err := in.Version()
			if err != nil {
				return nil, err
			}
			sc, err := d.tenantAdmin(ctx, in.Tenant, authz.PermResourceManage)
			if err != nil {
				return nil, err
			}
			// Deleting a resource removes the assignments scoped to it and its descendants.
			if err := d.mayRemoveResource(ctx, sc, in.Resource); err != nil {
				return nil, err
			}
			if err := d.Authz.DeleteResource(ctx, change(ctx, in.ManagedBy.ManagedBy), sc, in.Resource, v); err != nil {
				return nil, d.fail("delete-resource", err)
			}
			return &struct{}{}, nil
		})
}

// mayRemoveResource checks the permissions of every assignment scoped to a resource or one of its descendants.
func (d *Deps) mayRemoveResource(ctx context.Context, sc tenancy.Scope, id string) error {
	if exempt(ctx, sc) {
		return nil
	}
	rs, err := d.Authz.Resources(ctx, sc)
	if err != nil {
		return d.fail("escalation", err)
	}
	doomed := map[string]bool{id: true}
	for changed := true; changed; {
		changed = false
		for _, r := range rs {
			if !doomed[r.ID] && doomed[r.ParentID] {
				doomed[r.ID], changed = true, true
			}
		}
	}
	as, err := d.Authz.Assignments(ctx, sc)
	if err != nil {
		return d.fail("escalation", err)
	}
	var perms []string
	for _, a := range as {
		if a.ScopeType == "resource" && doomed[a.ScopeResourceID] {
			ps, err := d.Engine.RolePermissions(ctx, sc.TenantID(), a.RoleID)
			if err != nil {
				return d.fail("escalation", err)
			}
			perms = append(perms, ps...)
		}
	}
	return d.mayGrant(ctx, sc, perms)
}

func registerPolicies(api huma.API, d *Deps) {
	tags := []string{"authz"}
	huma.Register(api, huma.Operation{OperationID: "validate-policy", Method: http.MethodPost, Path: "/tenants/{tenant}/policies/validate",
		Summary: "Compile an expression against the policy environment without saving it", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			TenantRef
			Body PolicyValidateRequest
		}) (*struct{ Body PolicyValidation }, error) {
			if _, err := d.tenantAdmin(ctx, in.Tenant, authz.PermPolicyManage); err != nil {
				return nil, err
			}
			out := PolicyValidation{Valid: true}
			if _, err := authz.Compile(in.Body.Expression); err != nil {
				out = PolicyValidation{Error: strings.TrimPrefix(err.Error(), authz.ErrPolicy.Error()+": ")}
			}
			return &struct{ Body PolicyValidation }{Body: out}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "list-policies", Method: http.MethodGet, Path: "/tenants/{tenant}/policies",
		Summary: "Policies of a tenant", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *TenantRef) (*struct{ Body []authz.PolicyDef }, error) {
			sc, err := d.tenantAdmin(ctx, in.Tenant, authz.PermPolicyManage)
			if err != nil {
				return nil, err
			}
			ps, err := d.Authz.Policies(ctx, sc)
			if err != nil {
				return nil, d.fail("list-policies", err)
			}
			return &struct{ Body []authz.PolicyDef }{Body: ps}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "create-policy", Method: http.MethodPost, Path: "/tenants/{tenant}/policies",
		DefaultStatus: http.StatusCreated, Summary: "Create a policy (needs a recent sign-in)", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			TenantRef
			ManagedBy
			Body PolicyRequest
		}) (*withETag[authz.PolicyDef], error) {
			sc, err := d.tenantAdmin(ctx, in.Tenant, authz.PermPolicyManage)
			if err != nil {
				return nil, err
			}
			if err := d.stepUp(ctx); err != nil {
				return nil, err
			}
			b := in.Body
			if err := d.mayGrant(ctx, sc, denyPerms(b.Effect, b.Actions)); err != nil {
				return nil, err
			}
			pol, err := d.Authz.CreatePolicy(ctx, change(ctx, in.ManagedBy.ManagedBy), sc, authz.PolicyParams{Slug: b.Slug, Name: b.Name,
				Effect: b.Effect, Expression: b.Expression, Actions: b.Actions})
			if err != nil {
				return nil, d.fail("create-policy", err)
			}
			return tagged(pol.Version, pol), nil
		})
	huma.Register(api, huma.Operation{OperationID: "get-policy", Method: http.MethodGet, Path: "/tenants/{tenant}/policies/{policy}",
		Summary: "Get a policy", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *PolicyRef) (*withETag[authz.PolicyDef], error) {
			sc, err := d.tenantAdmin(ctx, in.Tenant, authz.PermPolicyManage)
			if err != nil {
				return nil, err
			}
			pol, err := d.Authz.GetPolicy(ctx, sc, in.Policy)
			if err != nil {
				return nil, d.fail("get-policy", err)
			}
			return tagged(pol.Version, pol), nil
		})
	huma.Register(api, huma.Operation{OperationID: "update-policy", Method: http.MethodPut, Path: "/tenants/{tenant}/policies/{policy}",
		Summary: "Replace a policy (needs a recent sign-in)", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			PolicyRef
			ManagedBy
			IfMatch
			Body PolicyRequest
		}) (*withETag[authz.PolicyDef], error) {
			sc, cur, err := d.policyChange(ctx, in.Tenant, in.Policy)
			if err != nil {
				return nil, err
			}
			v, err := in.Version()
			if err != nil {
				return nil, err
			}
			b := in.Body
			if err := d.mayGrant(ctx, sc, denyPerms(b.Effect, b.Actions)); err != nil {
				return nil, err
			}
			pol, err := d.Authz.UpdatePolicy(ctx, change(ctx, in.ManagedBy.ManagedBy), sc, cur.ID, authz.PolicyParams{Name: b.Name, Effect: b.Effect,
				Expression: b.Expression, Actions: b.Actions, IfVersion: v})
			if err != nil {
				return nil, d.fail("update-policy", err)
			}
			return tagged(pol.Version, pol), nil
		})
	huma.Register(api, huma.Operation{OperationID: "delete-policy", Method: http.MethodDelete, Path: "/tenants/{tenant}/policies/{policy}",
		DefaultStatus: http.StatusNoContent, Summary: "Delete a policy and the conditional assignments using it (needs a recent sign-in)",
		Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			PolicyRef
			ManagedBy
			IfMatch
		}) (*struct{}, error) {
			v, err := in.Version()
			if err != nil {
				return nil, err
			}
			sc, cur, err := d.policyChange(ctx, in.Tenant, in.Policy)
			if err != nil {
				return nil, err
			}
			if err := d.Authz.DeletePolicy(ctx, change(ctx, in.ManagedBy.ManagedBy), sc, cur.ID, v); err != nil {
				return nil, d.fail("delete-policy", err)
			}
			return &struct{}{}, nil
		})
}

// denyPerms is what a deny policy restricts: a delegated administrator may only deny what they hold, so they cannot
// lock out administrators above them.
func denyPerms(effect string, actions []string) []string {
	if effect != "deny" {
		return nil
	}
	out := make([]string, 0, len(actions))
	for _, a := range actions {
		if a == "*" {
			a = "*:*"
		}
		out = append(out, a)
	}
	return out
}

// policyChange authorizes changing or deleting an existing policy. Loosening a condition widens every assignment that
// references it, and removing a deny lifts its restriction, so the caller must hold all of those permissions.
func (d *Deps) policyChange(ctx context.Context, tenant, ref string) (tenancy.Scope, authz.PolicyDef, error) {
	sc, err := d.tenantAdmin(ctx, tenant, authz.PermPolicyManage)
	if err != nil {
		return sc, authz.PolicyDef{}, err
	}
	if err := d.stepUp(ctx); err != nil {
		return sc, authz.PolicyDef{}, err
	}
	cur, err := d.Authz.GetPolicy(ctx, sc, ref)
	if err != nil {
		return sc, cur, d.fail("policy", err)
	}
	if exempt(ctx, sc) {
		return sc, cur, nil
	}
	perms := denyPerms(cur.Effect, cur.Actions)
	if cur.Effect == "condition" {
		as, err := d.Authz.Assignments(ctx, sc)
		if err != nil {
			return sc, cur, d.fail("policy", err)
		}
		for _, a := range as {
			if a.ConditionPolicyID != cur.ID {
				continue
			}
			ps, err := d.Engine.RolePermissions(ctx, sc.TenantID(), a.RoleID)
			if err != nil {
				return sc, cur, d.fail("policy", err)
			}
			perms = append(perms, ps...)
		}
	}
	return sc, cur, d.mayGrant(ctx, sc, perms)
}

func registerAssignments(api huma.API, d *Deps) {
	tags := []string{"authz"}
	huma.Register(api, huma.Operation{OperationID: "list-assignments", Method: http.MethodGet, Path: "/tenants/{tenant}/assignments",
		Summary: "Role assignments of a tenant", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			TenantRef
			SubjectType string `query:"subject_type" enum:"user,group,service_account" required:"false"`
			SubjectID   string `query:"subject_id" maxLength:"64" required:"false"`
			RoleID      string `query:"role_id" maxLength:"64" required:"false"`
		}) (*struct{ Body []authz.Assignment }, error) {
			sc, err := d.tenantAdmin(ctx, in.Tenant, authz.PermRoleManage)
			if err != nil {
				return nil, err
			}
			as, err := d.Authz.Assignments(ctx, sc)
			if err != nil {
				return nil, d.fail("list-assignments", err)
			}
			out := make([]authz.Assignment, 0, len(as))
			for _, a := range as {
				if (in.SubjectType == "" || a.SubjectType == in.SubjectType) && (in.SubjectID == "" || a.SubjectID == in.SubjectID) &&
					(in.RoleID == "" || a.RoleID == in.RoleID) {
					out = append(out, a)
				}
			}
			return &struct{ Body []authz.Assignment }{Body: out}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "create-assignment", Method: http.MethodPost, Path: "/tenants/{tenant}/assignments",
		DefaultStatus: http.StatusCreated, Summary: "Assign a role (delegated administrators may only grant roles whose permissions they hold)",
		Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			TenantRef
			ManagedBy
			Body AssignmentRequest
		}) (*struct{ Body authz.Assignment }, error) {
			sc, err := d.tenantAdmin(ctx, in.Tenant, authz.PermRoleManage)
			if err != nil {
				return nil, err
			}
			b := in.Body
			role, err := d.Authz.GetRole(ctx, sc, b.RoleID)
			if err != nil {
				return nil, d.fail("create-assignment", err)
			}
			if err := d.mayGrantRole(ctx, sc, role.ID); err != nil {
				return nil, err
			}
			p := authz.AssignmentParams{SubjectType: b.SubjectType, SubjectID: b.SubjectID, RoleID: role.ID, ScopeType: b.ScopeType,
				ScopeResourceType: b.ScopeResourceType, ScopeResourceID: b.ScopeResourceID, ConditionPolicyID: b.ConditionPolicyID}
			if b.ExpiresAt != nil {
				p.ExpiresAt = b.ExpiresAt
			}
			a, err := d.Authz.Assign(ctx, change(ctx, in.ManagedBy.ManagedBy), sc, p)
			if err != nil {
				return nil, d.fail("create-assignment", err)
			}
			return &struct{ Body authz.Assignment }{Body: a}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "delete-assignment", Method: http.MethodDelete, Path: "/tenants/{tenant}/assignments/{assignment}",
		DefaultStatus: http.StatusNoContent, Summary: "Remove a role assignment", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			TenantRef
			Assignment string `path:"assignment" maxLength:"64"`
		}) (*struct{}, error) {
			sc, err := d.tenantAdmin(ctx, in.Tenant, authz.PermRoleManage)
			if err != nil {
				return nil, err
			}
			a, err := d.Authz.GetAssignment(ctx, sc, in.Assignment)
			if err != nil {
				return nil, d.fail("delete-assignment", err)
			}
			if err := d.mayGrantRole(ctx, sc, a.RoleID); err != nil {
				return nil, err
			}
			if err := d.Authz.Unassign(ctx, change(ctx, ""), sc, a.ID); err != nil {
				return nil, d.fail("delete-assignment", err)
			}
			return &struct{}{}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "effective-permissions", Method: http.MethodGet, Path: "/tenants/{tenant}/authz/effective",
		Summary: "Every grant reaching a subject and how (conditions are reported, not evaluated)", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			TenantRef
			SubjectType string `query:"subject_type" enum:"user,service_account" required:"true"`
			SubjectID   string `query:"subject_id" minLength:"1" maxLength:"64" required:"true"`
		}) (*struct{ Body []authz.EffectiveGrant }, error) {
			sc, err := d.tenantAdmin(ctx, in.Tenant, authz.PermRoleManage)
			if err != nil {
				return nil, err
			}
			gs, err := d.Engine.Effective(ctx, sc.TenantID(), in.SubjectType, in.SubjectID)
			if err != nil {
				return nil, d.fail("effective", err)
			}
			if gs == nil {
				gs = []authz.EffectiveGrant{}
			}
			return &struct{ Body []authz.EffectiveGrant }{Body: gs}, nil
		})
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

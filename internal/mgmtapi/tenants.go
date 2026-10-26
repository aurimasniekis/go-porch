package mgmtapi

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/aurimasniekis/go-porch/internal/apperr"
	"github.com/aurimasniekis/go-porch/internal/authz"
	"github.com/aurimasniekis/go-porch/internal/identity"
	"github.com/aurimasniekis/go-porch/internal/tenancy"
)

// Tenant is the API representation of a tenant.
type Tenant struct {
	ID                     string    `json:"id"`
	Slug                   string    `json:"slug"`
	Name                   string    `json:"name"`
	Status                 string    `json:"status" enum:"active,disabled"`
	SessionIdleSeconds     int64     `json:"session_idle_seconds,omitempty" doc:"Shortens members' idle timeout (0 = installation default; the strictest tenant of a member wins)."`
	SessionAbsoluteSeconds int64     `json:"session_absolute_seconds,omitempty" doc:"Shortens members' absolute session lifetime (0 = installation default; the strictest tenant wins)."`
	Version                int64     `json:"version"`
	ManagedBy              string    `json:"managed_by"`
	LastChangedBy          string    `json:"last_changed_by,omitempty"`
	CreatedAt              time.Time `json:"created_at"`
	UpdatedAt              time.Time `json:"updated_at"`
}

func tenantDTO(t tenancy.Tenant) Tenant {
	out := Tenant{ID: t.ID, Slug: t.Slug, Name: t.Name, Status: t.Status, Version: t.Version, ManagedBy: t.ManagedBy,
		LastChangedBy: t.LastChangedBy, CreatedAt: t.CreatedAt, UpdatedAt: t.UpdatedAt}
	if t.SessionIdle != nil {
		out.SessionIdleSeconds = int64(*t.SessionIdle / time.Second)
	}
	if t.SessionAbsolute != nil {
		out.SessionAbsoluteSeconds = int64(*t.SessionAbsolute / time.Second)
	}
	return out
}

type tenantOutput struct {
	ETag string `header:"ETag"`
	Body Tenant
}

// TenantList is one page of tenants.
type TenantList struct {
	Items      []Tenant `json:"items"`
	NextCursor string   `json:"next_cursor,omitempty"`
}

type TenantRef struct {
	Tenant string `path:"tenant" maxLength:"64" doc:"Tenant ID or slug."`
}

// operatorScope resolves a tenant for an installation owner/admin.
func (d *Deps) operatorScope(ctx context.Context, ref string) (tenancy.Scope, error) {
	p, err := requireOperator(ctx, identity.RoleOwner, identity.RoleAdmin)
	if err != nil {
		return tenancy.Scope{}, err
	}
	sc, err := d.Tenants.ResolveForOperator(ctx, p.UserID, ref)
	if err != nil {
		return sc, d.fail("tenant-scope", err)
	}
	return sc, nil
}

// CreateTenantRequest is the request body of the operation.
type CreateTenantRequest struct {
	Slug string `json:"slug" minLength:"2" maxLength:"63" pattern:"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"`
	Name string `json:"name" minLength:"1" maxLength:"200"`
}

// UpdateTenantRequest is the request body of the operation.
type UpdateTenantRequest struct {
	Name                   *string `json:"name,omitempty" minLength:"1" maxLength:"200"`
	Status                 *string `json:"status,omitempty" enum:"active,disabled"`
	SessionIdleSeconds     *int64  `json:"session_idle_seconds,omitempty" minimum:"0"`
	SessionAbsoluteSeconds *int64  `json:"session_absolute_seconds,omitempty" minimum:"0"`
}

func registerTenants(api huma.API, d *Deps) {
	tags := []string{"tenants"}
	huma.Register(api, huma.Operation{OperationID: "list-tenants", Method: http.MethodGet, Path: "/tenants", Summary: "List tenants",
		Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct{ Pagination }) (*struct{ Body TenantList }, error) {
			if _, err := requireOperator(ctx, identity.RoleOwner, identity.RoleAdmin, identity.RoleAuditor, identity.RoleInspector); err != nil {
				return nil, err
			}
			page, err := in.Page()
			if err != nil {
				return nil, err
			}
			ts, next, err := d.Tenants.List(ctx, page)
			if err != nil {
				return nil, d.fail("list-tenants", err)
			}
			out := TenantList{Items: make([]Tenant, 0, len(ts)), NextCursor: next}
			for _, t := range ts {
				out.Items = append(out.Items, tenantDTO(t))
			}
			return &struct{ Body TenantList }{Body: out}, nil
		})

	type createInput struct {
		ManagedBy
		Body CreateTenantRequest
	}
	huma.Register(api, huma.Operation{OperationID: "create-tenant", Method: http.MethodPost, Path: "/tenants", DefaultStatus: http.StatusCreated,
		Summary: "Create a tenant", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *createInput) (*tenantOutput, error) {
			if _, err := requireOperator(ctx, identity.RoleOwner, identity.RoleAdmin); err != nil {
				return nil, err
			}
			t, err := d.Tenants.Create(ctx, change(ctx, in.ManagedBy.ManagedBy), tenancy.CreateParams{Slug: in.Body.Slug, Name: in.Body.Name})
			if err != nil {
				return nil, d.fail("create-tenant", err)
			}
			return &tenantOutput{ETag: etag(t.Version), Body: tenantDTO(t)}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "get-tenant", Method: http.MethodGet, Path: "/tenants/{tenant}", Summary: "Get a tenant",
		Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *TenantRef) (*tenantOutput, error) {
			sc, err := d.tenantReader(ctx, in.Tenant, authz.PermTenantRead, authz.PermTenantManage)
			if err != nil {
				return nil, err
			}
			t, err := d.Tenants.Get(ctx, sc)
			if err != nil {
				return nil, d.fail("get-tenant", err)
			}
			return &tenantOutput{ETag: etag(t.Version), Body: tenantDTO(t)}, nil
		})

	type updateInput struct {
		TenantRef
		ManagedBy
		IfMatch
		Body UpdateTenantRequest
	}
	huma.Register(api, huma.Operation{OperationID: "update-tenant", Method: http.MethodPatch, Path: "/tenants/{tenant}", Summary: "Update a tenant",
		Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *updateInput) (*tenantOutput, error) {
			sc, err := d.tenantAdmin(ctx, in.Tenant, authz.PermTenantManage)
			if err != nil {
				return nil, err
			}
			if in.Body.Status != nil && sc.Via() != tenancy.ViaOperator {
				return nil, problem(http.StatusForbidden, apperr.CodeForbidden, "only installation operators can enable or disable tenants", nil)
			}
			v, err := in.Version()
			if err != nil {
				return nil, err
			}
			p := tenancy.UpdateParams{Name: in.Body.Name, Status: in.Body.Status, IfVersion: v}
			if in.Body.SessionIdleSeconds != nil {
				dd := time.Duration(*in.Body.SessionIdleSeconds) * time.Second
				p.SessionIdle = &dd
			}
			if in.Body.SessionAbsoluteSeconds != nil {
				dd := time.Duration(*in.Body.SessionAbsoluteSeconds) * time.Second
				p.SessionAbsolute = &dd
			}
			t, err := d.Tenants.Update(ctx, change(ctx, in.ManagedBy.ManagedBy), sc, p)
			if err != nil {
				return nil, d.fail("update-tenant", err)
			}
			return &tenantOutput{ETag: etag(t.Version), Body: tenantDTO(t)}, nil
		})

	type deleteInput struct {
		TenantRef
		ManagedBy
		IfMatch
	}
	huma.Register(api, huma.Operation{OperationID: "delete-tenant", Method: http.MethodDelete, Path: "/tenants/{tenant}",
		DefaultStatus: http.StatusNoContent, Summary: "Delete a tenant and everything it owns", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *deleteInput) (*struct{}, error) {
			sc, err := d.operatorScope(ctx, in.Tenant)
			if err != nil {
				return nil, err
			}
			v, err := in.Version()
			if err != nil {
				return nil, err
			}
			if err := d.Tenants.Delete(ctx, change(ctx, in.ManagedBy.ManagedBy), sc, v); err != nil {
				return nil, d.fail("delete-tenant", err)
			}
			return &struct{}{}, nil
		})
}

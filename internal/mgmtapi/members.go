package mgmtapi

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/aurimasniekis/go-porch/internal/authz"
	"github.com/aurimasniekis/go-porch/internal/tenancy"
)

// Member is a tenant membership.
type Member struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	UserID        string    `json:"user_id"`
	DisplayName   string    `json:"display_name,omitempty"`
	Email         string    `json:"email,omitempty"`
	Status        string    `json:"status" enum:"active,suspended"`
	Source        string    `json:"source" doc:"manual, terraform, setup, domain_rule:<id>, dirsync:<id>"`
	Version       int64     `json:"version"`
	ManagedBy     string    `json:"managed_by"`
	LastChangedBy string    `json:"last_changed_by,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func memberDTO(m tenancy.Membership) Member {
	return Member{ID: m.ID, TenantID: m.TenantID, UserID: m.UserID, DisplayName: m.DisplayName, Email: m.Email, Status: m.Status,
		Source: m.Source, Version: m.Version, ManagedBy: m.ManagedBy, LastChangedBy: m.LastChangedBy, CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt}
}

type memberOutput struct {
	ETag string `header:"ETag"`
	Body Member
}

// MemberList is one page of members.
type MemberList struct {
	Items      []Member `json:"items"`
	NextCursor string   `json:"next_cursor,omitempty"`
}

type MemberRef struct {
	TenantRef
	Member string `path:"member" maxLength:"64" doc:"Membership ID."`
}

// AddMemberRequest is the request body of the operation.
type AddMemberRequest struct {
	UserID string `json:"user_id" minLength:"1" maxLength:"64"`
}

// UpdateMemberRequest is the request body of the operation.
type UpdateMemberRequest struct {
	Status string `json:"status" enum:"active,suspended"`
}

func registerMembers(api huma.API, d *Deps) {
	tags := []string{"members"}
	type listInput struct {
		TenantRef
		Pagination
	}
	huma.Register(api, huma.Operation{OperationID: "list-members", Method: http.MethodGet, Path: "/tenants/{tenant}/members",
		Summary: "List tenant members (member, group or role managers)", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *listInput) (*struct{ Body MemberList }, error) {
			sc, err := d.tenantAdminAny(ctx, in.Tenant, authz.PermMemberManage, authz.PermGroupManage, authz.PermRoleManage)
			if err != nil {
				return nil, err
			}
			page, err := in.Page()
			if err != nil {
				return nil, err
			}
			ms, next, err := d.Tenants.ListMembers(ctx, sc, page)
			if err != nil {
				return nil, d.fail("list-members", err)
			}
			out := MemberList{Items: make([]Member, 0, len(ms)), NextCursor: next}
			for _, m := range ms {
				out.Items = append(out.Items, memberDTO(m))
			}
			return &struct{ Body MemberList }{Body: out}, nil
		})

	type addInput struct {
		TenantRef
		ManagedBy
		Body AddMemberRequest
	}
	huma.Register(api, huma.Operation{OperationID: "add-member", Method: http.MethodPost, Path: "/tenants/{tenant}/members",
		DefaultStatus: http.StatusCreated, Summary: "Add a user to a tenant", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *addInput) (*memberOutput, error) {
			sc, err := d.tenantAdmin(ctx, in.Tenant, authz.PermMemberManage)
			if err != nil {
				return nil, err
			}
			ch := change(ctx, in.ManagedBy.ManagedBy)
			source := tenancy.SourceManual
			if ch.Managed() == "terraform" {
				source = tenancy.SourceTerraform
			}
			m, err := d.Tenants.AddMember(ctx, ch, sc, in.Body.UserID, source)
			if err != nil {
				return nil, d.fail("add-member", err)
			}
			return &memberOutput{ETag: etag(m.Version), Body: memberDTO(m)}, nil
		})

	type updateInput struct {
		MemberRef
		ManagedBy
		IfMatch
		Body UpdateMemberRequest
	}
	huma.Register(api, huma.Operation{OperationID: "update-member", Method: http.MethodPatch, Path: "/tenants/{tenant}/members/{member}",
		Summary: "Suspend or reactivate a membership", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *updateInput) (*memberOutput, error) {
			sc, err := d.tenantAdmin(ctx, in.Tenant, authz.PermMemberManage)
			if err != nil {
				return nil, err
			}
			v, err := in.Version()
			if err != nil {
				return nil, err
			}
			m, err := d.Tenants.SetMemberStatus(ctx, change(ctx, in.ManagedBy.ManagedBy), sc, in.Member, in.Body.Status, v)
			if err != nil {
				return nil, d.fail("update-member", err)
			}
			return &memberOutput{ETag: etag(m.Version), Body: memberDTO(m)}, nil
		})

	type deleteInput struct {
		MemberRef
		ManagedBy
		IfMatch
	}
	huma.Register(api, huma.Operation{OperationID: "remove-member", Method: http.MethodDelete, Path: "/tenants/{tenant}/members/{member}",
		DefaultStatus: http.StatusNoContent, Summary: "Remove a user from a tenant", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *deleteInput) (*struct{}, error) {
			sc, err := d.tenantAdmin(ctx, in.Tenant, authz.PermMemberManage)
			if err != nil {
				return nil, err
			}
			v, err := in.Version()
			if err != nil {
				return nil, err
			}
			if err := d.Tenants.RemoveMember(ctx, change(ctx, in.ManagedBy.ManagedBy), sc, in.Member, v); err != nil {
				return nil, d.fail("remove-member", err)
			}
			return &struct{}{}, nil
		})
}

package mgmtapi

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/aurimasniekis/go-porch/internal/apperr"
	"github.com/aurimasniekis/go-porch/internal/authz"
	"github.com/aurimasniekis/go-porch/internal/identity"
)

// Single-object reads for objects that previously only had list endpoints (import and refresh in Terraform).
func registerLookups(api huma.API, d *Deps) {
	huma.Register(api, huma.Operation{OperationID: "get-identity-provider", Method: http.MethodGet, Path: "/identity-providers/{provider}",
		Summary: "Get an identity provider", Tags: []string{"identity-providers"}, Security: sessionSecurity},
		func(ctx context.Context, in *ProviderRef) (*providerOutput, error) {
			if _, err := requireOperator(ctx, identity.RoleOwner, identity.RoleAdmin, identity.RoleAuditor, identity.RoleInspector); err != nil {
				return nil, err
			}
			p, err := d.IDP.Provider(ctx, d.providerID(ctx, in.Provider))
			if err != nil {
				return nil, d.fail("get-provider", err)
			}
			return &providerOutput{ETag: etag(p.Version), Body: d.providerDTO(p)}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "get-domain-rule", Method: http.MethodGet, Path: "/tenants/{tenant}/domain-rules/{rule}",
		Summary: "Get a domain rule (by ID or domain)", Tags: []string{"enrollment"}, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			TenantRef
			Rule string `path:"rule" maxLength:"253"`
		}) (*struct {
			ETag string `header:"ETag"`
			Body DomainRule
		}, error) {
			sc, err := d.tenantReader(ctx, in.Tenant)
			if err != nil {
				return nil, err
			}
			rs, err := d.IDP.Rules(ctx, sc)
			if err != nil {
				return nil, d.fail("get-rule", err)
			}
			for _, r := range rs {
				if r.ID == in.Rule || r.Domain == in.Rule {
					return &struct {
						ETag string `header:"ETag"`
						Body DomainRule
					}{ETag: etag(r.Version), Body: ruleDTO(r)}, nil
				}
			}
			return nil, problem(http.StatusNotFound, apperr.CodeNotFound, "domain rule not found", nil)
		})
	huma.Register(api, huma.Operation{OperationID: "get-invite", Method: http.MethodGet, Path: "/tenants/{tenant}/invites/{invite}",
		Summary: "Get an invitation", Tags: []string{"enrollment"}, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			TenantRef
			Invite string `path:"invite" maxLength:"64"`
		}) (*struct{ Body Invite }, error) {
			sc, err := d.tenantReader(ctx, in.Tenant, authz.PermInviteRead, authz.PermInviteManage)
			if err != nil {
				return nil, err
			}
			is, err := d.IDP.Invites(ctx, sc)
			if err != nil {
				return nil, d.fail("get-invite", err)
			}
			for _, i := range is {
				if i.ID == in.Invite {
					return &struct{ Body Invite }{Body: Invite{ID: i.ID, TenantID: i.TenantID, Email: i.Email, CreatedAt: i.CreatedAt,
						ExpiresAt: i.ExpiresAt, ConsumedAt: i.ConsumedAt}}, nil
				}
			}
			return nil, problem(http.StatusNotFound, apperr.CodeNotFound, "invitation not found", nil)
		})
	huma.Register(api, huma.Operation{OperationID: "get-member", Method: http.MethodGet, Path: "/tenants/{tenant}/members/{member}",
		Summary: "Get a membership (by membership ID or user ID)", Tags: []string{"members"}, Security: sessionSecurity},
		func(ctx context.Context, in *MemberRef) (*memberOutput, error) {
			sc, err := d.tenantReader(ctx, in.Tenant, authz.PermMemberRead, authz.PermMemberManage, authz.PermGroupManage, authz.PermRoleManage)
			if err != nil {
				return nil, err
			}
			m, err := d.Tenants.GetMember(ctx, sc, in.Member)
			if err != nil {
				return nil, d.fail("get-member", err)
			}
			return &memberOutput{ETag: etag(m.Version), Body: memberDTO(m)}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "get-assignment", Method: http.MethodGet, Path: "/tenants/{tenant}/assignments/{assignment}",
		Summary: "Get a role assignment", Tags: []string{"authz"}, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			TenantRef
			Assignment string `path:"assignment" maxLength:"64"`
		}) (*struct{ Body authz.Assignment }, error) {
			sc, err := d.tenantReader(ctx, in.Tenant, authz.PermRoleRead, authz.PermRoleManage)
			if err != nil {
				return nil, err
			}
			a, err := d.Authz.GetAssignment(ctx, sc, in.Assignment)
			if err != nil {
				return nil, d.fail("get-assignment", err)
			}
			return &struct{ Body authz.Assignment }{Body: a}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "get-application-share", Method: http.MethodGet, Path: "/tenants/{tenant}/applications/{app}/shares/{target}",
		Summary: "Get one share of an application (target tenant ID or slug)", Tags: []string{"applications"}, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			AppRef
			Target string `path:"target" maxLength:"64"`
		}) (*struct{ Body AppShare }, error) {
			sc, err := d.tenantReader(ctx, in.Tenant)
			if err != nil {
				return nil, err
			}
			ss, err := d.Apps.Shares(ctx, sc, in.App)
			if err != nil {
				return nil, d.fail("get-share", err)
			}
			for _, x := range ss {
				if x.TenantID == in.Target || x.TenantSlug == in.Target {
					return &struct{ Body AppShare }{Body: AppShare(x)}, nil
				}
			}
			return nil, problem(http.StatusNotFound, apperr.CodeNotFound, "share not found", nil)
		})
}

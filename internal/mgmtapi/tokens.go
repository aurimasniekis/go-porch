package mgmtapi

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/aurimasniekis/go-porch/internal/apperr"
	"github.com/aurimasniekis/go-porch/internal/authz"
	"github.com/aurimasniekis/go-porch/internal/automation"
	"github.com/aurimasniekis/go-porch/internal/identity"
	"github.com/aurimasniekis/go-porch/internal/tenancy"
)

// InstallationTokenRequest creates an installation automation token.
type InstallationTokenRequest struct {
	Name          string `json:"name" minLength:"1" maxLength:"200"`
	Role          string `json:"role" enum:"admin,auditor" doc:"admin manages every tenant and installation setting; auditor reads."`
	ExpiresInDays int    `json:"expires_in_days,omitempty" minimum:"0" maximum:"366" doc:"1–366; omit when never_expires is set."`
	NeverExpires  bool   `json:"never_expires,omitempty" doc:"Issue a token that never expires and does not depend on the identity provider confirming you (installation owners only, ADR-0046). Revoke it when it is no longer needed."`
}

// TenantTokenRequest creates a tenant automation token.
type TenantTokenRequest struct {
	Name          string   `json:"name" minLength:"1" maxLength:"200"`
	Permissions   []string `json:"permissions" minItems:"1" maxItems:"50" doc:"Tenant permissions; you must hold each of them."`
	ExpiresInDays int      `json:"expires_in_days" minimum:"1" maximum:"366"`
}

// CreatedToken includes the token secret exactly once.
type CreatedToken struct {
	automation.Token
	Secret string `json:"token" doc:"Send as Authorization: Bearer <token>. Shown only in this response."`
}

// TokenRef addresses a token.
type TokenRef struct {
	Token string `path:"token" maxLength:"64"`
}

func registerTokens(api huma.API, d *Deps) {
	tags := []string{"automation"}
	days := func(n int) time.Duration { return time.Duration(n) * 24 * time.Hour }
	huma.Register(api, huma.Operation{OperationID: "list-installation-tokens", Method: http.MethodGet, Path: "/installation/automation-tokens",
		Summary: "Installation automation tokens (owner, admin or auditor)", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*struct{ Body []automation.Token }, error) {
			if _, err := requireOperator(ctx, identity.RoleOwner, identity.RoleAdmin, identity.RoleAuditor); err != nil {
				return nil, err
			}
			ts, err := d.Tokens.List(ctx, "")
			if err != nil {
				return nil, d.fail("list-tokens", err)
			}
			return &struct{ Body []automation.Token }{Body: ts}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "create-installation-token", Method: http.MethodPost, Path: "/installation/automation-tokens",
		DefaultStatus: http.StatusCreated, Summary: "Issue an installation automation token (owner; needs a recent sign-in)", Tags: tags,
		Security: sessionSecurity},
		func(ctx context.Context, in *struct{ Body InstallationTokenRequest }) (*struct{ Body CreatedToken }, error) {
			p, err := requireOperator(ctx, identity.RoleOwner)
			if err != nil {
				return nil, err
			}
			if err := d.stepUp(ctx); err != nil {
				return nil, err
			}
			t, secret, err := d.Tokens.Create(ctx, change(ctx, ""), automation.CreateParams{Name: in.Body.Name, Kind: automation.KindInstallation,
				Role: in.Body.Role, Lifetime: days(in.Body.ExpiresInDays), NeverExpires: in.Body.NeverExpires, CreatedBy: p.UserID})
			if err != nil {
				return nil, d.fail("create-token", err)
			}
			return &struct{ Body CreatedToken }{Body: CreatedToken{Token: t, Secret: secret}}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "revoke-installation-token", Method: http.MethodDelete,
		Path: "/installation/automation-tokens/{token}", DefaultStatus: http.StatusNoContent, Summary: "Revoke an installation automation token (owner)",
		Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *TokenRef) (*struct{}, error) {
			if _, err := requireOperator(ctx, identity.RoleOwner); err != nil {
				return nil, err
			}
			t, err := d.Tokens.Get(ctx, in.Token)
			if err != nil || t.Kind != automation.KindInstallation {
				return nil, d.fail("revoke-token", automation.ErrNotFound)
			}
			if err := d.Tokens.Revoke(ctx, change(ctx, ""), t.ID); err != nil {
				return nil, d.fail("revoke-token", err)
			}
			return &struct{}{}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "list-tenant-tokens", Method: http.MethodGet, Path: "/tenants/{tenant}/automation-tokens",
		Summary: "Automation tokens of a tenant (tenant:manage)", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *TenantRef) (*struct{ Body []automation.Token }, error) {
			sc, err := d.tenantAdmin(ctx, in.Tenant, authz.PermTenantManage)
			if err != nil {
				return nil, err
			}
			ts, err := d.Tokens.List(ctx, sc.TenantID())
			if err != nil {
				return nil, d.fail("list-tokens", err)
			}
			return &struct{ Body []automation.Token }{Body: ts}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "create-tenant-token", Method: http.MethodPost, Path: "/tenants/{tenant}/automation-tokens",
		DefaultStatus: http.StatusCreated, Summary: "Issue a tenant automation token with permissions you hold (needs a recent sign-in)", Tags: tags,
		Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			TenantRef
			Body TenantTokenRequest
		}) (*struct{ Body CreatedToken }, error) {
			for _, perm := range in.Body.Permissions {
				if !authz.ValidPermission(perm) {
					return nil, problem(http.StatusUnprocessableEntity, apperr.CodeInvalid, "permissions: "+perm+" is not <resource_type>:<action>", nil)
				}
			}
			sc, err := d.tenantAdminAny(ctx, in.Tenant, in.Body.Permissions...)
			if err != nil {
				return nil, err
			}
			if err := d.stepUp(ctx); err != nil {
				return nil, err
			}
			if err := d.mayGrant(ctx, sc, in.Body.Permissions); err != nil {
				return nil, err
			}
			t, secret, err := d.Tokens.Create(ctx, change(ctx, ""), automation.CreateParams{Name: in.Body.Name, Kind: automation.KindTenant,
				TenantID: sc.TenantID(), Permissions: in.Body.Permissions, Lifetime: days(in.Body.ExpiresInDays), CreatedBy: Principal(ctx).UserID})
			if err != nil {
				return nil, d.fail("create-token", err)
			}
			return &struct{ Body CreatedToken }{Body: CreatedToken{Token: t, Secret: secret}}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "revoke-tenant-token", Method: http.MethodDelete, Path: "/tenants/{tenant}/automation-tokens/{token}",
		DefaultStatus: http.StatusNoContent, Summary: "Revoke a tenant automation token (its creator or tenant:manage)", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			TenantRef
			TokenRef
		}) (*struct{}, error) {
			p := Principal(ctx)
			sc, err := d.tenantMember(ctx, in.Tenant)
			if err != nil {
				return nil, err
			}
			t, err := d.Tokens.Get(ctx, in.Token)
			if err != nil || t.TenantID != sc.TenantID() {
				return nil, d.fail("revoke-token", automation.ErrNotFound)
			}
			if t.CreatedBy != p.UserID || p.Token != nil {
				if _, err := d.tenantAdmin(ctx, in.Tenant, authz.PermTenantManage); err != nil {
					return nil, err
				}
			}
			if err := d.Tokens.Revoke(ctx, change(ctx, ""), t.ID); err != nil {
				return nil, d.fail("revoke-token", err)
			}
			return &struct{}{}, nil
		})
}

// tenantMember resolves a tenant the caller administers as an operator or belongs to as an active member.
func (d *Deps) tenantMember(ctx context.Context, ref string) (tenancy.Scope, error) {
	p := Principal(ctx)
	if p.IsOperator(identity.RoleOwner, identity.RoleAdmin) {
		return d.operatorScope(ctx, ref)
	}
	sc, err := d.Tenants.ResolveForMember(ctx, p.UserID, ref)
	if err != nil {
		return sc, d.fail("tenant", err)
	}
	return sc, nil
}

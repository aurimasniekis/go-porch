package mgmtapi

import (
	"context"
	"net/http"
	"slices"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/aurimasniekis/go-porch/internal/apperr"
	"github.com/aurimasniekis/go-porch/internal/authz"
	"github.com/aurimasniekis/go-porch/internal/automation"
	"github.com/aurimasniekis/go-porch/internal/identity"
	"github.com/aurimasniekis/go-porch/internal/session"
	"github.com/aurimasniekis/go-porch/internal/tenancy"
)

// InstallationTokenRequest creates an installation automation token.
type InstallationTokenRequest struct {
	Name          string `json:"name" minLength:"1" maxLength:"200"`
	Role          string `json:"role" enum:"admin,auditor,inspector" doc:"admin manages every tenant and installation setting; auditor reads installation health and the audit log; inspector reads the configuration of every tenant."`
	ExpiresInDays int    `json:"expires_in_days,omitempty" minimum:"0" maximum:"366" doc:"1–366; omit when never_expires is set. A token issued by another token cannot outlive it."`
	NeverExpires  bool   `json:"never_expires,omitempty" doc:"Issue a token that never expires and does not depend on the identity provider confirming you (installation owners only, ADR-0046; from a token, only one that never expires). Revoke it when it is no longer needed."`
}

// TenantTokenRequest creates a tenant automation token.
type TenantTokenRequest struct {
	Name          string   `json:"name" minLength:"1" maxLength:"200"`
	Permissions   []string `json:"permissions" minItems:"1" maxItems:"50" doc:"Tenant permissions; you (and the issuing token, if any) must hold each of them."`
	ExpiresInDays int      `json:"expires_in_days" minimum:"1" maximum:"366" doc:"A token issued by another token cannot outlive it."`
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
	huma.Register(api, huma.Operation{OperationID: "get-installation-token", Method: http.MethodGet, Path: "/installation/automation-tokens/{token}",
		Summary: "An installation automation token (owner, admin or auditor, or the token that issued it)", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *TokenRef) (*struct{ Body automation.Token }, error) {
			p := Principal(ctx)
			t, err := d.Tokens.Get(ctx, in.Token)
			if err != nil || t.Kind != automation.KindInstallation {
				t, err = automation.Token{}, automation.ErrNotFound
			}
			if !p.IsOperator(identity.RoleOwner, identity.RoleAdmin, identity.RoleAuditor) {
				if err == nil {
					err = d.issuedByCaller(ctx, t)
				}
				if err != nil {
					return nil, d.fail("get-token", automation.ErrNotFound)
				}
			}
			if err != nil {
				return nil, d.fail("get-token", err)
			}
			return &struct{ Body automation.Token }{Body: t}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "create-installation-token", Method: http.MethodPost, Path: "/installation/automation-tokens",
		DefaultStatus: http.StatusCreated,
		Summary:       "Issue an installation automation token (owner with a recent sign-in, or an installation token an owner created)", Tags: tags,
		Security: sessionSecurity},
		func(ctx context.Context, in *struct{ Body InstallationTokenRequest }) (*struct{ Body CreatedToken }, error) {
			p := Principal(ctx)
			if p == nil {
				return nil, huma.Error401Unauthorized("authentication required")
			}
			if p.Token != nil {
				if err := d.mayIssueFromInstallationToken(ctx, p); err != nil {
					return nil, err
				}
			} else {
				if _, err := requireOperator(ctx, identity.RoleOwner); err != nil {
					return nil, err
				}
				if err := d.stepUp(ctx); err != nil {
					return nil, err
				}
			}
			t, secret, err := d.Tokens.Create(ctx, change(ctx, ""), automation.CreateParams{Name: in.Body.Name, Kind: automation.KindInstallation,
				Role: in.Body.Role, Lifetime: days(in.Body.ExpiresInDays), NeverExpires: in.Body.NeverExpires, CreatedBy: p.UserID, Issuer: p.Token})
			if err != nil {
				return nil, d.fail("create-token", err)
			}
			return &struct{ Body CreatedToken }{Body: CreatedToken{Token: t, Secret: secret}}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "revoke-installation-token", Method: http.MethodDelete,
		Path: "/installation/automation-tokens/{token}", DefaultStatus: http.StatusNoContent,
		Summary: "Revoke an installation automation token and every token it issued (owner, or the token that issued it)", Tags: tags,
		Security: sessionSecurity},
		func(ctx context.Context, in *TokenRef) (*struct{}, error) {
			p := Principal(ctx)
			if p.Token == nil {
				if _, err := requireOperator(ctx, identity.RoleOwner); err != nil {
					return nil, err
				}
			}
			t, err := d.Tokens.Get(ctx, in.Token)
			if err != nil || t.Kind != automation.KindInstallation {
				return nil, d.fail("revoke-token", automation.ErrNotFound)
			}
			if p.Token != nil {
				if err := d.issuedByCaller(ctx, t); err != nil {
					return nil, err
				}
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
	huma.Register(api, huma.Operation{OperationID: "get-tenant-token", Method: http.MethodGet, Path: "/tenants/{tenant}/automation-tokens/{token}",
		Summary: "A tenant automation token (tenant:manage, or the token that issued it)", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			TenantRef
			TokenRef
		}) (*struct{ Body automation.Token }, error) {
			p := Principal(ctx)
			sc, err := d.tenantAdmin(ctx, in.Tenant, authz.PermTenantManage)
			issuerOnly := err != nil && p.Token != nil // without tenant:manage, a token reads only the tokens it issued
			if issuerOnly {
				sc, err = d.tokenTenant(ctx, in.Tenant)
			}
			if err != nil {
				return nil, err
			}
			t, err := d.Tokens.Get(ctx, in.Token)
			if err != nil || t.TenantID != sc.TenantID() {
				return nil, d.fail("get-token", automation.ErrNotFound)
			}
			if issuerOnly && d.issuedByCaller(ctx, t) != nil {
				return nil, d.fail("get-token", automation.ErrNotFound)
			}
			return &struct{ Body automation.Token }{Body: t}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "create-tenant-token", Method: http.MethodPost, Path: "/tenants/{tenant}/automation-tokens",
		DefaultStatus: http.StatusCreated,
		Summary:       "Issue a tenant automation token with permissions you hold (needs a recent sign-in; from a token, no broader than it)", Tags: tags,
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
			p := Principal(ctx)
			if p.Token != nil && p.Token.TenantID == "" {
				if err := d.mayIssueFromInstallationToken(ctx, p); err != nil {
					return nil, err
				}
			}
			if err := mayIssueFromToken(p); err != nil {
				return nil, err
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
				TenantID: sc.TenantID(), Permissions: in.Body.Permissions, Lifetime: days(in.Body.ExpiresInDays), CreatedBy: p.UserID, Issuer: p.Token})
			if err != nil {
				return nil, d.fail("create-token", err)
			}
			return &struct{ Body CreatedToken }{Body: CreatedToken{Token: t, Secret: secret}}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "revoke-tenant-token", Method: http.MethodDelete, Path: "/tenants/{tenant}/automation-tokens/{token}",
		DefaultStatus: http.StatusNoContent,
		Summary:       "Revoke a tenant automation token and every token it issued (its creator, tenant:manage, or the token that issued it)", Tags: tags,
		Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			TenantRef
			TokenRef
		}) (*struct{}, error) {
			p := Principal(ctx)
			sc, err := d.tokenTenant(ctx, in.Tenant)
			if err != nil {
				return nil, err
			}
			t, err := d.Tokens.Get(ctx, in.Token)
			if err != nil || t.TenantID != sc.TenantID() {
				return nil, d.fail("revoke-token", automation.ErrNotFound)
			}
			if (t.CreatedBy != p.UserID || p.Token != nil) && (p.Token == nil || d.issuedByCaller(ctx, t) != nil) {
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

// tokenTenant resolves the tenant of a tenant automation token issued by an installation operator (which acts through
// the operator scope, limited to its own tenant); for anyone else it is tenantMember.
func (d *Deps) tokenTenant(ctx context.Context, ref string) (tenancy.Scope, error) {
	p := Principal(ctx)
	if g := p.Token; g != nil && g.TenantID != "" && g.CreatorOperator {
		sc, err := d.Tenants.ResolveForOperator(ctx, p.UserID, ref)
		if err != nil || sc.TenantID() != g.TenantID {
			return tenancy.Scope{}, d.fail("tenant", tenancy.ErrNoAccess)
		}
		return sc, nil
	}
	return d.tenantMember(ctx, ref)
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

// mayIssueFromInstallationToken allows an installation token to issue tokens only while its creator is an
// installation owner (ADR-0048); what it may issue is checked by automation.Create.
func (d *Deps) mayIssueFromInstallationToken(ctx context.Context, p *session.Principal) error {
	roles, err := d.Store.R().ListOperatorRoles(ctx, p.UserID)
	if err != nil {
		return d.fail("issue-token", err)
	}
	if p.Token.TenantID != "" || !slices.Contains(roles, identity.RoleOwner) {
		return problem(http.StatusForbidden, apperr.CodeForbidden, "only installation tokens created by an installation owner can issue installation tokens", nil)
	}
	return mayIssueFromToken(p)
}

// mayIssueFromToken refuses token issuance to read-only tokens (ADR-0048).
func mayIssueFromToken(p *session.Principal) error {
	if p.Token != nil && automation.ReadOnly(p.Token) {
		return problem(http.StatusForbidden, apperr.CodeForbidden, "a read-only token cannot issue tokens", nil)
	}
	return nil
}

// issuedByCaller succeeds when the calling automation token issued t (directly or through other tokens).
func (d *Deps) issuedByCaller(ctx context.Context, t automation.Token) error {
	p := Principal(ctx)
	if p.Token == nil {
		return automation.ErrNotFound
	}
	ok, err := d.Tokens.IssuedBy(ctx, t.ID, p.Token.ID)
	if err != nil {
		return d.fail("token", err)
	}
	if !ok {
		return d.fail("token", automation.ErrNotFound)
	}
	return nil
}

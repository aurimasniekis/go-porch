package mgmtapi

import (
	"context"
	"net/http"
	"slices"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/aurimasniekis/go-porch/internal/authz"
	"github.com/aurimasniekis/go-porch/internal/identity"
	"github.com/aurimasniekis/go-porch/internal/serviceacct"
	"github.com/aurimasniekis/go-porch/internal/tenancy"
)

// ServiceAccountRequest creates a service account.
type ServiceAccountRequest struct {
	Slug           string   `json:"slug" minLength:"1" maxLength:"63"`
	Name           string   `json:"name" minLength:"1" maxLength:"200"`
	Description    string   `json:"description,omitempty" maxLength:"2000"`
	Audiences      []string `json:"audiences,omitempty" maxItems:"20" doc:"API audiences its access tokens may target (RFC 8707 resource values)."`
	AccessTokenTTL int64    `json:"access_token_ttl_seconds,omitempty" minimum:"0" maximum:"3600" doc:"0 = default (600)."`
}

// ServiceAccountUpdate edits a service account; omitted fields are unchanged.
type ServiceAccountUpdate struct {
	Name           *string  `json:"name,omitempty" maxLength:"200"`
	Description    *string  `json:"description,omitempty" maxLength:"2000"`
	Enabled        *bool    `json:"enabled,omitempty"`
	Audiences      []string `json:"audiences,omitempty" maxItems:"20"`
	AccessTokenTTL *int64   `json:"access_token_ttl_seconds,omitempty" minimum:"60" maximum:"3600"`
}

// ServiceAccount is a tenant machine identity. Use its id as client_id with the client credentials grant.
type ServiceAccount struct {
	serviceacct.Account
	TokenEndpoint string `json:"token_endpoint"`
}

// CreatedServiceAccount includes the secret exactly once.
type CreatedServiceAccount struct {
	ServiceAccount
	ClientSecret string `json:"client_secret" doc:"Shown only in this response. Store it now."`
}

// ServiceAccountRef addresses a service account.
type ServiceAccountRef struct {
	TenantRef
	ServiceAccount string `path:"sa" maxLength:"64" doc:"Service account ID or slug."`
}

func (d *Deps) saDTO(a serviceacct.Account) ServiceAccount {
	return ServiceAccount{Account: a, TokenEndpoint: d.Origin + "/oauth2/token"}
}

func registerServiceAccounts(api huma.API, d *Deps) {
	tags := []string{"service-accounts"}
	perm := authz.PermServiceAccount
	huma.Register(api, huma.Operation{OperationID: "list-service-accounts", Method: http.MethodGet, Path: "/tenants/{tenant}/service-accounts",
		Summary: "Service accounts of a tenant", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *TenantRef) (*struct{ Body []ServiceAccount }, error) {
			sc, err := d.tenantReader(ctx, in.Tenant, authz.PermServiceAccountRead, perm)
			if err != nil {
				return nil, err
			}
			as, err := d.SAs.List(ctx, sc)
			if err != nil {
				return nil, d.fail("list-sa", err)
			}
			out := make([]ServiceAccount, 0, len(as))
			for _, a := range as {
				out = append(out, d.saDTO(a))
			}
			return &struct{ Body []ServiceAccount }{Body: out}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "create-service-account", Method: http.MethodPost, Path: "/tenants/{tenant}/service-accounts",
		DefaultStatus: http.StatusCreated, Summary: "Create a service account (grant it roles with assignments)", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			TenantRef
			ManagedBy
			Body ServiceAccountRequest
		}) (*withETag[CreatedServiceAccount], error) {
			sc, err := d.tenantAdmin(ctx, in.Tenant, perm)
			if err != nil {
				return nil, err
			}
			// Issuing a persistent machine credential needs a recent sign-in, like rotating one (security review L5).
			if err := d.stepUp(ctx); err != nil {
				return nil, err
			}
			b := in.Body
			if err := d.audiencesFree(ctx, sc, b.Audiences); err != nil {
				return nil, err
			}
			p := serviceacct.Params{Slug: b.Slug, Name: &b.Name, Description: &b.Description, Audiences: b.Audiences}
			if b.AccessTokenTTL > 0 {
				ttl := time.Duration(b.AccessTokenTTL) * time.Second
				p.AccessTokenTTL = &ttl
			}
			cr, err := d.SAs.Create(ctx, change(ctx, in.ManagedBy.ManagedBy), sc, p)
			if err != nil {
				return nil, d.fail("create-sa", err)
			}
			return tagged(cr.Account.Version, CreatedServiceAccount{ServiceAccount: d.saDTO(cr.Account), ClientSecret: cr.Secret}), nil
		})
	huma.Register(api, huma.Operation{OperationID: "get-service-account", Method: http.MethodGet, Path: "/tenants/{tenant}/service-accounts/{sa}",
		Summary: "Get a service account", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *ServiceAccountRef) (*withETag[ServiceAccount], error) {
			sc, err := d.tenantReader(ctx, in.Tenant, authz.PermServiceAccountRead, perm)
			if err != nil {
				return nil, err
			}
			a, err := d.SAs.Get(ctx, sc, in.ServiceAccount)
			if err != nil {
				return nil, d.fail("get-sa", err)
			}
			return tagged(a.Version, d.saDTO(a)), nil
		})
	huma.Register(api, huma.Operation{OperationID: "update-service-account", Method: http.MethodPatch, Path: "/tenants/{tenant}/service-accounts/{sa}",
		Summary: "Update a service account", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			ServiceAccountRef
			ManagedBy
			IfMatch
			Body ServiceAccountUpdate
		}) (*withETag[ServiceAccount], error) {
			sc, err := d.tenantAdmin(ctx, in.Tenant, perm)
			if err != nil {
				return nil, err
			}
			v, err := in.Version()
			if err != nil {
				return nil, err
			}
			b := in.Body
			cur, err := d.SAs.Get(ctx, sc, in.ServiceAccount)
			if err != nil {
				return nil, d.fail("update-sa", err)
			}
			// Re-enabling or retargeting a service account changes what its existing grants can reach.
			if err := d.mayControlSA(ctx, sc, cur.ID); err != nil {
				return nil, err
			}
			if err := d.audiencesFree(ctx, sc, b.Audiences); err != nil {
				return nil, err
			}
			p := serviceacct.Params{Name: b.Name, Description: b.Description, Enabled: b.Enabled, Audiences: b.Audiences, IfVersion: v}
			if b.AccessTokenTTL != nil {
				ttl := time.Duration(*b.AccessTokenTTL) * time.Second
				p.AccessTokenTTL = &ttl
			}
			a, err := d.SAs.Update(ctx, change(ctx, in.ManagedBy.ManagedBy), sc, cur.ID, p)
			if err != nil {
				return nil, d.fail("update-sa", err)
			}
			return tagged(a.Version, d.saDTO(a)), nil
		})
	huma.Register(api, huma.Operation{OperationID: "rotate-service-account-secret", Method: http.MethodPost,
		Path: "/tenants/{tenant}/service-accounts/{sa}/rotate-secret", Summary: "Issue a new secret (needs a recent sign-in; the old secret stops working)",
		Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *ServiceAccountRef) (*struct{ Body ClientSecret }, error) {
			sc, err := d.tenantAdmin(ctx, in.Tenant, perm)
			if err != nil {
				return nil, err
			}
			if err := d.stepUp(ctx); err != nil {
				return nil, err
			}
			a, err := d.SAs.Get(ctx, sc, in.ServiceAccount)
			if err != nil {
				return nil, d.fail("rotate-sa", err)
			}
			// A new secret is the service account's power in the caller's hands (security review H2).
			if err := d.mayControlSA(ctx, sc, a.ID); err != nil {
				return nil, err
			}
			secret, err := d.SAs.RotateSecret(ctx, change(ctx, ""), sc, a.ID)
			if err != nil {
				return nil, d.fail("rotate-sa", err)
			}
			return &struct{ Body ClientSecret }{Body: ClientSecret{ClientID: a.ID, ClientSecret: secret}}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "delete-service-account", Method: http.MethodDelete, Path: "/tenants/{tenant}/service-accounts/{sa}",
		DefaultStatus: http.StatusNoContent, Summary: "Delete a service account and its role assignments", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			ServiceAccountRef
			ManagedBy
			IfMatch
		}) (*struct{}, error) {
			sc, err := d.tenantAdmin(ctx, in.Tenant, perm)
			if err != nil {
				return nil, err
			}
			v, err := in.Version()
			if err != nil {
				return nil, err
			}
			a, err := d.SAs.Get(ctx, sc, in.ServiceAccount)
			if err != nil {
				return nil, d.fail("delete-sa", err)
			}
			// Deleting removes its assignments: the caller must hold what it holds.
			if err := d.mayControlSA(ctx, sc, a.ID); err != nil {
				return nil, err
			}
			if err := d.SAs.Delete(ctx, change(ctx, in.ManagedBy.ManagedBy), sc, a.ID, v); err != nil {
				return nil, d.fail("delete-sa", err)
			}
			return &struct{}{}, nil
		})
}

// mayControlSA requires the caller to hold everything a service account holds (rotating, re-enabling, retargeting or
// deleting it).
func (d *Deps) mayControlSA(ctx context.Context, sc tenancy.Scope, id string) error {
	if exempt(ctx, sc) {
		return nil
	}
	grants, err := d.Engine.Effective(ctx, sc.TenantID(), "service_account", id)
	if err != nil {
		return d.fail("escalation", err)
	}
	perms := make([]string, 0, len(grants))
	for _, g := range grants {
		perms = append(perms, g.Permission)
	}
	return d.mayGrant(ctx, sc, perms)
}

// AdminTenant is a tenant the caller can administer and what they may do there.
type AdminTenant struct {
	ID          string   `json:"id"`
	Slug        string   `json:"slug"`
	Name        string   `json:"name"`
	Via         string   `json:"via" enum:"operator,inspector,delegated"`
	Permissions []string `json:"permissions" doc:"Management permissions held at tenant scope (system catalogue subset)."`
}

// AdminCapabilities tells the UI which administration surfaces to show.
type AdminCapabilities struct {
	OperatorRoles []string      `json:"operator_roles"`
	Installation  bool          `json:"installation" doc:"Installation administration (owner or admin)."`
	Auditor       bool          `json:"auditor" doc:"Installation-wide audit and health (owner, admin or auditor)."`
	Inspector     bool          `json:"inspector" doc:"Reads the configuration of every tenant (installation inspector, ADR-0048)."`
	Tenants       []AdminTenant `json:"tenants"`
}

func registerAdminCapabilities(api huma.API, d *Deps) {
	huma.Register(api, huma.Operation{OperationID: "get-my-admin", Method: http.MethodGet, Path: "/me/admin",
		Summary: "What the caller can administer", Tags: []string{"me"}, Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*struct{ Body AdminCapabilities }, error) {
			p := Principal(ctx)
			out := AdminCapabilities{OperatorRoles: nonNilStrings(p.OperatorRoles), Tenants: []AdminTenant{},
				Installation: p.IsOperator(identity.RoleOwner, identity.RoleAdmin),
				Auditor:      p.IsOperator(identity.RoleOwner, identity.RoleAdmin, identity.RoleAuditor),
				Inspector:    p.IsOperator(identity.RoleInspector)}
			mgmt := slices.DeleteFunc(slices.Clone(authz.SystemPermissions), func(s string) bool { return s == authz.PermAppAccess })
			if out.Installation {
				rows, err := d.Store.R().ListAllTenants(ctx)
				if err != nil {
					return nil, d.fail("me-admin", err)
				}
				for _, t := range rows {
					out.Tenants = append(out.Tenants, AdminTenant{ID: t.ID, Slug: t.Slug, Name: t.Name, Via: "operator", Permissions: mgmt})
				}
				return &struct{ Body AdminCapabilities }{Body: out}, nil
			}
			// Inspectors read every tenant; where they also administer a tenant, they keep those permissions too.
			inspected := map[string]int{}
			if out.Inspector {
				rows, err := d.Store.R().ListAllTenants(ctx)
				if err != nil {
					return nil, d.fail("me-admin", err)
				}
				for _, t := range rows {
					inspected[t.ID] = len(out.Tenants)
					out.Tenants = append(out.Tenants, AdminTenant{ID: t.ID, Slug: t.Slug, Name: t.Name, Via: "inspector",
						Permissions: slices.Clone(authz.ReadPermissions)})
				}
			}
			rows, err := d.Tenants.UserMemberships(ctx, p.UserID)
			if err != nil {
				return nil, d.fail("me-admin", err)
			}
			for _, m := range rows {
				if m.Status != "active" || m.TenantStatus != "active" {
					continue
				}
				var held []string
				for _, perm := range mgmt {
					ok, err := d.holds(ctx, m.TenantID, perm)
					if err != nil {
						return nil, d.fail("me-admin", err)
					}
					if ok {
						held = append(held, perm)
					}
				}
				if i, ok := inspected[m.TenantID]; ok {
					merged := append(out.Tenants[i].Permissions, held...)
					slices.Sort(merged)
					out.Tenants[i].Permissions = slices.Compact(merged)
					continue
				}
				if len(held) > 0 {
					out.Tenants = append(out.Tenants, AdminTenant{ID: m.TenantID, Slug: m.TenantSlug, Name: m.TenantName, Via: "delegated", Permissions: held})
				}
			}
			return &struct{ Body AdminCapabilities }{Body: out}, nil
		})
}

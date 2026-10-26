package mgmtapi

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/aurimasniekis/go-porch/internal/identity"
	"github.com/aurimasniekis/go-porch/internal/idp"
)

// IdentityProvider is an upstream provider (the client secret is write-only).
type IdentityProvider struct {
	ID            string    `json:"id"`
	Slug          string    `json:"slug"`
	Kind          string    `json:"kind" enum:"google,oidc"`
	Name          string    `json:"name"`
	Issuer        string    `json:"issuer"`
	ClientID      string    `json:"client_id"`
	AllowedHDs    []string  `json:"allowed_hds" doc:"Google Workspace domains this provider accepts (empty = any account)."`
	Scopes        string    `json:"scopes"`
	Enabled       bool      `json:"enabled"`
	CallbackURL   string    `json:"callback_url" doc:"Register this redirect URI at the provider."`
	Version       int64     `json:"version"`
	ManagedBy     string    `json:"managed_by"`
	LastChangedBy string    `json:"last_changed_by,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func (d *Deps) providerDTO(p idp.Provider) IdentityProvider {
	return IdentityProvider{ID: p.ID, Slug: p.Slug, Kind: p.Kind, Name: p.Name, Issuer: p.Issuer, ClientID: p.ClientID, AllowedHDs: p.AllowedHDs,
		Scopes: p.Scopes, Enabled: p.Enabled, CallbackURL: d.Origin + "/login/" + p.Slug + "/callback", Version: p.Version, ManagedBy: p.ManagedBy,
		LastChangedBy: p.LastChangedBy, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt}
}

// CreateProviderRequest adds a provider.
type CreateProviderRequest struct {
	Slug         string   `json:"slug" minLength:"2" maxLength:"63"`
	Kind         string   `json:"kind" enum:"google,oidc"`
	Name         string   `json:"name" minLength:"1" maxLength:"200"`
	Issuer       string   `json:"issuer,omitempty" maxLength:"512" doc:"Defaults to https://accounts.google.com for google."`
	ClientID     string   `json:"client_id" minLength:"1" maxLength:"512"`
	ClientSecret string   `json:"client_secret" minLength:"1" maxLength:"1024"`
	AllowedHDs   []string `json:"allowed_hds,omitempty" maxItems:"50"`
	Scopes       string   `json:"scopes,omitempty" maxLength:"512"`
	Enabled      *bool    `json:"enabled,omitempty"`
}

// UpdateProviderRequest edits a provider; omitted fields are unchanged.
type UpdateProviderRequest struct {
	Name         string   `json:"name,omitempty" maxLength:"200"`
	Issuer       string   `json:"issuer,omitempty" maxLength:"512"`
	ClientID     string   `json:"client_id,omitempty" maxLength:"512"`
	ClientSecret string   `json:"client_secret,omitempty" maxLength:"1024" doc:"Rotates the stored secret."`
	AllowedHDs   []string `json:"allowed_hds,omitempty" maxItems:"50"`
	Scopes       string   `json:"scopes,omitempty" maxLength:"512"`
	Enabled      *bool    `json:"enabled,omitempty"`
}

type providerOutput struct {
	ETag string `header:"ETag"`
	Body IdentityProvider
}

// ProviderRef addresses a provider.
type ProviderRef struct {
	Provider string `path:"provider" maxLength:"64" doc:"Provider ID or slug."`
}

// providerID resolves a provider reference (ID or slug).
func (d *Deps) providerID(ctx context.Context, ref string) string {
	if p, err := d.Store.R().GetProviderBySlug(ctx, ref); err == nil {
		return p.ID
	}
	return ref
}

// LoginSettings configures the sign-in page.
type LoginSettings struct {
	DirectProvider string `json:"direct_provider" maxLength:"64" doc:"Slug of an enabled provider the sign-in page sends people to directly; empty shows every sign-in method. /login?all=1 always shows them."`
}

func registerProviders(api huma.API, d *Deps) {
	tags := []string{"identity-providers"}
	huma.Register(api, huma.Operation{OperationID: "get-login-settings", Method: http.MethodGet, Path: "/installation/login",
		Summary: "Sign-in page settings", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*struct{ Body LoginSettings }, error) {
			if _, err := requireOperator(ctx, identity.RoleOwner, identity.RoleAdmin, identity.RoleAuditor); err != nil {
				return nil, err
			}
			slug, err := d.IDP.DirectProvider(ctx)
			if err != nil {
				return nil, d.fail("login-settings", err)
			}
			return &struct{ Body LoginSettings }{Body: LoginSettings{DirectProvider: slug}}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "update-login-settings", Method: http.MethodPut, Path: "/installation/login",
		Summary: "Change the sign-in page settings", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct{ Body LoginSettings }) (*struct{ Body LoginSettings }, error) {
			if _, err := requireOperator(ctx, identity.RoleOwner, identity.RoleAdmin); err != nil {
				return nil, err
			}
			if err := d.stepUp(ctx); err != nil {
				return nil, err
			}
			if err := d.IDP.SetDirectProvider(ctx, change(ctx, ""), in.Body.DirectProvider); err != nil {
				return nil, d.fail("login-settings", err)
			}
			return &struct{ Body LoginSettings }{Body: in.Body}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "list-identity-providers", Method: http.MethodGet, Path: "/identity-providers",
		Summary: "List upstream identity providers", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*struct{ Body []IdentityProvider }, error) {
			if _, err := requireOperator(ctx, identity.RoleOwner, identity.RoleAdmin, identity.RoleAuditor, identity.RoleInspector); err != nil {
				return nil, err
			}
			ps, err := d.IDP.Providers(ctx)
			if err != nil {
				return nil, d.fail("list-providers", err)
			}
			out := make([]IdentityProvider, 0, len(ps))
			for _, p := range ps {
				out = append(out, d.providerDTO(p))
			}
			return &struct{ Body []IdentityProvider }{Body: out}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "create-identity-provider", Method: http.MethodPost, Path: "/identity-providers",
		DefaultStatus: http.StatusCreated, Summary: "Add an upstream identity provider (needs a recent sign-in)", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			ManagedBy
			Body CreateProviderRequest
		}) (*providerOutput, error) {
			if _, err := requireOperator(ctx, identity.RoleOwner, identity.RoleAdmin); err != nil {
				return nil, err
			}
			if err := d.stepUp(ctx); err != nil {
				return nil, err
			}
			b := in.Body
			p, err := d.IDP.CreateProvider(ctx, change(ctx, in.ManagedBy.ManagedBy), idp.ProviderParams{Slug: b.Slug, Kind: b.Kind, Name: b.Name,
				Issuer: b.Issuer, ClientID: b.ClientID, Secret: b.ClientSecret, AllowedHDs: b.AllowedHDs, Scopes: b.Scopes, Enabled: b.Enabled})
			if err != nil {
				return nil, d.fail("create-provider", err)
			}
			return &providerOutput{ETag: etag(p.Version), Body: d.providerDTO(p)}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "update-identity-provider", Method: http.MethodPatch, Path: "/identity-providers/{provider}",
		Summary: "Update an identity provider (needs a recent sign-in)", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			ProviderRef
			ManagedBy
			IfMatch
			Body UpdateProviderRequest
		}) (*providerOutput, error) {
			if _, err := requireOperator(ctx, identity.RoleOwner, identity.RoleAdmin); err != nil {
				return nil, err
			}
			if err := d.stepUp(ctx); err != nil {
				return nil, err
			}
			v, err := in.Version()
			if err != nil {
				return nil, err
			}
			b := in.Body
			p, err := d.IDP.UpdateProvider(ctx, change(ctx, in.ManagedBy.ManagedBy), d.providerID(ctx, in.Provider), idp.ProviderParams{Name: b.Name, Issuer: b.Issuer,
				ClientID: b.ClientID, Secret: b.ClientSecret, AllowedHDs: b.AllowedHDs, Scopes: b.Scopes, Enabled: b.Enabled, IfVersion: v})
			if err != nil {
				return nil, d.fail("update-provider", err)
			}
			return &providerOutput{ETag: etag(p.Version), Body: d.providerDTO(p)}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "delete-identity-provider", Method: http.MethodDelete, Path: "/identity-providers/{provider}",
		DefaultStatus: http.StatusNoContent, Summary: "Delete an identity provider and its linked identities (needs a recent sign-in)", Tags: tags,
		Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			ProviderRef
			ManagedBy
			IfMatch
		}) (*struct{}, error) {
			if _, err := requireOperator(ctx, identity.RoleOwner, identity.RoleAdmin); err != nil {
				return nil, err
			}
			if err := d.stepUp(ctx); err != nil {
				return nil, err
			}
			v, err := in.Version()
			if err != nil {
				return nil, err
			}
			if err := d.IDP.DeleteProvider(ctx, change(ctx, in.ManagedBy.ManagedBy), d.providerID(ctx, in.Provider), v); err != nil {
				return nil, d.fail("delete-provider", err)
			}
			return &struct{}{}, nil
		})
}

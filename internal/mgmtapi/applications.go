package mgmtapi

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/aurimasniekis/go-porch/internal/apps"
)

// Disclosure controls optional claims released to an application.
type Disclosure struct {
	Email        bool `json:"email"`
	Groups       bool `json:"groups"`
	Roles        bool `json:"roles"`
	Entitlements bool `json:"entitlements"`
}

// OIDCClient is an application's OAuth/OIDC client (the secret is never returned after creation).
type OIDCClient struct {
	ClientID          string   `json:"client_id"`
	ClientType        string   `json:"client_type" enum:"confidential,public"`
	ApplicationType   string   `json:"application_type" enum:"web,native,user_agent"`
	SecretHint        string   `json:"secret_hint,omitempty" doc:"Last characters of the current secret."`
	RedirectURIs      []string `json:"redirect_uris"`
	PostLogoutURIs    []string `json:"post_logout_redirect_uris"`
	GrantTypes        []string `json:"grant_types"`
	AllowedScopes     []string `json:"allowed_scopes"`
	Audiences         []string `json:"audiences" doc:"API audiences access tokens may be issued for (RFC 8707 resource values)."`
	AllowedOrigins    []string `json:"allowed_origins" doc:"Browser origins allowed to call the token endpoint (SPA clients)."`
	RequirePKCE       bool     `json:"require_pkce"`
	SigningAlg        string   `json:"signing_alg" enum:"ES256,RS256"`
	AccessTokenTTL    int64    `json:"access_token_ttl_seconds"`
	IDTokenTTL        int64    `json:"id_token_ttl_seconds"`
	RefreshTTL        int64    `json:"refresh_ttl_seconds"`
	RefreshIdle       int64    `json:"refresh_idle_seconds"`
	Issuer            string   `json:"issuer"`
	DiscoveryURL      string   `json:"discovery_url"`
	RedirectURIsExact bool     `json:"redirect_uris_exact" doc:"Always true: redirect URIs match exactly (loopback port exception for native clients)."`
}

// Application is a tenant application.
type Application struct {
	ID             string            `json:"id"`
	TenantID       string            `json:"tenant_id"`
	Slug           string            `json:"slug"`
	Name           string            `json:"name"`
	Kind           string            `json:"kind" enum:"oidc,forward_auth"`
	Description    string            `json:"description"`
	LaunchURL      string            `json:"launch_url"`
	Enabled        bool              `json:"enabled"`
	Disclosure     Disclosure        `json:"disclosure"`
	AccessMode     string            `json:"access_mode" enum:"all_members,assigned" doc:"all_members: every active member (and shared tenants); assigned: explicit app:access grants only."`
	Hosts          []string          `json:"hosts" doc:"Hosts protected by a forward_auth application."`
	ForwardHeaders map[string]string `json:"forward_headers" doc:"Identity headers sent to forward-auth backends (header → sub|email|name|groups|tenant|roles); empty = defaults."`
	Client         *OIDCClient       `json:"client,omitempty"`
	Version        int64             `json:"version"`
	ManagedBy      string            `json:"managed_by"`
	LastChangedBy  string            `json:"last_changed_by,omitempty"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
}

func (d *Deps) appDTO(a apps.Application, c *apps.Client) Application {
	out := Application{ID: a.ID, TenantID: a.TenantID, Slug: a.Slug, Name: a.Name, Kind: a.Kind, Description: a.Description, LaunchURL: a.LaunchURL,
		Enabled: a.Enabled, Disclosure: Disclosure(a.Disclosure), AccessMode: a.AccessMode, Hosts: a.Hosts, ForwardHeaders: a.ForwardHeaders,
		Version: a.Version, ManagedBy: a.ManagedBy, LastChangedBy: a.LastChangedBy,
		CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt}
	if c != nil {
		out.Client = &OIDCClient{ClientID: c.ID, ClientType: c.Type, ApplicationType: c.ApplicationType, SecretHint: c.SecretHint,
			RedirectURIs: c.RedirectURIs, PostLogoutURIs: c.PostLogoutURIs, GrantTypes: c.GrantTypes, AllowedScopes: c.AllowedScopes,
			Audiences: c.Audiences, AllowedOrigins: c.AllowedOrigins, RequirePKCE: c.RequirePKCE, SigningAlg: c.SigningAlg,
			AccessTokenTTL: c.AccessTokenTTL, IDTokenTTL: c.IDTokenTTL, RefreshTTL: c.RefreshTTL, RefreshIdle: c.RefreshIdle,
			Issuer: d.Origin, DiscoveryURL: d.Origin + "/.well-known/openid-configuration", RedirectURIsExact: true}
	}
	return out
}

// ClientConfig configures an OIDC client.
type ClientConfig struct {
	ClientType      string   `json:"client_type,omitempty" enum:"confidential,public" doc:"Create only; default confidential."`
	ApplicationType string   `json:"application_type,omitempty" enum:"web,native,user_agent" doc:"Create only; default web."`
	RedirectURIs    []string `json:"redirect_uris,omitempty" maxItems:"20"`
	PostLogoutURIs  []string `json:"post_logout_redirect_uris,omitempty" maxItems:"20"`
	GrantTypes      []string `json:"grant_types,omitempty" maxItems:"3"`
	AllowedScopes   []string `json:"allowed_scopes,omitempty" maxItems:"10"`
	Audiences       []string `json:"audiences,omitempty" maxItems:"20"`
	AllowedOrigins  []string `json:"allowed_origins,omitempty" maxItems:"20"`
	RequirePKCE     *bool    `json:"require_pkce,omitempty" doc:"Default true; public clients always require PKCE."`
	SigningAlg      string   `json:"signing_alg,omitempty" enum:"ES256,RS256"`
	AccessTokenTTL  int64    `json:"access_token_ttl_seconds,omitempty" minimum:"0"`
	IDTokenTTL      int64    `json:"id_token_ttl_seconds,omitempty" minimum:"0"`
	RefreshTTL      int64    `json:"refresh_ttl_seconds,omitempty" minimum:"0"`
	RefreshIdle     int64    `json:"refresh_idle_seconds,omitempty" minimum:"0"`
}

func (c *ClientConfig) params() *apps.ClientParams {
	if c == nil {
		return nil
	}
	t := c.ClientType
	if t == "" {
		t = "confidential"
	}
	sec := func(n int64) time.Duration { return time.Duration(n) * time.Second }
	return &apps.ClientParams{Type: t, ApplicationType: c.ApplicationType, RedirectURIs: c.RedirectURIs, PostLogoutURIs: c.PostLogoutURIs,
		GrantTypes: c.GrantTypes, AllowedScopes: c.AllowedScopes, Audiences: c.Audiences, AllowedOrigins: c.AllowedOrigins, RequirePKCE: c.RequirePKCE,
		SigningAlg: c.SigningAlg, AccessTokenTTL: sec(c.AccessTokenTTL), IDTokenTTL: sec(c.IDTokenTTL), RefreshTTL: sec(c.RefreshTTL),
		RefreshIdle: sec(c.RefreshIdle)}
}

// CreateApplicationRequest adds an application.
type CreateApplicationRequest struct {
	Slug           string            `json:"slug" minLength:"1" maxLength:"63"`
	Name           string            `json:"name" minLength:"1" maxLength:"200"`
	Kind           string            `json:"kind" enum:"oidc,forward_auth"`
	Description    string            `json:"description,omitempty" maxLength:"2000"`
	LaunchURL      string            `json:"launch_url,omitempty" maxLength:"2048"`
	Disclosure     *Disclosure       `json:"disclosure,omitempty"`
	Client         *ClientConfig     `json:"client,omitempty"`
	AccessMode     string            `json:"access_mode,omitempty" enum:"all_members,assigned"`
	Hosts          []string          `json:"hosts,omitempty" maxItems:"20"`
	ForwardHeaders map[string]string `json:"forward_headers,omitempty"`
}

// CreatedApplication includes the client secret exactly once.
type CreatedApplication struct {
	Application
	ClientSecret string `json:"client_secret,omitempty" doc:"Shown only in this response. Store it now."`
}

// UpdateApplicationRequest edits an application; omitted fields are unchanged. client replaces the client config.
type UpdateApplicationRequest struct {
	Name           *string           `json:"name,omitempty" maxLength:"200"`
	Description    *string           `json:"description,omitempty" maxLength:"2000"`
	LaunchURL      *string           `json:"launch_url,omitempty" maxLength:"2048"`
	Enabled        *bool             `json:"enabled,omitempty"`
	Disclosure     *Disclosure       `json:"disclosure,omitempty"`
	Client         *ClientConfig     `json:"client,omitempty"`
	AccessMode     *string           `json:"access_mode,omitempty" enum:"all_members,assigned"`
	Hosts          []string          `json:"hosts,omitempty" maxItems:"20"`
	ForwardHeaders map[string]string `json:"forward_headers,omitempty"`
}

// ClientSecret is a newly issued client secret.
type ClientSecret struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret" doc:"Shown only in this response."`
}

// AppRef addresses an application.
type AppRef struct {
	TenantRef
	App string `path:"app" maxLength:"64"`
}

// AppShare is a tenant an application is shared with.
type AppShare struct {
	TenantID   string    `json:"tenant_id"`
	TenantSlug string    `json:"tenant_slug"`
	TenantName string    `json:"tenant_name"`
	CreatedAt  time.Time `json:"created_at"`
}

// ShareRequest shares an application with another tenant.
type ShareRequest struct {
	Tenant string `json:"tenant" minLength:"1" maxLength:"64" doc:"Target tenant ID or slug."`
}

func registerApplications(api huma.API, d *Deps) {
	tags := []string{"applications"}
	huma.Register(api, huma.Operation{OperationID: "list-application-shares", Method: http.MethodGet, Path: "/tenants/{tenant}/applications/{app}/shares",
		Summary: "Tenants an application is shared with", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *AppRef) (*struct{ Body []AppShare }, error) {
			sc, err := d.operatorScope(ctx, in.Tenant)
			if err != nil {
				return nil, err
			}
			ss, err := d.Apps.Shares(ctx, sc, in.App)
			if err != nil {
				return nil, d.fail("shares", err)
			}
			out := make([]AppShare, 0, len(ss))
			for _, x := range ss {
				out = append(out, AppShare(x))
			}
			return &struct{ Body []AppShare }{Body: out}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "share-application", Method: http.MethodPost, Path: "/tenants/{tenant}/applications/{app}/shares",
		DefaultStatus: http.StatusNoContent, Summary: "Share an application with another tenant (explicit cross-tenant access)", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			AppRef
			Body ShareRequest
		}) (*struct{}, error) {
			sc, err := d.operatorScope(ctx, in.Tenant)
			if err != nil {
				return nil, err
			}
			target, err := d.operatorScope(ctx, in.Body.Tenant)
			if err != nil {
				return nil, err
			}
			if err := d.Apps.ShareWith(ctx, change(ctx, ""), sc, in.App, target.TenantID()); err != nil {
				return nil, d.fail("share", err)
			}
			return &struct{}{}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "unshare-application", Method: http.MethodDelete, Path: "/tenants/{tenant}/applications/{app}/shares/{target}",
		DefaultStatus: http.StatusNoContent, Summary: "Stop sharing an application", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			AppRef
			Target string `path:"target" maxLength:"64"`
		}) (*struct{}, error) {
			sc, err := d.operatorScope(ctx, in.Tenant)
			if err != nil {
				return nil, err
			}
			target, err := d.operatorScope(ctx, in.Target)
			if err != nil {
				return nil, err
			}
			if err := d.Apps.Unshare(ctx, change(ctx, ""), sc, in.App, target.TenantID()); err != nil {
				return nil, d.fail("unshare", err)
			}
			return &struct{}{}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "list-applications", Method: http.MethodGet, Path: "/tenants/{tenant}/applications",
		Summary: "Applications of a tenant", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *TenantRef) (*struct{ Body []Application }, error) {
			sc, err := d.operatorScope(ctx, in.Tenant)
			if err != nil {
				return nil, err
			}
			as, err := d.Apps.List(ctx, sc)
			if err != nil {
				return nil, d.fail("list-apps", err)
			}
			out := make([]Application, 0, len(as))
			for _, a := range as {
				_, c, err := d.Apps.Get(ctx, sc, a.ID)
				if err != nil {
					return nil, d.fail("list-apps", err)
				}
				out = append(out, d.appDTO(a, c))
			}
			return &struct{ Body []Application }{Body: out}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "create-application", Method: http.MethodPost, Path: "/tenants/{tenant}/applications",
		DefaultStatus: http.StatusCreated, Summary: "Create an application (OIDC client or forward-auth)", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			TenantRef
			ManagedBy
			Body CreateApplicationRequest
		}) (*struct {
			ETag string `header:"ETag"`
			Body CreatedApplication
		}, error) {
			sc, err := d.operatorScope(ctx, in.Tenant)
			if err != nil {
				return nil, err
			}
			b := in.Body
			var disc *apps.Disclosure
			if b.Disclosure != nil {
				x := apps.Disclosure(*b.Disclosure)
				disc = &x
			}
			cr, err := d.Apps.Create(ctx, change(ctx, in.ManagedBy.ManagedBy), sc, apps.CreateParams{Slug: b.Slug, Name: b.Name, Kind: b.Kind,
				Description: b.Description, LaunchURL: b.LaunchURL, Disclosure: disc, Client: b.Client.params(), AccessMode: b.AccessMode, Hosts: b.Hosts,
				ForwardHeaders: b.ForwardHeaders})
			if err != nil {
				return nil, d.fail("create-app", err)
			}
			return &struct {
				ETag string `header:"ETag"`
				Body CreatedApplication
			}{ETag: etag(cr.App.Version), Body: CreatedApplication{Application: d.appDTO(cr.App, cr.Client), ClientSecret: cr.Secret}}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "get-application", Method: http.MethodGet, Path: "/tenants/{tenant}/applications/{app}",
		Summary: "Get an application", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *AppRef) (*struct {
			ETag string `header:"ETag"`
			Body Application
		}, error) {
			sc, err := d.operatorScope(ctx, in.Tenant)
			if err != nil {
				return nil, err
			}
			a, c, err := d.Apps.Get(ctx, sc, in.App)
			if err != nil {
				return nil, d.fail("get-app", err)
			}
			return &struct {
				ETag string `header:"ETag"`
				Body Application
			}{ETag: etag(a.Version), Body: d.appDTO(a, c)}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "update-application", Method: http.MethodPatch, Path: "/tenants/{tenant}/applications/{app}",
		Summary: "Update an application", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			AppRef
			ManagedBy
			IfMatch
			Body UpdateApplicationRequest
		}) (*struct {
			ETag string `header:"ETag"`
			Body Application
		}, error) {
			sc, err := d.operatorScope(ctx, in.Tenant)
			if err != nil {
				return nil, err
			}
			v, err := in.Version()
			if err != nil {
				return nil, err
			}
			b := in.Body
			var disc *apps.Disclosure
			if b.Disclosure != nil {
				x := apps.Disclosure(*b.Disclosure)
				disc = &x
			}
			a, c, err := d.Apps.Update(ctx, change(ctx, in.ManagedBy.ManagedBy), sc, in.App, apps.UpdateParams{Name: b.Name, Description: b.Description,
				LaunchURL: b.LaunchURL, Enabled: b.Enabled, Disclosure: disc, Client: b.Client.params(), AccessMode: b.AccessMode, Hosts: b.Hosts,
				ForwardHeaders: b.ForwardHeaders, IfVersion: v})
			if err != nil {
				return nil, d.fail("update-app", err)
			}
			return &struct {
				ETag string `header:"ETag"`
				Body Application
			}{ETag: etag(a.Version), Body: d.appDTO(a, c)}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "rotate-client-secret", Method: http.MethodPost, Path: "/tenants/{tenant}/applications/{app}/rotate-secret",
		Summary: "Issue a new client secret (needs a recent sign-in; the old secret stops working)", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *AppRef) (*struct{ Body ClientSecret }, error) {
			sc, err := d.operatorScope(ctx, in.Tenant)
			if err != nil {
				return nil, err
			}
			if err := d.stepUp(ctx); err != nil {
				return nil, err
			}
			secret, err := d.Apps.RotateSecret(ctx, change(ctx, ""), sc, in.App)
			if err != nil {
				return nil, d.fail("rotate-secret", err)
			}
			_, c, err := d.Apps.Get(ctx, sc, in.App)
			if err != nil || c == nil {
				return nil, d.fail("rotate-secret", err)
			}
			return &struct{ Body ClientSecret }{Body: ClientSecret{ClientID: c.ID, ClientSecret: secret}}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "delete-application", Method: http.MethodDelete, Path: "/tenants/{tenant}/applications/{app}",
		DefaultStatus: http.StatusNoContent, Summary: "Delete an application and its client", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			AppRef
			ManagedBy
			IfMatch
		}) (*struct{}, error) {
			sc, err := d.operatorScope(ctx, in.Tenant)
			if err != nil {
				return nil, err
			}
			v, err := in.Version()
			if err != nil {
				return nil, err
			}
			if err := d.Apps.Delete(ctx, change(ctx, in.ManagedBy.ManagedBy), sc, in.App, v); err != nil {
				return nil, d.fail("delete-app", err)
			}
			return &struct{}{}, nil
		})
}

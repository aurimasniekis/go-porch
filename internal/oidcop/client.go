package oidcop

import (
	"slices"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/aurimasniekis/go-porch/internal/store/db"
)

// client adapts an oauth_clients row to zitadel's op.Client.
type client struct {
	row            db.OauthClient
	sa             *db.ServiceAccount // set for service accounts (client credentials only)
	redirects      []string
	postLogout     []string
	grants         []oidc.GrantType
	scopes         []string
	audiences      []string
	accessTokenTTL time.Duration
	idTokenTTL     time.Duration
}

func newClient(r db.OauthClient) *client {
	c := &client{row: r, redirects: jsonList(r.RedirectUris), postLogout: jsonList(r.PostLogoutUris), scopes: jsonList(r.AllowedScopes),
		audiences: jsonList(r.Audiences), accessTokenTTL: time.Duration(r.AccessTokenTtlSecs) * time.Second,
		idTokenTTL: time.Duration(r.IDTokenTtlSecs) * time.Second}
	for _, g := range jsonList(r.GrantTypes) {
		c.grants = append(c.grants, oidc.GrantType(g))
	}
	return c
}

// newServiceAccountClient presents a service account as a confidential client limited to the client credentials grant.
func newServiceAccountClient(sa db.ServiceAccount) *client {
	r := db.OauthClient{ID: sa.ID, TenantID: sa.TenantID, ClientType: "confidential", ApplicationType: "web", SecretMac: sa.SecretMac,
		GrantTypes: `["client_credentials"]`, AllowedScopes: "[]", Audiences: sa.Audiences, RedirectUris: "[]", PostLogoutUris: "[]",
		SigningAlg: "ES256", AccessTokenTtlSecs: sa.AccessTokenTtlSecs, IDTokenTtlSecs: 600}
	c := newClient(r)
	c.sa = &sa
	return c
}

func (c *client) GetID() string                    { return c.row.ID }
func (c *client) RedirectURIs() []string           { return c.redirects }
func (c *client) PostLogoutRedirectURIs() []string { return c.postLogout }
func (c *client) ApplicationType() op.ApplicationType {
	switch c.row.ApplicationType {
	case "native":
		return op.ApplicationTypeNative
	case "user_agent":
		return op.ApplicationTypeUserAgent
	}
	return op.ApplicationTypeWeb
}

func (c *client) AuthMethod() oidc.AuthMethod {
	if c.row.ClientType == "confidential" {
		return oidc.AuthMethodBasic
	}
	return oidc.AuthMethodNone
}
func (c *client) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}
func (c *client) GrantTypes() []oidc.GrantType        { return c.grants }
func (c *client) LoginURL(id string) string           { return "/oauth2/continue?ar=" + id }
func (c *client) AccessTokenType() op.AccessTokenType { return op.AccessTokenTypeJWT }
func (c *client) IDTokenLifetime() time.Duration      { return c.idTokenTTL }
func (c *client) DevMode() bool                       { return false }
func (c *client) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}

func (c *client) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}
func (c *client) IsScopeAllowed(scope string) bool     { return slices.Contains(c.scopes, scope) }
func (c *client) IDTokenUserinfoClaimsAssertion() bool { return false }
func (c *client) ClockSkew() time.Duration             { return 0 }
func (c *client) confidential() bool                   { return c.row.ClientType == "confidential" }
func (c *client) hasGrant(g oidc.GrantType) bool       { return slices.Contains(c.grants, g) }

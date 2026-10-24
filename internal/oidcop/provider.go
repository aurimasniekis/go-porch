// Package oidcop is Porch's OpenID Provider (ADR-0013, ADR-0014, ADR-0030). It implements zitadel/oidc's op.Server, so
// zitadel parses and validates protocol requests (redirect URI matching including RFC 8252 loopback ports, client
// authentication parsing, error formatting) while Porch issues every token itself: ES256/RS256 ID tokens for the
// client, RFC 9068 access tokens (typ at+jwt) for API audiences, and opaque rotating refresh tokens with family reuse
// detection.
package oidcop

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/aurimasniekis/go-porch/internal/apps"
	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/authz"
	"github.com/aurimasniekis/go-porch/internal/clock"
	"github.com/aurimasniekis/go-porch/internal/domain"
	"github.com/aurimasniekis/go-porch/internal/ids"
	"github.com/aurimasniekis/go-porch/internal/keyring"
	"github.com/aurimasniekis/go-porch/internal/obs/metrics"
	"github.com/aurimasniekis/go-porch/internal/session"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/store/db"
	"github.com/aurimasniekis/go-porch/internal/tenancy"
)

// Endpoint paths.
const (
	PathAuthorize  = "/oauth2/authorize"
	PathToken      = "/oauth2/token" //nolint:gosec // an endpoint path, not a credential
	PathUserinfo   = "/oauth2/userinfo"
	PathRevoke     = "/oauth2/revoke"
	PathIntrospect = "/oauth2/introspect"
	PathEndSession = "/oauth2/end_session"
	PathContinue   = "/oauth2/continue"
	PathJWKS       = "/jwks"
)

// Lifetimes.
const (
	authRequestTTL = 10 * time.Minute
	codeTTL        = time.Minute
	// maxPorchClaimBytes caps the namespaced claim; groups then roles are dropped beyond it (porch.truncated).
	maxPorchClaimBytes = 2048
)

// Provider implements op.Server.
type Provider struct {
	op.UnimplementedServer

	Issuer   string
	Store    *store.Store
	Keyring  *keyring.Keyring
	Audit    *audit.Writer
	Signing  *Keys
	Apps     *apps.Service
	Sessions *session.Manager
	Tenants  *tenancy.Service
	Engine   *authz.Engine
	Clock    clock.Clock
	Metrics  *metrics.Metrics
	Log      *slog.Logger
}

func (p *Provider) now() time.Time { return p.Clock.Now() }

// Handler returns the protocol handler for the paths above plus discovery. CORS is allowed only for origins
// registered on some client (SPA clients), and never for the authorize or end-session endpoints.
func (p *Provider) Handler() http.Handler {
	eps := op.Endpoints{
		Authorization: op.NewEndpoint(PathAuthorize),
		Token:         op.NewEndpoint(PathToken),
		Introspection: op.NewEndpoint(PathIntrospect),
		Userinfo:      op.NewEndpoint(PathUserinfo),
		Revocation:    op.NewEndpoint(PathRevoke),
		EndSession:    op.NewEndpoint(PathEndSession),
		JwksURI:       op.NewEndpoint(PathJWKS),
	}
	h := op.RegisterServer(p, eps, op.WithServerCORSOptions(nil))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" && corsPath(r.URL.Path) && p.originAllowed(r.Context(), o) {
			w.Header().Set("Access-Control-Allow-Origin", o)
			w.Header().Set("Vary", "Origin")
			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				w.Header().Set("Access-Control-Max-Age", "600")
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		h.ServeHTTP(w, r.WithContext(op.ContextWithIssuer(r.Context(), p.Issuer)))
	})
}

func corsPath(path string) bool {
	switch path {
	case PathToken, PathUserinfo, PathRevoke, PathJWKS, oidc.DiscoveryEndpoint:
		return true
	}
	return false
}

func (p *Provider) originAllowed(ctx context.Context, origin string) bool {
	rows, err := p.Store.R().ListAllowedOrigins(ctx)
	if err != nil {
		return false
	}
	for _, r := range rows {
		if slices.Contains(jsonList(r), origin) {
			return true
		}
	}
	return false
}

// Health implements op.Server.
func (p *Provider) Health(context.Context, *op.Request[struct{}]) (*op.Response, error) {
	return op.NewResponse(op.Status{Status: "ok"}), nil
}

// Ready implements op.Server.
func (p *Provider) Ready(context.Context, *op.Request[struct{}]) (*op.Response, error) {
	return op.NewResponse(op.Status{Status: "ok"}), nil
}

// Discovery implements op.Server.
func (p *Provider) Discovery(context.Context, *op.Request[struct{}]) (*op.Response, error) {
	iss := p.Issuer
	return op.NewResponse(&discovery{DiscoveryConfiguration: oidc.DiscoveryConfiguration{
		Issuer:                                    iss,
		AuthorizationEndpoint:                     iss + PathAuthorize,
		TokenEndpoint:                             iss + PathToken,
		IntrospectionEndpoint:                     iss + PathIntrospect,
		UserinfoEndpoint:                          iss + PathUserinfo,
		RevocationEndpoint:                        iss + PathRevoke,
		EndSessionEndpoint:                        iss + PathEndSession,
		JwksURI:                                   iss + PathJWKS,
		ScopesSupported:                           []string{"openid", "profile", "email", "offline_access", "groups"},
		ResponseTypesSupported:                    []string{"code"},
		ResponseModesSupported:                    []string{"query"},
		GrantTypesSupported:                       []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken, oidc.GrantTypeClientCredentials},
		SubjectTypesSupported:                     []string{"public"},
		IDTokenSigningAlgValuesSupported:          []string{AlgES256, AlgRS256},
		TokenEndpointAuthMethodsSupported:         []oidc.AuthMethod{oidc.AuthMethodBasic, oidc.AuthMethodPost, oidc.AuthMethodNone},
		IntrospectionEndpointAuthMethodsSupported: []oidc.AuthMethod{oidc.AuthMethodBasic, oidc.AuthMethodPost},
		RevocationEndpointAuthMethodsSupported:    []oidc.AuthMethod{oidc.AuthMethodBasic, oidc.AuthMethodPost, oidc.AuthMethodNone},
		CodeChallengeMethodsSupported:             []oidc.CodeChallengeMethod{oidc.CodeChallengeMethodS256},
		ClaimsSupported:                           []string{"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "amr", "azp", "at_hash", "name", "email", "email_verified", "porch"},
		RequestParameterSupported:                 false,
		RequestURIParameterSupported:              false,
	}, ISSParameterSupported: true}), nil
}

// discovery adds RFC 9207's authorization_response_iss_parameter_supported.
type discovery struct {
	oidc.DiscoveryConfiguration
	ISSParameterSupported bool `json:"authorization_response_iss_parameter_supported"`
}

// Keys implements op.Server.
func (p *Provider) Keys(context.Context, *op.Request[struct{}]) (*op.Response, error) {
	return op.NewResponse(p.Signing.JWKS()), nil
}

func (p *Provider) loadClient(ctx context.Context, id string) (*client, error) {
	if id == "" || len(id) > 64 {
		return nil, oidc.ErrInvalidClient().WithDescription("unknown client")
	}
	r, err := p.Store.R().GetClient(ctx, id)
	if err != nil {
		return nil, oidc.ErrInvalidClient().WithDescription("unknown client")
	}
	app, err := p.Store.R().GetApplicationByID(ctx, r.AppID)
	if err != nil || app.Enabled != 1 {
		return nil, oidc.ErrInvalidClient().WithDescription("application disabled")
	}
	return newClient(r), nil
}

// VerifyClient implements op.Server: confidential clients must present their secret; public clients must not.
func (p *Provider) VerifyClient(ctx context.Context, r *op.Request[op.ClientCredentials]) (op.Client, error) {
	cc := r.Data
	if cc.ClientAssertion != "" || cc.ClientAssertionType != "" {
		return nil, op.NewStatusError(oidc.ErrInvalidClient().WithDescription("client assertions are not supported"), http.StatusUnauthorized)
	}
	c, err := p.loadClient(ctx, cc.ClientID)
	if err != nil {
		return nil, err
	}
	if c.confidential() {
		if !p.Apps.VerifySecret(c.row, cc.ClientSecret) {
			p.auditTx(ctx, audit.Event{Actor: audit.Actor{Type: audit.ActorClient, ID: c.row.ID}, TenantID: c.row.TenantID, Action: "oidc.client_auth",
				Outcome: audit.OutcomeFailure, ReasonCode: "bad_secret"})
			return nil, op.NewStatusError(oidc.ErrInvalidClient().WithDescription("client authentication failed"), http.StatusUnauthorized)
		}
	} else if cc.ClientSecret != "" {
		return nil, op.NewStatusError(oidc.ErrInvalidClient().WithDescription("public clients must not send a secret"), http.StatusUnauthorized)
	}
	return c, nil
}

// VerifyAuthRequest implements op.Server.
func (p *Provider) VerifyAuthRequest(ctx context.Context, r *op.Request[oidc.AuthRequest]) (*op.ClientRequest[oidc.AuthRequest], error) {
	c, err := p.loadClient(ctx, r.Data.ClientID)
	if err != nil {
		return nil, err
	}
	return &op.ClientRequest[oidc.AuthRequest]{Request: r, Client: c}, nil
}

// Authorize implements op.Server: validates the rest of the request (errors reach the client's redirect URI) and sends
// the browser to /oauth2/continue, which handles the session, step-up, access decision and code.
func (p *Provider) Authorize(ctx context.Context, r *op.ClientRequest[oidc.AuthRequest]) (*op.Redirect, error) {
	ar := r.Data
	c := r.Client.(*client)
	if ar.RequestParam != "" {
		return nil, oidc.ErrRequestNotSupported()
	}
	if ar.ResponseMode != "" && ar.ResponseMode != oidc.ResponseModeQuery {
		return nil, oidc.ErrInvalidRequest().WithDescription("only response_mode=query is supported")
	}
	if !c.hasGrant(oidc.GrantTypeCode) {
		return nil, oidc.ErrUnauthorizedClient().WithDescription("client may not use the authorization code grant")
	}
	pkceRequired := c.row.RequirePkce == 1 || !c.confidential()
	switch {
	case ar.CodeChallenge == "" && pkceRequired:
		return nil, oidc.ErrInvalidRequest().WithDescription("PKCE (code_challenge with S256) is required")
	case ar.CodeChallenge != "" && ar.CodeChallengeMethod != oidc.CodeChallengeMethodS256:
		return nil, oidc.ErrInvalidRequest().WithDescription("code_challenge_method must be S256")
	}
	if !slices.Contains(ar.Scopes, oidc.ScopeOpenID) {
		return nil, oidc.ErrInvalidScope().WithDescription("the openid scope is required")
	}
	scopes := slices.DeleteFunc(slices.Clone([]string(ar.Scopes)), func(s string) bool { return !c.IsScopeAllowed(s) })
	resources := r.URL.Query()["resource"]
	for _, res := range resources {
		if !slices.Contains(c.audiences, res) {
			return nil, (&oidc.Error{ErrorType: "invalid_target", Description: "resource is not registered for this client"})
		}
	}
	var maxAge sql.NullInt64
	if ar.MaxAge != nil {
		maxAge = sql.NullInt64{Int64: int64(*ar.MaxAge), Valid: true} //nolint:gosec // bounded by uint parsing
	}
	id := ids.New(ids.AuthRequest)
	err := p.Store.W().TxNamed(ctx, "oidc.auth_request", func(tx *store.Tx) error {
		return tx.Q.InsertAuthRequest(ctx, db.InsertAuthRequestParams{ID: id, ClientID: c.row.ID, TenantID: c.row.TenantID, RedirectUri: ar.RedirectURI,
			Scopes: mustJSON(scopes), State: ar.State, Nonce: ar.Nonce, CodeChallenge: ar.CodeChallenge, ResponseMode: string(ar.ResponseMode),
			Prompt: mustJSON(nonNil(ar.Prompt)), MaxAge: maxAge, LoginHint: ar.LoginHint, Resources: mustJSON(nonNil(resources)),
			CreatedAt: tx.NowMicros(), ExpiresAt: tx.Now.Add(authRequestTTL).UnixMicro()})
	})
	if err != nil {
		return nil, oidc.ErrServerError().WithParent(err)
	}
	return op.NewRedirect(PathContinue + "?ar=" + id), nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (p *Provider) codeMAC(code string) ([][]byte, error) {
	return p.Keyring.MACAll(keyring.PurposeToken, []byte("porch/auth-code/v1|"+code))
}

func (p *Provider) refreshMACs(token string) ([][]byte, error) {
	return p.Keyring.MACAll(keyring.PurposeToken, []byte("porch/refresh/v1|"+token))
}

// CodeExchange implements op.Server.
func (p *Provider) CodeExchange(ctx context.Context, r *op.ClientRequest[oidc.AccessTokenRequest]) (*op.Response, error) {
	c := r.Client.(*client)
	macs, err := p.codeMAC(r.Data.Code)
	if err != nil {
		return nil, oidc.ErrServerError().WithParent(err)
	}
	var code db.AuthCode
	found := false
	for _, m := range macs {
		if row, err := p.Store.R().GetAuthCode(ctx, m); err == nil {
			code, found = row, true
			break
		}
	}
	if !found || code.ClientID != c.row.ID {
		return nil, oidc.ErrInvalidGrant().WithDescription("invalid authorization code")
	}
	used := false
	err = p.Store.W().TxNamed(ctx, "oidc.use_code", func(tx *store.Tx) error {
		n, err := tx.Q.UseAuthCode(ctx, db.UseAuthCodeParams{UsedAt: sqlMicros(tx.Now), Mac: code.Mac})
		if err != nil {
			return err
		}
		if n == 1 {
			return nil
		}
		// Replay (RFC 6749 §4.1.2): revoke whatever the first exchange issued.
		used = true
		cur, err := tx.Q.GetAuthCode(ctx, code.Mac)
		if err != nil {
			return err
		}
		if cur.FamilyID.Valid {
			if _, err := tx.Q.RevokeRefreshFamily(ctx, db.RevokeRefreshFamilyParams{RevokedAt: sqlMicros(tx.Now), RevokeReason: domain.NullStr("code_replay"),
				FamilyID: cur.FamilyID.String}); err != nil {
				return err
			}
		}
		if cur.AccessJti.Valid {
			if err := tx.Q.RevokeAccessToken(ctx, db.RevokeAccessTokenParams{Jti: cur.AccessJti.String, ExpiresAt: tx.Now.Add(time.Hour).UnixMicro(),
				Reason: "code_replay"}); err != nil {
				return err
			}
		}
		_, err = p.Audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorClient, ID: c.row.ID}, TenantID: c.row.TenantID,
			Action: "oidc.code_replay", Outcome: audit.OutcomeDenied, ReasonCode: "code_reused", Target: audit.Target{Type: "user", ID: cur.UserID}})
		return err
	})
	if err != nil {
		return nil, oidc.ErrServerError().WithParent(err)
	}
	if used {
		return nil, oidc.ErrInvalidGrant().WithDescription("authorization code already used; tokens issued from it were revoked")
	}
	now := p.now()
	if !now.Before(domain.FromMicros(code.ExpiresAt)) {
		return nil, oidc.ErrInvalidGrant().WithDescription("authorization code expired")
	}
	if r.Data.RedirectURI != code.RedirectUri {
		return nil, oidc.ErrInvalidGrant().WithDescription("redirect_uri does not match the authorization request")
	}
	if code.CodeChallenge != "" {
		sum := sha256.Sum256([]byte(r.Data.CodeVerifier))
		if r.Data.CodeVerifier == "" || subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(code.CodeChallenge)) != 1 {
			return nil, oidc.ErrInvalidGrant().WithDescription("PKCE verification failed")
		}
	} else if r.Data.CodeVerifier != "" {
		return nil, oidc.ErrInvalidGrant().WithDescription("unexpected code_verifier")
	}
	g := grant{clientID: c.row.ID, tenantID: code.TenantID, userID: code.UserID, scopes: jsonList(code.Scopes), resources: jsonList(code.Resources),
		authTime: domain.FromMicros(code.AuthTime), amr: jsonList(code.Amr), nonce: code.Nonce}
	if err := p.checkStillAllowed(ctx, c, g); err != nil {
		return nil, err
	}
	resp, family, jti, err := p.issue(ctx, c, g, true, "")
	if err != nil {
		return nil, err
	}
	_ = p.Store.W().TxNamed(ctx, "oidc.code_tokens", func(tx *store.Tx) error {
		return tx.Q.SetAuthCodeTokens(ctx, db.SetAuthCodeTokensParams{FamilyID: domain.NullStr(family), AccessJti: domain.NullStr(jti), Mac: code.Mac})
	})
	return op.NewResponse(resp), nil
}

// checkStillAllowed re-runs the access decision at every token issuance (app:access on the client's application). Token
// requests come from the application's server, so there is no browser context: conditions that depend on the network
// evaluate against an empty client address and fail closed.
func (p *Provider) checkStillAllowed(ctx context.Context, c *client, g grant) error {
	u, err := p.Store.R().GetUser(ctx, g.userID)
	if err != nil || u.Status != "active" {
		return oidc.ErrInvalidGrant().WithDescription("user is not active")
	}
	d, err := p.Engine.Check(ctx, authz.Request{TenantID: c.row.TenantID, Subject: authz.Subject{Type: "user", ID: g.userID, AuthTime: g.authTime},
		Action: authz.PermAppAccess, Resource: authz.Resource{Type: "app", ID: c.row.AppID}})
	if err != nil {
		return oidc.ErrServerError().WithParent(err)
	}
	if !d.Allowed {
		return oidc.ErrInvalidGrant().WithDescription("user no longer has access to this application")
	}
	return nil
}

// RefreshToken implements op.Server: rotation with reuse detection (ADR-0014).
func (p *Provider) RefreshToken(ctx context.Context, r *op.ClientRequest[oidc.RefreshTokenRequest]) (*op.Response, error) {
	c := r.Client.(*client)
	if !c.hasGrant(oidc.GrantTypeRefreshToken) {
		return nil, oidc.ErrUnauthorizedClient()
	}
	macs, err := p.refreshMACs(r.Data.RefreshToken)
	if err != nil {
		return nil, oidc.ErrServerError().WithParent(err)
	}
	var rt db.RefreshToken
	found := false
	for _, m := range macs {
		if row, err := p.Store.R().GetRefreshTokenByMAC(ctx, m); err == nil {
			rt, found = row, true
			break
		}
	}
	if !found || rt.ClientID != c.row.ID {
		return nil, oidc.ErrInvalidGrant().WithDescription("invalid refresh token")
	}
	now := p.now()
	inst, err := p.Store.R().GetInstallation(ctx)
	if err != nil {
		return nil, oidc.ErrServerError().WithParent(err)
	}
	u, err := p.Store.R().GetUser(ctx, rt.UserID)
	if err != nil {
		return nil, oidc.ErrInvalidGrant()
	}
	switch {
	case rt.State == "rotated":
		err := p.Store.W().TxNamed(ctx, "oidc.refresh_reuse", func(tx *store.Tx) error {
			if _, err := tx.Q.RevokeRefreshFamily(ctx, db.RevokeRefreshFamilyParams{RevokedAt: sqlMicros(tx.Now), RevokeReason: domain.NullStr("reuse_detected"),
				FamilyID: rt.FamilyID}); err != nil {
				return err
			}
			_, err := p.Audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorClient, ID: c.row.ID}, TenantID: rt.TenantID,
				Action: "oidc.refresh_reuse", Outcome: audit.OutcomeDenied, ReasonCode: "reuse_detected", Target: audit.Target{Type: "user", ID: rt.UserID},
				Details: map[string]any{"family_id": rt.FamilyID}})
			return err
		})
		if err != nil {
			return nil, oidc.ErrServerError().WithParent(err)
		}
		return nil, oidc.ErrInvalidGrant().WithDescription("refresh token reuse detected; the whole token family was revoked")
	case rt.State != "active",
		!now.Before(domain.FromMicros(rt.FamilyExpiresAt)),
		!now.Before(domain.FromMicros(rt.IdleExpiresAt)),
		rt.InstallEpoch != inst.SecurityEpoch,
		rt.UserEpoch != u.SecurityEpoch:
		return nil, oidc.ErrInvalidGrant().WithDescription("refresh token expired or revoked")
	}
	scopes := jsonList(rt.Scopes)
	if len(r.Data.Scopes) > 0 {
		for _, s := range r.Data.Scopes {
			if !slices.Contains(scopes, s) {
				return nil, oidc.ErrInvalidScope().WithDescription("scope %q was not granted", s)
			}
		}
		scopes = r.Data.Scopes
	}
	g := grant{clientID: c.row.ID, tenantID: rt.TenantID, userID: rt.UserID, scopes: scopes, resources: jsonList(rt.Resources),
		authTime: domain.FromMicros(rt.AuthTime), amr: jsonList(rt.Amr), familyID: rt.FamilyID, parentID: rt.ID,
		familyExpires: domain.FromMicros(rt.FamilyExpiresAt)}
	if res := r.Form["resource"]; len(res) > 0 {
		for _, x := range res {
			if !slices.Contains(g.resources, x) && !slices.Contains(c.audiences, x) {
				return nil, &oidc.Error{ErrorType: "invalid_target", Description: "resource not allowed"}
			}
		}
		g.resources = res
	}
	if err := p.checkStillAllowed(ctx, c, g); err != nil {
		return nil, err
	}
	resp, _, _, err := p.issue(ctx, c, g, slices.Contains(scopes, oidc.ScopeOpenID), rt.ID)
	if err != nil {
		return nil, err
	}
	return op.NewResponse(resp), nil
}

// ClientCredentialsExchange implements op.Server (service-to-service access tokens; no ID or refresh token).
func (p *Provider) ClientCredentialsExchange(ctx context.Context, r *op.ClientRequest[oidc.ClientCredentialsRequest]) (*op.Response, error) {
	c := r.Client.(*client)
	if !c.confidential() || !c.hasGrant(oidc.GrantTypeClientCredentials) {
		return nil, oidc.ErrUnauthorizedClient()
	}
	for _, s := range r.Data.Scope {
		if s == oidc.ScopeOpenID || s == oidc.ScopeOfflineAccess {
			return nil, oidc.ErrInvalidScope().WithDescription("%s is not available for client credentials", s)
		}
	}
	resources := r.Form["resource"]
	for _, x := range resources {
		if !slices.Contains(c.audiences, x) {
			return nil, &oidc.Error{ErrorType: "invalid_target", Description: "resource not registered"}
		}
	}
	if len(resources) == 0 {
		resources = c.audiences
	}
	if len(resources) == 0 {
		return nil, &oidc.Error{ErrorType: "invalid_target", Description: "client has no API audience configured"}
	}
	g := grant{clientID: c.row.ID, tenantID: c.row.TenantID, scopes: r.Data.Scope, resources: resources, authTime: p.now()}
	at, exp, jti, err := p.accessToken(ctx, c, g, c.row.ID)
	if err != nil {
		return nil, err
	}
	p.Metrics.TokenIssued("access_token")
	p.auditTx(ctx, audit.Event{Actor: audit.Actor{Type: audit.ActorClient, ID: c.row.ID}, TenantID: c.row.TenantID, Action: "oidc.token_issued",
		Details: map[string]any{"grant": "client_credentials", "jti": jti}})
	return op.NewResponse(&oidc.AccessTokenResponse{AccessToken: at, TokenType: oidc.BearerToken, ExpiresIn: uint64(time.Until(exp).Seconds()), //nolint:gosec // positive
		Scope: r.Data.Scope}), nil
}

func (p *Provider) auditTx(ctx context.Context, ev audit.Event) {
	_ = p.Store.W().TxNamed(ctx, "oidc.audit", func(tx *store.Tx) error {
		_, err := p.Audit.Append(ctx, tx, ev)
		return err
	})
}

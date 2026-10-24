package oidcop

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/domain"
	"github.com/aurimasniekis/go-porch/internal/session"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/store/db"
)

var errInvalidToken = errors.New("invalid token")

// verifyAccessToken checks signature, typ at+jwt, issuer, expiry and the revocation list.
func (p *Provider) verifyAccessToken(ctx context.Context, token string) (accessTokenClaims, error) {
	var c accessTokenClaims
	payload, typ, err := p.Signing.Verify(token)
	if err != nil || !strings.EqualFold(typ, "at+jwt") {
		return c, errInvalidToken
	}
	if err := json.Unmarshal(payload, &c); err != nil || c.Issuer != p.Issuer || c.JTI == "" {
		return c, errInvalidToken
	}
	if !p.now().Before(time.Unix(c.Expiry, 0)) {
		return c, errInvalidToken
	}
	if n, err := p.Store.R().IsAccessTokenRevoked(ctx, c.JTI); err != nil || n > 0 {
		return c, errInvalidToken
	}
	return c, nil
}

// Introspect implements op.Server (RFC 7662). Only confidential clients may introspect, and only tokens issued to them
// or addressed to them (aud).
func (p *Provider) Introspect(ctx context.Context, r *op.Request[op.IntrospectionRequest]) (*op.Response, error) {
	cc := r.Data.ClientCredentials
	if cc == nil {
		return nil, oidc.ErrInvalidClient()
	}
	caller, err := p.VerifyClient(ctx, &op.Request[op.ClientCredentials]{Data: cc})
	if err != nil {
		return nil, err
	}
	cl := caller.(*client)
	if !cl.confidential() {
		return nil, oidc.ErrInvalidClient().WithDescription("introspection requires a confidential client")
	}
	token := r.Data.Token
	if at, err := p.verifyAccessToken(ctx, token); err == nil {
		if at.ClientID != cl.row.ID && !slices.Contains(at.Audience, cl.row.ID) && !anyIn(at.Audience, cl.audiences) {
			return op.NewResponse(&oidc.IntrospectionResponse{Active: false}), nil
		}
		resp := &oidc.IntrospectionResponse{Active: true, Scope: strings.Fields(at.Scope), ClientID: at.ClientID, TokenType: "access_token",
			Expiration: oidc.FromTime(time.Unix(at.Expiry, 0)), IssuedAt: oidc.FromTime(time.Unix(at.IssuedAt, 0)), Subject: at.Subject,
			Audience: at.Audience, Issuer: at.Issuer, JWTID: at.JTI}
		if at.AuthTime > 0 {
			resp.AuthTime = oidc.FromTime(time.Unix(at.AuthTime, 0))
		}
		resp.Claims = map[string]any{"porch": at.Porch}
		return op.NewResponse(resp), nil
	}
	macs, err := p.refreshMACs(token)
	if err == nil {
		for _, m := range macs {
			rt, err := p.Store.R().GetRefreshTokenByMAC(ctx, m)
			if err != nil {
				continue
			}
			active := rt.State == "active" && rt.ClientID == cl.row.ID && p.now().Before(domain.FromMicros(rt.IdleExpiresAt)) &&
				p.now().Before(domain.FromMicros(rt.FamilyExpiresAt))
			if !active {
				break
			}
			u, _ := p.Store.R().GetUser(ctx, rt.UserID)
			return op.NewResponse(&oidc.IntrospectionResponse{Active: true, Scope: jsonList(rt.Scopes), ClientID: rt.ClientID, TokenType: "refresh_token",
				Expiration: oidc.FromTime(domain.FromMicros(rt.IdleExpiresAt)), IssuedAt: oidc.FromTime(domain.FromMicros(rt.CreatedAt)),
				Subject: u.PublicID, Issuer: p.Issuer}), nil
		}
	}
	return op.NewResponse(&oidc.IntrospectionResponse{Active: false}), nil
}

func anyIn(a, b []string) bool {
	for _, x := range a {
		if slices.Contains(b, x) {
			return true
		}
	}
	return false
}

// UserInfo implements op.Server.
func (p *Provider) UserInfo(ctx context.Context, r *op.Request[oidc.UserInfoRequest]) (*op.Response, error) {
	at, err := p.verifyAccessToken(ctx, r.Data.AccessToken)
	if err != nil {
		return nil, op.NewStatusError(oidc.ErrAccessDenied().WithDescription("invalid access token"), http.StatusUnauthorized)
	}
	u, err := p.Store.R().GetUserByPublicID(ctx, at.Subject)
	if err != nil || u.Status != "active" {
		return nil, op.NewStatusError(oidc.ErrAccessDenied().WithDescription("invalid access token"), http.StatusUnauthorized)
	}
	c, err := p.loadClient(ctx, at.ClientID)
	if err != nil {
		return nil, op.NewStatusError(oidc.ErrAccessDenied(), http.StatusUnauthorized)
	}
	scopes := strings.Fields(at.Scope)
	tenantID := ""
	if t, ok := at.Porch["tenant"].(map[string]any); ok {
		tenantID, _ = t["id"].(string)
	}
	si, err := p.subject(ctx, grant{userID: u.ID, tenantID: tenantID})
	if err != nil {
		return nil, oidc.ErrServerError().WithParent(err)
	}
	info := &oidc.UserInfo{Subject: si.publicID}
	if slices.Contains(scopes, oidc.ScopeProfile) {
		info.Name = si.name
	}
	d := p.disclosure(ctx, c)
	if slices.Contains(scopes, oidc.ScopeEmail) && d.Email && si.email != "" {
		info.Email, info.EmailVerified = si.email, oidc.Bool(si.emailVerified)
	}
	info.AppendClaims("porch", porchClaim(si, d, scopes))
	return op.NewResponse(info), nil
}

// Revocation implements op.Server (RFC 7009): a refresh token revokes its family; an access token is denylisted.
// Unknown tokens and tokens of other clients succeed silently.
func (p *Provider) Revocation(ctx context.Context, r *op.ClientRequest[oidc.RevocationRequest]) (*op.Response, error) {
	cl := r.Client.(*client)
	token := r.Data.Token
	if at, err := p.verifyAccessToken(ctx, token); err == nil {
		if at.ClientID == cl.row.ID {
			p.auditStore(ctx, func(tx *store.Tx) error {
				return tx.Q.RevokeAccessToken(ctx, db.RevokeAccessTokenParams{Jti: at.JTI, ExpiresAt: time.Unix(at.Expiry, 0).UnixMicro(), Reason: "revoked"})
			}, audit.Event{Actor: audit.Actor{Type: audit.ActorClient, ID: cl.row.ID}, TenantID: cl.row.TenantID, Action: "oidc.token_revoked",
				Details: map[string]any{"kind": "access_token", "jti": at.JTI}})
		}
		return op.NewResponse(struct{}{}), nil
	}
	if macs, err := p.refreshMACs(token); err == nil {
		for _, m := range macs {
			rt, err := p.Store.R().GetRefreshTokenByMAC(ctx, m)
			if err != nil || rt.ClientID != cl.row.ID {
				continue
			}
			p.auditStore(ctx, func(tx *store.Tx) error {
				_, err := tx.Q.RevokeRefreshFamily(ctx, db.RevokeRefreshFamilyParams{RevokedAt: sqlMicros(tx.Now), RevokeReason: domain.NullStr("revoked"),
					FamilyID: rt.FamilyID})
				return err
			}, audit.Event{Actor: audit.Actor{Type: audit.ActorClient, ID: cl.row.ID}, TenantID: rt.TenantID, Action: "oidc.token_revoked",
				Target: audit.Target{Type: "user", ID: rt.UserID}, Details: map[string]any{"kind": "refresh_token", "family_id": rt.FamilyID}})
			break
		}
	}
	return op.NewResponse(struct{}{}), nil
}

func (p *Provider) auditStore(ctx context.Context, fn func(tx *store.Tx) error, ev audit.Event) {
	_ = p.Store.W().TxNamed(ctx, "oidc.change", func(tx *store.Tx) error {
		if err := fn(tx); err != nil {
			return err
		}
		_, err := p.Audit.Append(ctx, tx, ev)
		return err
	})
}

// EndSession implements op.Server (RP-initiated logout): ends the Porch browser session and revokes this client's
// refresh tokens for the user. There is no front- or back-channel logout in v1 (ADR-0013).
func (p *Provider) EndSession(ctx context.Context, r *op.Request[oidc.EndSessionRequest]) (*op.Redirect, error) {
	req := r.Data
	clientID, subject := req.ClientID, ""
	if req.IdTokenHint != "" {
		payload, _, err := p.Signing.Verify(req.IdTokenHint) // expired hints are fine; the signature must verify
		if err != nil {
			return nil, oidc.ErrInvalidRequest().WithDescription("invalid id_token_hint")
		}
		var hint struct {
			Iss string   `json:"iss"`
			Sub string   `json:"sub"`
			Aud []string `json:"aud"`
		}
		if err := json.Unmarshal(payload, &hint); err != nil || hint.Iss != p.Issuer || len(hint.Aud) == 0 {
			return nil, oidc.ErrInvalidRequest().WithDescription("invalid id_token_hint")
		}
		if clientID != "" && !slices.Contains(hint.Aud, clientID) {
			return nil, oidc.ErrInvalidRequest().WithDescription("id_token_hint was not issued to client_id")
		}
		clientID, subject = hint.Aud[0], hint.Sub
	}
	target := "/login?logged_out=1"
	if req.PostLogoutRedirectURI != "" {
		c, err := p.loadClient(ctx, clientID)
		if err != nil || !slices.Contains(c.postLogout, req.PostLogoutRedirectURI) {
			return nil, oidc.ErrInvalidRequest().WithDescription("post_logout_redirect_uri is not registered for this client")
		}
		u, _ := url.Parse(req.PostLogoutRedirectURI)
		if req.State != "" {
			q := u.Query()
			q.Set("state", req.State)
			u.RawQuery = q.Encode()
		}
		target = u.String()
	}
	sess, _ := p.Sessions.Validate(ctx, cookieValue(r.Header, session.CookieName))
	userID := ""
	if subject != "" {
		if u, err := p.Store.R().GetUserByPublicID(ctx, subject); err == nil {
			userID = u.ID
		}
	} else if sess != nil {
		userID = sess.UserID
	}
	if userID != "" {
		ev := audit.Event{Actor: audit.Actor{Type: audit.ActorUser, ID: userID}, Action: "oidc.end_session", Target: audit.Target{Type: "oauth_client", ID: clientID}}
		p.auditStore(ctx, func(tx *store.Tx) error {
			if sess != nil && sess.UserID == userID {
				if err := p.Sessions.RevokeTx(ctx, tx, sess.SessionID, "rp_logout"); err != nil {
					return err
				}
			}
			if clientID != "" {
				_, err := tx.Q.RevokeUserClientRefresh(ctx, db.RevokeUserClientRefreshParams{RevokedAt: sqlMicros(tx.Now), RevokeReason: domain.NullStr("rp_logout"),
					UserID: userID, ClientID: clientID})
				return err
			}
			return nil
		}, ev)
	}
	return op.NewRedirect(target), nil
}

func cookieValue(h http.Header, name string) string {
	r := &http.Request{Header: h}
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

package oidcop

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"slices"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/aurimasniekis/go-porch/internal/apps"
	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/domain"
	"github.com/aurimasniekis/go-porch/internal/ids"
	"github.com/aurimasniekis/go-porch/internal/keyring"
	"github.com/aurimasniekis/go-porch/internal/session"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/store/db"
)

// grant is everything a token issuance needs.
type grant struct {
	clientID, tenantID, userID string
	scopes, resources, amr     []string
	authTime                   time.Time
	authMethod                 string
	nonce                      string
	familyID, parentID         string
	familyExpires              time.Time
}

// accessTokenClaims are RFC 9068 claims plus Porch's namespaced claim.
type accessTokenClaims struct {
	Issuer   string         `json:"iss"`
	Subject  string         `json:"sub"`
	Audience []string       `json:"aud"`
	Expiry   int64          `json:"exp"`
	IssuedAt int64          `json:"iat"`
	JTI      string         `json:"jti"`
	ClientID string         `json:"client_id"`
	Scope    string         `json:"scope,omitempty"`
	AuthTime int64          `json:"auth_time,omitempty"`
	AMR      []string       `json:"amr,omitempty"`
	Porch    map[string]any `json:"porch,omitempty"`
}

// subjectInfo describes a user for claims.
type subjectInfo struct {
	publicID, name, email string
	emailVerified         bool
	tenantID, tenantSlug  string
	groups                []string
}

func (p *Provider) subject(ctx context.Context, g grant) (subjectInfo, error) {
	t, err := p.Store.R().GetTenant(ctx, g.tenantID)
	if err != nil {
		return subjectInfo{}, err
	}
	si := subjectInfo{tenantID: t.ID, tenantSlug: t.Slug}
	if g.userID == "" {
		return si, nil
	}
	u, err := p.Store.R().GetUser(ctx, g.userID)
	if err != nil {
		return subjectInfo{}, err
	}
	si.publicID, si.name, si.email = u.PublicID, u.DisplayName, u.PrimaryEmail.String
	if si.email != "" {
		emails, _ := p.Store.R().ListUserEmails(ctx, u.ID)
		for _, e := range emails {
			if e.Email == si.email && e.Verified == 1 {
				si.emailVerified = true
			}
		}
	}
	si.groups, err = p.Store.R().ListUserGroupSlugs(ctx, db.ListUserGroupSlugsParams{TenantID: t.ID, UserID: u.ID})
	return si, err
}

func (p *Provider) disclosure(ctx context.Context, c *client) apps.Disclosure {
	a, err := p.Store.R().GetApplicationByID(ctx, c.row.AppID)
	if err != nil {
		return apps.Disclosure{}
	}
	return apps.AppFromRow(a).Disclosure
}

// porchClaim builds {v, tenant, roles, groups?} within the size cap (ADR-0014). Roles come from the authorization
// engine (M5); until then the list is empty.
func porchClaim(si subjectInfo, d apps.Disclosure, scopes []string) map[string]any {
	claim := map[string]any{"v": 1, "tenant": map[string]any{"id": si.tenantID, "slug": si.tenantSlug}}
	if d.Roles {
		claim["roles"] = []string{}
	}
	if d.Groups && slices.Contains(scopes, "groups") {
		claim["groups"] = nonNil(si.groups)
	}
	for _, drop := range []string{"groups", "roles"} {
		if b, _ := json.Marshal(claim); len(b) <= maxPorchClaimBytes {
			break
		}
		if _, ok := claim[drop]; ok {
			delete(claim, drop)
			claim["truncated"] = true
		}
	}
	return claim
}

func (p *Provider) accessToken(ctx context.Context, c *client, g grant, subjectOverride string) (token string, exp time.Time, jti string, err error) {
	si, err := p.subject(ctx, g)
	if err != nil {
		return "", time.Time{}, "", err
	}
	now := p.now()
	exp = now.Add(c.accessTokenTTL)
	jti = ids.New(ids.AccessToken)
	aud := g.resources
	if len(aud) == 0 {
		aud = []string{c.row.ID}
	}
	sub := si.publicID
	if subjectOverride != "" {
		sub = subjectOverride
	}
	claims := accessTokenClaims{Issuer: p.Issuer, Subject: sub, Audience: aud, Expiry: exp.Unix(), IssuedAt: now.Unix(), JTI: jti,
		ClientID: c.row.ID, Scope: joinScopes(g.scopes), AMR: g.amr, Porch: porchClaim(si, p.disclosure(ctx, c), g.scopes)}
	if g.userID != "" {
		claims.AuthTime = g.authTime.Unix()
	}
	token, err = p.Signing.Sign(c.row.SigningAlg, "at+jwt", claims)
	return token, exp, jti, err
}

func joinScopes(s []string) string {
	out := ""
	for i, x := range s {
		if i > 0 {
			out += " "
		}
		out += x
	}
	return out
}

// atHash is the OIDC at_hash: left half of SHA-256 of the access token (ES256 and RS256 both use SHA-256).
func atHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

func (p *Provider) idToken(ctx context.Context, c *client, g grant, accessToken string) (string, error) {
	si, err := p.subject(ctx, g)
	if err != nil {
		return "", err
	}
	now := p.now()
	claims := map[string]any{"iss": p.Issuer, "sub": si.publicID, "aud": []string{c.row.ID}, "azp": c.row.ID, "exp": now.Add(c.idTokenTTL).Unix(),
		"iat": now.Unix(), "auth_time": g.authTime.Unix()}
	if g.nonce != "" {
		claims["nonce"] = g.nonce
	}
	if len(g.amr) > 0 {
		claims["amr"] = g.amr
	}
	if accessToken != "" {
		claims["at_hash"] = atHash(accessToken)
	}
	d := p.disclosure(ctx, c)
	if slices.Contains(g.scopes, oidc.ScopeProfile) {
		claims["name"] = si.name
	}
	if slices.Contains(g.scopes, oidc.ScopeEmail) && d.Email && si.email != "" {
		claims["email"], claims["email_verified"] = si.email, si.emailVerified
	}
	claims["porch"] = porchClaim(si, d, g.scopes)
	return p.Signing.Sign(c.row.SigningAlg, "JWT", claims)
}

// issue mints access (+ID) tokens and, when offline_access was granted, a rotating refresh token. parentID is the
// refresh token being rotated ("" for a code exchange).
func (p *Provider) issue(ctx context.Context, c *client, g grant, withIDToken bool, parentID string) (*oidc.AccessTokenResponse, string, string, error) {
	at, exp, jti, err := p.accessToken(ctx, c, g, "")
	if err != nil {
		return nil, "", "", oidc.ErrServerError().WithParent(err)
	}
	resp := &oidc.AccessTokenResponse{AccessToken: at, TokenType: oidc.BearerToken, ExpiresIn: uint64(time.Until(exp).Round(time.Second).Seconds()), //nolint:gosec // positive
		Scope: g.scopes}
	if exp.Sub(p.now()) > 0 {
		resp.ExpiresIn = uint64(exp.Sub(p.now()).Seconds()) //nolint:gosec // positive
	}
	if withIDToken {
		if resp.IDToken, err = p.idToken(ctx, c, g, at); err != nil {
			return nil, "", "", oidc.ErrServerError().WithParent(err)
		}
		p.Metrics.TokenIssued("id_token")
	}
	p.Metrics.TokenIssued("access_token")
	family := g.familyID
	wantRefresh := parentID != "" || (slices.Contains(g.scopes, oidc.ScopeOfflineAccess) && c.hasGrant(oidc.GrantTypeRefreshToken))
	var refresh string
	err = p.Store.W().TxNamed(ctx, "oidc.issue", func(tx *store.Tx) error {
		if parentID != "" {
			n, err := tx.Q.RotateRefreshToken(ctx, db.RotateRefreshTokenParams{RotatedAt: sqlMicros(tx.Now), ID: parentID})
			if err != nil {
				return err
			}
			if n != 1 {
				return errConcurrentRotation
			}
		}
		if wantRefresh {
			var err error
			if refresh, family, err = p.newRefreshTx(ctx, tx, c, g); err != nil {
				return err
			}
		}
		action, details := "oidc.token_issued", map[string]any{"jti": jti, "scopes": g.scopes, "refresh": wantRefresh}
		if parentID != "" {
			details["grant"] = "refresh_token"
		} else {
			details["grant"] = "authorization_code"
		}
		_, err := p.Audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorUser, ID: g.userID}, TenantID: g.tenantID, Action: action,
			Target: audit.Target{Type: "oauth_client", ID: c.row.ID}, Details: details})
		return err
	})
	if err == errConcurrentRotation { //nolint:errorlint // sentinel compared inside this package
		return nil, "", "", oidc.ErrInvalidGrant().WithDescription("refresh token was already used")
	}
	if err != nil {
		return nil, "", "", oidc.ErrServerError().WithParent(err)
	}
	if refresh != "" {
		resp.RefreshToken = refresh
		p.Metrics.TokenIssued("refresh_token")
	}
	return resp, family, jti, nil
}

type rotationError struct{}

func (rotationError) Error() string { return "refresh token rotated concurrently" }

var errConcurrentRotation error = rotationError{}

func (p *Provider) newRefreshTx(ctx context.Context, tx *store.Tx, c *client, g grant) (token, family string, err error) {
	raw, err := session.RandomToken()
	if err != nil {
		return "", "", err
	}
	token = "porch_rt_" + raw
	mac, err := p.Keyring.MAC(keyring.PurposeToken, []byte("porch/refresh/v1|"+token))
	if err != nil {
		return "", "", err
	}
	inst, err := tx.Q.GetInstallation(ctx)
	if err != nil {
		return "", "", err
	}
	u, err := tx.Q.GetUser(ctx, g.userID)
	if err != nil {
		return "", "", err
	}
	family = g.familyID
	famExp := g.familyExpires
	if family == "" {
		family = ids.New(ids.RefreshFamily)
		famExp = tx.Now.Add(time.Duration(c.row.RefreshTtlSecs) * time.Second)
	}
	idle := tx.Now.Add(time.Duration(c.row.RefreshIdleSecs) * time.Second)
	if idle.After(famExp) {
		idle = famExp
	}
	err = tx.Q.InsertRefreshToken(ctx, db.InsertRefreshTokenParams{ID: ids.New(ids.RefreshToken), Mac: mac, FamilyID: family, ParentID: domain.NullStr(g.parentID),
		ClientID: c.row.ID, TenantID: g.tenantID, UserID: g.userID, Scopes: mustJSON(g.scopes), Resources: mustJSON(nonNil(g.resources)),
		AuthTime: g.authTime.UnixMicro(), Amr: mustJSON(nonNil(g.amr)), AuthMethod: g.authMethod, InstallEpoch: inst.SecurityEpoch, UserEpoch: u.SecurityEpoch,
		CreatedAt: tx.NowMicros(), FamilyExpiresAt: famExp.UnixMicro(), IdleExpiresAt: idle.UnixMicro()})
	return token, family, err
}

package oidcop

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/authz"
	"github.com/aurimasniekis/go-porch/internal/domain"
	"github.com/aurimasniekis/go-porch/internal/httpx"
	"github.com/aurimasniekis/go-porch/internal/ids"
	"github.com/aurimasniekis/go-porch/internal/keyring"
	"github.com/aurimasniekis/go-porch/internal/session"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/store/db"
)

// ProviderSlug resolves a provider ID to its slug (portal URLs for recheck and step-up).
type ProviderSlug func(ctx context.Context, providerID string) string

// Continue serves /oauth2/continue?ar=<id>: the authorization request resumes here after the browser has (re)
// authenticated. It decides between login, step-up, upstream recheck, an error to the client, or a code.
func (p *Provider) Continue(slug ProviderSlug) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		arID := r.URL.Query().Get("ar")
		ar, err := p.Store.R().GetAuthRequest(ctx, arID)
		if err != nil || !p.now().Before(domain.FromMicros(ar.ExpiresAt)) {
			http.Error(w, "This sign-in request expired. Go back to the application and start again.", http.StatusBadRequest)
			return
		}
		here := PathContinue + "?ar=" + url.QueryEscape(ar.ID)
		prompt := jsonList(ar.Prompt)
		sess, _ := p.Sessions.Authenticate(ctx, session.TokenFromRequest(r))
		if slices.Contains(prompt, "none") {
			if sess == nil || p.needsReauth(sess, ar, prompt) || p.Sessions.NeedsUpstreamRecheck(sess) {
				p.redirectError(w, r, ar, "login_required", "no active session")
				return
			}
		}
		if sess == nil {
			http.Redirect(w, r, "/login?return_to="+url.QueryEscape(here), http.StatusFound)
			return
		}
		if p.Sessions.NeedsUpstreamRecheck(sess) {
			if s := slug(ctx, sess.ProviderID); s != "" {
				http.Redirect(w, r, "/login/"+s+"?intent=recheck&return_to="+url.QueryEscape(here), http.StatusFound)
				return
			}
		}
		if p.needsReauth(sess, ar, prompt) {
			if err := p.Store.W().TxNamed(ctx, "oidc.reauth", func(tx *store.Tx) error {
				return tx.Q.SetAuthRequestReauth(ctx, db.SetAuthRequestReauthParams{ReauthSessionID: domain.NullStr(sess.SessionID), ID: ar.ID})
			}); err != nil {
				p.redirectError(w, r, ar, "server_error", "")
				return
			}
			switch sess.Method {
			case session.MethodGoogle, session.MethodOIDC:
				if s := slug(ctx, sess.ProviderID); s != "" {
					http.Redirect(w, r, "/login/"+s+"?intent=stepup&return_to="+url.QueryEscape(here), http.StatusFound)
					return
				}
			case session.MethodBackup:
				http.Redirect(w, r, "/login?stepup=backup&return_to="+url.QueryEscape(here), http.StatusFound)
				return
			}
			p.redirectError(w, r, ar, "login_required", "re-authentication required")
			return
		}
		if sess.Method == session.MethodSetup || sess.Method == session.MethodRecoveryLink {
			p.redirectError(w, r, ar, "access_denied", "setup and recovery sessions cannot sign in to applications")
			return
		}
		// Access decision: app:access on the client's application (tenant gate, shares, roles, policies; ADR-0011).
		cl, err := p.Store.R().GetClient(ctx, ar.ClientID)
		if err != nil {
			p.redirectError(w, r, ar, "server_error", "")
			return
		}
		d, err := p.Engine.Check(ctx, authz.Request{TenantID: ar.TenantID, Subject: authz.Subject{Type: "user", ID: sess.UserID, AuthMethod: sess.Method,
			AuthTime: sess.AuthTime}, Action: authz.PermAppAccess, Resource: authz.Resource{Type: "app", ID: cl.AppID}, ClientIP: httpx.ClientIP(ctx)})
		if err != nil || !d.Allowed {
			reason := d.Reason
			if err != nil {
				reason = "error"
			}
			p.auditTx(ctx, audit.Event{Actor: audit.Actor{Type: audit.ActorUser, ID: sess.UserID}, TenantID: ar.TenantID, Action: "oidc.authorize",
				Outcome: audit.OutcomeDenied, ReasonCode: reason, Target: audit.Target{Type: "oauth_client", ID: ar.ClientID}})
			p.redirectError(w, r, ar, "access_denied", "you do not have access to this application")
			return
		}
		// The token names the tenant through which the user has access: the owner, or the tenant the app is shared with.
		claimTenant := ar.TenantID
		if via := d.Trace.TenantGate.Via; strings.HasPrefix(via, "share:") {
			if t, err := p.Store.R().GetTenantBySlug(ctx, strings.TrimPrefix(via, "share:")); err == nil {
				claimTenant = t.ID
			}
		}
		ar.TenantID = claimTenant
		code, err := p.newCode(ctx, ar, sess)
		if err != nil {
			p.Log.Error("issue code", "err", err)
			p.redirectError(w, r, ar, "server_error", "")
			return
		}
		p.Metrics.TokenIssued("code")
		u, _ := url.Parse(ar.RedirectUri)
		q := u.Query()
		q.Set("code", code)
		if ar.State != "" {
			q.Set("state", ar.State)
		}
		q.Set("iss", p.Issuer) // RFC 9207
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	})
}

// needsReauth applies prompt=login and max_age. prompt=login is satisfied once the session that was sent to
// re-authenticate comes back rotated (step-up issues a new session) with a fresh auth_time. max_age (zitadel sets 0 for
// prompt=login) is satisfied by any authentication after the request (OIDC Core 3.1.2.1): a session created — by login
// or step-up rotation, on Porch's own clock — after the request was made, or an auth_time no older than max_age
// seconds before it (whole seconds; upstream auth_time may be slightly skewed).
func (p *Provider) needsReauth(sess *session.Principal, ar db.AuthRequest, prompt []string) bool {
	if slices.Contains(prompt, "login") {
		fresh := p.now().Sub(sess.AuthTime) <= p.Sessions.Options().StepUpWindow
		if !ar.ReauthSessionID.Valid || ar.ReauthSessionID.String == sess.SessionID || !fresh {
			return true
		}
	}
	if ar.MaxAge.Valid {
		created := domain.FromMicros(ar.CreatedAt)
		freshSession := !sess.CreatedAt.Before(created)
		if !freshSession && sess.AuthTime.Unix() < created.Unix()-ar.MaxAge.Int64 {
			return true
		}
	}
	return false
}

func amrFor(method string) []string {
	switch method {
	case session.MethodBackup:
		return []string{"pwd", "kba"}
	case session.MethodRecoveryLink:
		return []string{"otp"}
	}
	return []string{}
}

func (p *Provider) newCode(ctx context.Context, ar db.AuthRequest, sess *session.Principal) (string, error) {
	code, err := session.RandomToken()
	if err != nil {
		return "", err
	}
	mac, err := p.Keyring.MAC(keyring.PurposeToken, []byte("porch/auth-code/v1|"+code))
	if err != nil {
		return "", err
	}
	err = p.Store.W().TxNamed(ctx, "oidc.code", func(tx *store.Tx) error {
		if err := tx.Q.InsertAuthCode(ctx, db.InsertAuthCodeParams{Mac: mac, ID: ids.New(ids.AuthCode), ClientID: ar.ClientID, TenantID: ar.TenantID,
			UserID: sess.UserID, SessionID: sess.SessionID, RedirectUri: ar.RedirectUri, Scopes: ar.Scopes, Nonce: ar.Nonce, CodeChallenge: ar.CodeChallenge,
			Resources: ar.Resources, AuthTime: sess.AuthTime.UnixMicro(), Amr: mustJSON(amrFor(sess.Method)), AuthMethod: sess.Method, CreatedAt: tx.NowMicros(),
			ExpiresAt: tx.Now.Add(codeTTL).UnixMicro()}); err != nil {
			return err
		}
		if err := tx.Q.DeleteAuthRequest(ctx, ar.ID); err != nil {
			return err
		}
		_, err := p.Audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorUser, ID: sess.UserID}, TenantID: ar.TenantID,
			Action: "oidc.authorize", AuthMethod: sess.Method, Target: audit.Target{Type: "oauth_client", ID: ar.ClientID}})
		return err
	})
	return code, err
}

// redirectError sends an OAuth error to the client's (already validated) redirect URI.
func (p *Provider) redirectError(w http.ResponseWriter, r *http.Request, ar db.AuthRequest, code, desc string) {
	ctx := r.Context()
	_ = p.Store.W().TxNamed(ctx, "oidc.auth_request_done", func(tx *store.Tx) error { return tx.Q.DeleteAuthRequest(ctx, ar.ID) })
	u, _ := url.Parse(ar.RedirectUri)
	q := u.Query()
	q.Set("error", code)
	if desc != "" {
		q.Set("error_description", desc)
	}
	if ar.State != "" {
		q.Set("state", ar.State)
	}
	q.Set("iss", p.Issuer)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

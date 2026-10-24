// Package forwardauth is Porch's forward-auth outpost (ADR-0015) for Caddy forward_auth, Traefik ForwardAuth and nginx
// auth_request. Each protected host gets its own host-only session cookie, set by a one-time code exchanged at
// https://<app-host>/.porch/callback (the proxy routes /.porch/* on the app host to Porch); there is never a cookie on a
// parent domain.
package forwardauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/aurimasniekis/go-porch/internal/apps"
	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/authz"
	"github.com/aurimasniekis/go-porch/internal/clock"
	"github.com/aurimasniekis/go-porch/internal/domain"
	"github.com/aurimasniekis/go-porch/internal/httpx"
	"github.com/aurimasniekis/go-porch/internal/ids"
	"github.com/aurimasniekis/go-porch/internal/keyring"
	"github.com/aurimasniekis/go-porch/internal/obs/metrics"
	"github.com/aurimasniekis/go-porch/internal/session"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/store/db"
)

// CookieName is the per-host forward-auth session cookie (host-only on the application host).
const CookieName = "__Host-porch_fa"

const codeTTL = time.Minute

// Outpost serves the forward-auth endpoints.
type Outpost struct {
	Store    *store.Store
	Keyring  *keyring.Keyring
	Audit    *audit.Writer
	Sessions *session.Manager
	Engine   *authz.Engine
	Clock    clock.Clock
	Metrics  *metrics.Metrics
	Log      *slog.Logger
	// PublicURL is Porch's own origin (where /outpost/start lives).
	PublicURL string
	// TrustedPeers may call /outpost/auth; loopback is always allowed.
	TrustedPeers []netip.Prefix
	// AllowHTTP permits http:// application hosts (development only).
	AllowHTTP bool
	// SessionTTL bounds forward-auth sessions.
	SessionTTL time.Duration
	// ProviderSlug resolves a session's upstream provider for the hourly recheck.
	ProviderSlug func(ctx context.Context, providerID string) string
}

// Register mounts the handlers.
func (o *Outpost) Register(mux *http.ServeMux) {
	mux.HandleFunc("/outpost/auth", o.auth)
	mux.HandleFunc("GET /outpost/start", o.start)
	mux.HandleFunc("GET /.porch/callback", o.callback)
	mux.HandleFunc("GET /.porch/logout", o.logout)
}

func (o *Outpost) peerTrusted(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	a = a.Unmap()
	if a.IsLoopback() {
		return true
	}
	for _, p := range o.TrustedPeers {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func normHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if hh, _, err := net.SplitHostPort(h); err == nil {
		return hh
	}
	return h
}

// original reconstructs the URL the browser asked for from the proxy's headers.
func original(r *http.Request) (*url.URL, bool) {
	if raw := r.Header.Get("X-Original-URL"); raw != "" { // nginx auth_request (configured by the operator)
		u, err := url.Parse(raw)
		return u, err == nil && u.Host != ""
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		return nil, false
	}
	proto := r.Header.Get("X-Forwarded-Proto")
	if proto != "http" {
		proto = "https"
	}
	uri := r.Header.Get("X-Forwarded-Uri")
	if uri == "" || !strings.HasPrefix(uri, "/") {
		uri = "/"
	}
	u, err := url.Parse(proto + "://" + host + uri)
	return u, err == nil
}

func (o *Outpost) appForHost(ctx context.Context, host string) (db.Application, error) {
	h, err := o.Store.R().GetAppHost(ctx, normHost(host))
	if err != nil {
		return db.Application{}, err
	}
	a, err := o.Store.R().GetApplication(ctx, db.GetApplicationParams{TenantID: h.TenantID, ID: h.AppID})
	if err != nil || a.Enabled != 1 || a.Kind != apps.KindForwardAuth {
		return db.Application{}, errDisabled
	}
	return a, nil
}

type outpostError string

func (e outpostError) Error() string { return string(e) }

const errDisabled = outpostError("application disabled")

// auth answers the proxy's subrequest: 200 + identity headers, a redirect to sign in, or 403.
func (o *Outpost) auth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !o.peerTrusted(r) {
		http.Error(w, "forward-auth requests are accepted only from configured proxies", http.StatusForbidden)
		return
	}
	orig, ok := original(r)
	if !ok {
		http.Error(w, "missing X-Forwarded-Host/X-Forwarded-Uri (or X-Original-URL)", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	app, err := o.appForHost(ctx, orig.Host)
	if err != nil {
		http.Error(w, "host is not protected by Porch", http.StatusForbidden)
		return
	}
	if fs, sess, ok := o.validSession(ctx, r, normHost(orig.Host)); ok {
		d, err := o.Engine.Check(ctx, authz.Request{TenantID: app.TenantID, Subject: authz.Subject{Type: "user", ID: fs.UserID,
			AuthMethod: sess.Method, AuthTime: sess.AuthTime}, Action: authz.PermAppAccess, Resource: authz.Resource{Type: "app", ID: app.ID},
			ClientIP: httpx.ClientIP(ctx)})
		if err != nil || !d.Allowed {
			http.Error(w, "You do not have access to "+app.Name+".", http.StatusForbidden)
			return
		}
		if err := o.writeIdentity(ctx, w, app, fs, sess); err != nil {
			o.Log.Error("forward-auth identity", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	method := r.Header.Get("X-Forwarded-Method")
	if (method != "" && method != http.MethodGet && method != http.MethodHead) || strings.Contains(r.Header.Get("Accept"), "application/json") {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	http.Redirect(w, r, o.PublicURL+"/outpost/start?rd="+url.QueryEscape(orig.String()), http.StatusFound)
}

// validSession checks the host's cookie and the Porch session behind it.
func (o *Outpost) validSession(ctx context.Context, r *http.Request, host string) (db.ForwardAuthSession, *session.Principal, bool) {
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" || len(c.Value) > 128 {
		return db.ForwardAuthSession{}, nil, false
	}
	macs, err := o.Keyring.MACAll(keyring.PurposeToken, []byte("porch/fa-session/v1|"+c.Value))
	if err != nil {
		return db.ForwardAuthSession{}, nil, false
	}
	for _, m := range macs {
		fs, err := o.Store.R().GetForwardAuthSession(ctx, m)
		if err != nil {
			continue
		}
		now := o.Clock.Now()
		if fs.RevokedAt.Valid || fs.Host != host || !now.Before(domain.FromMicros(fs.ExpiresAt)) {
			return fs, nil, false
		}
		sess, err := o.Sessions.ByID(ctx, fs.SessionID)
		if err != nil || sess.UserID != fs.UserID || o.Sessions.NeedsUpstreamRecheck(sess) {
			return fs, nil, false
		}
		return fs, sess, true
	}
	return db.ForwardAuthSession{}, nil, false
}

// sanitize keeps header values to one printable line.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

func (o *Outpost) writeIdentity(ctx context.Context, w http.ResponseWriter, app db.Application, fs db.ForwardAuthSession, sess *session.Principal) error {
	headers := map[string]string{}
	_ = json.Unmarshal([]byte(app.ForwardHeaders), &headers)
	if len(headers) == 0 {
		headers = apps.DefaultForwardHeaders
	}
	t, err := o.Store.R().GetTenant(ctx, fs.TenantID)
	if err != nil {
		return err
	}
	groups, err := o.Store.R().ListUserGroupSlugs(ctx, db.ListUserGroupSlugsParams{TenantID: fs.TenantID, UserID: fs.UserID})
	if err != nil {
		return err
	}
	values := map[string]string{"sub": sess.PublicID, "email": sess.Email, "name": sess.DisplayName, "groups": strings.Join(groups, ","),
		"tenant": t.Slug, "roles": ""}
	names := make([]string, 0, len(headers))
	for n := range headers {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		w.Header().Set(n, sanitize(values[headers[n]]))
	}
	return nil
}

// validTarget checks rd: an absolute URL on a host protected by an enabled forward-auth app (T-B2-6).
func (o *Outpost) validTarget(ctx context.Context, rd string) (*url.URL, db.Application, bool) {
	u, err := url.Parse(rd)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && (!o.AllowHTTP || u.Scheme != "http")) {
		return nil, db.Application{}, false
	}
	app, err := o.appForHost(ctx, u.Host)
	if err != nil {
		return nil, db.Application{}, false
	}
	return u, app, true
}

var page = template.Must(template.New("p").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{{.Title}} — Porch</title>
<meta name="viewport" content="width=device-width, initial-scale=1"></head><body><main><h1>{{.Title}}</h1><p>{{.Message}}</p>
<p><a href="/">Back to Porch</a></p></main></body></html>`))

func render(w http.ResponseWriter, status int, title, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = page.Execute(w, map[string]string{"Title": title, "Message": msg})
}

// start runs on Porch's origin: it needs a Porch session and access, then hands a one-time code to the app host.
func (o *Outpost) start(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rd := r.URL.Query().Get("rd")
	target, app, ok := o.validTarget(ctx, rd)
	if !ok {
		render(w, http.StatusBadRequest, "Unknown application", "The address you came from is not protected by this Porch installation.")
		return
	}
	here := "/outpost/start?rd=" + url.QueryEscape(target.String())
	sess, err := o.Sessions.Authenticate(ctx, session.TokenFromRequest(r))
	if err != nil {
		http.Redirect(w, r, "/login?return_to="+url.QueryEscape(here), http.StatusFound)
		return
	}
	if o.Sessions.NeedsUpstreamRecheck(sess) && o.ProviderSlug != nil {
		if s := o.ProviderSlug(ctx, sess.ProviderID); s != "" {
			http.Redirect(w, r, "/login/"+s+"?intent=recheck&return_to="+url.QueryEscape(here), http.StatusFound)
			return
		}
	}
	if sess.Method == session.MethodSetup || sess.Method == session.MethodRecoveryLink {
		render(w, http.StatusForbidden, "Not available", "Setup and recovery sessions cannot open applications. Sign in normally first.")
		return
	}
	d, err := o.Engine.Check(ctx, authz.Request{TenantID: app.TenantID, Subject: authz.Subject{Type: "user", ID: sess.UserID,
		AuthMethod: sess.Method, AuthTime: sess.AuthTime}, Action: authz.PermAppAccess, Resource: authz.Resource{Type: "app", ID: app.ID},
		ClientIP: httpx.ClientIP(ctx)})
	if err != nil || !d.Allowed {
		o.auditDenied(ctx, sess, app, d.Reason)
		render(w, http.StatusForbidden, "No access", "You do not have access to "+app.Name+". Ask an administrator of your group.")
		return
	}
	tenantID := app.TenantID
	if strings.HasPrefix(d.Trace.TenantGate.Via, "share:") {
		if t, err := o.Store.R().GetTenantBySlug(ctx, strings.TrimPrefix(d.Trace.TenantGate.Via, "share:")); err == nil {
			tenantID = t.ID
		}
	}
	code, err := randomToken()
	if err != nil {
		render(w, http.StatusInternalServerError, "Error", "Please try again.")
		return
	}
	mac, err := o.Keyring.MAC(keyring.PurposeToken, []byte("porch/fa-code/v1|"+code))
	if err != nil {
		render(w, http.StatusInternalServerError, "Error", "Please try again.")
		return
	}
	returnTo := httpx.SafeReturnTo(target.RequestURI(), "/")
	host := normHost(target.Host)
	err = o.Store.W().TxNamed(ctx, "forwardauth.code", func(tx *store.Tx) error {
		return tx.Q.InsertForwardAuthCode(ctx, db.InsertForwardAuthCodeParams{Mac: mac, AppID: app.ID, Host: host, TenantID: tenantID, UserID: sess.UserID,
			SessionID: sess.SessionID, ReturnTo: returnTo, ExpiresAt: tx.Now.Add(codeTTL).UnixMicro()})
	})
	if err != nil {
		render(w, http.StatusInternalServerError, "Error", "Please try again.")
		return
	}
	cb := url.URL{Scheme: target.Scheme, Host: target.Host, Path: "/.porch/callback", RawQuery: url.Values{"code": {code}}.Encode()}
	http.Redirect(w, r, cb.String(), http.StatusFound)
}

func (o *Outpost) auditDenied(ctx context.Context, sess *session.Principal, app db.Application, reason string) {
	_ = o.Store.W().TxNamed(ctx, "forwardauth.denied", func(tx *store.Tx) error {
		_, err := o.Audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorUser, ID: sess.UserID}, TenantID: app.TenantID,
			Action: "app.access", Outcome: audit.OutcomeDenied, ReasonCode: reason, Target: audit.Target{Type: "application", ID: app.ID}})
		return err
	})
}

// callback runs on the application host (proxied to Porch): it exchanges the code for a host-only cookie.
func (o *Outpost) callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	code := r.URL.Query().Get("code")
	if code == "" || len(code) > 128 {
		render(w, http.StatusBadRequest, "Sign-in failed", "Missing or invalid sign-in code.")
		return
	}
	macs, err := o.Keyring.MACAll(keyring.PurposeToken, []byte("porch/fa-code/v1|"+code))
	if err != nil {
		render(w, http.StatusInternalServerError, "Error", "Please try again.")
		return
	}
	host := normHost(r.Host)
	var token string
	var fc db.ForwardAuthCode
	// Any redemption attempt burns the code, even one on the wrong host (committed before validation).
	found := false
	err = o.Store.W().TxNamed(ctx, "forwardauth.take_code", func(tx *store.Tx) error {
		for _, m := range macs {
			c, err := tx.Q.TakeForwardAuthCode(ctx, db.TakeForwardAuthCodeParams{UsedAt: domain.NullMicros(&tx.Now), Mac: m})
			if err == nil {
				fc, found = c, true
				return nil
			}
		}
		return nil
	})
	if err == nil && (!found || fc.ExpiresAt <= o.Clock.Now().UnixMicro() || fc.Host != host) {
		err = errBadCode
	}
	if err == nil {
		err = o.Store.W().TxNamed(ctx, "forwardauth.callback", func(tx *store.Tx) error {
			sess, err := tx.Q.GetSession(ctx, fc.SessionID)
			if err != nil {
				return errBadCode
			}
			var terr error
			if token, terr = randomToken(); terr != nil {
				return terr
			}
			mac, err := o.Keyring.MAC(keyring.PurposeToken, []byte("porch/fa-session/v1|"+token))
			if err != nil {
				return err
			}
			exp := tx.Now.Add(o.SessionTTL)
			if sexp := domain.FromMicros(sess.AbsoluteExpiresAt); sexp.Before(exp) {
				exp = sexp
			}
			id := ids.New(ids.Session)
			if err := tx.Q.InsertForwardAuthSession(ctx, db.InsertForwardAuthSessionParams{ID: id, Mac: mac, AppID: fc.AppID, Host: host,
				TenantID: fc.TenantID, UserID: fc.UserID, SessionID: fc.SessionID, CreatedAt: tx.NowMicros(), ExpiresAt: exp.UnixMicro()}); err != nil {
				return err
			}
			_, err = o.Audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorUser, ID: fc.UserID}, TenantID: fc.TenantID,
				Action: "app.forward_auth_login", Target: audit.Target{Type: "application", ID: fc.AppID}, Details: map[string]any{"host": host}})
			return err
		})
	}
	if err != nil {
		render(w, http.StatusBadRequest, "Sign-in failed", "This sign-in link expired or was already used. Open the application again.")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, httpx.SafeReturnTo(fc.ReturnTo, "/"), http.StatusFound)
}

const errBadCode = outpostError("invalid code")

func (o *Outpost) logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if fs, _, ok := o.validSession(ctx, r, normHost(r.Host)); ok {
		_ = o.Store.W().TxNamed(ctx, "forwardauth.logout", func(tx *store.Tx) error {
			_, err := tx.Q.RevokeForwardAuthSession(ctx, db.RevokeForwardAuthSessionParams{RevokedAt: domain.NullMicros(&tx.Now), ID: fs.ID})
			return err
		})
	}
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	render(w, http.StatusOK, "Signed out", "You are signed out of this application.")
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

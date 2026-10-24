// Package portal serves the browser-facing login endpoints that are redirects rather than API calls: the upstream
// (Google / OIDC) login round trip for login, silent recheck, step-up and identity linking.
package portal

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/aurimasniekis/go-porch/internal/apperr"
	"github.com/aurimasniekis/go-porch/internal/httpx"
	"github.com/aurimasniekis/go-porch/internal/idp"
	"github.com/aurimasniekis/go-porch/internal/session"
)

// Handler serves /login/{provider} and /login/{provider}/callback.
type Handler struct {
	IDP      *idp.Service
	Sessions *session.Manager
	Log      *slog.Logger
	Limiter  *httpx.Limiter
}

// Register mounts the handlers on mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /login/{provider}", h.begin)
	mux.HandleFunc("GET /login/{provider}/callback", h.callback)
}

func (h *Handler) begin(w http.ResponseWriter, r *http.Request) {
	if h.Limiter != nil && !h.Limiter.Allow(httpx.SourceKey(httpx.ClientIP(r.Context()))) {
		http.Error(w, "too many login attempts", http.StatusTooManyRequests)
		return
	}
	q := r.URL.Query()
	intent := q.Get("intent")
	if intent == "" {
		intent = idp.IntentLogin
	}
	returnTo := httpx.SafeReturnTo(q.Get("return_to"), "/")
	var p *session.Principal
	if intent != idp.IntentLogin {
		var err error
		if p, err = h.Sessions.Validate(r.Context(), session.TokenFromRequest(r)); err != nil {
			loginError(w, r, "session_expired", returnTo)
			return
		}
	}
	authURL, state, err := h.IDP.Begin(r.Context(), idp.BeginParams{ProviderSlug: r.PathValue("provider"), Intent: intent, Session: p,
		ReturnTo: returnTo, LoginHint: q.Get("login_hint")})
	if err != nil {
		h.Log.Warn("upstream login could not start", "provider", r.PathValue("provider"), "err", err)
		code := "unavailable"
		switch {
		case errors.Is(err, session.ErrReauthRequired):
			code = "reauth_required"
		case apperr.CodeOf(err) == apperr.CodeNotFound:
			code = "unknown_provider"
		}
		loginError(w, r, code, returnTo)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: idp.StateCookie, Value: state, Path: "/", MaxAge: int(idp.StateTTL.Seconds()), Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (h *Handler) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	cookieState := ""
	if c, err := r.Cookie(idp.StateCookie); err == nil {
		cookieState = c.Value
	}
	http.SetCookie(w, &http.Cookie{Name: idp.StateCookie, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	res, err := h.IDP.Complete(r.Context(), idp.CompleteParams{ProviderSlug: r.PathValue("provider"), State: q.Get("state"), CookieState: cookieState,
		Code: q.Get("code"), Error: q.Get("error"), SessionToken: session.TokenFromRequest(r), IP: httpx.ClientIP(r.Context()).String(),
		UserAgent: r.UserAgent()})
	if err != nil {
		code := "login_failed"
		switch {
		case errors.Is(err, idp.ErrNotEnrolled):
			code = "not_enrolled"
		case errors.Is(err, idp.ErrHDNotAllowed):
			code = "domain_not_allowed"
		case errors.Is(err, idp.ErrBadState):
			code = "expired"
		case errors.Is(err, idp.ErrWrongAccount):
			code = "wrong_account"
		case errors.Is(err, idp.ErrStaleAuth):
			code = "stale_auth"
		case errors.Is(err, idp.ErrAlreadyLinked):
			code = "already_linked"
		case errors.Is(err, idp.ErrDisabled):
			code = "disabled"
		}
		if apperr.CodeOf(err) == "" {
			h.Log.Error("upstream login failed", "err", err)
		}
		loginError(w, r, code, res.ReturnTo)
		return
	}
	if res.Revoked {
		session.ClearCookie(w)
		loginError(w, r, "session_ended", res.ReturnTo)
		return
	}
	if res.Session != nil {
		session.SetCookie(w, *res.Session)
	}
	http.Redirect(w, r, httpx.SafeReturnTo(res.ReturnTo, "/"), http.StatusFound)
}

func loginError(w http.ResponseWriter, r *http.Request, code, returnTo string) {
	v := url.Values{"error": {code}}
	if rt := httpx.SafeReturnTo(returnTo, ""); rt != "" {
		v.Set("return_to", rt)
	}
	http.Redirect(w, r, "/login?"+v.Encode(), http.StatusFound)
}

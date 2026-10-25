package idp

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/aurimasniekis/go-porch/internal/apperr"
	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/domain"
	"github.com/aurimasniekis/go-porch/internal/idp/upstream"
	"github.com/aurimasniekis/go-porch/internal/ids"
	"github.com/aurimasniekis/go-porch/internal/keyring"
	"github.com/aurimasniekis/go-porch/internal/session"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/store/db"
)

// Intents of an upstream round trip.
const (
	IntentLogin   = "login"
	IntentRecheck = "recheck"
	IntentStepUp  = "stepup"
	IntentLink    = "link"
)

// StateCookie binds an upstream login to the browser that started it.
const StateCookie = "__Host-porch_oidc"

// StateTTL bounds how long an upstream login may take.
const StateTTL = 10 * time.Minute

// Errors (all rendered as generic login failures to the browser; the reason is audited).
var (
	ErrBadState      = apperr.New(apperr.CodeUnauthorized, "login session expired or invalid; start again")
	ErrNotEnrolled   = apperr.New(apperr.CodeForbidden, "this account is not enrolled in Porch")
	ErrHDNotAllowed  = apperr.New(apperr.CodeForbidden, "this account's Google Workspace domain is not allowed")
	ErrWrongAccount  = apperr.New(apperr.CodeForbidden, "signed in with a different account than this session")
	ErrStaleAuth     = apperr.New(apperr.CodeForbidden, "the provider did not perform a fresh sign-in")
	ErrDisabled      = apperr.New(apperr.CodeForbidden, "account disabled")
	ErrAlreadyLinked = apperr.New(apperr.CodeConflict, "this provider account is already linked to a user")
	ErrEmailInUse    = apperr.New(apperr.CodeConflict, "a user with this email already exists; sign in another way and link this account")
)

// BeginParams start an upstream round trip.
type BeginParams struct {
	ProviderSlug string
	Intent       string
	Session      *session.Principal // required for recheck, stepup and link
	ReturnTo     string             // already validated by the caller
	LoginHint    string
}

// Begin returns the provider authorization URL and the state value the caller sets as StateCookie.
func (svc *Service) Begin(ctx context.Context, p BeginParams) (authURL, state string, err error) {
	prov, err := svc.s.R().GetProviderBySlug(ctx, p.ProviderSlug)
	if err != nil || prov.Enabled != 1 {
		return "", "", ErrProviderNotFound
	}
	sessionID := ""
	switch p.Intent {
	case IntentLogin:
	case IntentRecheck, IntentStepUp:
		if p.Session == nil {
			return "", "", session.ErrUnauthorized
		}
		sessionID = p.Session.SessionID
	case IntentLink:
		if p.Session == nil {
			return "", "", session.ErrUnauthorized
		}
		if err := svc.sessions.RequireStepUp(p.Session); err != nil {
			return "", "", err
		}
		sessionID = p.Session.SessionID
	default:
		return "", "", apperr.New(apperr.CodeInvalid, "unknown intent")
	}
	cfg, err := svc.upstreamConfig(prov)
	if err != nil {
		return "", "", err
	}
	state, err = session.RandomToken()
	if err != nil {
		return "", "", err
	}
	secrets, err := upstream.NewSecrets()
	if err != nil {
		return "", "", err
	}
	opts := upstream.AuthOptions{LoginHint: p.LoginHint}
	var hds []string
	_ = json.Unmarshal([]byte(prov.AllowedHds), &hds)
	if len(hds) == 1 {
		opts.HDHint = hds[0]
	}
	switch p.Intent {
	case IntentRecheck:
		opts.Prompt = "none"
		if opts.LoginHint == "" {
			opts.LoginHint = p.Session.Email
		}
	case IntentStepUp, IntentLink:
		if reauthCapable(prov) {
			opts.Prompt, opts.MaxAge0 = "login", true
		} else {
			opts.Prompt = "select_account"
		}
	default:
		if prov.Kind == KindGoogle {
			opts.Prompt = "select_account"
		}
	}
	authURL, err = svc.up.AuthURL(ctx, cfg, state, secrets, opts) // network (discovery) outside any transaction
	if err != nil {
		return "", "", err
	}
	mac, err := svc.kr.MAC(keyring.PurposeToken, []byte("porch/oidc-state/v1|"+state))
	if err != nil {
		return "", "", err
	}
	id := ids.New(ids.LoginState)
	plain, _ := json.Marshal(secrets)
	sealed, err := svc.kr.Seal(keyring.PurposeField, keyring.FieldAAD("oidc_login_states", "secrets_enc", id), plain)
	if err != nil {
		return "", "", err
	}
	err = svc.s.W().TxNamed(ctx, "idp.begin", func(tx *store.Tx) error {
		return tx.Q.InsertLoginState(ctx, db.InsertLoginStateParams{ID: id, StateMac: mac, ProviderID: prov.ID, Intent: p.Intent,
			SessionID: domain.NullStr(sessionID), SecretsEnc: sealed, ReturnTo: p.ReturnTo, CreatedAt: tx.NowMicros(),
			ExpiresAt: tx.Now.Add(StateTTL).UnixMicro()})
	})
	return authURL, state, err
}

// CompleteParams carry the provider callback.
type CompleteParams struct {
	ProviderSlug string
	State        string // query parameter
	CookieState  string // StateCookie value
	Code         string
	Error        string // provider error parameter
	SessionToken string // current Porch session cookie (recheck, stepup, link)
	IP           string
	UserAgent    string
}

// Result of a completed round trip.
type Result struct {
	Intent   string
	ReturnTo string
	UserID   string
	// Session is set when a new session cookie must be written (login, step-up rotation).
	Session *session.Created
	// Revoked is set when a failed recheck ended the session.
	Revoked bool
}

// Complete validates the callback, exchanges the code and applies the intent.
func (svc *Service) Complete(ctx context.Context, p CompleteParams) (Result, error) {
	if p.State == "" || p.CookieState == "" || subtle.ConstantTimeCompare([]byte(p.State), []byte(p.CookieState)) != 1 {
		svc.failure(ctx, "", "state_mismatch", nil)
		return Result{}, ErrBadState
	}
	mac, err := svc.kr.MAC(keyring.PurposeToken, []byte("porch/oidc-state/v1|"+p.State))
	if err != nil {
		return Result{}, err
	}
	var st db.OidcLoginState
	err = svc.s.W().TxNamed(ctx, "idp.take_state", func(tx *store.Tx) error {
		var err error
		st, err = tx.Q.TakeLoginState(ctx, mac) // single use
		return err
	})
	if errors.Is(err, sql.ErrNoRows) {
		svc.failure(ctx, "", "state_unknown", nil)
		return Result{}, ErrBadState
	}
	if err != nil {
		return Result{}, err
	}
	now := svc.opts.Clock.Now()
	prov, err := svc.s.R().GetProvider(ctx, st.ProviderID)
	if err != nil || prov.Slug != p.ProviderSlug || !now.Before(domain.FromMicros(st.ExpiresAt)) {
		svc.failure(ctx, st.ProviderID, "state_expired", nil)
		return Result{}, ErrBadState
	}
	res := Result{Intent: st.Intent, ReturnTo: st.ReturnTo}
	var cur *session.Principal
	if st.SessionID.Valid {
		cur, err = svc.sessions.Validate(ctx, p.SessionToken)
		if err != nil || cur.SessionID != st.SessionID.String {
			svc.failure(ctx, prov.ID, "session_mismatch", nil)
			return Result{}, ErrBadState
		}
	}
	if p.Error != "" {
		if st.Intent == IntentRecheck {
			return svc.recheckFailed(ctx, cur, prov, "upstream_"+p.Error, res)
		}
		svc.failure(ctx, prov.ID, "upstream_"+truncate(p.Error, 40), nil)
		return Result{}, ErrBadState
	}
	plain, err := svc.kr.Open(keyring.PurposeField, keyring.FieldAAD("oidc_login_states", "secrets_enc", st.ID), st.SecretsEnc)
	if err != nil {
		return Result{}, err
	}
	var secrets upstream.Secrets
	if err := json.Unmarshal(plain, &secrets); err != nil {
		return Result{}, err
	}
	cfg, err := svc.upstreamConfig(prov)
	if err != nil {
		return Result{}, err
	}
	claims, err := svc.up.Exchange(ctx, cfg, p.Code, secrets) // network outside any transaction
	if err != nil {
		if st.Intent == IntentRecheck {
			return svc.recheckFailed(ctx, cur, prov, "upstream_invalid", res)
		}
		svc.failure(ctx, prov.ID, "invalid_token", nil)
		return Result{}, ErrBadState
	}
	var hds []string
	_ = json.Unmarshal([]byte(prov.AllowedHds), &hds)
	if len(hds) > 0 && (claims.HD == "" || !slices.Contains(hds, claims.HD)) {
		if st.Intent == IntentRecheck {
			return svc.recheckFailed(ctx, cur, prov, "hd_not_allowed", res)
		}
		svc.failure(ctx, prov.ID, "hd_not_allowed", map[string]any{"hd": claims.HD})
		return Result{}, ErrHDNotAllowed
	}
	method := session.MethodOIDC
	if prov.Kind == KindGoogle {
		method = session.MethodGoogle
	}
	// For a provider that cannot re-authenticate on request, completing this interactive sign-in is the authentication
	// (ADR-0047); its auth_time, when sent at all, is the age of the upstream session.
	authTime := claims.AuthTime
	if authTime.IsZero() || !reauthCapable(prov) {
		authTime = now
	}
	switch st.Intent {
	case IntentLogin:
		err = svc.s.W().TxNamed(ctx, "idp.login", func(tx *store.Tx) error {
			uid, err := svc.resolveTx(ctx, tx, prov, claims)
			if err != nil {
				return err
			}
			if err := svc.reevaluateTx(ctx, tx, prov, claims, uid); err != nil {
				return err
			}
			c, err := svc.sessions.CreateTx(ctx, tx, session.NewParams{UserID: uid, Method: method, ProviderID: prov.ID, AuthTime: authTime,
				UpstreamCheckedAt: &tx.Now, IP: p.IP, UserAgent: p.UserAgent})
			if err != nil {
				return err
			}
			if err := tx.Q.SetUserUpstreamConfirmed(ctx, db.SetUserUpstreamConfirmedParams{UpstreamConfirmedAt: domain.NullMicros(&tx.Now), ID: uid}); err != nil {
				return err
			}
			res.UserID, res.Session = uid, &c
			_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorUser, ID: uid}, Action: "login.upstream",
				AuthMethod: method, Target: audit.Target{Type: "session", ID: c.ID}, Details: map[string]any{"provider_id": prov.ID, "hd": claims.HD}})
			return err
		})
		if err != nil {
			code := apperr.CodeOf(err)
			reason := "error"
			switch {
			case errors.Is(err, ErrNotEnrolled):
				reason = "not_enrolled"
			case errors.Is(err, ErrEmailInUse):
				reason = "email_in_use"
			case errors.Is(err, ErrDisabled):
				reason = "user_disabled"
			case code != "":
				reason = string(code)
			}
			svc.failure(ctx, prov.ID, reason, map[string]any{"hd": claims.HD})
			return Result{}, err
		}
		svc.opts.Metrics.Login(method, "success")
		return res, nil
	case IntentRecheck:
		err = svc.s.W().TxNamed(ctx, "idp.recheck", func(tx *store.Tx) error {
			uid, err := svc.identityOwner(ctx, tx, prov, claims)
			if err != nil || uid != cur.UserID {
				return ErrWrongAccount
			}
			if err := svc.reevaluateTx(ctx, tx, prov, claims, uid); err != nil {
				return err
			}
			res.UserID = uid
			if err := tx.Q.SetUserUpstreamConfirmed(ctx, db.SetUserUpstreamConfirmedParams{UpstreamConfirmedAt: domain.NullMicros(&tx.Now), ID: uid}); err != nil {
				return err
			}
			_, err = tx.Q.SetSessionUpstreamChecked(ctx, db.SetSessionUpstreamCheckedParams{UpstreamCheckedAt: domain.NullMicros(&tx.Now), ID: cur.SessionID})
			return err
		})
		if err != nil {
			return svc.recheckFailed(ctx, cur, prov, "wrong_account", res)
		}
		return res, nil
	case IntentStepUp:
		// A re-authentication capable provider that does not report a fresh auth_time did not prove a fresh sign-in
		// (review L9).
		if reauthCapable(prov) && (claims.AuthTime.IsZero() || now.Sub(authTime) > svc.sessions.Options().StepUpWindow) {
			svc.failure(ctx, prov.ID, "stale_auth_time", nil)
			return Result{}, ErrStaleAuth
		}
		err = svc.s.W().TxNamed(ctx, "idp.stepup", func(tx *store.Tx) error {
			uid, err := svc.identityOwner(ctx, tx, prov, claims)
			if err != nil || uid != cur.UserID {
				return ErrWrongAccount
			}
			c, err := svc.sessions.RotateTx(ctx, tx, cur, authTime, p.IP, p.UserAgent)
			if err != nil {
				return err
			}
			if err := tx.Q.SetUserUpstreamConfirmed(ctx, db.SetUserUpstreamConfirmedParams{UpstreamConfirmedAt: domain.NullMicros(&tx.Now), ID: uid}); err != nil {
				return err
			}
			res.UserID, res.Session = uid, &c
			_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorUser, ID: uid}, Action: "session.step_up",
				AuthMethod: method, Target: audit.Target{Type: "session", ID: c.ID}})
			return err
		})
		if err != nil {
			svc.failure(ctx, prov.ID, "stepup_failed", nil)
		}
		return res, err
	case IntentLink:
		if reauthCapable(prov) && (claims.AuthTime.IsZero() || now.Sub(authTime) > svc.sessions.Options().StepUpWindow) {
			svc.failure(ctx, prov.ID, "stale_auth_time", nil)
			return Result{}, ErrStaleAuth
		}
		err = svc.s.W().TxNamed(ctx, "idp.link", func(tx *store.Tx) error {
			owner, err := svc.identityOwner(ctx, tx, prov, claims)
			switch {
			case err == nil && owner == cur.UserID:
				return nil
			case err == nil:
				return ErrAlreadyLinked
			case !errors.Is(err, ErrNotEnrolled):
				return err
			}
			if err := svc.linkTx(ctx, tx, prov, claims, cur.UserID); err != nil {
				return err
			}
			res.UserID = cur.UserID
			_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorUser, ID: cur.UserID}, Action: "identity.linked",
				Target: audit.Target{Type: "user", ID: cur.UserID}, Details: map[string]any{"provider_id": prov.ID, "hd": claims.HD}})
			return err
		})
		return res, err
	}
	return Result{}, ErrBadState
}

// reauthCapable reports whether the provider honours prompt=login and max_age=0 and reports auth_time, so step-up and
// linking can demand a fresh upstream sign-in. Google does not support re-authentication requests and sends auth_time
// only to verified apps that opted in; for it, a completed interactive sign-in bound to this browser's login state is
// the proof (ADR-0047).
func reauthCapable(prov db.IdentityProvider) bool { return prov.Kind != KindGoogle }

func (svc *Service) recheckFailed(ctx context.Context, cur *session.Principal, prov db.IdentityProvider, reason string, res Result) (Result, error) {
	err := svc.s.W().TxNamed(ctx, "idp.recheck_failed", func(tx *store.Tx) error {
		if err := svc.sessions.RevokeTx(ctx, tx, cur.SessionID, "upstream_recheck_failed"); err != nil {
			return err
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorUser, ID: cur.UserID}, Action: "session.upstream_recheck",
			Outcome: audit.OutcomeDenied, ReasonCode: reason, Target: audit.Target{Type: "session", ID: cur.SessionID},
			Details: map[string]any{"provider_id": prov.ID}})
		return err
	})
	res.Revoked = true
	return res, err
}

// failure records a failed upstream login (best effort: an audit failure must not mask the login error).
func (svc *Service) failure(ctx context.Context, providerID, reason string, details map[string]any) {
	if details == nil {
		details = map[string]any{}
	}
	details["provider_id"] = providerID
	_ = svc.s.W().TxNamed(ctx, "idp.failure", func(tx *store.Tx) error {
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorUser}, Action: "login.upstream", Outcome: audit.OutcomeDenied,
			ReasonCode: reason, Details: details})
		return err
	})
	svc.opts.Metrics.Login("upstream", "failure")
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

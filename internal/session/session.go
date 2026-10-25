// Package session implements server-side browser sessions (ADR-0021): the cookie carries a random token, the database
// stores only HMAC(token key, token). Sessions end on idle or absolute expiry, revocation, a user epoch bump
// (disable, credential change) or an installation epoch bump (restore). Step-up checks auth_time (ADR-0010).
//
// Adapted from HallPass internal/opauth/sessions.go (Apache-2.0).
package session

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/aurimasniekis/go-porch/internal/apperr"
	"github.com/aurimasniekis/go-porch/internal/clock"
	"github.com/aurimasniekis/go-porch/internal/domain"
	"github.com/aurimasniekis/go-porch/internal/ids"
	"github.com/aurimasniekis/go-porch/internal/keyring"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/store/db"
)

// CookieName is the session cookie. The __Host- prefix forces Secure, Path=/ and no Domain attribute, so sibling
// subdomains can neither read nor plant it.
const CookieName = "__Host-porch_session"

// Methods recorded on sessions.
const (
	MethodSetup        = "setup"
	MethodGoogle       = "google"
	MethodOIDC         = "oidc"
	MethodBackup       = "backup"
	MethodRecoveryLink = "recovery_link"
	// MethodAutomation marks principals authenticated with an automation token (never stored on sessions).
	MethodAutomation = "automation"
)

// Options configure the manager.
type Options struct {
	Idle            time.Duration
	Absolute        time.Duration
	StepUpWindow    time.Duration
	UpstreamRecheck time.Duration
	SetupAbsolute   time.Duration
	Clock           clock.Clock
}

// Manager creates and validates sessions.
type Manager struct {
	s    *store.Store
	kr   *keyring.Keyring
	opts Options
}

// New returns a manager.
func New(s *store.Store, kr *keyring.Keyring, opts Options) *Manager {
	if opts.Clock == nil {
		opts.Clock = clock.System{}
	}
	return &Manager{s: s, kr: kr, opts: opts}
}

// Options returns the effective options.
func (m *Manager) Options() Options { return m.opts }

// Principal is the authenticated user behind a request.
type Principal struct {
	SessionID         string
	UserID            string
	PublicID          string
	DisplayName       string
	Email             string
	TenantID          string
	Method            string
	ProviderID        string
	AuthTime          time.Time
	UpstreamCheckedAt *time.Time
	ExpiresAt         time.Time
	// CreatedAt is when this session (or its latest rotation) was created by Porch: a login or step-up.
	CreatedAt     time.Time
	OperatorRoles []string
	CSRFToken     string
	csrfSecret    []byte
	// Token is set when the request authenticated with an automation token instead of a browser session (ADR-0041).
	Token *TokenGrant
}

// TokenGrant restricts a principal to what an automation token allows: an installation role, or a tenant and a set
// of tenant permissions. The creator's current rights still apply on every request.
type TokenGrant struct {
	ID          string
	TenantID    string   // empty for installation tokens
	Role        string   // installation tokens: admin or auditor
	Permissions []string // tenant tokens
	// CreatedAt is when the token was issued (its principal's auth_time: tokens never count as a fresh sign-in).
	CreatedAt time.Time
	// CreatorOperator is true while the creator of a tenant token holds installation owner or admin: such tokens act
	// through the operator scope, still limited to their tenant and permissions.
	CreatorOperator bool
	// NeverExpires marks an owner's installation token without expiry (ADR-0046): it does not depend on the identity
	// provider confirming its creator.
	NeverExpires bool
}

// IsOperator reports whether the principal holds one of the given installation roles.
func (p *Principal) IsOperator(roles ...string) bool {
	for _, have := range p.OperatorRoles {
		for _, want := range roles {
			if have == want {
				return true
			}
		}
	}
	return false
}

// VerifyCSRF checks a request's CSRF token in constant time.
func (p *Principal) VerifyCSRF(token string) bool {
	return token != "" && hmac.Equal([]byte(token), []byte(csrfToken(p.csrfSecret, p.SessionID)))
}

func csrfToken(secret []byte, sessionID string) string {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte("porch/csrf/v1|" + sessionID))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func (m *Manager) mac(token string) ([]byte, error) {
	return m.kr.MAC(keyring.PurposeToken, []byte("porch/session/v1|"+token))
}

// NewParams describe a session to create.
type NewParams struct {
	UserID            string
	TenantID          string
	Method            string
	ProviderID        string
	AuthTime          time.Time
	UpstreamCheckedAt *time.Time
	IP                string
	UserAgent         string
}

// Created is a new session; Token goes into the cookie and is never stored.
type Created struct {
	ID        string
	Token     string
	ExpiresAt time.Time
}

// RandomToken returns 32 random bytes, base64url.
func RandomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// limits returns the session lifetimes for a user: the installation defaults, shortened by the overrides of every
// active tenant the user belongs to. Sessions are installation-wide, so the strictest tenant wins; an override can
// shorten sessions but never lengthen them beyond the installation defaults. The tenant the session was started for
// (loginTenantID, may be empty) counts even without a membership.
func (m *Manager) limits(ctx context.Context, tx *store.Tx, userID, loginTenantID string) (idle, absolute time.Duration, err error) {
	idle, absolute = m.opts.Idle, m.opts.Absolute
	ms, err := tx.Q.ListUserMemberships(ctx, userID)
	if err != nil {
		return 0, 0, err
	}
	tenantIDs := make([]string, 0, len(ms)+1)
	if loginTenantID != "" {
		tenantIDs = append(tenantIDs, loginTenantID)
	}
	for _, mem := range ms {
		if mem.Status == "active" && mem.TenantStatus == "active" {
			tenantIDs = append(tenantIDs, mem.TenantID)
		}
	}
	for _, id := range tenantIDs {
		t, err := tx.Q.GetTenant(ctx, id)
		if err != nil {
			return 0, 0, err
		}
		if t.SessionIdleSecs.Valid {
			idle = min(idle, time.Duration(t.SessionIdleSecs.Int64)*time.Second)
		}
		if t.SessionAbsoluteSecs.Valid {
			absolute = min(absolute, time.Duration(t.SessionAbsoluteSecs.Int64)*time.Second)
		}
	}
	return idle, absolute, nil
}

// CreateTx inserts a session inside tx.
func (m *Manager) CreateTx(ctx context.Context, tx *store.Tx, p NewParams) (Created, error) {
	token, err := RandomToken()
	if err != nil {
		return Created{}, err
	}
	mac, err := m.mac(token)
	if err != nil {
		return Created{}, err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return Created{}, err
	}
	inst, err := tx.Q.GetInstallation(ctx)
	if err != nil {
		return Created{}, err
	}
	u, err := tx.Q.GetUser(ctx, p.UserID)
	if err != nil {
		return Created{}, err
	}
	idle, absolute, err := m.limits(ctx, tx, p.UserID, p.TenantID)
	if err != nil {
		return Created{}, err
	}
	if p.Method == MethodSetup {
		absolute = min(absolute, m.opts.SetupAbsolute)
	}
	if p.AuthTime.IsZero() {
		p.AuthTime = tx.Now
	}
	if len(p.UserAgent) > 256 {
		p.UserAgent = p.UserAgent[:256]
	}
	id := ids.New(ids.Session)
	exp := tx.Now.Add(absolute)
	err = tx.Q.InsertSession(ctx, db.InsertSessionParams{ID: id, Mac: mac, UserID: p.UserID, TenantID: domain.NullStr(p.TenantID),
		Method: p.Method, ProviderID: domain.NullStr(p.ProviderID), AuthTime: p.AuthTime.UnixMicro(),
		UpstreamCheckedAt: domain.NullMicros(p.UpstreamCheckedAt), CsrfSecret: secret, InstallEpoch: inst.SecurityEpoch,
		UserEpoch: u.SecurityEpoch, IdleSecs: int64(idle / time.Second), AbsoluteExpiresAt: exp.UnixMicro(), CreatedAt: tx.NowMicros(),
		LastSeenAt: tx.NowMicros(), Ip: p.IP, UserAgent: p.UserAgent})
	if err != nil {
		return Created{}, err
	}
	if err := tx.Q.TouchUserLogin(ctx, db.TouchUserLoginParams{LastLoginAt: sql.NullInt64{Int64: tx.NowMicros(), Valid: true}, ID: p.UserID}); err != nil {
		return Created{}, err
	}
	return Created{ID: id, Token: token, ExpiresAt: exp}, nil
}

// ErrUnauthorized means no valid session.
var ErrUnauthorized = apperr.New(apperr.CodeUnauthorized, "authentication required")

// ErrReauthRequired means the operation needs a fresh authentication (step-up).
var ErrReauthRequired = apperr.New(apperr.CodeReauth, "recent authentication required")

// Authenticate resolves a cookie token to a principal and marks the session active.
func (m *Manager) Authenticate(ctx context.Context, token string) (*Principal, error) {
	return m.authenticate(ctx, token, true)
}

// Validate is Authenticate without touching the idle timer.
func (m *Manager) Validate(ctx context.Context, token string) (*Principal, error) {
	return m.authenticate(ctx, token, false)
}

func (m *Manager) authenticate(ctx context.Context, token string, touch bool) (*Principal, error) {
	if token == "" || len(token) > 128 {
		return nil, ErrUnauthorized
	}
	macs, err := m.kr.MACAll(keyring.PurposeToken, []byte("porch/session/v1|"+token))
	if err != nil {
		return nil, err
	}
	var row db.Session
	found := false
	for _, mac := range macs {
		row, err = m.s.R().GetSessionByMAC(ctx, mac)
		if err == nil {
			found = true
			break
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
	}
	if !found {
		return nil, ErrUnauthorized
	}
	return m.principal(ctx, row, touch)
}

// ByID validates the session with this ID (without touching its idle timer). Forward-auth sessions use it to check that
// the Porch session behind them is still valid.
func (m *Manager) ByID(ctx context.Context, id string) (*Principal, error) {
	row, err := m.s.R().GetSession(ctx, id)
	if err != nil {
		return nil, ErrUnauthorized
	}
	return m.principal(ctx, row, false)
}

func (m *Manager) principal(ctx context.Context, row db.Session, touch bool) (*Principal, error) {
	now := m.opts.Clock.Now()
	if row.RevokedAt.Valid || !now.Before(domain.FromMicros(row.AbsoluteExpiresAt)) ||
		now.Sub(domain.FromMicros(row.LastSeenAt)) > time.Duration(row.IdleSecs)*time.Second {
		return nil, ErrUnauthorized
	}
	inst, err := m.s.R().GetInstallation(ctx)
	if err != nil {
		return nil, err
	}
	u, err := m.s.R().GetUser(ctx, row.UserID)
	if err != nil || u.Status != "active" || u.SecurityEpoch != row.UserEpoch || inst.SecurityEpoch != row.InstallEpoch {
		return nil, ErrUnauthorized
	}
	roles, err := m.s.R().ListOperatorRoles(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	p := &Principal{SessionID: row.ID, UserID: u.ID, PublicID: u.PublicID, DisplayName: u.DisplayName, Email: u.PrimaryEmail.String,
		TenantID: row.TenantID.String, Method: row.Method, ProviderID: row.ProviderID.String, AuthTime: domain.FromMicros(row.AuthTime),
		UpstreamCheckedAt: domain.OptMicros(row.UpstreamCheckedAt), ExpiresAt: domain.FromMicros(row.AbsoluteExpiresAt), CreatedAt: domain.FromMicros(row.CreatedAt),
		OperatorRoles: roles, csrfSecret: row.CsrfSecret}
	p.CSRFToken = csrfToken(row.CsrfSecret, row.ID)
	if touch && now.Sub(domain.FromMicros(row.LastSeenAt)) > time.Minute {
		_ = m.s.W().TxNamed(ctx, "session.touch", func(tx *store.Tx) error {
			return tx.Q.TouchSession(ctx, db.TouchSessionParams{LastSeenAt: tx.NowMicros(), ID: row.ID})
		})
	}
	return p, nil
}

// RequireStepUp returns ErrReauthRequired unless the session authenticated within the step-up window.
func (m *Manager) RequireStepUp(p *Principal) error {
	if p == nil || m.opts.Clock.Now().Sub(p.AuthTime) > m.opts.StepUpWindow {
		return ErrReauthRequired
	}
	return nil
}

// NeedsUpstreamRecheck reports whether a federated session is due for its silent upstream re-check (ADR-0007).
func (m *Manager) NeedsUpstreamRecheck(p *Principal) bool {
	if p.Method != MethodGoogle && p.Method != MethodOIDC {
		return false
	}
	last := p.AuthTime
	if p.UpstreamCheckedAt != nil && p.UpstreamCheckedAt.After(last) {
		last = *p.UpstreamCheckedAt
	}
	return m.opts.Clock.Now().Sub(last) > m.opts.UpstreamRecheck
}

// RevokeTx ends a session inside tx.
func (m *Manager) RevokeTx(ctx context.Context, tx *store.Tx, sessionID, reason string) error {
	_, err := tx.Q.RevokeSession(ctx, db.RevokeSessionParams{RevokedAt: domain.NullMicros(&tx.Now), RevokeReason: domain.NullStr(reason), ID: sessionID})
	return err
}

// Revoke ends a session.
func (m *Manager) Revoke(ctx context.Context, sessionID, reason string) error {
	return m.s.W().TxNamed(ctx, "session.revoke", func(tx *store.Tx) error { return m.RevokeTx(ctx, tx, sessionID, reason) })
}

// RotateTx replaces a session with a new token (same user, tenant and method) inside tx: used after step-up and on
// privilege changes so a token observed before cannot be replayed. authTime, when non-zero, becomes the new auth_time.
func (m *Manager) RotateTx(ctx context.Context, tx *store.Tx, old *Principal, authTime time.Time, ip, ua string) (Created, error) {
	if authTime.IsZero() {
		authTime = old.AuthTime
	}
	c, err := m.CreateTx(ctx, tx, NewParams{UserID: old.UserID, TenantID: old.TenantID, Method: old.Method, ProviderID: old.ProviderID,
		AuthTime: authTime, UpstreamCheckedAt: old.UpstreamCheckedAt, IP: ip, UserAgent: ua})
	if err != nil {
		return Created{}, err
	}
	return c, m.RevokeTx(ctx, tx, old.SessionID, "rotated")
}

// SetTenant selects the session's current tenant.
func (m *Manager) SetTenant(ctx context.Context, sessionID, tenantID string) error {
	return m.s.W().TxNamed(ctx, "session.set_tenant", func(tx *store.Tx) error {
		_, err := tx.Q.SetSessionTenant(ctx, db.SetSessionTenantParams{TenantID: domain.NullStr(tenantID), ID: sessionID})
		return err
	})
}

// SetCookie writes the session cookie.
func SetCookie(w http.ResponseWriter, c Created) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: c.Token, Path: "/", Expires: c.ExpiresAt, Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode})
}

// ClearCookie removes the session cookie.
func ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

// TokenFromRequest returns the session cookie value.
func TokenFromRequest(r *http.Request) string {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

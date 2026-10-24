package mgmtapi

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/aurimasniekis/go-porch/internal/apperr"
	"github.com/aurimasniekis/go-porch/internal/httpx"
	"github.com/aurimasniekis/go-porch/internal/session"
	"github.com/aurimasniekis/go-porch/internal/setup"
)

// SetupStatus reports whether the first owner exists.
type SetupStatus struct {
	Completed bool `json:"completed"`
}

// SessionInfo describes the caller's session.
type SessionInfo struct {
	ID        string    `json:"id"`
	Method    string    `json:"method"`
	AuthTime  time.Time `json:"auth_time"`
	ExpiresAt time.Time `json:"expires_at"`
	TenantID  string    `json:"tenant_id,omitempty"`
}

// MeMembership is one tenant the caller belongs to.
type MeMembership struct {
	TenantID   string `json:"tenant_id"`
	TenantSlug string `json:"tenant_slug"`
	TenantName string `json:"tenant_name"`
	Status     string `json:"status"`
}

// Me is the authenticated caller.
type Me struct {
	UserID        string         `json:"user_id"`
	PublicID      string         `json:"public_id"`
	DisplayName   string         `json:"display_name"`
	Email         string         `json:"email,omitempty"`
	OperatorRoles []string       `json:"operator_roles"`
	Memberships   []MeMembership `json:"memberships"`
	Session       SessionInfo    `json:"session"`
	CSRFToken     string         `json:"csrf_token" doc:"Send as X-Porch-CSRF on state-changing requests."`
}

type meOutput struct {
	SetCookie http.Cookie `header:"Set-Cookie"`
	Body      Me
}

func (d *Deps) me(ctx context.Context, p *session.Principal) (Me, error) {
	rows, err := d.Tenants.UserMemberships(ctx, p.UserID)
	if err != nil {
		return Me{}, d.fail("me", err)
	}
	ms := make([]MeMembership, 0, len(rows))
	for _, r := range rows {
		if r.TenantStatus != "active" {
			continue
		}
		ms = append(ms, MeMembership{TenantID: r.TenantID, TenantSlug: r.TenantSlug, TenantName: r.TenantName, Status: r.Status})
	}
	roles := p.OperatorRoles
	if roles == nil {
		roles = []string{}
	}
	return Me{UserID: p.UserID, PublicID: p.PublicID, DisplayName: p.DisplayName, Email: p.Email, OperatorRoles: roles, Memberships: ms,
		Session:   SessionInfo{ID: p.SessionID, Method: p.Method, AuthTime: p.AuthTime, ExpiresAt: p.ExpiresAt, TenantID: p.TenantID},
		CSRFToken: p.CSRFToken}, nil
}

func sessionCookie(c session.Created) http.Cookie {
	return http.Cookie{Name: session.CookieName, Value: c.Token, Path: "/", Expires: c.ExpiresAt, Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode}
}

// SetupRequest is the request body of complete-setup.
type SetupRequest struct {
	Token       string `json:"token" minLength:"1" maxLength:"128" doc:"Setup token printed by 'porch admin setup-token'."`
	DisplayName string `json:"display_name" minLength:"1" maxLength:"200"`
	Email       string `json:"email,omitempty" maxLength:"254"`
}

func registerSetup(api huma.API, d *Deps) {
	tags := []string{"session"}
	huma.Register(api, huma.Operation{OperationID: "get-setup-status", Method: http.MethodGet, Path: "/setup/status",
		Summary: "Whether first-run setup is complete", Tags: tags},
		func(ctx context.Context, _ *struct{}) (*struct{ Body SetupStatus }, error) {
			done, err := d.Setup.Completed(ctx)
			if err != nil {
				return nil, d.fail("setup-status", err)
			}
			return &struct{ Body SetupStatus }{Body: SetupStatus{Completed: done}}, nil
		})

	type setupInput struct {
		UserAgent string `header:"User-Agent" required:"false"`
		Body      SetupRequest
	}
	huma.Register(api, huma.Operation{OperationID: "complete-setup", Method: http.MethodPost, Path: "/setup", DefaultStatus: http.StatusCreated,
		Summary:     "Consume a setup token and create the first installation owner",
		Description: "Creates the owner and a short setup session (1 h) used to enroll a login method. Only works while no operator exists.",
		Tags:        tags},
		func(ctx context.Context, in *setupInput) (*meOutput, error) {
			ip := httpx.ClientIP(ctx)
			if d.SetupRate != nil && !d.SetupRate.Allow(httpx.SourceKey(ip)) {
				return nil, fail(apperr.New(apperr.CodeRateLimited, "too many attempts; try again later"))
			}
			res, err := d.Setup.Consume(ctx, setup.ConsumeParams{Token: in.Body.Token, DisplayName: in.Body.DisplayName, Email: in.Body.Email,
				IP: ip.String(), UserAgent: in.UserAgent})
			if err != nil {
				return nil, d.fail("setup", err)
			}
			p, err := d.Sessions.Validate(ctx, res.Session.Token)
			if err != nil {
				return nil, d.fail("setup", err)
			}
			me, err := d.me(ctx, p)
			if err != nil {
				return nil, err
			}
			return &meOutput{SetCookie: sessionCookie(res.Session), Body: me}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "get-me", Method: http.MethodGet, Path: "/me", Summary: "The authenticated caller",
		Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*struct{ Body Me }, error) {
			me, err := d.me(ctx, Principal(ctx))
			if err != nil {
				return nil, err
			}
			return &struct{ Body Me }{Body: me}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "logout", Method: http.MethodPost, Path: "/logout", DefaultStatus: http.StatusNoContent,
		Summary: "End the current session", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*struct {
			SetCookie http.Cookie `header:"Set-Cookie"`
		}, error) {
			p := Principal(ctx)
			if err := d.Sessions.Revoke(ctx, p.SessionID, "logout"); err != nil {
				return nil, d.fail("logout", err)
			}
			out := &struct {
				SetCookie http.Cookie `header:"Set-Cookie"`
			}{SetCookie: http.Cookie{Name: session.CookieName, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}}
			return out, nil
		})
}

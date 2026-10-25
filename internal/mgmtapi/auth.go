package mgmtapi

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/aurimasniekis/go-porch/internal/apperr"
	"github.com/aurimasniekis/go-porch/internal/httpx"
	"github.com/aurimasniekis/go-porch/internal/localauth"
)

// LoginProvider is an enabled upstream provider shown on the login page.
type LoginProvider struct {
	Slug     string `json:"slug"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	LoginURL string `json:"login_url"`
}

// LoginOptions describes how users can sign in.
type LoginOptions struct {
	Providers     []LoginProvider `json:"providers"`
	BackupEnabled bool            `json:"backup_enabled"`
	SetupComplete bool            `json:"setup_complete"`
	// DirectProvider is the slug of the provider the sign-in page redirects to ("" = show every method).
	DirectProvider string `json:"direct_provider"`
}

// BackupStartRequest is step 1 of the backup login.
type BackupStartRequest struct {
	Identifier string `json:"identifier" minLength:"1" maxLength:"254" doc:"Backup handle, or email when no handle is set."`
	Password   string `json:"password" minLength:"1" maxLength:"4096"`
}

// BackupChallenge is returned after a correct password.
type BackupChallenge struct {
	Titles    []string  `json:"titles" doc:"The user's own recovery titles, in order."`
	ExpiresAt time.Time `json:"expires_at"`
}

// BackupFinishRequest is step 2 of the backup login.
type BackupFinishRequest struct {
	Answers []string `json:"answers" minItems:"1" maxItems:"12"`
}

// RecoveryRequest consumes an offline recovery link.
type RecoveryRequest struct {
	Token string `json:"token" minLength:"1" maxLength:"128"`
}

func challengeCookie(value string, maxAge int) http.Cookie {
	return http.Cookie{Name: localauth.ChallengeCookie, Value: value, Path: "/", MaxAge: maxAge, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
}

// loginOrigin enforces Origin on unauthenticated login POSTs (login CSRF).
func (d *Deps) loginOrigin(ctx context.Context, origin, fetchSite string) error {
	r := &http.Request{Header: http.Header{}}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if fetchSite != "" {
		r.Header.Set("Sec-Fetch-Site", fetchSite)
	}
	if !httpx.SameOrigin(r, d.Origin) {
		return problem(http.StatusForbidden, apperr.CodeForbidden, "cross-origin request refused", nil)
	}
	return nil
}

func (d *Deps) meta(ctx context.Context, ua, sessionToken string) localauth.Meta {
	ip := httpx.ClientIP(ctx)
	m := localauth.Meta{SourceKey: httpx.SourceKey(ip), IP: ip.String(), UserAgent: ua}
	if sessionToken != "" {
		if p, err := d.Sessions.Validate(ctx, sessionToken); err == nil {
			m.Session = p
		}
	}
	return m
}

type LoginHeaders struct {
	Origin    string `header:"Origin" required:"false"`
	FetchSite string `header:"Sec-Fetch-Site" required:"false"`
	UserAgent string `header:"User-Agent" required:"false"`
	Session   string `cookie:"__Host-porch_session" required:"false"`
}

func registerAuth(api huma.API, d *Deps) {
	tags := []string{"login"}
	huma.Register(api, huma.Operation{OperationID: "get-login-options", Method: http.MethodGet, Path: "/auth/options",
		Summary: "Sign-in methods available on this installation", Tags: tags},
		func(ctx context.Context, _ *struct{}) (*struct{ Body LoginOptions }, error) {
			out := LoginOptions{Providers: []LoginProvider{}, BackupEnabled: d.Local != nil && !d.Local.Policy().Disabled}
			if d.IDP != nil {
				ps, err := d.IDP.Providers(ctx)
				if err != nil {
					return nil, d.fail("login-options", err)
				}
				for _, p := range ps {
					if p.Enabled {
						out.Providers = append(out.Providers, LoginProvider{Slug: p.Slug, Name: p.Name, Kind: p.Kind, LoginURL: "/login/" + p.Slug})
					}
				}
				if out.DirectProvider, err = d.IDP.DirectProvider(ctx); err != nil {
					return nil, d.fail("login-options", err)
				}
			}
			done, err := d.Setup.Completed(ctx)
			if err != nil {
				return nil, d.fail("login-options", err)
			}
			out.SetupComplete = done
			return &struct{ Body LoginOptions }{Body: out}, nil
		})

	type startInput struct {
		LoginHeaders
		Body BackupStartRequest
	}
	type startOutput struct {
		SetCookie []http.Cookie `header:"Set-Cookie"`
		Body      BackupChallenge
	}
	huma.Register(api, huma.Operation{OperationID: "backup-login-start", Method: http.MethodPost, Path: "/auth/backup/start",
		Summary: "Backup login step 1: identifier and password",
		Description: "On a correct password returns the user's recovery titles and sets a short-lived challenge cookie. Every failure — unknown " +
			"identifier, wrong password, locked account — returns the same 401. With a valid session cookie this performs a step-up.",
		Tags: tags},
		func(ctx context.Context, in *startInput) (*startOutput, error) {
			if err := d.loginOrigin(ctx, in.Origin, in.FetchSite); err != nil {
				return nil, err
			}
			res, err := d.Local.Start(ctx, in.Body.Identifier, in.Body.Password, d.meta(ctx, in.UserAgent, in.Session))
			if err != nil {
				return nil, d.fail("backup-start", err)
			}
			ttl := int(time.Until(res.ExpiresAt).Seconds())
			return &startOutput{SetCookie: []http.Cookie{challengeCookie(res.Challenge, max(ttl, 1))},
				Body: BackupChallenge{Titles: res.Titles, ExpiresAt: res.ExpiresAt}}, nil
		})

	type finishInput struct {
		LoginHeaders
		Challenge string `cookie:"__Host-porch_bchal" required:"false"`
		Body      BackupFinishRequest
	}
	type finishOutput struct {
		SetCookie []http.Cookie `header:"Set-Cookie"`
		Body      Me
	}
	huma.Register(api, huma.Operation{OperationID: "backup-login-finish", Method: http.MethodPost, Path: "/auth/backup/finish",
		Summary: "Backup login step 2: recovery answers", Tags: tags},
		func(ctx context.Context, in *finishInput) (*finishOutput, error) {
			if err := d.loginOrigin(ctx, in.Origin, in.FetchSite); err != nil {
				return nil, err
			}
			c, err := d.Local.Finish(ctx, in.Challenge, in.Body.Answers, d.meta(ctx, in.UserAgent, in.Session))
			if err != nil {
				return nil, d.fail("backup-finish", err)
			}
			p, err := d.Sessions.Validate(ctx, c.Token)
			if err != nil {
				return nil, d.fail("backup-finish", err)
			}
			me, err := d.me(ctx, p)
			if err != nil {
				return nil, err
			}
			return &finishOutput{SetCookie: []http.Cookie{challengeCookie("", -1), sessionCookie(c)}, Body: me}, nil
		})

	type recoveryInput struct {
		LoginHeaders
		Body RecoveryRequest
	}
	huma.Register(api, huma.Operation{OperationID: "use-recovery-link", Method: http.MethodPost, Path: "/auth/recovery",
		Summary: "Sign in with a one-time offline recovery link", Tags: tags},
		func(ctx context.Context, in *recoveryInput) (*meOutput, error) {
			if err := d.loginOrigin(ctx, in.Origin, in.FetchSite); err != nil {
				return nil, err
			}
			if d.LoginRate != nil && !d.LoginRate.Allow(httpx.SourceKey(httpx.ClientIP(ctx))) {
				return nil, fail(apperr.New(apperr.CodeRateLimited, "too many attempts"))
			}
			c, err := d.Local.UseRecoveryLink(ctx, in.Body.Token, d.meta(ctx, in.UserAgent, ""))
			if err != nil {
				return nil, d.fail("recovery", err)
			}
			p, err := d.Sessions.Validate(ctx, c.Token)
			if err != nil {
				return nil, d.fail("recovery", err)
			}
			me, err := d.me(ctx, p)
			if err != nil {
				return nil, err
			}
			return &meOutput{SetCookie: []http.Cookie{sessionCookie(c)}, Body: me}, nil
		})
}

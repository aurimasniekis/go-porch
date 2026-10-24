package mgmtapi

import (
	"context"
	"net/http"
	"slices"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/aurimasniekis/go-porch/internal/apperr"
	"github.com/aurimasniekis/go-porch/internal/apps"
	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/authz"
	"github.com/aurimasniekis/go-porch/internal/domain"
	"github.com/aurimasniekis/go-porch/internal/httpx"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/store/db"
)

// LauncherApp is an application the caller may open.
type LauncherApp struct {
	ID          string `json:"id"`
	Slug        string `json:"slug"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Kind        string `json:"kind"`
	LaunchURL   string `json:"launch_url"`
	TenantSlug  string `json:"tenant_slug"`
	TenantName  string `json:"tenant_name"`
	Shared      bool   `json:"shared" doc:"Owned by another tenant and shared with yours."`
}

// MySession is one of the caller's browser sessions.
type MySession struct {
	ID         string    `json:"id"`
	Method     string    `json:"method"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	IP         string    `json:"ip"`
	UserAgent  string    `json:"user_agent"`
	Current    bool      `json:"current"`
}

// AppGrant is an application holding a refresh token for the caller (offline access).
type AppGrant struct {
	FamilyID  string    `json:"family_id"`
	AppID     string    `json:"app_id"`
	AppName   string    `json:"app_name"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// AuthzCheckRequest asks whether a user may perform an action.
type AuthzCheckRequest struct {
	UserID   string `json:"user_id" minLength:"1" maxLength:"64"`
	Action   string `json:"action" minLength:"3" maxLength:"65" doc:"<resource_type>:<action>, e.g. app:access"`
	Resource struct {
		Type string `json:"type" maxLength:"32"`
		ID   string `json:"id,omitempty" maxLength:"64"`
	} `json:"resource"`
	// Context simulates request context (simulator only; flagged in the trace).
	Context *authz.ContextV1 `json:"context,omitempty"`
}

// AuthzBatchRequest checks several requests.
type AuthzBatchRequest struct {
	Checks []AuthzCheckRequest `json:"checks" minItems:"1" maxItems:"100"`
}

func registerPortal(api huma.API, d *Deps) {
	tags := []string{"account"}
	huma.Register(api, huma.Operation{OperationID: "list-my-apps", Method: http.MethodGet, Path: "/me/apps",
		Summary: "Applications you can open (launcher)", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*struct{ Body []LauncherApp }, error) {
			p := Principal(ctx)
			ms, err := d.Tenants.UserMemberships(ctx, p.UserID)
			if err != nil {
				return nil, d.fail("my-apps", err)
			}
			out := []LauncherApp{}
			seen := map[string]bool{}
			consider := func(a db.Application, t db.ListUserMembershipsRow, shared bool) error {
				if seen[a.ID] || a.Enabled != 1 {
					return nil
				}
				dec, err := d.Engine.Check(ctx, authz.Request{TenantID: a.TenantID, Subject: authz.Subject{Type: "user", ID: p.UserID,
					AuthMethod: p.Method, AuthTime: p.AuthTime}, Action: authz.PermAppAccess, Resource: authz.Resource{Type: "app", ID: a.ID},
					ClientIP: httpx.ClientIP(ctx)})
				if err != nil {
					return err
				}
				if !dec.Allowed {
					return nil
				}
				seen[a.ID] = true
				launch := a.LaunchUrl
				if launch == "" && a.Kind == apps.KindForwardAuth {
					if hosts, err := d.Store.R().ListAppHosts(ctx, a.ID); err == nil && len(hosts) > 0 {
						launch = "https://" + hosts[0] + "/"
					}
				}
				out = append(out, LauncherApp{ID: a.ID, Slug: a.Slug, Name: a.Name, Description: a.Description, Kind: a.Kind, LaunchURL: launch,
					TenantSlug: t.TenantSlug, TenantName: t.TenantName, Shared: shared})
				return nil
			}
			for _, m := range ms {
				if m.Status != "active" || m.TenantStatus != "active" {
					continue
				}
				owned, err := d.Store.R().ListApplications(ctx, m.TenantID)
				if err != nil {
					return nil, d.fail("my-apps", err)
				}
				for _, a := range owned {
					if err := consider(a, m, false); err != nil {
						return nil, d.fail("my-apps", err)
					}
				}
				shared, err := d.Store.R().ListAppsSharedTo(ctx, m.TenantID)
				if err != nil {
					return nil, d.fail("my-apps", err)
				}
				for _, a := range shared {
					if err := consider(a, m, true); err != nil {
						return nil, d.fail("my-apps", err)
					}
				}
			}
			slices.SortFunc(out, func(a, b LauncherApp) int {
				if a.Name < b.Name {
					return -1
				}
				return 1
			})
			return &struct{ Body []LauncherApp }{Body: out}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "list-my-sessions", Method: http.MethodGet, Path: "/me/sessions",
		Summary: "Your active browser sessions", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*struct{ Body []MySession }, error) {
			p := Principal(ctx)
			rows, err := d.Store.R().ListUserSessions(ctx, db.ListUserSessionsParams{UserID: p.UserID, AbsoluteExpiresAt: d.now().UnixMicro()})
			if err != nil {
				return nil, d.fail("my-sessions", err)
			}
			out := make([]MySession, 0, len(rows))
			for _, r := range rows {
				out = append(out, MySession{ID: r.ID, Method: r.Method, CreatedAt: domain.FromMicros(r.CreatedAt), LastSeenAt: domain.FromMicros(r.LastSeenAt),
					ExpiresAt: domain.FromMicros(r.AbsoluteExpiresAt), IP: r.Ip, UserAgent: r.UserAgent, Current: r.ID == p.SessionID})
			}
			return &struct{ Body []MySession }{Body: out}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "revoke-my-session", Method: http.MethodDelete, Path: "/me/sessions/{session}",
		DefaultStatus: http.StatusNoContent, Summary: "Sign out one of your sessions", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			Session string `path:"session" maxLength:"64"`
		}) (*struct{}, error) {
			p := Principal(ctx)
			err := d.Store.W().TxNamed(ctx, "me.revoke_session", func(tx *store.Tx) error {
				s, err := tx.Q.GetSession(ctx, in.Session)
				if err != nil || s.UserID != p.UserID {
					return apperr.New(apperr.CodeNotFound, "session not found")
				}
				if err := d.Sessions.RevokeTx(ctx, tx, s.ID, "user_revoked"); err != nil {
					return err
				}
				_, err = d.Audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorUser, ID: p.UserID}, Action: "session.revoked",
					Target: audit.Target{Type: "session", ID: s.ID}})
				return err
			})
			if err != nil {
				return nil, d.fail("revoke-session", err)
			}
			return &struct{}{}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "list-my-grants", Method: http.MethodGet, Path: "/me/grants",
		Summary: "Applications with offline access to your account (refresh tokens)", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*struct{ Body []AppGrant }, error) {
			rows, err := d.Store.R().ListUserFamiliesWithApps(ctx, Principal(ctx).UserID)
			if err != nil {
				return nil, d.fail("my-grants", err)
			}
			out := make([]AppGrant, 0, len(rows))
			for _, r := range rows {
				out = append(out, AppGrant{FamilyID: r.FamilyID, AppID: r.AppID, AppName: r.AppName, CreatedAt: domain.FromMicros(toInt(r.CreatedAt)),
					ExpiresAt: domain.FromMicros(toInt(r.IdleExpiresAt))})
			}
			return &struct{ Body []AppGrant }{Body: out}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "revoke-my-grant", Method: http.MethodDelete, Path: "/me/grants/{family}",
		DefaultStatus: http.StatusNoContent, Summary: "Revoke an application's offline access", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			Family string `path:"family" maxLength:"64"`
		}) (*struct{}, error) {
			p := Principal(ctx)
			err := d.Store.W().TxNamed(ctx, "me.revoke_grant", func(tx *store.Tx) error {
				n, err := tx.Q.RevokeUserFamily(ctx, db.RevokeUserFamilyParams{RevokedAt: domain.NullMicros(&tx.Now), RevokeReason: domain.NullStr("user_revoked"),
					UserID: p.UserID, FamilyID: in.Family})
				if err != nil {
					return err
				}
				if n == 0 {
					return apperr.New(apperr.CodeNotFound, "grant not found")
				}
				_, err = d.Audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorUser, ID: p.UserID}, Action: "oidc.grant_revoked",
					Details: map[string]any{"family_id": in.Family}})
				return err
			})
			if err != nil {
				return nil, d.fail("revoke-grant", err)
			}
			return &struct{}{}, nil
		})

	atags := []string{"authorization"}
	check := func(ctx context.Context, tenantID string, in AuthzCheckRequest) (authz.Decision, error) {
		return d.Engine.Check(ctx, authz.Request{TenantID: tenantID, Subject: authz.Subject{Type: "user", ID: in.UserID}, Action: in.Action,
			Resource: authz.Resource{Type: in.Resource.Type, ID: in.Resource.ID}, ClientIP: httpx.ClientIP(ctx), SimulatedContext: in.Context})
	}
	huma.Register(api, huma.Operation{OperationID: "authz-check", Method: http.MethodPost, Path: "/tenants/{tenant}/authz/check",
		Summary: "Decide (and explain) whether a user may perform an action", Tags: atags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			TenantRef
			Body AuthzCheckRequest
		}) (*struct{ Body authz.Decision }, error) {
			sc, err := d.tenantAdmin(ctx, in.Tenant, authz.PermAuthzSimulate)
			if err != nil {
				return nil, err
			}
			dec, err := check(ctx, sc.TenantID(), in.Body)
			if err != nil {
				return nil, d.fail("authz-check", err)
			}
			return &struct{ Body authz.Decision }{Body: dec}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "authz-check-batch", Method: http.MethodPost, Path: "/tenants/{tenant}/authz/check-batch",
		Summary: "Several authorization decisions at once", Tags: atags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			TenantRef
			Body AuthzBatchRequest
		}) (*struct{ Body []authz.Decision }, error) {
			sc, err := d.tenantAdmin(ctx, in.Tenant, authz.PermAuthzSimulate)
			if err != nil {
				return nil, err
			}
			out := make([]authz.Decision, 0, len(in.Body.Checks))
			for _, c := range in.Body.Checks {
				dec, err := check(ctx, sc.TenantID(), c)
				if err != nil {
					return nil, d.fail("authz-check", err)
				}
				out = append(out, dec)
			}
			return &struct{ Body []authz.Decision }{Body: out}, nil
		})
}

func toInt(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case float64:
		return int64(x)
	}
	return 0
}

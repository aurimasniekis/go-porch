// Package mgmtapi serves the management API under /api/v1 with Huma v2 (ADR-0016). The OpenAPI 3.1 document is
// generated from this code (`porch openapi`), committed as api/openapi.json and drift-checked in CI.
package mgmtapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	"github.com/aurimasniekis/go-porch/internal/apperr"
	"github.com/aurimasniekis/go-porch/internal/apps"
	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/domain"
	"github.com/aurimasniekis/go-porch/internal/httpx"
	"github.com/aurimasniekis/go-porch/internal/identity"
	"github.com/aurimasniekis/go-porch/internal/idp"
	"github.com/aurimasniekis/go-porch/internal/localauth"
	"github.com/aurimasniekis/go-porch/internal/obs/metrics"
	"github.com/aurimasniekis/go-porch/internal/oidcop"
	"github.com/aurimasniekis/go-porch/internal/session"
	"github.com/aurimasniekis/go-porch/internal/setup"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/tenancy"
)

// Prefix is the API mount point.
const Prefix = "/api/v1"

// CSRFHeader carries the session's CSRF token on state-changing cookie-authenticated requests.
const CSRFHeader = "X-Porch-CSRF"

// ManagedByHeader lets clients declare provenance (ui, api, terraform).
const ManagedByHeader = "X-Porch-Managed-By"

// Deps are the services the API needs.
type Deps struct {
	Log       *slog.Logger
	Version   string
	Origin    string // public origin, for Origin checks
	Store     *store.Store
	Audit     *audit.Writer
	Users     *identity.Service
	Tenants   *tenancy.Service
	Sessions  *session.Manager
	Setup     *setup.Service
	IDP       *idp.Service
	Local     *localauth.Service
	Apps      *apps.Service
	OP        *oidcop.Provider
	Metrics   *metrics.Metrics
	SetupRate *httpx.Limiter
	LoginRate *httpx.Limiter
}

func (d *Deps) log() *slog.Logger {
	if d.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return d.Log
}

// Security scheme names.
const (
	schemeSession = "session"
)

// Config returns the Huma configuration (shared with the openapi command).
func Config(version string) huma.Config {
	c := huma.DefaultConfig("Porch management API", version)
	c.Servers = []*huma.Server{{URL: Prefix}}
	c.DocsPath = "" // the docs UI loads third-party scripts, which the CSP forbids
	c.OpenAPIPath = "/openapi"
	c.SchemasPath = ""
	c.CreateHooks = nil // no $schema links in bodies
	c.Info.Description = "Management API for Porch. Browser clients authenticate with the __Host-porch_session cookie and " +
		"send the session's CSRF token in X-Porch-CSRF on state-changing requests. Automation clients use " +
		"`Authorization: Bearer porch_at_…` (milestone M6)."
	c.Components.SecuritySchemes = map[string]*huma.SecurityScheme{
		schemeSession: {Type: "apiKey", In: "cookie", Name: session.CookieName},
	}
	return c
}

// New registers every operation on mux and returns the API.
func New(mux *http.ServeMux, d *Deps) huma.API {
	api := humago.NewWithPrefix(mux, Prefix, Config(d.Version))
	api.UseMiddleware(d.authenticate(api))
	registerSetup(api, d)
	registerInstallation(api, d)
	registerTenants(api, d)
	registerUsers(api, d)
	registerMembers(api, d)
	registerAuth(api, d)
	registerAccount(api, d)
	registerProviders(api, d)
	registerDomainRules(api, d)
	registerAlerts(api, d)
	registerApplications(api, d)
	registerSigningKeys(api, d)
	return api
}

var sessionSecurity = []map[string][]string{{schemeSession: {}}}

type principalKey struct{}

// Principal returns the authenticated principal (nil for public operations).
func Principal(ctx context.Context) *session.Principal {
	p, _ := ctx.Value(principalKey{}).(*session.Principal)
	return p
}

// authenticate resolves the session for operations that declare security, enforces Origin + CSRF on unsafe methods
// and attaches audit metadata.
func (d *Deps) authenticate(api huma.API) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		r, _ := humago.Unwrap(ctx)
		meta := audit.Meta{SourceIP: httpx.ClientIP(r.Context()).String(), RequestID: httpx.GetRequestID(r.Context())}
		op := ctx.Operation()
		if op == nil || len(op.Security) == 0 {
			next(huma.WithContext(ctx, audit.WithMeta(ctx.Context(), meta)))
			return
		}
		if !httpx.IsSafeMethod(r.Method) && !httpx.SameOrigin(r, d.Origin) {
			_ = huma.WriteErr(api, ctx, http.StatusForbidden, "cross-origin request refused")
			return
		}
		p, err := d.Sessions.Authenticate(r.Context(), session.TokenFromRequest(r))
		if err != nil {
			_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "authentication required")
			return
		}
		if !httpx.IsSafeMethod(r.Method) && !p.VerifyCSRF(r.Header.Get(CSRFHeader)) {
			_ = huma.WriteErr(api, ctx, http.StatusForbidden, "missing or invalid CSRF token")
			return
		}
		if !recheckExempt[op.OperationID] && d.Sessions.NeedsUpstreamRecheck(p) {
			// Federated sessions must re-confirm the upstream account at least hourly (ADR-0007). The UI follows the action URL.
			pr := problem(http.StatusUnauthorized, "upstream_recheck_required", "the session must be re-confirmed with the identity provider", nil)
			pr.Action = d.providerAction(r.Context(), p, idp.IntentRecheck)
			_ = writeProblem(api, ctx, pr)
			return
		}
		meta.AuthMethod = p.Method
		c := context.WithValue(audit.WithMeta(ctx.Context(), meta), principalKey{}, p)
		next(huma.WithContext(ctx, c))
	}
}

// recheckExempt operations work even while an upstream recheck is due (so the UI can show who is signed in).
var recheckExempt = map[string]bool{"get-me": true, "logout": true}

// providerAction returns the portal URL that runs an upstream round trip (recheck or step-up) for the session's provider.
func (d *Deps) providerAction(ctx context.Context, p *session.Principal, intent string) string {
	if d.IDP == nil || p.ProviderID == "" {
		return ""
	}
	prov, err := d.IDP.Provider(ctx, p.ProviderID)
	if err != nil {
		return ""
	}
	return "/login/" + prov.Slug + "?intent=" + intent
}

// stepUp enforces a recent authentication (ADR-0010). The problem's action tells the UI how to re-authenticate.
func (d *Deps) stepUp(ctx context.Context) error {
	p := Principal(ctx)
	if err := d.Sessions.RequireStepUp(p); err == nil {
		return nil
	}
	pr := problem(http.StatusForbidden, apperr.CodeReauth, "this action needs a recent sign-in", nil)
	switch p.Method {
	case session.MethodGoogle, session.MethodOIDC:
		pr.Action = d.providerAction(ctx, p, idp.IntentStepUp)
	default:
		pr.Action = "/login?stepup=backup"
	}
	return pr
}

// change derives provenance for a mutation.
func change(ctx context.Context, managedBy string) domain.Change {
	p := Principal(ctx)
	ch := domain.Change{ManagedBy: managedBy}
	if p != nil {
		ch.Actor = audit.Actor{Type: audit.ActorUser, ID: p.UserID}
	} else {
		ch.Actor = audit.Actor{Type: audit.ActorUser}
	}
	return ch
}

// requireOperator checks installation roles.
func requireOperator(ctx context.Context, roles ...string) (*session.Principal, error) {
	p := Principal(ctx)
	if p == nil {
		return nil, huma.Error401Unauthorized("authentication required")
	}
	if !p.IsOperator(roles...) {
		return nil, problem(http.StatusForbidden, apperr.CodeForbidden, "installation role required: "+strings.Join(roles, " or "), nil)
	}
	return p, nil
}

// ManagedBy is embedded by mutating inputs.
type ManagedBy struct {
	ManagedBy string `header:"X-Porch-Managed-By" enum:"ui,api,terraform" required:"false" doc:"Provenance of the change (informational)."`
}

// IfMatch is embedded by inputs of conditional mutations.
type IfMatch struct {
	IfMatch string `header:"If-Match" required:"false" doc:"ETag (resource version) the change is based on; mismatches fail with 412."`
}

// Version parses the If-Match header ("" → 0 = unconditional).
func (m IfMatch) Version() (int64, error) {
	s := strings.TrimSpace(m.IfMatch)
	if s == "" || s == "*" {
		return 0, nil
	}
	s = strings.TrimPrefix(s, "W/")
	s = strings.Trim(s, `"`)
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v <= 0 {
		return 0, problem(http.StatusBadRequest, apperr.CodeInvalid, "If-Match must be an ETag returned by this API", nil)
	}
	return v, nil
}

func etag(version int64) string { return fmt.Sprintf(`"%d"`, version) }

// Pagination is embedded by list inputs.
type Pagination struct {
	Limit  int    `query:"limit" minimum:"1" maximum:"200" default:"50" doc:"Page size."`
	Cursor string `query:"cursor" maxLength:"128" doc:"Opaque cursor from next_cursor."`
}

// Page converts to a domain page.
func (p Pagination) Page() (domain.Page, error) {
	pg, err := domain.ParsePage(p.Limit, p.Cursor)
	if err != nil {
		return pg, fail(err)
	}
	return pg, nil
}

// fail converts a domain error into an RFC 9457 problem, logging unexpected errors without leaking them.
func (d *Deps) fail(op string, err error) error {
	var ae *apperr.Error
	if errors.As(err, &ae) {
		return fail(err)
	}
	if errors.Is(err, context.Canceled) {
		return huma.NewError(499, "client closed request")
	}
	d.log().Error("api error", "op", op, "err", err)
	return problem(http.StatusInternalServerError, "internal", "internal error", nil)
}

func fail(err error) error {
	var ae *apperr.Error
	if !errors.As(err, &ae) {
		return err
	}
	return problem(statusFor(ae.Code), ae.Code, ae.Message, ae.Fields)
}

func statusFor(c apperr.Code) int {
	switch c {
	case apperr.CodeInvalid:
		return http.StatusUnprocessableEntity
	case apperr.CodeNotFound:
		return http.StatusNotFound
	case apperr.CodeAlreadyExists, apperr.CodeConflict:
		return http.StatusConflict
	case apperr.CodeForbidden, apperr.CodeReauth, apperr.CodeMFARequired:
		return http.StatusForbidden
	case apperr.CodePrecondition:
		return http.StatusPreconditionFailed
	case apperr.CodeUnavailable:
		return http.StatusServiceUnavailable
	case apperr.CodeRateLimited:
		return http.StatusTooManyRequests
	case apperr.CodeUnauthorized:
		return http.StatusUnauthorized
	}
	return http.StatusBadRequest
}

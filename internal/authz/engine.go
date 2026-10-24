package authz

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/aurimasniekis/go-porch/internal/clock"
	"github.com/aurimasniekis/go-porch/internal/obs/metrics"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/store/db"
)

// Subject is who asks.
type Subject struct {
	Type       string // user | service_account
	ID         string // internal ID
	AuthMethod string
	AuthTime   time.Time
}

// Resource is what the action applies to. For apps, Type is "app" and ID the application ID.
type Resource struct {
	Type string
	ID   string
}

// Request is one authorization question.
type Request struct {
	TenantID string // the tenant that owns the resource
	Subject  Subject
	Action   string
	Resource Resource
	// ClientIP is the trusted client address (from httpx); Porch derives the policy context from it.
	ClientIP netip.Addr
	// SimulatedContext overrides the derived context (simulator only; flagged in the trace).
	SimulatedContext *ContextV1
}

// Decision is an answer with its explain trace.
type Decision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"` // tenant_gate | denied_by_policy | granted | default_deny | invalid_request
	Trace   Trace  `json:"trace"`
}

// Trace explains a decision.
type Trace struct {
	TenantGate   GateTrace     `json:"tenant_gate"`
	Groups       []string      `json:"groups"`
	Candidates   []GrantTrace  `json:"candidates"`
	DenyPolicies []PolicyTrace `json:"deny_policies"`
	Context      ContextV1     `json:"context"`
	Simulated    bool          `json:"simulated"`
	Epoch        int64         `json:"epoch"`
}

// GateTrace explains the tenant gate.
type GateTrace struct {
	Passed bool   `json:"passed"`
	Via    string `json:"via"` // membership | share:<tenant> | none
}

// GrantTrace is one candidate grant.
type GrantTrace struct {
	AssignmentID string       `json:"assignment_id,omitempty"`
	Role         string       `json:"role"`
	Via          string       `json:"via"` // user | group:<slug> | implicit:all_members | share
	Scope        string       `json:"scope"`
	Permission   string       `json:"permission"`
	Condition    *PolicyTrace `json:"condition,omitempty"`
	Applies      bool         `json:"applies"`
}

// PolicyTrace is one policy evaluation.
type PolicyTrace struct {
	PolicyID string `json:"policy_id"`
	Slug     string `json:"slug"`
	Result   bool   `json:"result"`
	Error    string `json:"error,omitempty"`
}

// Engine evaluates requests.
type Engine struct {
	s       *store.Store
	clock   clock.Clock
	trusted []netip.Prefix
	metrics *metrics.Metrics
	models  cache
}

// NewEngine returns an engine. trustedNetworks are CIDRs reported to policies as context.network == "trusted".
func NewEngine(s *store.Store, c clock.Clock, m *metrics.Metrics, trustedNetworks []string) *Engine {
	e := &Engine{s: s, clock: c, metrics: m}
	if e.clock == nil {
		e.clock = clock.System{}
	}
	for _, t := range trustedNetworks {
		if p, err := netip.ParsePrefix(t); err == nil {
			e.trusted = append(e.trusted, p.Masked())
		}
	}
	return e
}

func (e *Engine) model(ctx context.Context, tenantID string) (*model, error) {
	epoch, err := e.s.R().GetAuthzEpoch(ctx, tenantID)
	if errors.Is(err, sql.ErrNoRows) {
		epoch = 0
	} else if err != nil {
		return nil, err
	}
	if m := e.models.get(tenantID, epoch); m != nil {
		return m, nil
	}
	m, err := loadModel(ctx, e.s, tenantID, epoch)
	if err != nil {
		return nil, err
	}
	e.models.put(tenantID, m)
	return m, nil
}

func deny(reason string, tr Trace) Decision {
	return Decision{Allowed: false, Reason: reason, Trace: tr}
}

// Check answers req. Errors are infrastructure failures; callers must treat them as deny.
func (e *Engine) Check(ctx context.Context, req Request) (Decision, error) {
	d, err := e.check(ctx, req)
	if err == nil {
		e.metrics.AuthzDecision(d.Allowed, d.Reason)
	}
	return d, err
}

func (e *Engine) check(ctx context.Context, req Request) (Decision, error) {
	now := e.clock.Now()
	tr := Trace{Groups: []string{}, Candidates: []GrantTrace{}, DenyPolicies: []PolicyTrace{}}
	if !ValidPermission(req.Action) || strings.Contains(req.Action, "*") || req.TenantID == "" || req.Subject.ID == "" {
		return deny("invalid_request", tr), nil
	}
	tenant, err := e.s.R().GetTenant(ctx, req.TenantID)
	if err != nil || tenant.Status != "active" {
		return deny("tenant_gate", tr), nil //nolint:nilerr // unknown or disabled tenant is a deny
	}
	m, err := e.model(ctx, req.TenantID)
	if err != nil {
		return Decision{}, err
	}
	tr.Epoch = m.epoch
	// Context: server-derived unless simulating.
	if req.SimulatedContext != nil {
		tr.Context, tr.Simulated = *req.SimulatedContext, true
		if tr.Context.TenantSlug == "" {
			tr.Context.TenantSlug = tenant.Slug // the tenant is never simulated
		}
	} else {
		tr.Context = ContextV1{IP: req.ClientIP.String(), Network: "external", TenantSlug: tenant.Slug, Hour: now.UTC().Hour(),
			Weekday: now.UTC().Weekday().String()[:3]}
		for _, p := range e.trusted {
			if req.ClientIP.IsValid() && p.Contains(req.ClientIP.Unmap()) {
				tr.Context.Network = "trusted"
			}
		}
	}
	// Resource attributes.
	res := ResourceV1{ID: req.Resource.ID, Type: req.Resource.Type, Attributes: map[string]string{}}
	var app *db.Application
	var ancestors []string
	switch req.Resource.Type {
	case "app":
		a, err := e.s.R().GetApplication(ctx, db.GetApplicationParams{TenantID: req.TenantID, ID: req.Resource.ID})
		if err != nil || a.Enabled != 1 {
			return deny("default_deny", tr), nil //nolint:nilerr // unknown or disabled app
		}
		app, res.Slug = &a, a.Slug
	case "tenant", "":
	default:
		if req.Resource.ID != "" {
			r, err := e.s.R().GetResource(ctx, db.GetResourceParams{TenantID: req.TenantID, ID: req.Resource.ID})
			if err != nil || r.Type != req.Resource.Type {
				return deny("default_deny", tr), nil //nolint:nilerr // unknown resource
			}
			res.Slug = r.Slug
			_ = json.Unmarshal([]byte(r.AttributesJson), &res.Attributes)
			for p, depth := r.ParentID, 0; p.Valid && depth < MaxDepth; depth++ {
				ancestors = append(ancestors, p.String)
				pr, err := e.s.R().GetResource(ctx, db.GetResourceParams{TenantID: req.TenantID, ID: p.String})
				if err != nil {
					break
				}
				p = pr.ParentID
			}
		}
	}
	// Principal and tenant gate.
	pr := PrincipalV1{Type: req.Subject.Type, AuthMethod: req.Subject.AuthMethod, Attributes: map[string]string{}}
	if !req.Subject.AuthTime.IsZero() {
		pr.AuthAge = int64(now.Sub(req.Subject.AuthTime) / time.Second)
	}
	var directGroups []string
	switch req.Subject.Type {
	case "user":
		u, err := e.s.R().GetUser(ctx, req.Subject.ID)
		if err != nil || u.Status != "active" {
			return deny("tenant_gate", tr), nil //nolint:nilerr // unknown or disabled user
		}
		pr.ID, pr.Email = u.PublicID, u.PrimaryEmail.String
		if i := strings.LastIndexByte(pr.Email, '@'); i > 0 {
			pr.EmailDomain = pr.Email[i+1:]
		}
		if mem, err := e.s.R().GetMembershipByUser(ctx, db.GetMembershipByUserParams{TenantID: req.TenantID, UserID: u.ID}); err == nil && mem.Status == "active" {
			tr.TenantGate = GateTrace{Passed: true, Via: "membership"}
		} else if app != nil {
			if via := e.shareGate(ctx, app.ID, u.ID); via != "" {
				tr.TenantGate = GateTrace{Passed: true, Via: via}
			}
		}
		if directGroups, err = e.s.R().ListUserGroupIDs(ctx, db.ListUserGroupIDsParams{TenantID: req.TenantID, UserID: u.ID}); err != nil {
			return Decision{}, err
		}
	case "service_account":
		sa, err := e.s.R().GetServiceAccountByID(ctx, req.Subject.ID)
		if err != nil || sa.TenantID != req.TenantID || sa.Enabled != 1 {
			return deny("tenant_gate", tr), nil //nolint:nilerr // unknown, foreign or disabled service account
		}
		pr.ID = sa.ID
		tr.TenantGate = GateTrace{Passed: true, Via: "service_account"}
	default:
		return deny("tenant_gate", tr), nil
	}
	if !tr.TenantGate.Passed {
		tr.TenantGate.Via = "none"
		return deny("tenant_gate", tr), nil
	}
	groups := m.groupClosure(directGroups)
	for _, g := range groups {
		pr.Groups = append(pr.Groups, m.groups[g].Slug)
		tr.Groups = append(tr.Groups, m.groups[g].Slug)
	}
	slices.Sort(pr.Groups)
	// Candidate grants.
	via := map[string]string{req.Subject.Type + ":" + req.Subject.ID: req.Subject.Type}
	for _, g := range groups {
		via["group:"+g] = "group:" + m.groups[g].Slug
	}
	roleSlugs := map[string]bool{}
	type cand struct {
		trace     GrantTrace
		condition string
	}
	var cands []cand
	for _, a := range m.assignments {
		v, ok := via[a.SubjectType+":"+a.SubjectID]
		if !ok || expired(a, now) {
			continue
		}
		scope := "tenant"
		switch a.ScopeType {
		case "resource_type":
			scope = "type:" + a.ScopeResourceType
			if a.ScopeResourceType != req.Resource.Type {
				continue
			}
		case "resource":
			scope = a.ScopeResourceType + ":" + a.ScopeResourceID
			if a.ScopeResourceType != req.Resource.Type || (a.ScopeResourceID != req.Resource.ID && !slices.Contains(ancestors, a.ScopeResourceID)) {
				continue
			}
		}
		for _, rid := range m.expandRoles(a.RoleID) {
			r := m.roles[rid]
			if a.ScopeType == "tenant" {
				roleSlugs[r.Slug] = true
			}
			for _, perm := range m.rolePerms[rid] {
				if Grants(perm, req.Action) {
					cands = append(cands, cand{trace: GrantTrace{AssignmentID: a.ID, Role: r.Slug, Via: v, Scope: scope, Permission: perm},
						condition: a.ConditionPolicyID.String})
				}
			}
		}
	}
	for s := range roleSlugs {
		pr.Roles = append(pr.Roles, s)
	}
	slices.Sort(pr.Roles)
	if app != nil && req.Subject.Type == "user" && req.Action == PermAppAccess && app.AccessMode == "all_members" {
		viaGate := "implicit:all_members"
		if strings.HasPrefix(tr.TenantGate.Via, "share:") {
			viaGate = "share"
		}
		cands = append(cands, cand{trace: GrantTrace{Role: RoleMember, Via: viaGate, Scope: "app:" + app.ID, Permission: PermAppAccess}})
	}
	env := EnvV1{Principal: pr, Resource: res, Action: req.Action, Context: tr.Context, Now: now}
	// Deny policies first: any match — or any evaluation error — denies.
	denied := false
	for _, pid := range m.denies {
		p := m.policies[pid]
		var acts []string
		_ = json.Unmarshal([]byte(p.Actions), &acts)
		if !slices.ContainsFunc(acts, func(a string) bool { return a == "*" || Grants(a, req.Action) }) {
			continue
		}
		pt := PolicyTrace{PolicyID: pid, Slug: p.Slug}
		if prog := m.compiled[pid]; prog == nil {
			pt.Error, pt.Result = "policy does not compile against the current environment", true
		} else if ok, err := prog.Eval(env); err != nil {
			pt.Error, pt.Result = err.Error(), true
		} else {
			pt.Result = ok
		}
		denied = denied || pt.Result
		tr.DenyPolicies = append(tr.DenyPolicies, pt)
	}
	allowed := false
	for _, c := range cands {
		ok := true
		if c.condition != "" {
			p := m.policies[c.condition]
			pt := &PolicyTrace{PolicyID: c.condition, Slug: p.Slug}
			if prog := m.compiled[c.condition]; prog == nil {
				pt.Error, ok = "policy does not compile against the current environment", false
			} else if r, err := prog.Eval(env); err != nil {
				pt.Error, ok = err.Error(), false
			} else {
				pt.Result, ok = r, r
			}
			c.trace.Condition = pt
		}
		c.trace.Applies = ok
		allowed = allowed || ok
		tr.Candidates = append(tr.Candidates, c.trace)
	}
	switch {
	case denied:
		return deny("denied_by_policy", tr), nil
	case allowed:
		return Decision{Allowed: true, Reason: "granted", Trace: tr}, nil
	}
	return deny("default_deny", tr), nil
}

// shareGate returns "share:<tenant-slug>" when the app is shared to a tenant where the user is an active member.
func (e *Engine) shareGate(ctx context.Context, appID, userID string) string {
	ms, err := e.s.R().ListUserMemberships(ctx, userID)
	if err != nil {
		return ""
	}
	for _, m := range ms {
		if m.Status != "active" || m.TenantStatus != "active" {
			continue
		}
		if _, err := e.s.R().GetAppShare(ctx, db.GetAppShareParams{AppID: appID, TargetTenantID: m.TenantID}); err == nil {
			return "share:" + m.TenantSlug
		}
	}
	return ""
}

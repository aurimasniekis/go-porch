// Package authz is Porch's authorization engine (ADR-0011, ADR-0012): roles bundling permissions, role bundles and nested
// groups (DAGs, depth ≤ 5), assignments scoped to a tenant, a resource type or a resource, expr-lang condition and deny
// policies, an explicit tenant gate and default deny. Every decision carries an explain trace.
package authz

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
)

// EnvVersion is the current policy environment version.
const EnvVersion = 1

// Limits on policy source and evaluation (ADR-0012).
const (
	MaxPolicySource = 2048
	maxNodes        = 256
	memoryBudget    = 20_000
)

// PrincipalV1 is the subject as seen by policies. All fields are server-derived.
type PrincipalV1 struct {
	ID          string            `expr:"id" json:"id"`
	Type        string            `expr:"type" json:"type"`
	Email       string            `expr:"email" json:"email"`
	EmailDomain string            `expr:"email_domain" json:"email_domain"`
	Groups      []string          `expr:"groups" json:"groups"`
	Roles       []string          `expr:"roles" json:"roles"`
	AuthMethod  string            `expr:"auth_method" json:"auth_method"`
	AuthAge     int64             `expr:"auth_age" json:"auth_age"` // seconds since authentication
	Attributes  map[string]string `expr:"attributes" json:"attributes"`
}

// ResourceV1 is the target.
type ResourceV1 struct {
	ID         string            `expr:"id" json:"id"`
	Type       string            `expr:"type" json:"type"`
	Slug       string            `expr:"slug" json:"slug"`
	Attributes map[string]string `expr:"attributes" json:"attributes"`
}

// ContextV1 is request context derived by the server (never taken from the client, except in the simulator).
type ContextV1 struct {
	IP         string `expr:"ip" json:"ip,omitempty"`
	Network    string `expr:"network" json:"network,omitempty"` // "trusted" when the client IP is in authz.trusted_networks, else "external"
	TenantSlug string `expr:"tenant" json:"tenant,omitempty"`
	Hour       int    `expr:"hour" json:"hour,omitempty"`       // UTC
	Weekday    string `expr:"weekday" json:"weekday,omitempty"` // UTC, e.g. "Mon"
}

// EnvV1 is the complete policy environment, version 1.
type EnvV1 struct {
	Principal PrincipalV1 `expr:"principal" json:"principal"`
	Resource  ResourceV1  `expr:"resource" json:"resource"`
	Action    string      `expr:"action" json:"action"`
	Context   ContextV1   `expr:"context" json:"context"`
	Now       time.Time   `expr:"now" json:"now"`
}

// allowedBuiltins are pure helpers; everything else is disabled.
var allowedBuiltins = []string{"len", "all", "any", "none", "one", "filter", "map", "count", "lower", "upper", "trim", "hasPrefix",
	"hasSuffix", "abs", "min", "max", "duration", "date"}

// helper functions: pure, operating only on their arguments.
var helpers = []expr.Option{
	expr.Function("inGroup", func(p ...any) (any, error) {
		pr, ok := p[0].(PrincipalV1)
		if !ok {
			return false, errors.New("inGroup: first argument must be principal")
		}
		slug, _ := p[1].(string)
		for _, g := range pr.Groups {
			if g == slug {
				return true, nil
			}
		}
		return false, nil
	}, new(func(PrincipalV1, string) bool)),
	expr.Function("hasAttr", func(p ...any) (any, error) {
		var attrs map[string]string
		switch v := p[0].(type) {
		case PrincipalV1:
			attrs = v.Attributes
		case ResourceV1:
			attrs = v.Attributes
		default:
			return false, errors.New("hasAttr: first argument must be principal or resource")
		}
		_, ok := attrs[p[1].(string)]
		return ok, nil
	}, new(func(PrincipalV1, string) bool), new(func(ResourceV1, string) bool)),
	expr.Function("before", func(p ...any) (any, error) {
		t, ok := p[0].(time.Time)
		if !ok {
			return false, errors.New("before: first argument must be a time")
		}
		lim, err := time.Parse(time.RFC3339, p[1].(string))
		if err != nil {
			return false, fmt.Errorf("before: %w", err)
		}
		return t.Before(lim), nil
	}, new(func(time.Time, string) bool)),
	expr.Function("cidrMatch", func(p ...any) (any, error) {
		ip, err := netip.ParseAddr(p[0].(string))
		if err != nil {
			return false, nil //nolint:nilerr // an unparsable address never matches
		}
		pf, err := netip.ParsePrefix(p[1].(string))
		if err != nil {
			return false, fmt.Errorf("cidrMatch: %w", err)
		}
		return pf.Contains(ip.Unmap()), nil
	}, new(func(string, string) bool)),
}

// Policy is a compiled expression.
type Policy struct {
	program *vm.Program
	Hash    string
}

// ErrPolicy wraps compile errors (shown to administrators on write).
var ErrPolicy = errors.New("invalid policy")

// Compile type-checks src against EnvV1 with the sandbox options. It must evaluate to a boolean.
func Compile(src string) (*Policy, error) {
	if len(src) == 0 || len(src) > MaxPolicySource {
		return nil, fmt.Errorf("%w: expression must be 1..%d bytes", ErrPolicy, MaxPolicySource)
	}
	opts := []expr.Option{expr.Env(EnvV1{}), expr.AsBool(), expr.MaxNodes(maxNodes), expr.DisableAllBuiltins()}
	for _, b := range allowedBuiltins {
		opts = append(opts, expr.EnableBuiltin(b))
	}
	opts = append(opts, helpers...)
	prog, err := expr.Compile(src, opts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPolicy, err)
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("v%d|%s", EnvVersion, src)))
	return &Policy{program: prog, Hash: hex.EncodeToString(sum[:])}, nil
}

// Eval runs the policy with a bounded memory budget. Any error is returned (callers fail closed).
func (p *Policy) Eval(env EnvV1) (result bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			result, err = false, fmt.Errorf("policy panicked: %v", r)
		}
	}()
	machine := vm.VM{MemoryBudget: memoryBudget}
	out, err := machine.Run(p.program, env)
	if err != nil {
		return false, err
	}
	b, ok := out.(bool)
	if !ok {
		return false, errors.New("policy did not return a boolean")
	}
	return b, nil
}

package authz

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func env() EnvV1 {
	return EnvV1{
		Principal: PrincipalV1{ID: "u_1", Type: "user", Email: "ada@smith.example", EmailDomain: "smith.example", Groups: []string{"adults", "family"},
			AuthMethod: "google", AuthAge: 120, Attributes: map[string]string{"country": "lt"}},
		Resource: ResourceV1{ID: "app_1", Type: "app", Slug: "jellyfin", Attributes: map[string]string{"rating": "pg"}},
		Action:   "app:access",
		Context:  ContextV1{IP: "10.1.2.3", Network: "trusted", TenantSlug: "smith", Hour: 20, Weekday: "Fri"},
		Now:      time.Date(2026, 10, 24, 20, 0, 0, 0, time.UTC),
	}
}

func TestPolicyEvaluation(t *testing.T) {
	cases := map[string]bool{
		`inGroup(principal, "adults")`:                                      true,
		`"family" in principal.groups`:                                      true,
		`inGroup(principal, "admins")`:                                      false,
		`context.network == "trusted" && context.hour >= 18`:                true,
		`cidrMatch(context.ip, "10.0.0.0/8")`:                               true,
		`cidrMatch(context.ip, "192.168.0.0/16")`:                           false,
		`hasAttr(resource, "rating") && resource.attributes.rating == "pg"`: true,
		`before(now, "2027-01-01T00:00:00Z")`:                               true,
		`principal.auth_method == "backup" || principal.auth_age < 300`:     true,
		`any(principal.groups, {# == "adults"})`:                            true,
		`principal.email_domain == "smith.example"`:                         true,
	}
	for src, want := range cases {
		p, err := Compile(src)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		got, err := p.Eval(env())
		if err != nil || got != want {
			t.Errorf("%s = %v, %v (want %v)", src, got, err, want)
		}
	}
}

// ADR-0012: non-boolean, unknown identifiers, disabled builtins, oversized sources and huge expressions are refused at
// write time.
func TestPolicyCompileRejects(t *testing.T) {
	for _, src := range []string{
		``, `1 + 1`, `principal.password == "x"`, `env`, `foo()`, `toJSON(principal) != ""`, `fromJSON("{}") != nil`,
		`sprintf("%v", 1) == "1"`, strings.Repeat("a", MaxPolicySource+1), strings.Repeat("true && ", 300) + "true",
		`now()`, `get(principal, "id") == "x"`,
	} {
		if _, err := Compile(src); !errors.Is(err, ErrPolicy) {
			t.Errorf("%.40q compiled (err=%v)", src, err)
		}
	}
}

// Runaway expressions hit the memory budget and fail closed.
func TestPolicyMemoryBudget(t *testing.T) {
	p, err := Compile(`len(filter(map(principal.groups, {repeatStr}), {true})) > 0`)
	if err == nil {
		t.Fatalf("unexpected compile: %v", p)
	}
	// 60 × 60 × 60 nested allocations exceed the VM memory budget.
	p, err = Compile(`count(map(principal.groups, {map(principal.groups, {map(principal.groups, {#})})}), {true}) >= 0`)
	if err != nil {
		t.Fatal(err)
	}
	e := env()
	e.Principal.Groups = make([]string, 60)
	if _, err := p.Eval(e); err == nil {
		t.Fatal("memory budget not enforced")
	}
}

func FuzzPolicyCompileEval(f *testing.F) {
	for _, s := range []string{`inGroup(principal, "a")`, `context.hour > 3`, `cidrMatch(context.ip, "10.0.0.0/8")`, `any(principal.groups, {# == "x"})`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		p, err := Compile(src)
		if err != nil {
			return
		}
		_, _ = p.Eval(env()) // must never panic or hang
	})
}

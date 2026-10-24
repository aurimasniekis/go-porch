package authz

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aurimasniekis/go-porch/internal/domain"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/store/db"
)

// MaxDepth bounds role-bundle and group nesting (ADR-0011).
const MaxDepth = 5

// model is an immutable snapshot of one tenant's authorization data at one epoch.
type model struct {
	epoch       int64
	roles       map[string]db.Role  // id → role
	rolePerms   map[string][]string // role id → direct permissions
	roleKids    map[string][]string // bundle → included roles
	groups      map[string]db.Group // id → group
	groupParent map[string][]string // child group → parent groups
	assignments []db.RoleAssignment
	policies    map[string]db.Policy
	compiled    map[string]*Policy // policy id → program (nil when it failed to compile)
	denies      []string           // deny policy ids
}

// cache keeps one model per tenant, replaced whenever the tenant's authz epoch changes.
type cache struct {
	mu     sync.Mutex
	models map[string]*model
}

func (c *cache) get(tenantID string, epoch int64) *model {
	c.mu.Lock()
	defer c.mu.Unlock()
	if m := c.models[tenantID]; m != nil && m.epoch == epoch {
		return m
	}
	return nil
}

func (c *cache) put(tenantID string, m *model) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.models == nil {
		c.models = map[string]*model{}
	}
	c.models[tenantID] = m
}

func loadModel(ctx context.Context, s *store.Store, tenantID string, epoch int64) (*model, error) {
	m := &model{epoch: epoch, roles: map[string]db.Role{}, rolePerms: map[string][]string{}, roleKids: map[string][]string{},
		groups: map[string]db.Group{}, groupParent: map[string][]string{}, policies: map[string]db.Policy{}, compiled: map[string]*Policy{}}
	err := s.ReadTx(ctx, func(q *db.Queries) error {
		roles, err := q.ListRoles(ctx, tenantID)
		if err != nil {
			return err
		}
		for _, r := range roles {
			m.roles[r.ID] = r
		}
		perms, err := q.ListTenantRolePermissions(ctx, tenantID)
		if err != nil {
			return err
		}
		for _, p := range perms {
			m.rolePerms[p.RoleID] = append(m.rolePerms[p.RoleID], p.Permission)
		}
		edges, err := q.ListRoleEdges(ctx, tenantID)
		if err != nil {
			return err
		}
		for _, e := range edges {
			m.roleKids[e.ParentID] = append(m.roleKids[e.ParentID], e.ChildID)
		}
		groups, err := q.ListGroups(ctx, tenantID)
		if err != nil {
			return err
		}
		for _, g := range groups {
			m.groups[g.ID] = g
		}
		gedges, err := q.ListGroupEdges(ctx, tenantID)
		if err != nil {
			return err
		}
		for _, e := range gedges {
			m.groupParent[e.ChildID] = append(m.groupParent[e.ChildID], e.ParentID)
		}
		if m.assignments, err = q.ListAssignments(ctx, tenantID); err != nil {
			return err
		}
		pols, err := q.ListPolicies(ctx, tenantID)
		if err != nil {
			return err
		}
		for _, p := range pols {
			m.policies[p.ID] = p
			prog, cerr := Compile(p.Expression)
			if cerr == nil && prog.Hash == p.CompiledHash {
				m.compiled[p.ID] = prog
			} else {
				m.compiled[p.ID] = nil // stale or broken: evaluates as an error (fail closed)
			}
			if p.Effect == "deny" {
				m.denies = append(m.denies, p.ID)
			}
		}
		return nil
	})
	return m, err
}

// expandRoles returns every role reachable from id through bundles (depth-limited; cycles cut).
func (m *model) expandRoles(id string) []string {
	var out []string
	seen := map[string]bool{}
	var walk func(string, int)
	walk = func(r string, depth int) {
		if seen[r] || depth > MaxDepth {
			return
		}
		seen[r] = true
		out = append(out, r)
		for _, k := range m.roleKids[r] {
			walk(k, depth+1)
		}
	}
	walk(id, 0)
	return out
}

// groupClosure returns the user's direct groups plus every ancestor (members of a child are members of the parent).
func (m *model) groupClosure(direct []string) []string {
	var out []string
	seen := map[string]bool{}
	var walk func(string, int)
	walk = func(g string, depth int) {
		if seen[g] || depth > MaxDepth {
			return
		}
		if _, ok := m.groups[g]; !ok {
			return
		}
		seen[g] = true
		out = append(out, g)
		for _, p := range m.groupParent[g] {
			walk(p, depth+1)
		}
	}
	for _, g := range direct {
		walk(g, 0)
	}
	return out
}

// checkDAG verifies adding edge parent→child keeps a DAG within MaxDepth (used on write).
func checkDAG(children map[string][]string, parent, child string) error {
	if parent == child {
		return fmt.Errorf("an item cannot include itself")
	}
	// Cycle: child already reaches parent.
	var reaches func(string, int) bool
	reaches = func(from string, depth int) bool {
		if from == parent {
			return true
		}
		if depth > 64 {
			return true
		}
		for _, k := range children[from] {
			if reaches(k, depth+1) {
				return true
			}
		}
		return false
	}
	if reaches(child, 0) {
		return fmt.Errorf("this would create a cycle")
	}
	// Depth: longest path through the new edge.
	var down func(string) int
	down = func(n string) int {
		best := 0
		for _, k := range children[n] {
			if d := down(k) + 1; d > best {
				best = d
			}
		}
		return best
	}
	parents := map[string][]string{}
	for p, ks := range children {
		for _, k := range ks {
			parents[k] = append(parents[k], p)
		}
	}
	var up func(string) int
	up = func(n string) int {
		best := 0
		for _, p := range parents[n] {
			if d := up(p) + 1; d > best {
				best = d
			}
		}
		return best
	}
	if up(parent)+1+down(child) > MaxDepth {
		return fmt.Errorf("nesting would exceed %d levels", MaxDepth)
	}
	return nil
}

func expired(a db.RoleAssignment, now time.Time) bool {
	return a.ExpiresAt.Valid && !now.Before(domain.FromMicros(a.ExpiresAt.Int64))
}

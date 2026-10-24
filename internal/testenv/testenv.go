// Package testenv assembles a store, keyring, audit writer and the core services for tests.
package testenv

import (
	"context"
	"testing"
	"time"

	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/authz"
	"github.com/aurimasniekis/go-porch/internal/clock"
	"github.com/aurimasniekis/go-porch/internal/domain"
	"github.com/aurimasniekis/go-porch/internal/identity"
	"github.com/aurimasniekis/go-porch/internal/installation"
	"github.com/aurimasniekis/go-porch/internal/keyring"
	"github.com/aurimasniekis/go-porch/internal/keyring/keyringtest"
	"github.com/aurimasniekis/go-porch/internal/session"
	"github.com/aurimasniekis/go-porch/internal/setup"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/store/storetest"
	"github.com/aurimasniekis/go-porch/internal/tenancy"
)

// Env is a ready-to-use set of services over a throwaway database.
type Env struct {
	Clock    *clock.Fake
	Store    *store.Store
	Keyring  *keyring.Keyring
	Audit    *audit.Writer
	Users    *identity.Service
	Tenants  *tenancy.Service
	Sessions *session.Manager
	Setup    *setup.Service
	Authz    *authz.Admin
	Engine   *authz.Engine
}

// Start is the fake clock's initial time.
var Start = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

// New builds an Env.
func New(t testing.TB) *Env {
	t.Helper()
	c := clock.NewFake(Start)
	s := storetest.Open(t, storetest.WithClock(c))
	if err := installation.Ensure(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	kr := keyringtest.Load(t, s)
	a := audit.NewWriter(kr)
	users := identity.New(s, a)
	sess := session.New(s, kr, session.Options{Idle: 8 * time.Hour, Absolute: 12 * time.Hour, StepUpWindow: 5 * time.Minute,
		UpstreamRecheck: time.Hour, SetupAbsolute: time.Hour, Clock: c})
	tenants := tenancy.New(s, a)
	tenants.OnCreate = authz.EnsureBuiltinsTx
	return &Env{Clock: c, Store: s, Keyring: kr, Audit: a, Users: users, Tenants: tenants, Sessions: sess, Authz: authz.NewAdmin(s, a),
		Engine: authz.NewEngine(s, c, nil, []string{"10.0.0.0/8"}),
		Setup:  setup.New(s, kr, a, users, sess)}
}

// Admin is a change made by a test operator.
var Admin = domain.Change{Actor: audit.Actor{Type: audit.ActorUser, ID: "usr_test"}, ManagedBy: domain.ManagedAPI}

// User creates a user.
func (e *Env) User(t testing.TB, name, email string) identity.User {
	t.Helper()
	u, err := e.Users.Create(context.Background(), Admin, identity.CreateParams{DisplayName: name, PrimaryEmail: email})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// Owner creates a user with the installation owner role.
func (e *Env) Owner(t testing.TB, name string) identity.User {
	t.Helper()
	u := e.User(t, name, "")
	err := e.Store.W().Tx(context.Background(), func(tx *store.Tx) error {
		return e.Users.GrantOperatorRoleTx(context.Background(), tx, Admin, u.ID, identity.RoleOwner, "test")
	})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// Tenant creates a tenant.
func (e *Env) Tenant(t testing.TB, slug string) tenancy.Tenant {
	t.Helper()
	tn, err := e.Tenants.Create(context.Background(), Admin, tenancy.CreateParams{Slug: slug, Name: slug})
	if err != nil {
		t.Fatal(err)
	}
	return tn
}

// Member adds u to tenant tn via a system scope.
func (e *Env) Member(t testing.TB, tn tenancy.Tenant, userID string) tenancy.Membership {
	t.Helper()
	ctx := context.Background()
	sc, err := e.Tenants.SystemScope(ctx, tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	m, err := e.Tenants.AddMember(ctx, Admin, sc, userID, tenancy.SourceManual)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

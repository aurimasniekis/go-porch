package session_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/identity"
	"github.com/aurimasniekis/go-porch/internal/installation"
	"github.com/aurimasniekis/go-porch/internal/session"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/testenv"
)

func create(t *testing.T, e *testenv.Env, p session.NewParams) session.Created {
	t.Helper()
	var c session.Created
	err := e.Store.W().Tx(context.Background(), func(tx *store.Tx) error {
		var err error
		c, err = e.Sessions.CreateTx(context.Background(), tx, p)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestIdleAndAbsoluteExpiry(t *testing.T) {
	e := testenv.New(t)
	ctx := context.Background()
	u := e.User(t, "Alice", "alice@example.com")
	c := create(t, e, session.NewParams{UserID: u.ID, Method: session.MethodGoogle})
	for range 3 { // keep active: 3h55m steps < 8h idle, total 11h45m < 12h absolute
		e.Clock.Advance(3*time.Hour + 55*time.Minute)
		if _, err := e.Sessions.Authenticate(ctx, c.Token); err != nil {
			t.Fatal(err)
		}
	}
	// 12h absolute reached even though active.
	e.Clock.Advance(16 * time.Minute)
	if _, err := e.Sessions.Authenticate(ctx, c.Token); !errors.Is(err, session.ErrUnauthorized) {
		t.Fatalf("absolute expiry: %v", err)
	}
	c2 := create(t, e, session.NewParams{UserID: u.ID, Method: session.MethodGoogle})
	e.Clock.Advance(8*time.Hour + time.Second)
	if _, err := e.Sessions.Authenticate(ctx, c2.Token); !errors.Is(err, session.ErrUnauthorized) {
		t.Fatalf("idle expiry: %v", err)
	}
}

func TestTenantOverride(t *testing.T) {
	e := testenv.New(t)
	ctx := context.Background()
	u := e.User(t, "Alice", "")
	tn := e.Tenant(t, "smith")
	sc, _ := e.Tenants.SystemScope(ctx, tn.ID)
	idle := 30 * time.Minute
	if _, err := e.Tenants.Update(ctx, testenv.Admin, sc, tenancyIdle(idle)); err != nil {
		t.Fatal(err)
	}
	c := create(t, e, session.NewParams{UserID: u.ID, TenantID: tn.ID, Method: session.MethodBackup})
	e.Clock.Advance(31 * time.Minute)
	if _, err := e.Sessions.Authenticate(ctx, c.Token); err == nil {
		t.Fatal("tenant idle override ignored")
	}
}

func TestEpochsAndDisableRevoke(t *testing.T) {
	e := testenv.New(t)
	ctx := context.Background()
	u := e.User(t, "Alice", "")
	c := create(t, e, session.NewParams{UserID: u.ID, Method: session.MethodGoogle})
	disabled := identity.StatusDisabled
	if _, err := e.Users.Update(ctx, testenv.Admin, u.ID, identity.UpdateParams{Status: &disabled}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Sessions.Authenticate(ctx, c.Token); err == nil {
		t.Fatal("disabled user's session still valid")
	}
	v := e.User(t, "Bob", "")
	c2 := create(t, e, session.NewParams{UserID: v.ID, Method: session.MethodGoogle})
	err := e.Store.W().Tx(ctx, func(tx *store.Tx) error {
		_, err := installation.BumpSecurityEpochTx(ctx, tx, e.Audit, audit.CLI, "restore")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Sessions.Authenticate(ctx, c2.Token); err == nil {
		t.Fatal("session survived installation epoch bump")
	}
}

func TestCSRFStepUpAndRotation(t *testing.T) {
	e := testenv.New(t)
	ctx := context.Background()
	u := e.User(t, "Alice", "")
	c := create(t, e, session.NewParams{UserID: u.ID, Method: session.MethodBackup})
	p, err := e.Sessions.Authenticate(ctx, c.Token)
	if err != nil {
		t.Fatal(err)
	}
	if !p.VerifyCSRF(p.CSRFToken) || p.VerifyCSRF("") || p.VerifyCSRF(p.CSRFToken+"x") {
		t.Fatal("csrf verification wrong")
	}
	if err := e.Sessions.RequireStepUp(p); err != nil {
		t.Fatalf("fresh session: %v", err)
	}
	e.Clock.Advance(6 * time.Minute)
	p, _ = e.Sessions.Authenticate(ctx, c.Token)
	if err := e.Sessions.RequireStepUp(p); !errors.Is(err, session.ErrReauthRequired) {
		t.Fatalf("stale auth_time: %v", err)
	}
	var nc session.Created
	err = e.Store.W().Tx(ctx, func(tx *store.Tx) error {
		var err error
		nc, err = e.Sessions.RotateTx(ctx, tx, p, e.Clock.Now(), "192.0.2.1", "test")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Sessions.Authenticate(ctx, c.Token); err == nil {
		t.Fatal("old token valid after rotation")
	}
	np, err := e.Sessions.Authenticate(ctx, nc.Token)
	if err != nil || e.Sessions.RequireStepUp(np) != nil || np.CSRFToken == p.CSRFToken {
		t.Fatalf("rotated session: %+v %v", np, err)
	}
}

func TestUpstreamRecheckDue(t *testing.T) {
	e := testenv.New(t)
	ctx := context.Background()
	u := e.User(t, "Alice", "")
	g := create(t, e, session.NewParams{UserID: u.ID, Method: session.MethodGoogle})
	b := create(t, e, session.NewParams{UserID: u.ID, Method: session.MethodBackup})
	e.Clock.Advance(61 * time.Minute)
	gp, _ := e.Sessions.Authenticate(ctx, g.Token)
	bp, _ := e.Sessions.Authenticate(ctx, b.Token)
	if !e.Sessions.NeedsUpstreamRecheck(gp) || e.Sessions.NeedsUpstreamRecheck(bp) {
		t.Fatal("recheck policy wrong")
	}
}

func TestGarbageTokens(t *testing.T) {
	e := testenv.New(t)
	for _, tok := range []string{"", "x", string(make([]byte, 200))} {
		if _, err := e.Sessions.Authenticate(context.Background(), tok); !errors.Is(err, session.ErrUnauthorized) {
			t.Fatalf("%q: %v", tok, err)
		}
	}
}

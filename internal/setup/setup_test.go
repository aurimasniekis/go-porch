package setup_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/setup"
	"github.com/aurimasniekis/go-porch/internal/testenv"
)

// M1 acceptance: many concurrent consumers (distinct tokens and the same token) → exactly one owner.
func TestConcurrentConsumeExactlyOneWinner(t *testing.T) {
	e := testenv.New(t)
	ctx := context.Background()
	const n = 16
	tokens := make([]string, n)
	for i := range n {
		tok, _, err := e.Setup.Issue(ctx, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		tokens[i] = tok
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := range 2 * n {
		wg.Go(func() {
			_, err := e.Setup.Consume(ctx, setup.ConsumeParams{Token: tokens[i%n], DisplayName: "Owner"})
			switch {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, setup.ErrAlreadySetUp), errors.Is(err, setup.ErrBadToken):
			default:
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("winners = %d, want exactly 1", wins.Load())
	}
	if n, _ := e.Store.R().CountOperators(ctx); n != 1 {
		t.Fatalf("operators = %d", n)
	}
	if _, _, err := e.Setup.Issue(ctx, time.Hour); !errors.Is(err, setup.ErrAlreadySetUp) {
		t.Fatalf("issue after setup: %v", err)
	}
	if res, err := audit.Verify(ctx, e.Store.R()); err != nil || !res.OK {
		t.Fatalf("audit chain: %+v %v", res, err)
	}
}

func TestTokenRules(t *testing.T) {
	e := testenv.New(t)
	ctx := context.Background()
	tok, _, err := e.Setup.Issue(ctx, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "porch_setup_", tok + "x", "nope", tok[:len(tok)-1]} {
		if _, err := e.Setup.Consume(ctx, setup.ConsumeParams{Token: bad, DisplayName: "x"}); !errors.Is(err, setup.ErrBadToken) {
			t.Fatalf("%q: %v", bad, err)
		}
	}
	e.Clock.Advance(2 * time.Minute)
	if _, err := e.Setup.Consume(ctx, setup.ConsumeParams{Token: tok, DisplayName: "x"}); !errors.Is(err, setup.ErrBadToken) {
		t.Fatalf("expired: %v", err)
	}
	tok2, _, _ := e.Setup.Issue(ctx, time.Hour)
	res, err := e.Setup.Consume(ctx, setup.ConsumeParams{Token: tok2, DisplayName: "Ada", Email: "ada@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := e.Sessions.Authenticate(ctx, res.Session.Token)
	if err != nil || !p.IsOperator("owner") || p.Method != "setup" {
		t.Fatalf("%+v %v", p, err)
	}
	// The setup session is short-lived (1 h) regardless of the 12 h default.
	e.Clock.Advance(61 * time.Minute)
	if _, err := e.Sessions.Authenticate(ctx, res.Session.Token); err == nil {
		t.Fatal("setup session outlived its 1h cap")
	}
}

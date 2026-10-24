package localauth_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aurimasniekis/go-porch/internal/apperr"
	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/localauth"
	"github.com/aurimasniekis/go-porch/internal/session"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/testenv"
)

var fastParams = localauth.Params{Memory: 1024, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16}

const (
	goodPassword = "correct-Horse-battery-79!"
)

var goodPairs = []localauth.Pair{
	{Title: "Street of the summer house", Answer: "Vaivorykštės gatvė 14"},
	{Title: "First concert I paid for", Answer: "Massive Attack in Riga, 2004"},
	{Title: "Grandmother's dog", Answer: "Kudlius the third"},
}

func answers(ps []localauth.Pair) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.Answer
	}
	return out
}

type fixture struct {
	e    *testenv.Env
	svc  *localauth.Service
	uid  string
	sess *session.Principal
}

func setup(t *testing.T, mutate ...func(*localauth.Policy)) *fixture {
	t.Helper()
	e := testenv.New(t)
	pol := localauth.DefaultPolicy()
	pol.Params = fastParams
	for _, m := range mutate {
		m(&pol)
	}
	svc := localauth.New(e.Store, e.Keyring, e.Audit, e.Sessions, e.Clock, nil, pol)
	u := e.User(t, "Ada Lovelace", "ada@example.com")
	var c session.Created
	err := e.Store.W().Tx(context.Background(), func(tx *store.Tx) error {
		var err error
		c, err = e.Sessions.CreateTx(context.Background(), tx, session.NewParams{UserID: u.ID, Method: session.MethodGoogle})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := e.Sessions.Validate(context.Background(), c.Token)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{e: e, svc: svc, uid: u.ID, sess: p}
	if _, err := svc.Enroll(context.Background(), p, localauth.EnrollParams{Password: goodPassword, Pairs: goodPairs, Confirm: answers(goodPairs)}); err != nil {
		t.Fatal(err)
	}
	return f
}

var src = localauth.Meta{SourceKey: "198.51.100.7", IP: "198.51.100.7"}

func TestHappyPathTitlesOnlyAfterPassword(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if _, err := f.svc.Start(ctx, "ada@example.com", "wrong-password-xx", src); !errors.Is(err, localauth.ErrLoginFailed) {
		t.Fatalf("wrong password: %v", err)
	}
	f.e.Clock.Advance(7 * time.Hour) // threshold 1: the wrong password locked the account for 6h
	r, err := f.svc.Start(ctx, "ADA@example.com ", goodPassword, src)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Titles) != 3 || r.Titles[1] != goodPairs[1].Title {
		t.Fatalf("titles %v", r.Titles)
	}
	// Punctuation/case-insensitive answers.
	c, err := f.svc.Finish(ctx, r.Challenge, []string{"vaivorykstes gatve 14", "MASSIVE attack in riga 2004", "kudlius  the third!"}, src)
	if err == nil {
		t.Fatal("diacritics must matter (ė ≠ e)")
	}
	_ = c
	f.e.Clock.Advance(13 * time.Hour) // second lock escalated to 12h
	r, err = f.svc.Start(ctx, "ada@example.com", goodPassword, src)
	if err != nil {
		t.Fatal(err)
	}
	c, err = f.svc.Finish(ctx, r.Challenge, []string{"vaivorykštės gatvė 14", "MASSIVE attack in riga 2004", "kudlius  the third!"}, src)
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.e.Sessions.Validate(ctx, c.Token)
	if err != nil || p.Method != session.MethodBackup || p.UserID != f.uid {
		t.Fatalf("%+v %v", p, err)
	}
	// The challenge is single use.
	if _, err := f.svc.Finish(ctx, r.Challenge, answers(goodPairs), src); !errors.Is(err, localauth.ErrLoginFailed) {
		t.Fatalf("challenge reuse: %v", err)
	}
}

// M2 acceptance: N parallel wrong attempts reserve exactly `threshold` hashes and lock the account.
func TestConcurrentAttemptsReserveExactlyThreshold(t *testing.T) {
	for _, threshold := range []int{1, 3} {
		f := setup(t, func(p *localauth.Policy) { p.Threshold = threshold; p.SourceLimit = 1000 })
		ctx := context.Background()
		before := f.svc.Verifications()
		var wg sync.WaitGroup
		var fails atomic.Int32
		const n = 24
		for range n {
			wg.Go(func() {
				if _, err := f.svc.Start(ctx, "ada@example.com", "wrong-password-xx", src); errors.Is(err, localauth.ErrLoginFailed) {
					fails.Add(1)
				} else {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		if fails.Load() != n {
			t.Fatalf("fails %d", fails.Load())
		}
		// Every attempt does exactly one Argon2id verification (real or dummy) so timing is uniform…
		if got := f.svc.Verifications() - before; got != n {
			t.Fatalf("verifications %d want %d", got, n)
		}
		// …but only `threshold` of them were checked against the real verifier: count wrong_password audit events.
		var real int
		err := f.e.Store.ReadDB().QueryRowContext(ctx,
			"SELECT count(*) FROM audit_events WHERE action = 'login.backup' AND reason_code = 'wrong_password'").Scan(&real)
		if err != nil || real != threshold {
			t.Fatalf("threshold %d: real checks %d %v", threshold, real, err)
		}
		st, _ := f.svc.StatusFor(ctx, f.uid, false)
		if st.LockedUntil == nil {
			t.Fatal("not locked")
		}
		// Even the correct password fails while locked.
		if _, err := f.svc.Start(ctx, "ada@example.com", goodPassword, src); !errors.Is(err, localauth.ErrLoginFailed) {
			t.Fatalf("locked account accepted: %v", err)
		}
	}
}

// Knowing the password buys no extra answer guesses: with threshold 1, one wrong answer set locks the account.
func TestPasswordStepGrantsNoExtraAnswerAttempts(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	r, err := f.svc.Start(ctx, "ada@example.com", goodPassword, src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Finish(ctx, r.Challenge, []string{"a", "b", "c"}, src); !errors.Is(err, localauth.ErrLoginFailed) {
		t.Fatalf("wrong answers: %v", err)
	}
	if _, err := f.svc.Start(ctx, "ada@example.com", goodPassword, src); !errors.Is(err, localauth.ErrLoginFailed) {
		t.Fatalf("password step after wrong answers should be locked: %v", err)
	}
	// Parallel step-2 attempts with several challenges: only one is judged.
	f2 := setup(t, func(p *localauth.Policy) { p.Threshold = 2 })
	var chs []string
	for range 2 {
		r, err := f2.svc.Start(ctx, "ada@example.com", goodPassword, src)
		if err != nil {
			t.Fatal(err)
		}
		chs = append(chs, r.Challenge)
	}
	for _, c := range chs {
		_, _ = f2.svc.Finish(ctx, c, []string{"x", "y", "z"}, src)
	}
	if _, err := f2.svc.Start(ctx, "ada@example.com", goodPassword, src); !errors.Is(err, localauth.ErrLoginFailed) {
		t.Fatalf("budget not shared across challenges: %v", err)
	}
}

// T-B2-9: unknown, wrong and locked all look the same and cost one verification each.
func TestEnumerationResistance(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	type outcome struct {
		err  string
		cost int64
	}
	try := func(id, pw string) outcome {
		before := f.svc.Verifications()
		_, err := f.svc.Start(ctx, id, pw, localauth.Meta{SourceKey: id})
		return outcome{err: err.Error(), cost: f.svc.Verifications() - before}
	}
	unknown := try("nobody@example.com", "whatever-password")
	wrong := try("ada@example.com", "whatever-password")
	locked := try("ada@example.com", goodPassword)
	if unknown != wrong || wrong != locked {
		t.Fatalf("distinguishable: unknown=%+v wrong=%+v locked=%+v", unknown, wrong, locked)
	}
	if unknown.cost != 1 {
		t.Fatalf("cost %d", unknown.cost)
	}
}

func TestEscalationAndUnlock(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	wantLock := []time.Duration{6 * time.Hour, 12 * time.Hour, 24 * time.Hour, 48 * time.Hour, 48 * time.Hour}
	for i, d := range wantLock {
		start := f.e.Clock.Now()
		if _, err := f.svc.Start(ctx, "ada@example.com", "wrong-password-xx", src); !errors.Is(err, localauth.ErrLoginFailed) {
			t.Fatal(err)
		}
		st, _ := f.svc.StatusFor(ctx, f.uid, false)
		if st.LockedUntil == nil || !st.LockedUntil.Equal(start.Add(d)) {
			t.Fatalf("lock %d: until %v want %v", i, st.LockedUntil, start.Add(d))
		}
		f.e.Clock.Advance(d + time.Second)
	}
	if _, err := f.svc.Start(ctx, "ada@example.com", "wrong-password-xx", src); err == nil {
		t.Fatal("expected failure")
	}
	if err := f.svc.Unlock(ctx, audit.CLI, f.uid); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Start(ctx, "ada@example.com", goodPassword, src); err != nil {
		t.Fatalf("after unlock: %v", err)
	}
}

func TestSourceThrottleAndCircuit(t *testing.T) {
	f := setup(t, func(p *localauth.Policy) { p.SourceLimit = 3; p.CircuitLimit = 5 })
	ctx := context.Background()
	for range 3 {
		_, _ = f.svc.Start(ctx, "nobody@example.com", "x-password-xx", src)
	}
	if _, err := f.svc.Start(ctx, "nobody@example.com", "x-password-xx", src); !errors.Is(err, localauth.ErrThrottled) {
		t.Fatalf("source throttle: %v", err)
	}
	other := localauth.Meta{SourceKey: "203.0.113.9"}
	if _, err := f.svc.Start(ctx, "nobody@example.com", "x-password-xx", other); !errors.Is(err, localauth.ErrLoginFailed) {
		t.Fatalf("other source should still be judged: %v", err)
	}
	_, _ = f.svc.Start(ctx, "nobody@example.com", "x-password-xx", localauth.Meta{SourceKey: "203.0.113.10"})
	// Installation circuit (5 failures/min) is now open for everyone, including a legitimate user.
	if _, err := f.svc.Start(ctx, "ada@example.com", goodPassword, localauth.Meta{SourceKey: "192.0.2.50"}); !errors.Is(err, localauth.ErrThrottled) {
		t.Fatalf("circuit: %v", err)
	}
	f.e.Clock.Advance(16 * time.Minute)
	if _, err := f.svc.Start(ctx, "ada@example.com", goodPassword, localauth.Meta{SourceKey: "192.0.2.50"}); err != nil {
		t.Fatalf("after windows: %v", err)
	}
}

func TestChallengeBoundToSourceAndTTL(t *testing.T) {
	f := setup(t, func(p *localauth.Policy) { p.Threshold = 5 })
	ctx := context.Background()
	r, _ := f.svc.Start(ctx, "ada@example.com", goodPassword, src)
	if _, err := f.svc.Finish(ctx, r.Challenge, answers(goodPairs), localauth.Meta{SourceKey: "203.0.113.1"}); err == nil {
		t.Fatal("challenge used from another source")
	}
	r, _ = f.svc.Start(ctx, "ada@example.com", goodPassword, src)
	f.e.Clock.Advance(6 * time.Minute)
	if _, err := f.svc.Finish(ctx, r.Challenge, answers(goodPairs), src); err == nil {
		t.Fatal("expired challenge accepted")
	}
}

func TestStepUpRotatesSession(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	tok := sessToken(t, f)
	f.e.Clock.Advance(time.Hour)
	p, _ := f.e.Sessions.Validate(ctx, tok)
	if err := f.e.Sessions.RequireStepUp(p); err == nil {
		t.Fatal("expected stale")
	}
	m := src
	m.Session = p
	r, err := f.svc.Start(ctx, "ada@example.com", goodPassword, m)
	if err != nil {
		t.Fatal(err)
	}
	c, err := f.svc.Finish(ctx, r.Challenge, answers(goodPairs), m)
	if err != nil {
		t.Fatal(err)
	}
	np, err := f.e.Sessions.Validate(ctx, c.Token)
	if err != nil || f.e.Sessions.RequireStepUp(np) != nil || np.Method != p.Method {
		t.Fatalf("step-up: %+v %v", np, err)
	}
	if _, err := f.e.Sessions.Validate(ctx, tok); err == nil {
		t.Fatal("old session still valid")
	}
}

var tokens sync.Map

func sessToken(t *testing.T, f *fixture) string {
	t.Helper()
	if v, ok := tokens.Load(f); ok {
		return v.(string)
	}
	var c session.Created
	_ = f.e.Store.W().Tx(context.Background(), func(tx *store.Tx) error {
		var err error
		c, err = f.e.Sessions.CreateTx(context.Background(), tx, session.NewParams{UserID: f.uid, Method: session.MethodGoogle})
		return err
	})
	tokens.Store(f, c.Token)
	return c.Token
}

func TestEnrollmentPolicy(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	fresh := func() *session.Principal { p, _ := f.e.Sessions.Validate(ctx, sessToken(t, f)); return p }
	cases := map[string]localauth.EnrollParams{
		"short password":     {Password: "short", Pairs: goodPairs, Confirm: answers(goodPairs)},
		"weak password":      {Password: "password1234", Pairs: goodPairs, Confirm: answers(goodPairs)},
		"too few pairs":      {Password: goodPassword, Pairs: goodPairs[:2], Confirm: answers(goodPairs[:2])},
		"confirm mismatch":   {Password: goodPassword, Pairs: goodPairs, Confirm: []string{"x", "y", "z"}},
		"repeated answer":    {Password: goodPassword, Pairs: []localauth.Pair{goodPairs[0], goodPairs[1], {Title: "other", Answer: goodPairs[0].Answer}}},
		"answer in title":    {Password: goodPassword, Pairs: []localauth.Pair{goodPairs[0], goodPairs[1], {Title: "my cat tom", Answer: "Tom"}}},
		"weak combined":      {Password: goodPassword, Pairs: []localauth.Pair{{Title: "a", Answer: "red"}, {Title: "b", Answer: "dog"}, {Title: "c", Answer: "cat"}}},
		"duplicate title":    {Password: goodPassword, Pairs: []localauth.Pair{{Title: "Pet", Answer: "biscuit tin"}, {Title: "pet!", Answer: "zebra crossing"}, goodPairs[2]}},
		"answer is password": {Password: goodPassword, Pairs: []localauth.Pair{goodPairs[0], goodPairs[1], {Title: "x", Answer: goodPassword}}},
	}
	for name, p := range cases {
		if p.Confirm == nil {
			p.Confirm = answers(p.Pairs)
		}
		if _, err := f.svc.Enroll(ctx, fresh(), p); apperr.CodeOf(err) != apperr.CodeInvalid {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Rotation needs a recent authentication.
	f.e.Clock.Advance(10 * time.Minute)
	if _, err := f.svc.Enroll(ctx, fresh(), localauth.EnrollParams{Password: goodPassword, Pairs: goodPairs, Confirm: answers(goodPairs)}); !errors.Is(err, session.ErrReauthRequired) {
		t.Fatalf("rotation without step-up: %v", err)
	}
}

func TestRecoveryLink(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	tok, _, err := f.svc.IssueRecoveryLink(ctx, f.uid)
	if err != nil || !strings.HasPrefix(tok, localauth.RecoveryLinkPrefix) {
		t.Fatal(err)
	}
	c, err := f.svc.UseRecoveryLink(ctx, tok, src)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := f.e.Sessions.Validate(ctx, c.Token); err != nil || p.Method != session.MethodRecoveryLink {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := f.svc.UseRecoveryLink(ctx, tok, src); err == nil {
		t.Fatal("reused")
	}
	alerts, _ := f.e.Store.R().ListOpenAlerts(ctx)
	if len(alerts) != 1 || alerts[0].Severity != "critical" {
		t.Fatalf("alerts %v", alerts)
	}
	tok2, _, _ := f.svc.IssueRecoveryLink(ctx, f.uid)
	f.e.Clock.Advance(16 * time.Minute)
	if _, err := f.svc.UseRecoveryLink(ctx, tok2, src); err == nil {
		t.Fatal("expired link accepted")
	}
}

func TestDisabledFlag(t *testing.T) {
	f := setup(t, func(p *localauth.Policy) { p.Disabled = true })
	if _, err := f.svc.Start(context.Background(), "ada@example.com", goodPassword, src); !errors.Is(err, localauth.ErrDisabled) {
		t.Fatal(err)
	}
}

func TestCanonicalAnswer(t *testing.T) {
	for in, want := range map[string]string{"  Biscuit, the Dog! ": "biscuit the dog", "ＡＢＣ": "abc", "a\t\nb": "a b", "Gatvė–14": "gatvė14"} {
		if got := localauth.CanonicalAnswer(in); got != want {
			t.Errorf("%q → %q want %q", in, got, want)
		}
	}
}

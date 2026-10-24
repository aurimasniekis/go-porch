package events_test

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/aurimasniekis/go-pulse/pkg/pulse"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/aurimasniekis/go-porch/internal/events"
	"github.com/aurimasniekis/go-porch/internal/testenv"
)

type fakePub struct {
	mu    sync.Mutex
	fails int // remaining failures
	ids   []string
}

func (f *fakePub) Publish(_ context.Context, _, _ string, _ any, opts ...pulse.PublishOption) (*pulse.PubAck, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fails != 0 {
		f.fails--
		return nil, errors.New("nats: no responders available for request")
	}
	f.ids = append(f.ids, "ok")
	return &pulse.PubAck{}, nil
}

func pending(t *testing.T, e *testenv.Env) (int64, int64) {
	t.Helper()
	c, err := e.Store.R().CountOutbox(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return c.Pending.(int64), c.Dead.(int64)
}

func TestBackoff(t *testing.T) {
	if d := events.Backoff(1, 0.5); d != time.Second {
		t.Fatalf("first retry %v", d)
	}
	if d := events.Backoff(4, 0.5); d != 8*time.Second {
		t.Fatalf("fourth retry %v", d)
	}
	if d := events.Backoff(40, 0.99); d != events.MaxBackoff {
		t.Fatalf("cap %v", d)
	}
	if d := events.Backoff(3, 0); d != 2*time.Second {
		t.Fatalf("jitter low %v", d)
	}
}

// Pulse being down never loses events: they retry with backoff and publish once pulse is back.
func TestRelayRetriesThenPublishes(t *testing.T) {
	e := testenv.New(t)
	e.Tenant(t, "smith")
	e.Tenant(t, "jones")
	before, _ := pending(t, e)
	if before == 0 {
		t.Fatal("no events enqueued")
	}
	pub := &fakePub{fails: 2}
	r := &events.Relay{Store: e.Store, Pub: pub, Clock: e.Clock, Log: slog.New(slog.DiscardHandler)}
	ctx := context.Background()
	if n, failed, err := r.Once(ctx); err != nil || n != 0 || failed != 1 {
		t.Fatalf("first round %d %d %v", n, failed, err)
	}
	for range 10 {
		e.Clock.Advance(10 * time.Second)
		if _, _, err := r.Once(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if p, d := pending(t, e); p != 0 || d != 0 || int64(len(pub.ids)) != before {
		t.Fatalf("pending %d dead %d published %d of %d", p, d, len(pub.ids), before)
	}
}

func TestRelayDeadLetters(t *testing.T) {
	e := testenv.New(t)
	e.Tenant(t, "smith")
	before, _ := pending(t, e)
	r := &events.Relay{Store: e.Store, Pub: &fakePub{fails: -1}, Clock: e.Clock, Log: slog.New(slog.DiscardHandler)}
	ctx := context.Background()
	if _, _, err := r.Once(ctx); err != nil {
		t.Fatal(err)
	}
	e.Clock.Advance(events.MaxAge + time.Minute)
	for range int(before) + 1 {
		if _, _, err := r.Once(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if p, d := pending(t, e); d == 0 || p+d != before {
		t.Fatalf("pending %d dead %d of %d", p, d, before)
	}
}

// Against a real NATS JetStream server through the pulse SDK: events keep their outbox ID (Nats-Msg-Id) and
// CloudEvents type, and a re-publish of the same event is deduplicated by JetStream.
func TestRelayJetStream(t *testing.T) {
	srv, err := natsserver.NewServer(&natsserver.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir(), NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	t.Cleanup(srv.Shutdown)
	if !srv.ReadyForConnections(10 * time.Second) {
		t.Fatal("nats not ready")
	}
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	ctx := context.Background()
	js, _ := jetstream.New(nc)
	if _, err := js.CreateStream(ctx, jetstream.StreamConfig{Name: pulse.DefaultStream, Subjects: []string{"evt.>"}, Duplicates: 2 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	pc, err := pulse.New(nc, "porch")
	if err != nil {
		t.Fatal(err)
	}
	e := testenv.New(t)
	e.Tenant(t, "smith")
	want, _ := pending(t, e)
	r := &events.Relay{Store: e.Store, Pub: pc, Clock: e.Clock, Log: slog.New(slog.DiscardHandler)}
	if n, failed, err := r.Once(ctx); err != nil || failed != 0 || int64(n) != want {
		t.Fatalf("published %d failed %d err %v (want %d)", n, failed, err, want)
	}
	cons, err := js.OrderedConsumer(ctx, pulse.DefaultStream, jetstream.OrderedConsumerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	var first *nats.Header
	for i := range int(want) {
		m, err := cons.Next(jetstream.FetchMaxWait(5 * time.Second))
		if err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
		h := m.Headers()
		if h.Get("Nats-Msg-Id") == "" || h.Get("ce-source") != "porch" || len(h.Get("ce-type")) < len("porch.x.y_z.v1") {
			t.Fatalf("headers %v", h)
		}
		if first == nil {
			first = &h
		}
		if string(m.Data()) == "" {
			t.Fatal("empty payload")
		}
	}
	// A crash between publish and marking would publish again with the same ID: JetStream drops the duplicate.
	ack, err := pc.Publish(ctx, "evt.porch.test.retry", (*first).Get("ce-type"), map[string]any{}, pulse.WithID((*first).Get("Nats-Msg-Id")))
	if err != nil || !ack.Duplicate {
		t.Fatalf("duplicate not detected: %+v %v", ack, err)
	}
}

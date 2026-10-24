// Package events relays outbox rows to pulse (NATS JetStream) after their transaction committed (ADR-0019). Each
// event keeps its outbox ID as the CloudEvents ID / Nats-Msg-Id, so consumers can deduplicate retries. A pulse outage
// never blocks Porch: events wait in the outbox, retry with capped exponential backoff and are dead-lettered after 50
// attempts or 24 hours.
package events

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/aurimasniekis/go-pulse/pkg/pulse"

	"github.com/aurimasniekis/go-porch/internal/clock"
	"github.com/aurimasniekis/go-porch/internal/domain"
	"github.com/aurimasniekis/go-porch/internal/obs/metrics"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/store/db"
)

// Publisher is the part of the pulse client the relay uses.
type Publisher interface {
	Publish(ctx context.Context, subject, typ string, data any, opts ...pulse.PublishOption) (*pulse.PubAck, error)
}

// Limits of the retry policy.
const (
	MaxAttempts = 50
	MaxAge      = 24 * time.Hour
	MaxBackoff  = 5 * time.Minute
	batch       = 100
)

// Relay publishes due outbox rows.
type Relay struct {
	Store   *store.Store
	Pub     Publisher
	Clock   clock.Clock
	Metrics *metrics.Metrics
	Log     *slog.Logger
}

// Backoff is the delay before attempt n+1 (n ≥ 1): 2^(n-1) s with ±50 % jitter, capped at MaxBackoff.
func Backoff(attempts int64, jitter float64) time.Duration {
	d := time.Second << min(attempts-1, 20)
	d = time.Duration(float64(d) * (0.5 + jitter))
	return min(d, MaxBackoff)
}

// Once publishes up to one batch of due events and returns how many were published and how many failed.
func (r *Relay) Once(ctx context.Context) (published, failed int, err error) {
	now := r.Clock.Now()
	rows, err := r.Store.R().DueOutbox(ctx, db.DueOutboxParams{NextAttemptAt: now.UnixMicro(), Limit: batch})
	if err != nil {
		return 0, 0, err
	}
	for _, row := range rows {
		pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		_, perr := r.Pub.Publish(pctx, row.Subject, row.Type, json.RawMessage(row.PayloadJson), pulse.WithID(row.ID),
			pulse.WithTime(domain.FromMicros(row.CreatedAt)))
		cancel()
		if ctx.Err() != nil {
			return published, failed, ctx.Err()
		}
		if perr == nil {
			published++
			r.Metrics.OutboxPublish("ok")
			if err := r.mark(ctx, func(tx *store.Tx) error {
				_, err := tx.Q.MarkOutboxPublished(ctx, db.MarkOutboxPublishedParams{PublishedAt: domain.NullMicros(&tx.Now), ID: row.ID})
				return err
			}); err != nil {
				return published, failed, err
			}
			continue
		}
		failed++
		msg := perr.Error()
		if len(msg) > 500 {
			msg = msg[:500]
		}
		attempts := row.Attempts + 1
		dead := attempts >= MaxAttempts || now.Sub(domain.FromMicros(row.CreatedAt)) >= MaxAge
		if dead {
			r.Metrics.OutboxPublish("dead")
			r.Log.Error("event dead-lettered", "id", row.ID, "type", row.Type, "attempts", attempts, "err", msg)
		} else {
			r.Metrics.OutboxPublish("error")
		}
		next := now.Add(Backoff(attempts, jitter()))
		if err := r.mark(ctx, func(tx *store.Tx) error {
			if dead {
				_, err := tx.Q.MarkOutboxDead(ctx, db.MarkOutboxDeadParams{DeadAt: domain.NullMicros(&tx.Now), LastError: domain.NullStr(msg), ID: row.ID})
				return err
			}
			_, err := tx.Q.MarkOutboxRetry(ctx, db.MarkOutboxRetryParams{NextAttemptAt: next.UnixMicro(), LastError: domain.NullStr(msg), ID: row.ID})
			return err
		}); err != nil {
			return published, failed, err
		}
		// One failure usually means pulse is unreachable: stop this round instead of timing out on every row.
		break
	}
	return published, failed, nil
}

// jitter returns a uniform value in [0, 1).
func jitter() float64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return float64(binary.BigEndian.Uint64(b[:])>>11) / (1 << 53)
}

func (r *Relay) mark(ctx context.Context, fn func(tx *store.Tx) error) error {
	return r.Store.W().TxNamed(context.WithoutCancel(ctx), "outbox.mark", fn)
}

// Run publishes until ctx ends, polling every interval and draining backlogs without waiting.
func (r *Relay) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		for {
			n, failed, err := r.Once(ctx)
			if err != nil && !errors.Is(err, context.Canceled) {
				r.Log.Warn("event relay", "err", err)
			}
			if err != nil || failed > 0 || n < batch {
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

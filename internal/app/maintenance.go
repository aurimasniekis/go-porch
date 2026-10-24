package app

import (
	"context"
	"database/sql"
	"time"

	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/store/db"
)

func sqlNull(v int64) sql.NullInt64 { return sql.NullInt64{Int64: v, Valid: true} }

// maintain periodically purges expired protocol state and retires signing keys whose overlap has passed.
func (a *App) maintain(ctx context.Context) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		a.RunMaintenance(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RunMaintenance performs one maintenance pass (exported for tests and the CLI).
func (a *App) RunMaintenance(ctx context.Context) {
	if _, err := a.OP.Signing.RetireExpired(ctx); err != nil {
		a.Log.Warn("retire signing keys", "err", err)
	}
	err := a.Store.W().TxNamed(ctx, "maintenance.purge", func(tx *store.Tx) error {
		now := tx.NowMicros()
		for _, f := range []func(context.Context, int64) (int64, error){
			tx.Q.PurgeAuthRequests, tx.Q.PurgeAuthCodes, tx.Q.PurgeRefreshTokens, tx.Q.PurgeRevokedAccessTokens, tx.Q.PurgeLoginStates,
			tx.Q.PurgeBackupChallenges, tx.Q.PurgeForwardAuthCodes, tx.Q.PurgeForwardAuthSessions,
		} {
			if _, err := f(ctx, now); err != nil {
				return err
			}
		}
		if _, err := tx.Q.PurgeSessions(ctx, db.PurgeSessionsParams{AbsoluteExpiresAt: now, RevokedAt: sqlNull(now - int64(30*24*time.Hour/time.Microsecond))}); err != nil {
			return err
		}
		if _, err := tx.Q.PurgePublishedOutbox(ctx, sqlNull(now-int64(7*24*time.Hour/time.Microsecond))); err != nil {
			return err
		}
		if _, err := tx.Q.PurgeIdempotencyKeys(ctx, now); err != nil {
			return err
		}
		// Expired and revoked automation tokens stay listed for 30 days so their last use remains visible.
		month := now - int64(30*24*time.Hour/time.Microsecond)
		if _, err := tx.Q.PurgeAutomationTokens(ctx, db.PurgeAutomationTokensParams{ExpiresAt: month, RevokedAt: sqlNull(month)}); err != nil {
			return err
		}
		_, err := tx.Q.PurgeThrottles(ctx, now-int64(24*time.Hour/time.Microsecond))
		return err
	})
	if err != nil {
		a.Log.Warn("maintenance purge", "err", err)
	}
	a.Metrics.JobRun("maintenance", err)
	if ob, err := a.Store.R().CountOutbox(ctx); err == nil {
		a.Metrics.SetOutbox(int(toInt64(ob.Pending)), int(toInt64(ob.Dead)))
	}
}

func toInt64(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case float64:
		return int64(x)
	}
	return 0
}

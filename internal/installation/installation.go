// Package installation manages the singleton installation row: its ID, setup state and the installation-wide security
// epoch. Bumping the epoch invalidates every session and refresh token at once (used after a restore, ADR-0018).
package installation

import (
	"context"
	"time"

	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/domain"
	"github.com/aurimasniekis/go-porch/internal/ids"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/store/db"
)

// Info describes the installation.
type Info struct {
	ID               string     `json:"id"`
	SecurityEpoch    int64      `json:"security_epoch"`
	SetupCompletedAt *time.Time `json:"setup_completed_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
}

// Ensure creates the installation row on first start.
func Ensure(ctx context.Context, s *store.Store) error {
	return s.W().TxNamed(ctx, "installation.ensure", func(tx *store.Tx) error {
		return tx.Q.InsertInstallation(ctx, db.InsertInstallationParams{InstallationID: ids.New(ids.Installation),
			CreatedAt: tx.NowMicros(), UpdatedAt: tx.NowMicros()})
	})
}

// Get returns the installation.
func Get(ctx context.Context, q *db.Queries) (Info, error) {
	r, err := q.GetInstallation(ctx)
	if err != nil {
		return Info{}, err
	}
	return Info{ID: r.InstallationID, SecurityEpoch: r.SecurityEpoch, SetupCompletedAt: domain.OptMicros(r.SetupCompletedAt),
		CreatedAt: domain.FromMicros(r.CreatedAt)}, nil
}

// BumpSecurityEpochTx invalidates every session and token issued before now.
func BumpSecurityEpochTx(ctx context.Context, tx *store.Tx, w *audit.Writer, actor audit.Actor, reason string) (int64, error) {
	epoch, err := tx.Q.BumpSecurityEpoch(ctx, tx.NowMicros())
	if err != nil {
		return 0, err
	}
	_, err = w.Append(ctx, tx, audit.Event{Actor: actor, Action: "installation.security_epoch_bumped",
		Target: audit.Target{Type: "installation"}, ReasonCode: reason, Details: map[string]any{"epoch": epoch}})
	return epoch, err
}

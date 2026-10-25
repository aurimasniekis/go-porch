package idp

import (
	"context"
	"database/sql"
	"errors"

	"github.com/aurimasniekis/go-porch/internal/apperr"
	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/domain"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/store/db"
)

// directSettingKey holds the slug of the provider the sign-in page sends people to directly ("" = show all methods).
const directSettingKey = "login.direct_provider"

// DirectProvider returns the slug of the provider the sign-in page redirects to, or "" when the page shows every
// method. A slug whose provider was deleted or disabled counts as "".
func (svc *Service) DirectProvider(ctx context.Context) (string, error) {
	row, err := svc.s.R().GetSetting(ctx, directSettingKey)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && row.Value == "") {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	p, err := svc.s.R().GetProviderBySlug(ctx, row.Value)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && p.Enabled != 1) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return p.Slug, nil
}

// SetDirectProvider makes the sign-in page go straight to the enabled provider slug ("" turns it off).
func (svc *Service) SetDirectProvider(ctx context.Context, ch domain.Change, slug string) error {
	return svc.s.W().TxNamed(ctx, "idp.direct_provider", func(tx *store.Tx) error {
		if slug != "" {
			p, err := tx.Q.GetProviderBySlug(ctx, slug)
			if errors.Is(err, sql.ErrNoRows) {
				return ErrProviderNotFound
			}
			if err != nil {
				return err
			}
			if p.Enabled != 1 {
				return apperr.New(apperr.CodeInvalid, "the provider is disabled")
			}
		}
		if err := tx.Q.UpsertSetting(ctx, db.UpsertSettingParams{Key: directSettingKey, Value: slug, UpdatedAt: tx.NowMicros(),
			UpdatedBy: sql.NullString{String: ch.Actor.ID, Valid: ch.Actor.ID != ""}}); err != nil {
			return err
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: ch.Actor, Action: "login.direct_provider_set", Target: audit.Target{Type: "installation"},
			Details: map[string]any{"provider": slug}})
		return err
	})
}

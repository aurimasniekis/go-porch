package app

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/domain"
)

var mediaID = regexp.MustCompile(`^[0-9a-f]{64}$`)

// serveMedia serves a stored icon or background (ADR-0045). The ID is the content hash, so responses never change:
// they are cached for a year. Only bytes Porch re-encoded itself are stored, and nosniff plus a sandboxing CSP keep a
// browser from treating them as anything but an image.
func (a *App) serveMedia(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !mediaID.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	ct, data, err := a.Appearance.Media(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	h := w.Header()
	h.Set("Content-Type", ct)
	h.Set("Content-Length", strconv.Itoa(len(data)))
	h.Set("Cache-Control", "public, max-age=31536000, immutable")
	h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("ETag", `"`+id+`"`)
	if r.Header.Get("If-None-Match") == `"`+id+`"` {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	_, _ = w.Write(data) //nolint:gosec // re-encoded image bytes, served with nosniff and a sandboxing CSP (ADR-0045)
}

// appearanceLoop renews the background pool when its refresh interval has passed (checked hourly, retried no sooner
// than six hours after a failure) and removes icons no application uses any more.
func (a *App) appearanceLoop(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	var lastFailure time.Time
	for {
		now := a.Clock.Now()
		if a.Appearance.RefreshDue(ctx) && now.Sub(lastFailure) >= 6*time.Hour {
			if _, err := a.Appearance.Refresh(ctx, domain.Change{Actor: audit.System}); err != nil {
				lastFailure = now
				a.Log.Warn("appearance: cannot refresh background images", "err", err)
			}
		}
		if n, err := a.Appearance.CollectIcons(ctx); err != nil {
			a.Log.Warn("appearance: cannot remove unused icons", "err", err)
		} else if n > 0 {
			a.Log.Info("appearance: removed unused icons", "count", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

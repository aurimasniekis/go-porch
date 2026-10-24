// Package appearance holds how the user-facing pages look: the installation title, login backgrounds pulled from open
// image sources, and the media store for backgrounds and application icons (ADR-0045). Every image is fetched by
// Porch through the outbound guard, decoded and re-encoded, stored in the database and served from Porch's own
// origin, so browsers never contact a third party and the Content-Security-Policy stays 'self'.
package appearance

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/aurimasniekis/go-porch/internal/apperr"
	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/clock"
	"github.com/aurimasniekis/go-porch/internal/domain"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/store/db"
)

// Background sources.
const (
	SourceNone      = "none"
	SourceWikimedia = "wikimedia"
	SourcePicsum    = "picsum"
)

// Rotation picks which pooled background a page shows.
const (
	RotateVisit = "visit" // a random one on every page load
	RotateDaily = "daily" // the same one for everybody all day
)

// DefaultCategory is the Wikimedia Commons category used when none is set.
const DefaultCategory = "Featured pictures of landscapes"

const settingsKey = "appearance"

// Settings is the installation's appearance.
type Settings struct {
	Title      string     `json:"title"`
	Background Background `json:"background"`
}

// Background configures login and launcher backgrounds.
type Background struct {
	Source   string   `json:"source"`
	Category string   `json:"category"` // wikimedia: Commons category
	Files    []string `json:"files"`    // wikimedia: file names; picsum: photo IDs (empty = random)
	Rotation string   `json:"rotation"`
	Count    int      `json:"count"` // how many images to keep
	Refresh  string   `json:"refresh"`
}

// Refresh intervals for the background pool.
const (
	RefreshNever  = "never"
	RefreshDaily  = "daily"
	RefreshWeekly = "weekly"
)

// Defaults: no backgrounds (Porch makes no outbound image requests until an operator picks a source); when one is
// picked, Wikimedia Commons featured landscapes, a new random set every week.
func Defaults() Settings {
	return Settings{Title: "Porch", Background: Background{Source: SourceNone, Category: DefaultCategory, Files: []string{},
		Rotation: RotateVisit, Count: 6, Refresh: RefreshWeekly}}
}

var (
	categoryRE = regexp.MustCompile(`^[^\x00-\x1f|#<>\[\]{}]{1,200}$`)
	fileRE     = regexp.MustCompile(`^[^\x00-\x1f|#<>\[\]{}]{1,240}$`)
)

func (s *Settings) normalize() error {
	d := Defaults()
	s.Title = strings.TrimSpace(s.Title)
	if s.Title == "" {
		s.Title = d.Title
	}
	b := &s.Background
	if b.Source == "" {
		b.Source = d.Background.Source
	}
	if b.Rotation == "" {
		b.Rotation = d.Background.Rotation
	}
	if b.Refresh == "" {
		b.Refresh = d.Background.Refresh
	}
	if b.Count == 0 {
		b.Count = d.Background.Count
	}
	if b.Files == nil {
		b.Files = []string{}
	}
	b.Category = strings.TrimPrefix(strings.TrimSpace(b.Category), "Category:")
	if b.Source == SourceWikimedia && b.Category == "" && len(b.Files) == 0 {
		b.Category = DefaultCategory
	}
	switch {
	case len([]rune(s.Title)) > 80:
		return apperr.New(apperr.CodeInvalid, "title is longer than 80 characters")
	case b.Source != SourceNone && b.Source != SourceWikimedia && b.Source != SourcePicsum:
		return apperr.New(apperr.CodeInvalid, "background.source must be none, wikimedia or picsum")
	case b.Rotation != RotateVisit && b.Rotation != RotateDaily:
		return apperr.New(apperr.CodeInvalid, "background.rotation must be visit or daily")
	case b.Refresh != RefreshNever && b.Refresh != RefreshDaily && b.Refresh != RefreshWeekly:
		return apperr.New(apperr.CodeInvalid, "background.refresh must be never, daily or weekly")
	case b.Count < 1 || b.Count > 12:
		return apperr.New(apperr.CodeInvalid, "background.count must be within 1..12")
	case len(b.Files) > 12:
		return apperr.New(apperr.CodeInvalid, "at most 12 background files")
	case b.Category != "" && !categoryRE.MatchString(b.Category):
		return apperr.New(apperr.CodeInvalid, "background.category is not a valid category name")
	}
	for i, f := range b.Files {
		f = strings.TrimSpace(f)
		if !fileRE.MatchString(f) {
			return apperr.New(apperr.CodeInvalid, "background.files[%d] is not a valid name", i)
		}
		b.Files[i] = f
	}
	return nil
}

// Image is a stored background with its credit.
type Image struct {
	ID         string    `json:"id"`
	URL        string    `json:"url"`
	Width      int       `json:"width"`
	Height     int       `json:"height"`
	Title      string    `json:"title"`
	Author     string    `json:"author"`
	License    string    `json:"license"`
	LicenseURL string    `json:"license_url"`
	SourceURL  string    `json:"source_url"`
	FetchedAt  time.Time `json:"fetched_at"`
}

// MediaURL is where an image is served (public, immutable).
func MediaURL(id string) string { return "/media/" + id }

// Service manages appearance settings and media.
type Service struct {
	s     *store.Store
	audit *audit.Writer
	fetch *Fetcher
	clock clock.Clock
	log   *slog.Logger
}

// New returns the service. fetch may be nil (no outbound fetching: tests, or a guard that cannot be built).
func New(s *store.Store, a *audit.Writer, fetch *Fetcher, c clock.Clock, log *slog.Logger) *Service {
	if c == nil {
		c = clock.System{}
	}
	if log == nil {
		log = slog.Default()
	}
	return &Service{s: s, audit: a, fetch: fetch, clock: c, log: log}
}

// Settings returns the stored settings (defaults when never saved).
func (svc *Service) Settings(ctx context.Context) (Settings, error) {
	row, err := svc.s.R().GetSetting(ctx, settingsKey)
	if errors.Is(err, sql.ErrNoRows) {
		return Defaults(), nil
	}
	if err != nil {
		return Settings{}, err
	}
	var s Settings
	if err := json.Unmarshal([]byte(row.Value), &s); err != nil {
		return Settings{}, err
	}
	if err := s.normalize(); err != nil {
		return Defaults(), nil //nolint:nilerr // a setting saved by an older version: fall back rather than fail pages
	}
	return s, nil
}

// Update saves new settings. Images are not fetched here (no network I/O inside the write transaction); call
// Refresh afterwards.
func (svc *Service) Update(ctx context.Context, ch domain.Change, s Settings) (Settings, error) {
	if err := s.normalize(); err != nil {
		return Settings{}, err
	}
	b, err := json.Marshal(s)
	if err != nil {
		return Settings{}, err
	}
	err = svc.s.W().TxNamed(ctx, "appearance.update", func(tx *store.Tx) error {
		if err := tx.Q.UpsertSetting(ctx, db.UpsertSettingParams{Key: settingsKey, Value: string(b), UpdatedAt: svc.clock.Now().UnixMicro(),
			UpdatedBy: sql.NullString{String: ch.Actor.ID, Valid: ch.Actor.ID != ""}}); err != nil {
			return err
		}
		if s.Background.Source == SourceNone {
			if err := tx.Q.DeleteAllBackgrounds(ctx); err != nil {
				return err
			}
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: ch.Actor, Action: "appearance.updated", Target: audit.Target{Type: "installation"},
			Details: map[string]any{"source": s.Background.Source, "category": s.Background.Category, "files": len(s.Background.Files),
				"rotation": s.Background.Rotation, "count": s.Background.Count}})
		return err
	})
	if err != nil {
		return Settings{}, err
	}
	return s, nil
}

// Backgrounds lists the pooled background images.
func (svc *Service) Backgrounds(ctx context.Context) ([]Image, error) {
	rows, err := svc.s.R().ListBackgrounds(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Image, 0, len(rows))
	for _, r := range rows {
		out = append(out, Image{ID: r.ID, URL: MediaURL(r.ID), Width: int(r.Width), Height: int(r.Height), Title: r.Title, Author: r.Author,
			License: r.License, LicenseURL: r.LicenseUrl, SourceURL: r.SourceUrl, FetchedAt: domain.FromMicros(r.CreatedAt)})
	}
	return out, nil
}

// Current picks the background a page should show now, or nil.
func (svc *Service) Current(ctx context.Context) (*Image, error) {
	s, err := svc.Settings(ctx)
	if err != nil || s.Background.Source == SourceNone {
		return nil, err
	}
	imgs, err := svc.Backgrounds(ctx)
	if err != nil || len(imgs) == 0 {
		return nil, err
	}
	i := randN(len(imgs))
	if s.Background.Rotation == RotateDaily {
		i = int(svc.clock.Now().UTC().Unix()/86400) % len(imgs)
	}
	return &imgs[i], nil
}

// ErrNoFetcher means outbound fetching is not available.
var ErrNoFetcher = errors.New("appearance: image fetching is not configured")

// Refresh replaces the background pool from the configured source. Downloads happen before, and outside, the short
// write transaction that stores the result; images that fail are skipped, and the old pool stays when none succeed.
func (svc *Service) Refresh(ctx context.Context, ch domain.Change) ([]Image, error) {
	s, err := svc.Settings(ctx)
	if err != nil {
		return nil, err
	}
	if s.Background.Source == SourceNone {
		return []Image{}, nil
	}
	if svc.fetch == nil {
		return nil, ErrNoFetcher
	}
	ctx, cancel := context.WithTimeout(ctx, 50*time.Second)
	defer cancel()
	b := s.Background
	var cands []Candidate
	if b.Source == SourceWikimedia {
		cands, err = svc.fetch.WikimediaCandidates(ctx, b.Category, b.Files, b.Count)
	} else {
		cands, err = svc.fetch.PicsumCandidates(ctx, b.Files, b.Count)
	}
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeUnavailable, err, "cannot list background images: %v", err)
	}
	type got struct {
		e Encoded
		c Candidate
	}
	var imgs []got
	var lastErr error
	for _, c := range cands {
		if len(imgs) >= b.Count {
			break
		}
		raw, err := svc.fetch.Image(ctx, c.URL, maxBgBytes)
		if err == nil {
			var e Encoded
			if e, err = EncodeBackground(raw); err == nil {
				imgs = append(imgs, got{e, c})
				continue
			}
		}
		lastErr = err
		svc.log.Warn("appearance: background image skipped", "source", c.SourceURL, "err", err)
	}
	if len(imgs) == 0 {
		return nil, apperr.Wrap(apperr.CodeUnavailable, lastErr, "no background image could be downloaded: %v", lastErr)
	}
	now := svc.clock.Now().UnixMicro()
	err = svc.s.W().TxNamed(ctx, "appearance.refresh", func(tx *store.Tx) error {
		keep := make([]string, 0, len(imgs))
		for _, g := range imgs {
			keep = append(keep, g.e.ID)
			if err := tx.Q.InsertMedia(ctx, db.InsertMediaParams{ID: g.e.ID, Kind: "background", ContentType: g.e.ContentType, Data: g.e.Data,
				Width: int64(g.e.Width), Height: int64(g.e.Height), Title: g.c.Title, Author: g.c.Author, License: g.c.License,
				LicenseUrl: g.c.LicenseURL, SourceUrl: g.c.SourceURL, CreatedAt: now}); err != nil {
				return err
			}
		}
		if err := tx.Q.DeleteBackgroundsExcept(ctx, keep); err != nil {
			return err
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: ch.Actor, Action: "appearance.backgrounds_refreshed", Target: audit.Target{Type: "installation"},
			Details: map[string]any{"source": b.Source, "images": len(imgs)}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return svc.Backgrounds(ctx)
}

// RefreshDue reports whether the background pool should be renewed now.
func (svc *Service) RefreshDue(ctx context.Context) bool {
	s, err := svc.Settings(ctx)
	if err != nil || s.Background.Source == SourceNone {
		return false
	}
	imgs, err := svc.Backgrounds(ctx)
	if err != nil {
		return false
	}
	if len(imgs) == 0 {
		return true
	}
	age := svc.clock.Now().Sub(imgs[len(imgs)-1].FetchedAt)
	switch s.Background.Refresh {
	case RefreshDaily:
		return age >= 24*time.Hour
	case RefreshWeekly:
		return age >= 7*24*time.Hour
	}
	return false
}

// Icon sources for applications.
const (
	IconNone           = ""
	IconURL            = "url"
	IconDashboardIcons = "dashboard_icons"
	IconTheSVG         = "thesvg"
	IconUpload         = "upload"
)

// FetchIcon downloads and re-encodes an application icon (network I/O: call outside write transactions).
func (svc *Service) FetchIcon(ctx context.Context, source, ref string) (Encoded, error) {
	if svc.fetch == nil {
		return Encoded{}, ErrNoFetcher
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var raw []byte
	var err error
	switch source {
	case IconURL:
		raw, err = svc.fetch.Image(ctx, ref, maxIconBytes)
	case IconDashboardIcons:
		raw, err = svc.fetch.DashboardIcon(ctx, ref)
	case IconTheSVG:
		raw, err = svc.fetch.TheSVG(ctx, ref)
	default:
		return Encoded{}, apperr.New(apperr.CodeInvalid, "icon source must be url, dashboard_icons or thesvg")
	}
	if err != nil {
		if errors.Is(err, ErrImage) {
			return Encoded{}, apperr.Wrap(apperr.CodeInvalid, err, "%v", err)
		}
		return Encoded{}, apperr.Wrap(apperr.CodeUnavailable, err, "cannot download the icon: %v", err)
	}
	e, err := EncodeIcon(raw)
	if err != nil {
		return Encoded{}, apperr.Wrap(apperr.CodeInvalid, err, "%v", err)
	}
	return e, nil
}

// StoreIconTx stores an encoded icon inside tx (idempotent: the ID is the content hash).
func StoreIconTx(ctx context.Context, tx *store.Tx, e Encoded, now time.Time) error {
	return tx.Q.InsertMedia(ctx, db.InsertMediaParams{ID: e.ID, Kind: "icon", ContentType: e.ContentType, Data: e.Data,
		Width: int64(e.Width), Height: int64(e.Height), CreatedAt: now.UnixMicro()})
}

// Media returns a stored image's bytes and content type.
func (svc *Service) Media(ctx context.Context, id string) (contentType string, data []byte, err error) {
	m, err := svc.s.R().GetMedia(ctx, id)
	if err != nil {
		return "", nil, err
	}
	return m.ContentType, m.Data, nil
}

// CollectIcons deletes icons no application uses any more (kept for an hour so concurrent edits never race).
func (svc *Service) CollectIcons(ctx context.Context) (int64, error) {
	var n int64
	err := svc.s.W().TxNamed(ctx, "appearance.collect_icons", func(tx *store.Tx) error {
		var err error
		n, err = tx.Q.DeleteUnusedIcons(ctx, svc.clock.Now().Add(-time.Hour).UnixMicro())
		return err
	})
	return n, err
}

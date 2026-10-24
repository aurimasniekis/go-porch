// Package idp manages upstream identity providers (Google, generic OIDC), external identities, domain enrollment rules
// and invites, and runs the upstream login flow: login, silent hourly recheck, step-up and identity linking
// (ADR-0005, ADR-0006, ADR-0007).
package idp

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/aurimasniekis/go-porch/internal/apperr"
	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/clock"
	"github.com/aurimasniekis/go-porch/internal/domain"
	"github.com/aurimasniekis/go-porch/internal/identity"
	"github.com/aurimasniekis/go-porch/internal/idp/upstream"
	"github.com/aurimasniekis/go-porch/internal/ids"
	"github.com/aurimasniekis/go-porch/internal/keyring"
	"github.com/aurimasniekis/go-porch/internal/obs/metrics"
	"github.com/aurimasniekis/go-porch/internal/outbox"
	"github.com/aurimasniekis/go-porch/internal/session"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/store/db"
	"github.com/aurimasniekis/go-porch/internal/tenancy"
)

// Provider kinds.
const (
	KindGoogle = "google"
	KindOIDC   = "oidc"
)

// Provider is an upstream identity provider. The client secret is never returned.
type Provider struct {
	ID            string    `json:"id"`
	Slug          string    `json:"slug"`
	Kind          string    `json:"kind"`
	Name          string    `json:"name"`
	Issuer        string    `json:"issuer"`
	ClientID      string    `json:"client_id"`
	AllowedHDs    []string  `json:"allowed_hds"`
	Scopes        string    `json:"scopes"`
	Enabled       bool      `json:"enabled"`
	Version       int64     `json:"version"`
	ManagedBy     string    `json:"managed_by"`
	LastChangedBy string    `json:"last_changed_by,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// Options configure the service.
type Options struct {
	PublicURL string // origin; callbacks are <origin>/login/<slug>/callback
	// AllowInsecureIssuers permits http:// issuers (development and tests only).
	AllowInsecureIssuers bool
	Clock                clock.Clock
	Metrics              *metrics.Metrics
}

// Service is the identity-provider service.
type Service struct {
	s        *store.Store
	kr       *keyring.Keyring
	audit    *audit.Writer
	users    *identity.Service
	tenants  *tenancy.Service
	sessions *session.Manager
	up       *upstream.Client
	opts     Options
}

// New returns the service.
func New(s *store.Store, kr *keyring.Keyring, a *audit.Writer, users *identity.Service, tenants *tenancy.Service, sessions *session.Manager,
	up *upstream.Client, opts Options) *Service {
	if opts.Clock == nil {
		opts.Clock = clock.System{}
	}
	return &Service{s: s, kr: kr, audit: a, users: users, tenants: tenants, sessions: sessions, up: up, opts: opts}
}

// ErrProviderNotFound is returned for unknown providers.
var ErrProviderNotFound = apperr.New(apperr.CodeNotFound, "identity provider not found")

func providerFromRow(r db.IdentityProvider) Provider {
	var hds []string
	_ = json.Unmarshal([]byte(r.AllowedHds), &hds)
	if hds == nil {
		hds = []string{}
	}
	return Provider{ID: r.ID, Slug: r.Slug, Kind: r.Kind, Name: r.Name, Issuer: r.Issuer, ClientID: r.ClientID, AllowedHDs: hds, Scopes: r.Scopes,
		Enabled: r.Enabled == 1, Version: r.Version, ManagedBy: r.ManagedBy, LastChangedBy: r.LastChangedBy.String,
		CreatedAt: domain.FromMicros(r.CreatedAt), UpdatedAt: domain.FromMicros(r.UpdatedAt)}
}

func secretAAD(id string) []byte { return keyring.FieldAAD("identity_providers", "secret_enc", id) }

// ProviderParams create or update a provider. Secret "" on update keeps the current secret.
type ProviderParams struct {
	Slug       string
	Kind       string
	Name       string
	Issuer     string
	ClientID   string
	Secret     string
	AllowedHDs []string
	Scopes     string
	Enabled    *bool
	IfVersion  int64
}

func (svc *Service) validateProvider(p *ProviderParams, creating bool, v *apperr.Validation) {
	if creating {
		if !domain.ValidSlug(p.Slug) || len(p.Slug) < 2 {
			v.Add("slug", "must be 2..63 lowercase letters, digits or inner hyphens")
		}
		if p.Kind != KindGoogle && p.Kind != KindOIDC {
			v.Add("kind", "must be google or oidc")
		}
		if p.Secret == "" {
			v.Add("client_secret", "is required")
		}
	}
	p.Name = domain.CleanName("name", p.Name, v)
	if p.Kind == KindGoogle && p.Issuer == "" {
		p.Issuer = upstream.GoogleIssuer
	}
	u, err := url.Parse(p.Issuer)
	switch {
	case err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "":
		v.Add("issuer", "must be an absolute URL")
	case u.Scheme != "https" && (!svc.opts.AllowInsecureIssuers || u.Scheme != "http"):
		v.Add("issuer", "must use https")
	}
	if p.Kind == KindGoogle && p.Issuer != upstream.GoogleIssuer && !svc.opts.AllowInsecureIssuers {
		v.Add("issuer", "google providers must use %s", upstream.GoogleIssuer)
	}
	if strings.TrimSpace(p.ClientID) == "" || len(p.ClientID) > 512 {
		v.Add("client_id", "is required")
	}
	for i, h := range p.AllowedHDs {
		h = strings.ToLower(strings.TrimSpace(h))
		p.AllowedHDs[i] = h
		if !validDomain(h) {
			v.Add("allowed_hds", "%q is not a domain name", h)
		}
	}
	if len(p.AllowedHDs) > 0 && p.Kind != KindGoogle {
		v.Add("allowed_hds", "only applies to google providers")
	}
	if p.Scopes == "" {
		p.Scopes = "openid email profile"
	}
	if !slices.Contains(strings.Fields(p.Scopes), "openid") {
		v.Add("scopes", "must include openid")
	}
}

func validDomain(d string) bool {
	if len(d) < 3 || len(d) > 253 || !strings.Contains(d, ".") {
		return false
	}
	for label := range strings.SplitSeq(d, ".") {
		if !domain.ValidSlug(label) {
			return false
		}
	}
	return true
}

// CreateProvider adds a provider (caller enforces operator role + step-up).
func (svc *Service) CreateProvider(ctx context.Context, ch domain.Change, p ProviderParams) (Provider, error) {
	var v apperr.Validation
	svc.validateProvider(&p, true, &v)
	if err := v.Err(); err != nil {
		return Provider{}, err
	}
	id := ids.New(ids.IdentityProv)
	sealed, err := svc.kr.Seal(keyring.PurposeField, secretAAD(id), []byte(p.Secret))
	if err != nil {
		return Provider{}, err
	}
	hds, _ := json.Marshal(nonNil(p.AllowedHDs))
	enabled := int64(1)
	if p.Enabled != nil && !*p.Enabled {
		enabled = 0
	}
	var out Provider
	err = svc.s.W().TxNamed(ctx, "idp.create_provider", func(tx *store.Tx) error {
		err := tx.Q.InsertProvider(ctx, db.InsertProviderParams{ID: id, Slug: p.Slug, Kind: p.Kind, Name: p.Name, Issuer: p.Issuer,
			ClientID: p.ClientID, SecretEnc: sealed, AllowedHds: string(hds), Scopes: p.Scopes, Enabled: enabled, ManagedBy: ch.Managed(),
			LastChangedBy: domain.NullStr(ch.ChangedBy()), CreatedAt: tx.NowMicros(), UpdatedAt: tx.NowMicros()})
		if store.IsConstraint(err) {
			return apperr.New(apperr.CodeAlreadyExists, "provider slug %q is taken", p.Slug)
		}
		if err != nil {
			return err
		}
		if _, err := svc.audit.Append(ctx, tx, audit.Event{Actor: ch.Actor, Action: "idp.provider_created", Target: audit.Target{Type: "identity_provider", ID: id},
			Details: map[string]any{"slug": p.Slug, "kind": p.Kind, "issuer": p.Issuer, "allowed_hds": nonNil(p.AllowedHDs)}}); err != nil {
			return err
		}
		if _, err := outbox.Enqueue(ctx, tx, outbox.Event{Area: "idp", Entity: "provider", Action: "created", Payload: map[string]any{"provider_id": id, "slug": p.Slug}}); err != nil {
			return err
		}
		r, err := tx.Q.GetProvider(ctx, id)
		out = providerFromRow(r)
		return err
	})
	return out, err
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// UpdateProvider edits a provider.
func (svc *Service) UpdateProvider(ctx context.Context, ch domain.Change, id string, p ProviderParams) (Provider, error) {
	var out Provider
	err := svc.s.W().TxNamed(ctx, "idp.update_provider", func(tx *store.Tx) error {
		r, err := tx.Q.GetProvider(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrProviderNotFound
		}
		if err != nil {
			return err
		}
		if err := domain.IfMatch(p.IfVersion, r.Version); err != nil {
			return err
		}
		cur := providerFromRow(r)
		if p.Name == "" {
			p.Name = cur.Name
		}
		if p.Issuer == "" {
			p.Issuer = cur.Issuer
		}
		if p.ClientID == "" {
			p.ClientID = cur.ClientID
		}
		if p.AllowedHDs == nil {
			p.AllowedHDs = cur.AllowedHDs
		}
		if p.Scopes == "" {
			p.Scopes = cur.Scopes
		}
		p.Kind = cur.Kind
		var v apperr.Validation
		svc.validateProvider(&p, false, &v)
		if err := v.Err(); err != nil {
			return err
		}
		sealed := r.SecretEnc
		if p.Secret != "" {
			if sealed, err = svc.kr.Seal(keyring.PurposeField, secretAAD(id), []byte(p.Secret)); err != nil {
				return err
			}
		}
		enabled := r.Enabled
		if p.Enabled != nil {
			enabled = 0
			if *p.Enabled {
				enabled = 1
			}
		}
		hds, _ := json.Marshal(nonNil(p.AllowedHDs))
		n, err := tx.Q.UpdateProvider(ctx, db.UpdateProviderParams{Name: p.Name, Issuer: p.Issuer, ClientID: p.ClientID, SecretEnc: sealed,
			AllowedHds: string(hds), Scopes: p.Scopes, Enabled: enabled, ManagedBy: ch.Managed(), LastChangedBy: domain.NullStr(ch.ChangedBy()),
			UpdatedAt: tx.NowMicros(), ID: id, Version: r.Version})
		if err != nil {
			return err
		}
		if n != 1 {
			return apperr.New(apperr.CodePrecondition, "provider was changed concurrently")
		}
		if _, err := svc.audit.Append(ctx, tx, audit.Event{Actor: ch.Actor, Action: "idp.provider_updated", Target: audit.Target{Type: "identity_provider", ID: id},
			Details: map[string]any{"issuer": p.Issuer, "allowed_hds": nonNil(p.AllowedHDs), "enabled": enabled == 1, "secret_rotated": p.Secret != ""}}); err != nil {
			return err
		}
		nr, err := tx.Q.GetProvider(ctx, id)
		out = providerFromRow(nr)
		return err
	})
	if err == nil {
		svc.up.Forget(id)
	}
	return out, err
}

// DeleteProvider removes a provider and every identity linked through it.
func (svc *Service) DeleteProvider(ctx context.Context, ch domain.Change, id string, ifVersion int64) error {
	err := svc.s.W().TxNamed(ctx, "idp.delete_provider", func(tx *store.Tx) error {
		r, err := tx.Q.GetProvider(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrProviderNotFound
		}
		if err != nil {
			return err
		}
		if err := domain.IfMatch(ifVersion, r.Version); err != nil {
			return err
		}
		if _, err := tx.Q.DeleteProvider(ctx, db.DeleteProviderParams{ID: id, Version: r.Version}); err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: ch.Actor, Action: "idp.provider_deleted", Target: audit.Target{Type: "identity_provider", ID: id},
			Details: map[string]any{"slug": r.Slug}})
		return err
	})
	if err == nil {
		svc.up.Forget(id)
	}
	return err
}

// Providers lists providers.
func (svc *Service) Providers(ctx context.Context) ([]Provider, error) {
	rows, err := svc.s.R().ListProviders(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Provider, 0, len(rows))
	for _, r := range rows {
		out = append(out, providerFromRow(r))
	}
	return out, nil
}

// Provider returns one provider by ID.
func (svc *Service) Provider(ctx context.Context, id string) (Provider, error) {
	r, err := svc.s.R().GetProvider(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return Provider{}, ErrProviderNotFound
	}
	if err != nil {
		return Provider{}, err
	}
	return providerFromRow(r), nil
}

// upstreamConfig unseals the secret for a provider row.
func (svc *Service) upstreamConfig(r db.IdentityProvider) (upstream.Config, error) {
	secret, err := svc.kr.Open(keyring.PurposeField, secretAAD(r.ID), r.SecretEnc)
	if err != nil {
		return upstream.Config{}, err
	}
	return upstream.Config{ID: r.ID, Kind: r.Kind, Issuer: r.Issuer, ClientID: r.ClientID, Secret: string(secret),
		Scopes: strings.Fields(r.Scopes), RedirectURL: strings.TrimSuffix(svc.opts.PublicURL, "/") + "/login/" + r.Slug + "/callback"}, nil
}

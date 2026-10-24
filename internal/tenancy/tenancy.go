// Package tenancy manages tenants and memberships and defines Scope, the only way to address tenant-scoped data
// (ADR-0004). A Scope can be obtained only through Resolve* after an access check, so repository code that accepts a
// Scope cannot be handed a tenant ID straight from request input.
package tenancy

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/aurimasniekis/go-porch/internal/apperr"
	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/domain"
	"github.com/aurimasniekis/go-porch/internal/ids"
	"github.com/aurimasniekis/go-porch/internal/outbox"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/store/db"
)

// Status values.
const (
	StatusActive    = "active"
	StatusDisabled  = "disabled"
	StatusSuspended = "suspended"
)

// Via records how a Scope was granted.
type Via string

// Scope grant paths.
const (
	ViaMembership Via = "membership" // the principal is an active member of the tenant
	ViaOperator   Via = "operator"   // an installation owner/admin acting on the tenant (audited)
	ViaDelegated  Via = "delegated"  // an active member holding the tenant permission the operation needs (ADR-0038)
	ViaSystem     Via = "system"     // Porch itself (jobs, enrollment)
)

// Scope is proof that the holder may address one tenant's data. The zero value is invalid.
type Scope struct {
	tenantID string
	slug     string
	via      Via
}

// TenantID returns the scoped tenant.
func (s Scope) TenantID() string { return s.tenantID }

// Slug returns the scoped tenant's slug.
func (s Scope) Slug() string { return s.slug }

// Via returns how the scope was granted.
func (s Scope) Via() Via { return s.via }

// Valid reports whether the scope was produced by a resolver.
func (s Scope) Valid() bool { return s.tenantID != "" && s.via != "" }

// Tenant is a family, friend group or homelab.
type Tenant struct {
	ID              string         `json:"id"`
	Slug            string         `json:"slug"`
	Name            string         `json:"name"`
	Status          string         `json:"status"`
	SessionIdle     *time.Duration `json:"session_idle,omitempty"`
	SessionAbsolute *time.Duration `json:"session_absolute,omitempty"`
	Version         int64          `json:"version"`
	ManagedBy       string         `json:"managed_by"`
	LastChangedBy   string         `json:"last_changed_by,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

func fromRow(r db.Tenant) Tenant {
	t := Tenant{ID: r.ID, Slug: r.Slug, Name: r.Name, Status: r.Status, Version: r.Version, ManagedBy: r.ManagedBy,
		LastChangedBy: r.LastChangedBy.String, CreatedAt: domain.FromMicros(r.CreatedAt), UpdatedAt: domain.FromMicros(r.UpdatedAt)}
	if r.SessionIdleSecs.Valid {
		d := time.Duration(r.SessionIdleSecs.Int64) * time.Second
		t.SessionIdle = &d
	}
	if r.SessionAbsoluteSecs.Valid {
		d := time.Duration(r.SessionAbsoluteSecs.Int64) * time.Second
		t.SessionAbsolute = &d
	}
	return t
}

// Service manages tenants and memberships.
type Service struct {
	s     *store.Store
	audit *audit.Writer
	// OnCreate runs inside the transaction that creates a tenant (built-in roles).
	OnCreate func(ctx context.Context, tx *store.Tx, tenantID string) error
}

// New returns a service.
func New(s *store.Store, a *audit.Writer) *Service { return &Service{s: s, audit: a} }

// Errors.
var (
	ErrNotFound       = apperr.New(apperr.CodeNotFound, "tenant not found")
	ErrMemberNotFound = apperr.New(apperr.CodeNotFound, "membership not found")
	// ErrNoAccess is deliberately indistinguishable from "not found" for callers without access.
	ErrNoAccess = apperr.New(apperr.CodeNotFound, "tenant not found")
)

func (svc *Service) lookup(ctx context.Context, q *db.Queries, ref string) (db.Tenant, error) {
	var r db.Tenant
	var err error
	if ids.Valid(ids.Tenant, ref) {
		r, err = q.GetTenant(ctx, ref)
	} else {
		r, err = q.GetTenantBySlug(ctx, ref)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	return r, err
}

// ResolveForMember returns a scope when userID is an active member of an active tenant ref (ID or slug).
func (svc *Service) ResolveForMember(ctx context.Context, userID, ref string) (Scope, error) {
	t, err := svc.lookup(ctx, svc.s.R(), ref)
	if err != nil {
		return Scope{}, ErrNoAccess
	}
	m, err := svc.s.R().GetMembershipByUser(ctx, db.GetMembershipByUserParams{TenantID: t.ID, UserID: userID})
	if err != nil || m.Status != StatusActive || t.Status != StatusActive {
		return Scope{}, ErrNoAccess
	}
	return Scope{tenantID: t.ID, slug: t.Slug, via: ViaMembership}, nil
}

// ResolveDelegated returns a scope for tenant administration by a member: userID must be an active member of the
// active tenant ref and allow (the caller's permission check, run with the resolved tenant ID) must succeed.
func (svc *Service) ResolveDelegated(ctx context.Context, userID, ref string, allow func(tenantID string) error) (Scope, error) {
	sc, err := svc.ResolveForMember(ctx, userID, ref)
	if err != nil {
		return Scope{}, err
	}
	if err := allow(sc.tenantID); err != nil {
		return Scope{}, err
	}
	sc.via = ViaDelegated
	return sc, nil
}

// ResolveForOperator returns a scope when userID holds installation role owner or admin. Operators can manage any
// tenant (including disabled ones) through explicit, audited operations.
func (svc *Service) ResolveForOperator(ctx context.Context, userID, ref string) (Scope, error) {
	n, err := svc.s.R().HasOperatorRole(ctx, db.HasOperatorRoleParams{UserID: userID, Roles: []string{"owner", "admin"}})
	if err != nil {
		return Scope{}, err
	}
	if n == 0 {
		return Scope{}, ErrNoAccess
	}
	t, err := svc.lookup(ctx, svc.s.R(), ref)
	if err != nil {
		return Scope{}, err
	}
	return Scope{tenantID: t.ID, slug: t.Slug, via: ViaOperator}, nil
}

// SystemScope is for Porch-internal work (enrollment, jobs) on a tenant ID that came from the database, never from
// request input.
func (svc *Service) SystemScope(ctx context.Context, tenantID string) (Scope, error) {
	t, err := svc.s.R().GetTenant(ctx, tenantID)
	if err != nil {
		return Scope{}, ErrNotFound
	}
	return Scope{tenantID: t.ID, slug: t.Slug, via: ViaSystem}, nil
}

// Get returns the scoped tenant.
func (svc *Service) Get(ctx context.Context, sc Scope) (Tenant, error) {
	if !sc.Valid() {
		return Tenant{}, ErrNoAccess
	}
	r, err := svc.s.R().GetTenant(ctx, sc.tenantID)
	if err != nil {
		return Tenant{}, ErrNotFound
	}
	return fromRow(r), nil
}

// CreateParams describes a new tenant.
type CreateParams struct {
	Slug string
	Name string
}

// Create adds a tenant. Only installation operators may call it (checked by the caller via RequireOperator).
func (svc *Service) Create(ctx context.Context, ch domain.Change, p CreateParams) (Tenant, error) {
	var v apperr.Validation
	if !domain.ValidSlug(p.Slug) || len(p.Slug) < 2 {
		v.Add("slug", "must be 2..63 lowercase letters, digits or inner hyphens")
	}
	name := domain.CleanName("name", p.Name, &v)
	if err := v.Err(); err != nil {
		return Tenant{}, err
	}
	var out Tenant
	err := svc.s.W().TxNamed(ctx, "tenancy.create", func(tx *store.Tx) error {
		id := ids.New(ids.Tenant)
		err := tx.Q.InsertTenant(ctx, db.InsertTenantParams{ID: id, Slug: p.Slug, Name: name, ManagedBy: ch.Managed(),
			LastChangedBy: domain.NullStr(ch.ChangedBy()), CreatedAt: tx.NowMicros(), UpdatedAt: tx.NowMicros()})
		if store.IsConstraint(err) {
			return apperr.New(apperr.CodeAlreadyExists, "tenant slug %q is taken", p.Slug)
		}
		if err != nil {
			return err
		}
		if svc.OnCreate != nil {
			if err := svc.OnCreate(ctx, tx, id); err != nil {
				return err
			}
		}
		if _, err := svc.audit.Append(ctx, tx, audit.Event{Actor: ch.Actor, TenantID: id, Action: "tenant.created",
			Target: audit.Target{Type: "tenant", ID: id}, Details: map[string]any{"slug": p.Slug, "managed_by": ch.Managed()}}); err != nil {
			return err
		}
		if _, err := outbox.Enqueue(ctx, tx, outbox.Event{Area: "tenancy", Entity: "tenant", Action: "created", TenantID: id,
			Payload: map[string]any{"slug": p.Slug}}); err != nil {
			return err
		}
		r, err := tx.Q.GetTenant(ctx, id)
		out = fromRow(r)
		return err
	})
	return out, err
}

// List returns tenants for operators.
func (svc *Service) List(ctx context.Context, page domain.Page) ([]Tenant, string, error) {
	rows, err := svc.s.R().ListTenants(ctx, db.ListTenantsParams{After: page.After, Lim: int64(page.Limit)})
	if err != nil {
		return nil, "", err
	}
	out := make([]Tenant, 0, len(rows))
	for _, r := range rows {
		out = append(out, fromRow(r))
	}
	last := ""
	if len(out) > 0 {
		last = out[len(out)-1].ID
	}
	return out, domain.NextCursor(len(out), page.Limit, last), nil
}

// UpdateParams changes tenant fields; nil fields are unchanged. A zero duration clears an override.
type UpdateParams struct {
	Name            *string
	Status          *string
	SessionIdle     *time.Duration
	SessionAbsolute *time.Duration
	IfVersion       int64
}

// Update modifies the scoped tenant.
func (svc *Service) Update(ctx context.Context, ch domain.Change, sc Scope, p UpdateParams) (Tenant, error) {
	if !sc.Valid() {
		return Tenant{}, ErrNoAccess
	}
	var out Tenant
	err := svc.s.W().TxNamed(ctx, "tenancy.update", func(tx *store.Tx) error {
		r, err := tx.Q.GetTenant(ctx, sc.tenantID)
		if err != nil {
			return ErrNotFound
		}
		if err := domain.IfMatch(p.IfVersion, r.Version); err != nil {
			return err
		}
		var v apperr.Validation
		name, status, idle, abs := r.Name, r.Status, r.SessionIdleSecs, r.SessionAbsoluteSecs
		if p.Name != nil {
			name = domain.CleanName("name", *p.Name, &v)
		}
		if p.Status != nil {
			status = *p.Status
			if status != StatusActive && status != StatusDisabled {
				v.Add("status", "must be active or disabled")
			}
		}
		if p.SessionIdle != nil {
			idle = secs(*p.SessionIdle, "session_idle", &v)
		}
		if p.SessionAbsolute != nil {
			abs = secs(*p.SessionAbsolute, "session_absolute", &v)
		}
		if idle.Valid && abs.Valid && idle.Int64 > abs.Int64 {
			v.Add("session_idle", "must not exceed session_absolute")
		}
		if err := v.Err(); err != nil {
			return err
		}
		n, err := tx.Q.UpdateTenant(ctx, db.UpdateTenantParams{Name: name, Status: status, SessionIdleSecs: idle, SessionAbsoluteSecs: abs,
			ManagedBy: ch.Managed(), LastChangedBy: domain.NullStr(ch.ChangedBy()), UpdatedAt: tx.NowMicros(), ID: r.ID, Version: r.Version})
		if err != nil {
			return err
		}
		if n != 1 {
			return apperr.New(apperr.CodePrecondition, "tenant was changed concurrently; reload and retry")
		}
		if _, err := svc.audit.Append(ctx, tx, audit.Event{Actor: ch.Actor, TenantID: r.ID, Action: "tenant.updated",
			Target: audit.Target{Type: "tenant", ID: r.ID}, Details: map[string]any{"status": status, "via": string(sc.via)}}); err != nil {
			return err
		}
		if _, err := outbox.Enqueue(ctx, tx, outbox.Event{Area: "tenancy", Entity: "tenant", Action: "updated", TenantID: r.ID,
			Payload: map[string]any{"status": status}}); err != nil {
			return err
		}
		nr, err := tx.Q.GetTenant(ctx, r.ID)
		out = fromRow(nr)
		return err
	})
	return out, err
}

func secs(d time.Duration, field string, v *apperr.Validation) sql.NullInt64 {
	if d == 0 {
		return sql.NullInt64{}
	}
	if d < time.Minute || d > 90*24*time.Hour {
		v.Add(field, "must be within 1m..90d (or 0 to use the installation default)")
	}
	return sql.NullInt64{Int64: int64(d / time.Second), Valid: true}
}

// Delete removes the scoped tenant and everything it owns.
func (svc *Service) Delete(ctx context.Context, ch domain.Change, sc Scope, ifVersion int64) error {
	if !sc.Valid() || sc.via == ViaMembership || sc.via == ViaDelegated {
		return apperr.New(apperr.CodeForbidden, "only installation operators can delete tenants")
	}
	return svc.s.W().TxNamed(ctx, "tenancy.delete", func(tx *store.Tx) error {
		r, err := tx.Q.GetTenant(ctx, sc.tenantID)
		if err != nil {
			return ErrNotFound
		}
		if err := domain.IfMatch(ifVersion, r.Version); err != nil {
			return err
		}
		if _, err := tx.Q.DeleteTenant(ctx, db.DeleteTenantParams{ID: r.ID, Version: r.Version}); err != nil {
			return err
		}
		if _, err := svc.audit.Append(ctx, tx, audit.Event{Actor: ch.Actor, TenantID: r.ID, Action: "tenant.deleted",
			Target: audit.Target{Type: "tenant", ID: r.ID}, Details: map[string]any{"slug": r.Slug}}); err != nil {
			return err
		}
		_, err = outbox.Enqueue(ctx, tx, outbox.Event{Area: "tenancy", Entity: "tenant", Action: "deleted", TenantID: r.ID,
			Payload: map[string]any{"slug": r.Slug}})
		return err
	})
}

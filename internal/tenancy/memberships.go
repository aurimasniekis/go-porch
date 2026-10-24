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

// Membership sources (ADR-0006). Derived memberships are removed when their evidence disappears; manual ones stay.
const (
	SourceManual    = "manual"
	SourceTerraform = "terraform"
	SourceSetup     = "setup"
)

// Membership links a user to a tenant.
type Membership struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	UserID        string    `json:"user_id"`
	Status        string    `json:"status"`
	Source        string    `json:"source"`
	DisplayName   string    `json:"display_name,omitempty"`
	Email         string    `json:"email,omitempty"`
	Version       int64     `json:"version"`
	ManagedBy     string    `json:"managed_by"`
	LastChangedBy string    `json:"last_changed_by,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func memberFromRow(r db.Membership) Membership {
	return Membership{ID: r.ID, TenantID: r.TenantID, UserID: r.UserID, Status: r.Status, Source: r.Source, Version: r.Version,
		ManagedBy: r.ManagedBy, LastChangedBy: r.LastChangedBy.String, CreatedAt: domain.FromMicros(r.CreatedAt),
		UpdatedAt: domain.FromMicros(r.UpdatedAt)}
}

// AddMemberTx adds userID to the scoped tenant inside tx.
func (svc *Service) AddMemberTx(ctx context.Context, tx *store.Tx, ch domain.Change, sc Scope, userID, source string) (Membership, error) {
	if !sc.Valid() {
		return Membership{}, ErrNoAccess
	}
	if source == "" {
		source = SourceManual
	}
	if _, err := tx.Q.GetUser(ctx, userID); errors.Is(err, sql.ErrNoRows) {
		return Membership{}, apperr.New(apperr.CodeInvalid, "user not found")
	} else if err != nil {
		return Membership{}, err
	}
	id := ids.New(ids.Membership)
	err := tx.Q.InsertMembership(ctx, db.InsertMembershipParams{ID: id, TenantID: sc.tenantID, UserID: userID, Status: StatusActive,
		Source: source, ManagedBy: ch.Managed(), LastChangedBy: domain.NullStr(ch.ChangedBy()), CreatedAt: tx.NowMicros(), UpdatedAt: tx.NowMicros()})
	if store.IsConstraint(err) {
		return Membership{}, apperr.New(apperr.CodeAlreadyExists, "user is already a member of this tenant")
	}
	if err != nil {
		return Membership{}, err
	}
	if _, err := svc.audit.Append(ctx, tx, audit.Event{Actor: ch.Actor, TenantID: sc.tenantID, Action: "membership.created",
		Target: audit.Target{Type: "user", ID: userID}, Details: map[string]any{"source": source, "via": string(sc.via)}}); err != nil {
		return Membership{}, err
	}
	if _, err := outbox.Enqueue(ctx, tx, outbox.Event{Area: "tenancy", Entity: "membership", Action: "created", TenantID: sc.tenantID,
		Payload: map[string]any{"user_id": userID, "source": source}}); err != nil {
		return Membership{}, err
	}
	r, err := tx.Q.GetMembership(ctx, db.GetMembershipParams{TenantID: sc.tenantID, ID: id})
	return memberFromRow(r), err
}

// AddMember adds userID to the scoped tenant.
func (svc *Service) AddMember(ctx context.Context, ch domain.Change, sc Scope, userID, source string) (Membership, error) {
	var m Membership
	err := svc.s.W().TxNamed(ctx, "tenancy.add_member", func(tx *store.Tx) error {
		var err error
		m, err = svc.AddMemberTx(ctx, tx, ch, sc, userID, source)
		return err
	})
	return m, err
}

// ListMembers returns one page of the scoped tenant's members.
func (svc *Service) ListMembers(ctx context.Context, sc Scope, page domain.Page) ([]Membership, string, error) {
	if !sc.Valid() {
		return nil, "", ErrNoAccess
	}
	rows, err := svc.s.R().ListMembers(ctx, db.ListMembersParams{TenantID: sc.tenantID, After: page.After, Lim: int64(page.Limit)})
	if err != nil {
		return nil, "", err
	}
	out := make([]Membership, 0, len(rows))
	for _, r := range rows {
		out = append(out, Membership{ID: r.ID, TenantID: r.TenantID, UserID: r.UserID, Status: r.Status, Source: r.Source,
			DisplayName: r.DisplayName, Email: r.PrimaryEmail.String, Version: r.Version, ManagedBy: r.ManagedBy,
			LastChangedBy: r.LastChangedBy.String, CreatedAt: domain.FromMicros(r.CreatedAt), UpdatedAt: domain.FromMicros(r.UpdatedAt)})
	}
	last := ""
	if len(out) > 0 {
		last = out[len(out)-1].ID
	}
	return out, domain.NextCursor(len(out), page.Limit, last), nil
}

// SetMemberStatus suspends or reactivates a membership.
func (svc *Service) SetMemberStatus(ctx context.Context, ch domain.Change, sc Scope, membershipID, status string, ifVersion int64) (Membership, error) {
	if !sc.Valid() {
		return Membership{}, ErrNoAccess
	}
	if status != StatusActive && status != StatusSuspended {
		return Membership{}, apperr.New(apperr.CodeInvalid, "status must be active or suspended")
	}
	var out Membership
	err := svc.s.W().TxNamed(ctx, "tenancy.member_status", func(tx *store.Tx) error {
		r, err := tx.Q.GetMembership(ctx, db.GetMembershipParams{TenantID: sc.tenantID, ID: membershipID})
		if errors.Is(err, sql.ErrNoRows) {
			return ErrMemberNotFound
		}
		if err != nil {
			return err
		}
		if err := domain.IfMatch(ifVersion, r.Version); err != nil {
			return err
		}
		if _, err := tx.Q.UpdateMembershipStatus(ctx, db.UpdateMembershipStatusParams{Status: status, ManagedBy: ch.Managed(),
			LastChangedBy: domain.NullStr(ch.ChangedBy()), UpdatedAt: tx.NowMicros(), TenantID: sc.tenantID, ID: r.ID, Version: r.Version}); err != nil {
			return err
		}
		if _, err := svc.audit.Append(ctx, tx, audit.Event{Actor: ch.Actor, TenantID: sc.tenantID, Action: "membership.status_changed",
			Target: audit.Target{Type: "user", ID: r.UserID}, Details: map[string]any{"status": status}}); err != nil {
			return err
		}
		if _, err := outbox.Enqueue(ctx, tx, outbox.Event{Area: "tenancy", Entity: "membership", Action: "updated", TenantID: sc.tenantID,
			Payload: map[string]any{"user_id": r.UserID, "status": status}}); err != nil {
			return err
		}
		nr, err := tx.Q.GetMembership(ctx, db.GetMembershipParams{TenantID: sc.tenantID, ID: r.ID})
		out = memberFromRow(nr)
		return err
	})
	return out, err
}

// RemoveMember deletes a membership (and, through the composite foreign key, the user's group memberships in it).
func (svc *Service) RemoveMember(ctx context.Context, ch domain.Change, sc Scope, membershipID string, ifVersion int64) error {
	if !sc.Valid() {
		return ErrNoAccess
	}
	return svc.s.W().TxNamed(ctx, "tenancy.remove_member", func(tx *store.Tx) error {
		r, err := tx.Q.GetMembership(ctx, db.GetMembershipParams{TenantID: sc.tenantID, ID: membershipID})
		if errors.Is(err, sql.ErrNoRows) {
			return ErrMemberNotFound
		}
		if err != nil {
			return err
		}
		if err := domain.IfMatch(ifVersion, r.Version); err != nil {
			return err
		}
		if _, err := tx.Q.DeleteMembership(ctx, db.DeleteMembershipParams{TenantID: sc.tenantID, ID: r.ID, Version: r.Version}); err != nil {
			return err
		}
		if _, err := svc.audit.Append(ctx, tx, audit.Event{Actor: ch.Actor, TenantID: sc.tenantID, Action: "membership.deleted",
			Target: audit.Target{Type: "user", ID: r.UserID}, Details: map[string]any{"source": r.Source}}); err != nil {
			return err
		}
		_, err = outbox.Enqueue(ctx, tx, outbox.Event{Area: "tenancy", Entity: "membership", Action: "deleted", TenantID: sc.tenantID,
			Payload: map[string]any{"user_id": r.UserID}})
		return err
	})
}

// GetMember returns one membership by membership ID or user ID, with the user's name and email.
func (svc *Service) GetMember(ctx context.Context, sc Scope, ref string) (Membership, error) {
	if !sc.Valid() {
		return Membership{}, ErrNoAccess
	}
	r, err := svc.s.R().GetMembership(ctx, db.GetMembershipParams{TenantID: sc.tenantID, ID: ref})
	if errors.Is(err, sql.ErrNoRows) {
		r, err = svc.s.R().GetMembershipByUser(ctx, db.GetMembershipByUserParams{TenantID: sc.tenantID, UserID: ref})
	}
	if errors.Is(err, sql.ErrNoRows) {
		return Membership{}, ErrMemberNotFound
	}
	if err != nil {
		return Membership{}, err
	}
	m := memberFromRow(r)
	if u, err := svc.s.R().GetUser(ctx, r.UserID); err == nil {
		m.DisplayName, m.Email = u.DisplayName, u.PrimaryEmail.String
	}
	return m, nil
}

// UserMemberships lists the tenants a user belongs to (any status).
func (svc *Service) UserMemberships(ctx context.Context, userID string) ([]db.ListUserMembershipsRow, error) {
	return svc.s.R().ListUserMemberships(ctx, userID)
}

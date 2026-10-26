// Package identity manages installation-wide users, their email attributes and installation (operator) roles.
// Email addresses are attributes, never identity: login identities are (issuer, subject) pairs (ADR-0005).
package identity

import (
	"context"
	"database/sql"
	"errors"
	"net/mail"
	"slices"
	"strings"
	"time"

	"github.com/aurimasniekis/go-porch/internal/apperr"
	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/domain"
	"github.com/aurimasniekis/go-porch/internal/ids"
	"github.com/aurimasniekis/go-porch/internal/outbox"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/store/db"
)

// Installation roles (ADR-0004). They never confer tenant roles. An inspector reads the configuration inside every
// tenant and changes nothing (ADR-0048).
const (
	RoleOwner     = "owner"
	RoleAdmin     = "admin"
	RoleAuditor   = "auditor"
	RoleInspector = "inspector"
)

// Status values.
const (
	StatusActive   = "active"
	StatusDisabled = "disabled"
)

// User is an installation-wide person.
type User struct {
	ID            string     `json:"id"`
	PublicID      string     `json:"public_id"`
	DisplayName   string     `json:"display_name"`
	PrimaryEmail  string     `json:"primary_email,omitempty"`
	Status        string     `json:"status"`
	BackupHandle  string     `json:"backup_handle,omitempty"`
	SecurityEpoch int64      `json:"-"`
	LastLoginAt   *time.Time `json:"last_login_at,omitempty"`
	Version       int64      `json:"version"`
	ManagedBy     string     `json:"managed_by"`
	LastChangedBy string     `json:"last_changed_by,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// Service manages users.
type Service struct {
	s     *store.Store
	audit *audit.Writer
}

// New returns a service.
func New(s *store.Store, a *audit.Writer) *Service { return &Service{s: s, audit: a} }

// FromRow converts a database row.
func FromRow(r db.User) User {
	return User{ID: r.ID, PublicID: r.PublicID, DisplayName: r.DisplayName, PrimaryEmail: r.PrimaryEmail.String, Status: r.Status,
		BackupHandle: r.BackupHandle.String, SecurityEpoch: r.SecurityEpoch, LastLoginAt: domain.OptMicros(r.LastLoginAt),
		Version: r.Version, ManagedBy: r.ManagedBy, LastChangedBy: r.LastChangedBy.String, CreatedAt: domain.FromMicros(r.CreatedAt),
		UpdatedAt: domain.FromMicros(r.UpdatedAt)}
}

// NormalizeEmail lowercases and validates an email address ("" stays "").
func NormalizeEmail(field, e string, v *apperr.Validation) string {
	e = strings.ToLower(strings.TrimSpace(e))
	if e == "" {
		return ""
	}
	a, err := mail.ParseAddress(e)
	if err != nil || a.Address != e || len(e) > 254 || !strings.Contains(e[strings.LastIndexByte(e, '@')+1:], ".") {
		v.Add(field, "must be a plain email address")
	}
	return e
}

// CreateParams describes a new user.
type CreateParams struct {
	DisplayName  string
	PrimaryEmail string
	// EmailVerified records whether the email was verified by an upstream provider (attribute only).
	EmailVerified bool
	EmailSource   string
}

// CreateTx inserts a user inside an existing transaction (used by enrollment and setup).
func (svc *Service) CreateTx(ctx context.Context, tx *store.Tx, ch domain.Change, p CreateParams) (User, error) {
	var v apperr.Validation
	name := domain.CleanName("display_name", p.DisplayName, &v)
	email := NormalizeEmail("primary_email", p.PrimaryEmail, &v)
	if err := v.Err(); err != nil {
		return User{}, err
	}
	id := ids.New(ids.User)
	row := db.InsertUserParams{ID: id, PublicID: ids.New(ids.UserPublic), DisplayName: name, PrimaryEmail: domain.NullStr(email),
		ManagedBy: ch.Managed(), LastChangedBy: domain.NullStr(ch.ChangedBy()), CreatedAt: tx.NowMicros(), UpdatedAt: tx.NowMicros()}
	if err := tx.Q.InsertUser(ctx, row); err != nil {
		return User{}, err
	}
	if email != "" {
		src := p.EmailSource
		if src == "" {
			src = "manual"
		}
		if err := tx.Q.UpsertUserEmail(ctx, db.UpsertUserEmailParams{ID: ids.New(ids.UserEmail), UserID: id, Email: email,
			Verified: boolInt(p.EmailVerified), Source: src, CreatedAt: tx.NowMicros()}); err != nil {
			return User{}, err
		}
	}
	if _, err := svc.audit.Append(ctx, tx, audit.Event{Actor: ch.Actor, Action: "user.created", Target: audit.Target{Type: "user", ID: id},
		Details: map[string]any{"managed_by": ch.Managed()}}); err != nil {
		return User{}, err
	}
	if _, err := outbox.Enqueue(ctx, tx, outbox.Event{Area: "identity", Entity: "user", Action: "created",
		Payload: map[string]any{"user_id": id}}); err != nil {
		return User{}, err
	}
	r, err := tx.Q.GetUser(ctx, id)
	if err != nil {
		return User{}, err
	}
	return FromRow(r), nil
}

// Create inserts a user in its own transaction.
func (svc *Service) Create(ctx context.Context, ch domain.Change, p CreateParams) (User, error) {
	var u User
	err := svc.s.W().TxNamed(ctx, "identity.create_user", func(tx *store.Tx) error {
		var err error
		u, err = svc.CreateTx(ctx, tx, ch, p)
		return err
	})
	return u, err
}

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// ErrNotFound is returned for unknown users.
var ErrNotFound = apperr.New(apperr.CodeNotFound, "user not found")

// Get returns a user by internal ID.
func (svc *Service) Get(ctx context.Context, id string) (User, error) {
	r, err := svc.s.R().GetUser(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	return FromRow(r), nil
}

// ListFilter narrows List.
type ListFilter struct {
	Email  string
	Status string
	// Query matches a case-insensitive substring of the display name or primary email.
	Query string
}

// List returns one page of users ordered by ID.
func (svc *Service) List(ctx context.Context, page domain.Page, f ListFilter) ([]User, string, error) {
	p := db.ListUsersParams{After: page.After, Lim: int64(page.Limit)}
	if f.Email != "" {
		p.Email = strings.ToLower(f.Email)
	}
	if f.Status != "" {
		p.Status = f.Status
	}
	if q := strings.ToLower(strings.TrimSpace(f.Query)); q != "" {
		p.Q = q
	}
	rows, err := svc.s.R().ListUsers(ctx, p)
	if err != nil {
		return nil, "", err
	}
	out := make([]User, 0, len(rows))
	for _, r := range rows {
		out = append(out, FromRow(r))
	}
	last := ""
	if len(out) > 0 {
		last = out[len(out)-1].ID
	}
	return out, domain.NextCursor(len(out), page.Limit, last), nil
}

// UpdateParams changes mutable user fields; nil fields are left unchanged.
type UpdateParams struct {
	DisplayName  *string
	PrimaryEmail *string
	Status       *string
	// IfVersion is the expected version (0 = unconditional).
	IfVersion int64
}

// Update modifies a user. Disabling a user revokes every session and bumps their security epoch.
func (svc *Service) Update(ctx context.Context, ch domain.Change, id string, p UpdateParams) (User, error) {
	var out User
	err := svc.s.W().TxNamed(ctx, "identity.update_user", func(tx *store.Tx) error {
		r, err := tx.Q.GetUser(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if err := domain.IfMatch(p.IfVersion, r.Version); err != nil {
			return err
		}
		var v apperr.Validation
		name, email, status := r.DisplayName, r.PrimaryEmail.String, r.Status
		if p.DisplayName != nil {
			name = domain.CleanName("display_name", *p.DisplayName, &v)
		}
		if p.PrimaryEmail != nil {
			email = NormalizeEmail("primary_email", *p.PrimaryEmail, &v)
		}
		if p.Status != nil {
			status = *p.Status
			if status != StatusActive && status != StatusDisabled {
				v.Add("status", "must be active or disabled")
			}
		}
		if err := v.Err(); err != nil {
			return err
		}
		n, err := tx.Q.UpdateUser(ctx, db.UpdateUserParams{DisplayName: name, PrimaryEmail: domain.NullStr(email), Status: status,
			ManagedBy: ch.Managed(), LastChangedBy: domain.NullStr(ch.ChangedBy()), UpdatedAt: tx.NowMicros(), ID: id, Version: r.Version})
		if err != nil {
			return err
		}
		if n != 1 {
			return apperr.New(apperr.CodePrecondition, "user was changed concurrently; reload and retry")
		}
		changed := []string{}
		if name != r.DisplayName {
			changed = append(changed, "display_name")
		}
		if email != r.PrimaryEmail.String {
			changed = append(changed, "primary_email")
		}
		if status != r.Status {
			changed = append(changed, "status")
			if status == StatusDisabled {
				if err := revokeAll(ctx, tx, id, "user_disabled"); err != nil {
					return err
				}
			}
		}
		if _, err := svc.audit.Append(ctx, tx, audit.Event{Actor: ch.Actor, Action: "user.updated", Target: audit.Target{Type: "user", ID: id},
			Details: map[string]any{"fields": changed, "status": status}}); err != nil {
			return err
		}
		if _, err := outbox.Enqueue(ctx, tx, outbox.Event{Area: "identity", Entity: "user", Action: "updated",
			Payload: map[string]any{"user_id": id, "fields": changed, "status": status}}); err != nil {
			return err
		}
		nr, err := tx.Q.GetUser(ctx, id)
		out = FromRow(nr)
		return err
	})
	return out, err
}

func revokeAll(ctx context.Context, tx *store.Tx, userID, reason string) error {
	if err := tx.Q.BumpUserEpoch(ctx, db.BumpUserEpochParams{UpdatedAt: tx.NowMicros(), ID: userID}); err != nil {
		return err
	}
	_, err := tx.Q.RevokeUserSessions(ctx, db.RevokeUserSessionsParams{RevokedAt: domain.NullMicros(&tx.Now),
		RevokeReason: domain.NullStr(reason), UserID: userID})
	return err
}

// Delete removes a user (cascading memberships, sessions and identities). The last installation owner cannot be deleted.
func (svc *Service) Delete(ctx context.Context, ch domain.Change, id string, ifVersion int64) error {
	return svc.s.W().TxNamed(ctx, "identity.delete_user", func(tx *store.Tx) error {
		r, err := tx.Q.GetUser(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if err := domain.IfMatch(ifVersion, r.Version); err != nil {
			return err
		}
		roles, err := tx.Q.ListOperatorRoles(ctx, id)
		if err != nil {
			return err
		}
		if slices.Contains(roles, RoleOwner) {
			owners, err := tx.Q.CountOwners(ctx)
			if err != nil {
				return err
			}
			if owners <= 1 {
				return apperr.New(apperr.CodeConflict, "cannot delete the last installation owner")
			}
		}
		if _, err := tx.Q.DeleteUser(ctx, db.DeleteUserParams{ID: id, Version: r.Version}); err != nil {
			return err
		}
		if _, err := svc.audit.Append(ctx, tx, audit.Event{Actor: ch.Actor, Action: "user.deleted", Target: audit.Target{Type: "user", ID: id}}); err != nil {
			return err
		}
		_, err = outbox.Enqueue(ctx, tx, outbox.Event{Area: "identity", Entity: "user", Action: "deleted", Payload: map[string]any{"user_id": id}})
		return err
	})
}

// RevokeOperatorRoleTx removes an installation role inside tx. The last owner cannot be removed.
func (svc *Service) RevokeOperatorRoleTx(ctx context.Context, tx *store.Tx, ch domain.Change, userID, role string) error {
	n, err := tx.Q.DeleteOperatorRole(ctx, db.DeleteOperatorRoleParams{UserID: userID, Role: role})
	if err != nil {
		return err
	}
	if n == 0 {
		return apperr.New(apperr.CodeNotFound, "the user does not have installation role %s", role)
	}
	if role == RoleOwner {
		owners, err := tx.Q.CountOwners(ctx)
		if err != nil {
			return err
		}
		if owners == 0 {
			return apperr.New(apperr.CodeConflict, "the installation must keep at least one owner")
		}
	}
	_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: ch.Actor, Action: "installation.role_revoked",
		Target: audit.Target{Type: "user", ID: userID}, Details: map[string]any{"role": role}})
	return err
}

// OperatorRoles returns the installation roles of a user.
func (svc *Service) OperatorRoles(ctx context.Context, userID string) ([]string, error) {
	return svc.s.R().ListOperatorRoles(ctx, userID)
}

// GrantOperatorRoleTx assigns an installation role inside tx.
func (svc *Service) GrantOperatorRoleTx(ctx context.Context, tx *store.Tx, ch domain.Change, userID, role, source string) error {
	if role != RoleOwner && role != RoleAdmin && role != RoleAuditor && role != RoleInspector {
		return apperr.New(apperr.CodeInvalid, "unknown installation role %q", role)
	}
	err := tx.Q.InsertOperatorRole(ctx, db.InsertOperatorRoleParams{ID: ids.New(ids.OperatorRole), UserID: userID, Role: role, Source: source,
		CreatedAt: tx.NowMicros(), CreatedBy: domain.NullStr(ch.ChangedBy())})
	if store.IsConstraint(err) {
		return apperr.New(apperr.CodeAlreadyExists, "user already has installation role %s", role)
	}
	if err != nil {
		return err
	}
	_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: ch.Actor, Action: "installation.role_granted",
		Target: audit.Target{Type: "user", ID: userID}, Details: map[string]any{"role": role, "source": source}})
	return err
}

package idp

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/aurimasniekis/go-porch/internal/apperr"
	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/domain"
	"github.com/aurimasniekis/go-porch/internal/identity"
	"github.com/aurimasniekis/go-porch/internal/ids"
	"github.com/aurimasniekis/go-porch/internal/outbox"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/store/db"
	"github.com/aurimasniekis/go-porch/internal/tenancy"
)

// Evidence kinds and enrollment modes (ADR-0006).
const (
	EvidenceWorkspaceHD   = "workspace_hd"
	EvidenceVerifiedEmail = "verified_email"
	ModeInviteOnly        = "invite_only"
	ModeJIT               = "jit"
)

// DomainRule maps a domain to a tenant.
type DomainRule struct {
	ID            string    `json:"id"`
	Domain        string    `json:"domain"`
	TenantID      string    `json:"tenant_id"`
	ProviderID    string    `json:"provider_id"`
	EvidenceKind  string    `json:"evidence_kind"`
	Mode          string    `json:"mode"`
	Version       int64     `json:"version"`
	ManagedBy     string    `json:"managed_by"`
	LastChangedBy string    `json:"last_changed_by,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func ruleFromRow(r db.DomainRule) DomainRule {
	return DomainRule{ID: r.ID, Domain: r.Domain, TenantID: r.TenantID, ProviderID: r.ProviderID, EvidenceKind: r.EvidenceKind, Mode: r.Mode,
		Version: r.Version, ManagedBy: r.ManagedBy, LastChangedBy: r.LastChangedBy.String, CreatedAt: domain.FromMicros(r.CreatedAt),
		UpdatedAt: domain.FromMicros(r.UpdatedAt)}
}

// RuleSource is the membership source recorded for rule-derived memberships.
func RuleSource(ruleID string) string { return "domain_rule:" + ruleID }

// ErrRuleNotFound is returned for unknown rules.
var ErrRuleNotFound = apperr.New(apperr.CodeNotFound, "domain rule not found")

// RuleParams create a rule.
type RuleParams struct {
	Domain       string
	ProviderID   string
	EvidenceKind string
	Mode         string
}

// CreateRule adds a domain rule for the scoped tenant. A domain can belong to only one tenant installation-wide.
func (svc *Service) CreateRule(ctx context.Context, ch domain.Change, sc tenancy.Scope, p RuleParams) (DomainRule, error) {
	if !sc.Valid() {
		return DomainRule{}, tenancy.ErrNoAccess
	}
	var v apperr.Validation
	p.Domain = strings.ToLower(strings.TrimSpace(p.Domain))
	if !validDomain(p.Domain) {
		v.Add("domain", "must be a domain name")
	}
	if p.EvidenceKind != EvidenceWorkspaceHD && p.EvidenceKind != EvidenceVerifiedEmail {
		v.Add("evidence_kind", "must be workspace_hd or verified_email")
	}
	if p.Mode != ModeInviteOnly && p.Mode != ModeJIT {
		v.Add("mode", "must be invite_only or jit")
	}
	if err := v.Err(); err != nil {
		return DomainRule{}, err
	}
	var out DomainRule
	err := svc.s.W().TxNamed(ctx, "idp.create_rule", func(tx *store.Tx) error {
		prov, err := tx.Q.GetProvider(ctx, p.ProviderID)
		if errors.Is(err, sql.ErrNoRows) {
			return apperr.New(apperr.CodeInvalid, "provider_id: unknown provider")
		}
		if err != nil {
			return err
		}
		if p.EvidenceKind == EvidenceWorkspaceHD && prov.Kind != KindGoogle {
			return apperr.New(apperr.CodeInvalid, "workspace_hd evidence requires a google provider")
		}
		id := ids.New(ids.DomainRule)
		err = tx.Q.InsertDomainRule(ctx, db.InsertDomainRuleParams{ID: id, Domain: p.Domain, TenantID: sc.TenantID(), ProviderID: p.ProviderID,
			EvidenceKind: p.EvidenceKind, Mode: p.Mode, BaselineRoleIds: "[]", ManagedBy: ch.Managed(), LastChangedBy: domain.NullStr(ch.ChangedBy()),
			CreatedAt: tx.NowMicros(), UpdatedAt: tx.NowMicros()})
		if store.IsConstraint(err) {
			return apperr.New(apperr.CodeAlreadyExists, "domain %s already has a rule", p.Domain)
		}
		if err != nil {
			return err
		}
		if _, err := svc.audit.Append(ctx, tx, audit.Event{Actor: ch.Actor, TenantID: sc.TenantID(), Action: "idp.domain_rule_created",
			Target: audit.Target{Type: "domain_rule", ID: id}, Details: map[string]any{"domain": p.Domain, "evidence_kind": p.EvidenceKind, "mode": p.Mode,
				"provider_id": p.ProviderID}}); err != nil {
			return err
		}
		if _, err := outbox.Enqueue(ctx, tx, outbox.Event{Area: "idp", Entity: "domain_rule", Action: "created", TenantID: sc.TenantID(),
			Payload: map[string]any{"rule_id": id, "domain": p.Domain}}); err != nil {
			return err
		}
		r, err := tx.Q.GetDomainRule(ctx, id)
		out = ruleFromRow(r)
		return err
	})
	return out, err
}

// Rules lists rules of the scoped tenant.
func (svc *Service) Rules(ctx context.Context, sc tenancy.Scope) ([]DomainRule, error) {
	if !sc.Valid() {
		return nil, tenancy.ErrNoAccess
	}
	rows, err := svc.s.R().ListDomainRules(ctx)
	if err != nil {
		return nil, err
	}
	out := []DomainRule{}
	for _, r := range rows {
		if r.TenantID == sc.TenantID() {
			out = append(out, ruleFromRow(r))
		}
	}
	return out, nil
}

// DeleteRule removes a rule and, in the same transaction, every membership derived from it (manual ones stay).
func (svc *Service) DeleteRule(ctx context.Context, ch domain.Change, sc tenancy.Scope, id string, ifVersion int64) error {
	if !sc.Valid() {
		return tenancy.ErrNoAccess
	}
	return svc.s.W().TxNamed(ctx, "idp.delete_rule", func(tx *store.Tx) error {
		r, err := tx.Q.GetDomainRule(ctx, id)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && r.TenantID != sc.TenantID()) {
			return ErrRuleNotFound
		}
		if err != nil {
			return err
		}
		if err := domain.IfMatch(ifVersion, r.Version); err != nil {
			return err
		}
		ms, err := tx.Q.ListMembershipsBySource(ctx, RuleSource(id))
		if err != nil {
			return err
		}
		for _, m := range ms {
			if _, err := tx.Q.DeleteMembershipByID(ctx, m.ID); err != nil {
				return err
			}
			if _, err := svc.audit.Append(ctx, tx, audit.Event{Actor: ch.Actor, TenantID: m.TenantID, Action: "membership.deleted",
				Target: audit.Target{Type: "user", ID: m.UserID}, ReasonCode: "domain_rule_deleted", Details: map[string]any{"source": m.Source}}); err != nil {
				return err
			}
		}
		if _, err := tx.Q.DeleteDomainRule(ctx, db.DeleteDomainRuleParams{ID: id, Version: r.Version}); err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: ch.Actor, TenantID: r.TenantID, Action: "idp.domain_rule_deleted",
			Target: audit.Target{Type: "domain_rule", ID: id}, Details: map[string]any{"domain": r.Domain, "memberships_removed": len(ms)}})
		return err
	})
}

// Invite is a pending invitation by email.
type Invite struct {
	ID         string     `json:"id"`
	TenantID   string     `json:"tenant_id"`
	Email      string     `json:"email"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	ConsumedAt *time.Time `json:"consumed_at,omitempty"`
}

// CreateInvite invites email to the scoped tenant. Accepting requires a verified upstream email that matches.
func (svc *Service) CreateInvite(ctx context.Context, ch domain.Change, sc tenancy.Scope, email string, ttl time.Duration) (Invite, error) {
	if !sc.Valid() {
		return Invite{}, tenancy.ErrNoAccess
	}
	var v apperr.Validation
	email = identity.NormalizeEmail("email", email, &v)
	if email == "" {
		v.Add("email", "is required")
	}
	if ttl <= 0 || ttl > 30*24*time.Hour {
		ttl = 7 * 24 * time.Hour
	}
	if err := v.Err(); err != nil {
		return Invite{}, err
	}
	var out Invite
	err := svc.s.W().TxNamed(ctx, "idp.create_invite", func(tx *store.Tx) error {
		id := ids.New(ids.Invite)
		exp := tx.Now.Add(ttl)
		if err := tx.Q.InsertInvite(ctx, db.InsertInviteParams{ID: id, TenantID: sc.TenantID(), Email: email, CreatedBy: domain.NullStr(ch.ChangedBy()),
			CreatedAt: tx.NowMicros(), ExpiresAt: exp.UnixMicro()}); err != nil {
			return err
		}
		out = Invite{ID: id, TenantID: sc.TenantID(), Email: email, CreatedAt: tx.Now, ExpiresAt: exp}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: ch.Actor, TenantID: sc.TenantID(), Action: "invite.created",
			Target: audit.Target{Type: "invite", ID: id}, Details: map[string]any{"email": email}})
		return err
	})
	return out, err
}

// Invites lists the scoped tenant's invites.
func (svc *Service) Invites(ctx context.Context, sc tenancy.Scope) ([]Invite, error) {
	if !sc.Valid() {
		return nil, tenancy.ErrNoAccess
	}
	rows, err := svc.s.R().ListInvites(ctx, sc.TenantID())
	if err != nil {
		return nil, err
	}
	out := make([]Invite, 0, len(rows))
	for _, r := range rows {
		out = append(out, Invite{ID: r.ID, TenantID: r.TenantID, Email: r.Email, CreatedAt: domain.FromMicros(r.CreatedAt),
			ExpiresAt: domain.FromMicros(r.ExpiresAt), ConsumedAt: domain.OptMicros(r.ConsumedAt)})
	}
	return out, nil
}

// DeleteInvite revokes an invite.
func (svc *Service) DeleteInvite(ctx context.Context, ch domain.Change, sc tenancy.Scope, id string) error {
	if !sc.Valid() {
		return tenancy.ErrNoAccess
	}
	return svc.s.W().TxNamed(ctx, "idp.delete_invite", func(tx *store.Tx) error {
		n, err := tx.Q.DeleteInvite(ctx, db.DeleteInviteParams{TenantID: sc.TenantID(), ID: id})
		if err != nil {
			return err
		}
		if n == 0 {
			return apperr.New(apperr.CodeNotFound, "invite not found")
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: ch.Actor, TenantID: sc.TenantID(), Action: "invite.deleted", Target: audit.Target{Type: "invite", ID: id}})
		return err
	})
}

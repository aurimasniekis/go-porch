package idp

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/domain"
	"github.com/aurimasniekis/go-porch/internal/identity"
	"github.com/aurimasniekis/go-porch/internal/idp/upstream"
	"github.com/aurimasniekis/go-porch/internal/ids"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/store/db"
)

// emailDomain returns the domain of a verified email ("" when unverified or malformed).
func emailDomain(c upstream.Claims) string {
	if !c.EmailVerified {
		return ""
	}
	i := strings.LastIndexByte(c.Email, '@')
	if i <= 0 {
		return ""
	}
	return c.Email[i+1:]
}

// evidence reports whether the verified claims satisfy rule r for provider prov.
func evidence(r db.DomainRule, prov db.IdentityProvider, c upstream.Claims) bool {
	if r.ProviderID != prov.ID {
		return false
	}
	switch r.EvidenceKind {
	case EvidenceWorkspaceHD:
		// Only the hd claim of a verified Google ID token counts; never the email suffix or the hd= request hint.
		return prov.Kind == KindGoogle && c.HD != "" && c.HD == r.Domain
	case EvidenceVerifiedEmail:
		return emailDomain(c) == r.Domain
	}
	return false
}

// identityOwner returns the user linked to (provider, issuer, subject), or ErrNotEnrolled.
func (svc *Service) identityOwner(ctx context.Context, tx *store.Tx, prov db.IdentityProvider, c upstream.Claims) (string, error) {
	x, err := tx.Q.GetExternalIdentity(ctx, db.GetExternalIdentityParams{ProviderID: prov.ID, Issuer: c.Issuer, Subject: c.Subject})
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotEnrolled
	}
	if err != nil {
		return "", err
	}
	if err := tx.Q.TouchExternalIdentity(ctx, db.TouchExternalIdentityParams{Email: domain.NullStr(c.Email), Hd: domain.NullStr(c.HD),
		LastLoginAt: domain.NullMicros(&tx.Now), ID: x.ID}); err != nil {
		return "", err
	}
	return x.UserID, nil
}

func (svc *Service) linkTx(ctx context.Context, tx *store.Tx, prov db.IdentityProvider, c upstream.Claims, userID string) error {
	err := tx.Q.InsertExternalIdentity(ctx, db.InsertExternalIdentityParams{ID: ids.New(ids.ExternalID), ProviderID: prov.ID, Issuer: c.Issuer,
		Subject: c.Subject, UserID: userID, Email: domain.NullStr(c.Email), Hd: domain.NullStr(c.HD), LinkedAt: tx.NowMicros(),
		LastLoginAt: domain.NullMicros(&tx.Now)})
	if store.IsConstraint(err) {
		return ErrAlreadyLinked
	}
	if err != nil {
		return err
	}
	if c.Email != "" {
		verified := int64(0)
		if c.EmailVerified {
			verified = 1
		}
		return tx.Q.UpsertUserEmail(ctx, db.UpsertUserEmailParams{ID: ids.New(ids.UserEmail), UserID: userID, Email: c.Email, Verified: verified,
			Source: "provider:" + prov.Slug, CreatedAt: tx.NowMicros()})
	}
	return nil
}

// resolveTx maps verified claims to a user: an existing (provider, issuer, subject) identity, or enrollment through a
// domain rule (jit, or invite_only with a matching invite) or a plain invite. Email never links to an existing user
// (ADR-0005): a new identity always creates a new user.
func (svc *Service) resolveTx(ctx context.Context, tx *store.Tx, prov db.IdentityProvider, c upstream.Claims) (string, error) {
	uid, err := svc.identityOwner(ctx, tx, prov, c)
	if err == nil {
		u, err := tx.Q.GetUser(ctx, uid)
		if err != nil {
			return "", err
		}
		if u.Status != identity.StatusActive {
			return "", ErrDisabled
		}
		return uid, nil
	}
	if !errors.Is(err, ErrNotEnrolled) {
		return "", err
	}
	var rule *db.DomainRule
	for _, d := range []string{c.HD, emailDomain(c)} {
		if d == "" {
			continue
		}
		r, err := tx.Q.GetDomainRuleByDomain(ctx, d)
		if err == nil && evidence(r, prov, c) {
			rule = &r
			break
		}
	}
	var invite *db.Invite
	if c.EmailVerified && c.Email != "" {
		var inv db.Invite
		var err error
		if rule != nil {
			inv, err = tx.Q.FindOpenInviteForTenant(ctx, db.FindOpenInviteForTenantParams{TenantID: rule.TenantID, Email: c.Email, ExpiresAt: tx.NowMicros()})
		} else {
			inv, err = tx.Q.FindOpenInvite(ctx, db.FindOpenInviteParams{Email: c.Email, ExpiresAt: tx.NowMicros()})
		}
		if err == nil {
			invite = &inv
		}
	}
	switch {
	case rule != nil && rule.Mode == ModeJIT:
	case invite != nil:
	default:
		return "", ErrNotEnrolled
	}
	name := c.Name
	if name == "" {
		name = c.Email
	}
	if name == "" {
		name = "User"
	}
	ch := domain.Change{Actor: audit.System, ManagedBy: domain.ManagedSystem}
	u, err := svc.users.CreateTx(ctx, tx, ch, identity.CreateParams{DisplayName: name, PrimaryEmail: c.Email, EmailVerified: c.EmailVerified,
		EmailSource: "provider:" + prov.Slug})
	if err != nil {
		return "", err
	}
	if err := svc.linkTx(ctx, tx, prov, c, u.ID); err != nil {
		return "", err
	}
	tenantID, source := "", ""
	switch {
	case rule != nil:
		tenantID, source = rule.TenantID, RuleSource(rule.ID)
	default:
		tenantID, source = invite.TenantID, "invite:"+invite.ID
	}
	if invite != nil {
		if _, err := tx.Q.ConsumeInvite(ctx, db.ConsumeInviteParams{ConsumedAt: domain.NullMicros(&tx.Now), ConsumedBy: domain.NullStr(u.ID), ID: invite.ID}); err != nil {
			return "", err
		}
	}
	sc, err := svc.tenants.SystemScope(ctx, tenantID)
	if err != nil {
		return "", err
	}
	if _, err := svc.tenants.AddMemberTx(ctx, tx, ch, sc, u.ID, source); err != nil {
		return "", err
	}
	_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: audit.System, TenantID: tenantID, Action: "user.enrolled", Target: audit.Target{Type: "user", ID: u.ID},
		Details: map[string]any{"provider_id": prov.ID, "source": source, "hd": c.HD}})
	return u.ID, err
}

// reevaluateTx keeps rule-derived memberships in line with the evidence in a fresh token: memberships whose rule
// belongs to this provider but whose evidence is gone are removed (manual memberships are never touched), and jit
// rules matching the current evidence add missing memberships.
func (svc *Service) reevaluateTx(ctx context.Context, tx *store.Tx, prov db.IdentityProvider, c upstream.Claims, userID string) error {
	ms, err := tx.Q.ListDerivedMemberships(ctx, userID)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for _, m := range ms {
		ruleID := strings.TrimPrefix(m.Source, "domain_rule:")
		r, err := tx.Q.GetDomainRule(ctx, ruleID)
		lost := false
		switch {
		case errors.Is(err, sql.ErrNoRows):
			lost = true
		case err != nil:
			return err
		case r.ProviderID != prov.ID:
			continue // evidence comes from another provider; this login cannot judge it
		default:
			lost = !evidence(r, prov, c)
		}
		if !lost {
			have[m.TenantID] = true
			continue
		}
		if _, err := tx.Q.DeleteMembershipByID(ctx, m.ID); err != nil {
			return err
		}
		if _, err := svc.audit.Append(ctx, tx, audit.Event{Actor: audit.System, TenantID: m.TenantID, Action: "membership.deleted",
			Target: audit.Target{Type: "user", ID: userID}, ReasonCode: "evidence_lost", Details: map[string]any{"source": m.Source, "hd": c.HD}}); err != nil {
			return err
		}
	}
	for _, d := range []string{c.HD, emailDomain(c)} {
		if d == "" {
			continue
		}
		r, err := tx.Q.GetDomainRuleByDomain(ctx, d)
		if err != nil || r.Mode != ModeJIT || !evidence(r, prov, c) || have[r.TenantID] {
			continue
		}
		if _, err := tx.Q.GetMembershipByUser(ctx, db.GetMembershipByUserParams{TenantID: r.TenantID, UserID: userID}); err == nil {
			continue // a manual (or other) membership already exists
		}
		sc, err := svc.tenants.SystemScope(ctx, r.TenantID)
		if err != nil {
			return err
		}
		if _, err := svc.tenants.AddMemberTx(ctx, tx, domain.SystemChange, sc, userID, RuleSource(r.ID)); err != nil {
			return err
		}
	}
	return nil
}

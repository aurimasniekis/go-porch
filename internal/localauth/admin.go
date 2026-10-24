package localauth

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/aurimasniekis/go-porch/internal/apperr"
	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/domain"
	"github.com/aurimasniekis/go-porch/internal/ids"
	"github.com/aurimasniekis/go-porch/internal/keyring"
	"github.com/aurimasniekis/go-porch/internal/session"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/store/db"
)

// Unlock clears a user's backup lockout (owner with step-up via API, or the host CLI). There is deliberately no API to
// lock someone (ADR-0008).
func (svc *Service) Unlock(ctx context.Context, actor audit.Actor, userID string) error {
	return svc.s.W().TxNamed(ctx, "localauth.unlock", func(tx *store.Tx) error {
		if _, err := tx.Q.GetUser(ctx, userID); errors.Is(err, sql.ErrNoRows) {
			return apperr.New(apperr.CodeNotFound, "user not found")
		} else if err != nil {
			return err
		}
		if err := tx.Q.UpsertBackupLockout(ctx, db.UpsertBackupLockoutParams{UserID: userID, UpdatedAt: tx.NowMicros()}); err != nil {
			return err
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "backup_credential.unlocked", Target: audit.Target{Type: "user", ID: userID}})
		return err
	})
}

// RecoveryLinkPrefix marks offline recovery tokens.
const RecoveryLinkPrefix = "porch_rl_"

// RecoveryLinkTTL bounds a recovery link's validity.
const RecoveryLinkTTL = 15 * time.Minute

// IssueRecoveryLink creates a one-time login link for userID (host CLI only: needs the data-directory lock and KEK).
func (svc *Service) IssueRecoveryLink(ctx context.Context, userID string) (string, time.Time, error) {
	secret, err := session.RandomToken()
	if err != nil {
		return "", time.Time{}, err
	}
	tok := RecoveryLinkPrefix + secret
	mac, err := svc.kr.MAC(keyring.PurposeToken, []byte("porch/recovery-link/v1|"+tok))
	if err != nil {
		return "", time.Time{}, err
	}
	var exp time.Time
	err = svc.s.W().TxNamed(ctx, "localauth.issue_recovery", func(tx *store.Tx) error {
		u, err := tx.Q.GetUser(ctx, userID)
		if errors.Is(err, sql.ErrNoRows) {
			return apperr.New(apperr.CodeNotFound, "user not found")
		}
		if err != nil {
			return err
		}
		if u.Status != "active" {
			return apperr.New(apperr.CodeConflict, "user is disabled")
		}
		exp = tx.Now.Add(RecoveryLinkTTL)
		id := ids.New(ids.RecoveryLink)
		if err := tx.Q.InsertRecoveryLink(ctx, db.InsertRecoveryLinkParams{ID: id, Mac: mac, UserID: userID, CreatedAt: tx.NowMicros(), ExpiresAt: exp.UnixMicro()}); err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: audit.CLI, Action: "recovery_link.issued", Target: audit.Target{Type: "user", ID: userID},
			Details: map[string]any{"expires_at": exp.Format(time.RFC3339)}})
		return err
	})
	return tok, exp, err
}

// UseRecoveryLink consumes a link and creates a recovery session. It raises a critical alert that stays until an
// operator acknowledges it.
func (svc *Service) UseRecoveryLink(ctx context.Context, token string, m Meta) (session.Created, error) {
	if !strings.HasPrefix(token, RecoveryLinkPrefix) || len(token) > 128 {
		return session.Created{}, ErrLoginFailed
	}
	macs, err := svc.kr.MACAll(keyring.PurposeToken, []byte("porch/recovery-link/v1|"+token))
	if err != nil {
		return session.Created{}, err
	}
	var out session.Created
	err = svc.s.W().TxNamed(ctx, "localauth.use_recovery", func(tx *store.Tx) error {
		var l db.RecoveryLink
		found := false
		for _, mac := range macs {
			if r, err := tx.Q.GetRecoveryLinkByMAC(ctx, mac); err == nil {
				l, found = r, true
				break
			}
		}
		if !found || l.ConsumedAt.Valid || l.ExpiresAt <= tx.NowMicros() {
			return ErrLoginFailed
		}
		if n, err := tx.Q.ConsumeRecoveryLink(ctx, db.ConsumeRecoveryLinkParams{ConsumedAt: domain.NullMicros(&tx.Now), ID: l.ID}); err != nil || n != 1 {
			return ErrLoginFailed
		}
		var err error
		out, err = svc.sessions.CreateTx(ctx, tx, session.NewParams{UserID: l.UserID, Method: session.MethodRecoveryLink, AuthTime: tx.Now,
			IP: m.IP, UserAgent: m.UserAgent})
		if err != nil {
			return err
		}
		if err := tx.Q.InsertAlert(ctx, db.InsertAlertParams{ID: ids.New(ids.Alert), Kind: "recovery_link_used",
			Severity: "critical", Message: "An offline recovery link was used to sign in. Review the audit log and acknowledge.",
			TargetID: domain.NullStr(l.UserID), CreatedAt: tx.NowMicros()}); err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorUser, ID: l.UserID}, Action: "login.recovery_link",
			AuthMethod: session.MethodRecoveryLink, Target: audit.Target{Type: "session", ID: out.ID}})
		return err
	})
	if err != nil {
		svc.metrics.Login("recovery_link", "failure")
		return session.Created{}, err
	}
	svc.metrics.Login("recovery_link", "success")
	return out, nil
}

package localauth

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/domain"
	"github.com/aurimasniekis/go-porch/internal/ids"
	"github.com/aurimasniekis/go-porch/internal/keyring"
	"github.com/aurimasniekis/go-porch/internal/session"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/store/db"
)

// Meta describes the client of a login attempt.
type Meta struct {
	SourceKey string // httpx.SourceKey of the trusted client IP
	IP        string
	UserAgent string
	// Session is the current session for step-up (nil for a fresh login).
	Session *session.Principal
}

// StartResult is returned after a correct password.
type StartResult struct {
	Challenge string
	Titles    []string
	ExpiresAt time.Time
}

const (
	circuitKey = "backup:circuit"
	srcPrefix  = "backup:src:"
)

// throttled reports whether the source or the installation circuit is over its limit (checked before anything else).
func (svc *Service) throttled(ctx context.Context, sourceKey string) bool {
	now := svc.clock.Now().UnixMicro()
	over := func(key string, limit int, window time.Duration) bool {
		b, err := svc.s.R().GetThrottle(ctx, key)
		return err == nil && now-b.WindowStart < window.Microseconds() && b.Count >= int64(limit)
	}
	return over(circuitKey, svc.policy.CircuitLimit, svc.policy.CircuitWindow) || over(srcPrefix+sourceKey, svc.policy.SourceLimit, svc.policy.SourceWindow)
}

// countFailureTx increments the source and circuit counters.
func (svc *Service) countFailureTx(ctx context.Context, tx *store.Tx, sourceKey string) error {
	bump := func(key string, window time.Duration) error {
		b, err := tx.Q.GetThrottle(ctx, key)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && tx.NowMicros()-b.WindowStart >= window.Microseconds()) {
			return tx.Q.UpsertThrottle(ctx, db.UpsertThrottleParams{Key: key, WindowStart: tx.NowMicros(), Count: 1})
		}
		if err != nil {
			return err
		}
		return tx.Q.UpsertThrottle(ctx, db.UpsertThrottleParams{Key: key, WindowStart: b.WindowStart, Count: b.Count + 1})
	}
	if err := bump(srcPrefix+sourceKey, svc.policy.SourceWindow); err != nil {
		return err
	}
	return bump(circuitKey, svc.policy.CircuitWindow)
}

// lockout returns the user's lockout row (zero row when absent).
func lockout(ctx context.Context, tx *store.Tx, uid string) (db.BackupLockout, error) {
	l, err := tx.Q.GetBackupLockout(ctx, uid)
	if errors.Is(err, sql.ErrNoRows) {
		return db.BackupLockout{UserID: uid}, nil
	}
	return l, err
}

// staleReservation is how long a reserved attempt may stay open (a hash takes well under a second); older
// reservations come from a crash mid-attempt and count as failures (fail closed).
const staleReservation = 2 * time.Minute

// reserveTx atomically takes one attempt from the account's budget before any hashing (ADR-0008). It returns false
// when the account is locked or its budget is already fully reserved by concurrent attempts.
func (svc *Service) reserveTx(ctx context.Context, tx *store.Tx, uid string) (bool, error) {
	l, err := lockout(ctx, tx, uid)
	if err != nil {
		return false, err
	}
	if l.LockedUntil > tx.NowMicros() {
		return false, nil
	}
	if l.Failures >= int64(svc.policy.Threshold) {
		if tx.NowMicros()-l.UpdatedAt > staleReservation.Microseconds() {
			return false, svc.lockTx(ctx, tx, l, "stale_reservation")
		}
		return false, nil
	}
	l.Failures++
	return true, tx.Q.UpsertBackupLockout(ctx, db.UpsertBackupLockoutParams{UserID: uid, Failures: l.Failures, LockedUntil: l.LockedUntil,
		Level: l.Level, UpdatedAt: tx.NowMicros()})
}

// failTx records a failed step: once the budget is spent the account locks.
func (svc *Service) failTx(ctx context.Context, tx *store.Tx, uid, step string) error {
	l, err := lockout(ctx, tx, uid)
	if err != nil {
		return err
	}
	if l.Failures >= int64(svc.policy.Threshold) {
		return svc.lockTx(ctx, tx, l, "failed_"+step)
	}
	return tx.Q.UpsertBackupLockout(ctx, db.UpsertBackupLockoutParams{UserID: uid, Failures: l.Failures, LockedUntil: l.LockedUntil, Level: l.Level,
		UpdatedAt: tx.NowMicros()})
}

// lockTx locks the account for Duration·2^level (capped) and escalates the level.
func (svc *Service) lockTx(ctx context.Context, tx *store.Tx, l db.BackupLockout, reason string) error {
	d := svc.policy.Duration << min(l.Level, 16)
	if d > svc.policy.MaxDuration || d <= 0 {
		d = svc.policy.MaxDuration
	}
	l.LockedUntil = tx.Now.Add(d).UnixMicro()
	l.Level++
	l.Failures = 0
	if err := tx.Q.UpsertBackupLockout(ctx, db.UpsertBackupLockoutParams{UserID: l.UserID, Failures: 0, LockedUntil: l.LockedUntil, Level: l.Level,
		UpdatedAt: tx.NowMicros()}); err != nil {
		return err
	}
	svc.metrics.BackupLockout()
	_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: audit.System, Action: "backup_credential.locked", Target: audit.Target{Type: "user", ID: l.UserID},
		ReasonCode: reason, Details: map[string]any{"locked_until": domain.FromMicros(l.LockedUntil).Format(time.RFC3339), "level": l.Level}})
	return err
}

// releaseTx returns a reservation after a correct password. It never lowers the counter below what other
// in-flight attempts reserved and never touches the escalation level, so a known password buys no extra answer
// guesses.
func (svc *Service) releaseTx(ctx context.Context, tx *store.Tx, uid string) error {
	l, err := lockout(ctx, tx, uid)
	if err != nil {
		return err
	}
	if l.Failures > 0 {
		l.Failures--
	}
	return tx.Q.UpsertBackupLockout(ctx, db.UpsertBackupLockoutParams{UserID: uid, Failures: l.Failures, LockedUntil: l.LockedUntil, Level: l.Level,
		UpdatedAt: tx.NowMicros()})
}

func (svc *Service) lookup(ctx context.Context, identifier string) (db.User, bool) {
	id := strings.ToLower(strings.TrimSpace(identifier))
	if id == "" || len(id) > 254 {
		return db.User{}, false
	}
	if u, err := svc.s.R().GetUserByBackupHandle(ctx, domain.NullStr(id)); err == nil {
		return u, true
	}
	us, err := svc.s.R().GetUsersByPrimaryEmail(ctx, domain.NullStr(id))
	if err != nil || len(us) != 1 || us[0].BackupHandle.Valid { // ambiguous email, or a handle replaces the email
		return db.User{}, false
	}
	return us[0], true
}

func (svc *Service) auditAttempt(ctx context.Context, tx *store.Tx, uid, outcome, reason, step string) error {
	_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorUser, ID: uid}, Action: "login.backup",
		AuthMethod: session.MethodBackup, Outcome: outcome, ReasonCode: reason, Details: map[string]any{"step": step}})
	return err
}

// Start runs step 1 (identifier + password). Only a correct password yields the user's titles and a challenge.
func (svc *Service) Start(ctx context.Context, identifier, password string, m Meta) (StartResult, error) {
	if svc.policy.Disabled {
		return StartResult{}, ErrDisabled
	}
	if svc.throttled(ctx, m.SourceKey) {
		svc.metrics.Login("backup", "throttled")
		return StartResult{}, ErrThrottled
	}
	pw, perr := NormalizePassword(password)
	u, found := svc.lookup(ctx, identifier)
	var cred db.BackupCredential
	if found {
		var err error
		cred, err = svc.s.R().GetBackupCredential(ctx, u.ID)
		found = err == nil && u.Status == "active"
	}
	if m.Session != nil && (!found || u.ID != m.Session.UserID) {
		found = false // step-up must be performed by the session's own user
	}
	reserved := false
	if found {
		err := svc.s.W().TxNamed(ctx, "localauth.reserve", func(tx *store.Tx) error {
			var err error
			reserved, err = svc.reserveTx(ctx, tx, u.ID)
			return err
		})
		if err != nil {
			return StartResult{}, err
		}
	}
	ok := false
	switch {
	case found && reserved && perr == nil:
		phc, err := svc.kr.Open(keyring.PurposeField, pwAAD(u.ID), cred.PasswordEnc)
		if err != nil {
			return StartResult{}, err
		}
		ok = svc.h.verify(pw, string(phc))
	default:
		svc.h.burn() // unknown, locked or malformed: same cost as a real check
	}
	if !ok {
		err := svc.s.W().TxNamed(ctx, "localauth.fail_password", func(tx *store.Tx) error {
			if err := svc.countFailureTx(ctx, tx, m.SourceKey); err != nil {
				return err
			}
			reason := "unknown_identifier"
			if found {
				reason = "locked"
				if reserved {
					reason = "wrong_password"
					if err := svc.failTx(ctx, tx, u.ID, "password"); err != nil {
						return err
					}
				}
			}
			uid := ""
			if found {
				uid = u.ID
			}
			return svc.auditAttempt(ctx, tx, uid, "failure", reason, "password")
		})
		if err != nil {
			return StartResult{}, err
		}
		svc.metrics.Login("backup", "failure")
		return StartResult{}, ErrLoginFailed
	}
	tok, err := session.RandomToken()
	if err != nil {
		return StartResult{}, err
	}
	mac, err := svc.kr.MAC(keyring.PurposeToken, []byte("porch/backup-challenge/v1|"+tok))
	if err != nil {
		return StartResult{}, err
	}
	var res StartResult
	err = svc.s.W().TxNamed(ctx, "localauth.challenge", func(tx *store.Tx) error {
		if err := svc.releaseTx(ctx, tx, u.ID); err != nil {
			return err
		}
		sid := ""
		if m.Session != nil {
			sid = m.Session.SessionID
		}
		exp := tx.Now.Add(svc.policy.ChallengeTTL)
		if err := tx.Q.InsertBackupChallenge(ctx, db.InsertBackupChallengeParams{ID: ids.New(ids.BackupChallenge), Mac: mac, UserID: u.ID,
			SourceKey: m.SourceKey, SessionID: domain.NullStr(sid), CreatedAt: tx.NowMicros(), ExpiresAt: exp.UnixMicro()}); err != nil {
			return err
		}
		titles, err := svc.titles(ctx, tx.Q, u.ID)
		if err != nil {
			return err
		}
		res = StartResult{Challenge: tok, Titles: titles, ExpiresAt: exp}
		return svc.auditAttempt(ctx, tx, u.ID, "success", "password_ok", "password")
	})
	return res, err
}

// Finish runs step 2 (answers). On success it creates a backup session, or for a step-up rotates the current one.
func (svc *Service) Finish(ctx context.Context, challenge string, answers []string, m Meta) (session.Created, error) {
	if svc.policy.Disabled {
		return session.Created{}, ErrDisabled
	}
	if svc.throttled(ctx, m.SourceKey) {
		return session.Created{}, ErrThrottled
	}
	macs, err := svc.kr.MACAll(keyring.PurposeToken, []byte("porch/backup-challenge/v1|"+challenge))
	if err != nil {
		return session.Created{}, err
	}
	var ch db.BackupChallenge
	var reserved, valid bool
	var cred db.BackupCredential
	err = svc.s.W().TxNamed(ctx, "localauth.reserve_answers", func(tx *store.Tx) error {
		valid, reserved = false, false
		for _, mac := range macs {
			c, err := tx.Q.GetBackupChallengeByMAC(ctx, mac)
			if err == nil {
				ch, valid = c, true
				break
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
		}
		if !valid || ch.ConsumedAt.Valid || ch.ExpiresAt <= tx.NowMicros() || ch.SourceKey != m.SourceKey {
			valid = false
			return nil
		}
		if sid := ch.SessionID.String; (sid != "") != (m.Session != nil) || (m.Session != nil && sid != m.Session.SessionID) {
			valid = false
			return nil
		}
		if n, err := tx.Q.ConsumeBackupChallenge(ctx, db.ConsumeBackupChallengeParams{ConsumedAt: domain.NullMicros(&tx.Now), ID: ch.ID}); err != nil || n != 1 {
			valid = false
			return err
		}
		var err error
		if cred, err = tx.Q.GetBackupCredential(ctx, ch.UserID); err != nil {
			valid = false
			return nil //nolint:nilerr // credential removed meanwhile: generic failure
		}
		reserved, err = svc.reserveTx(ctx, tx, ch.UserID)
		return err
	})
	if err != nil {
		return session.Created{}, err
	}
	ok := false
	if valid && reserved && len(answers) == int(cred.PairCount) {
		phc, err := svc.kr.Open(keyring.PurposeField, ansAAD(ch.UserID), cred.AnswersEnc)
		if err != nil {
			return session.Created{}, err
		}
		ok = svc.h.verify(answersInput(answers), string(phc))
	} else {
		svc.h.burn()
	}
	var out session.Created
	err = svc.s.W().TxNamed(ctx, "localauth.finish", func(tx *store.Tx) error {
		if !ok {
			if err := svc.countFailureTx(ctx, tx, m.SourceKey); err != nil {
				return err
			}
			if valid && reserved {
				if err := svc.failTx(ctx, tx, ch.UserID, "answers"); err != nil {
					return err
				}
			}
			reason := "invalid_challenge"
			if valid {
				reason = "locked"
				if reserved {
					reason = "wrong_answers"
				}
			}
			return svc.auditAttempt(ctx, tx, ch.UserID, "failure", reason, "answers")
		}
		if err := tx.Q.UpsertBackupLockout(ctx, db.UpsertBackupLockoutParams{UserID: ch.UserID, UpdatedAt: tx.NowMicros()}); err != nil {
			return err
		}
		var err error
		if m.Session != nil {
			out, err = svc.sessions.RotateTx(ctx, tx, m.Session, tx.Now, m.IP, m.UserAgent)
		} else {
			out, err = svc.sessions.CreateTx(ctx, tx, session.NewParams{UserID: ch.UserID, Method: session.MethodBackup, AuthTime: tx.Now,
				IP: m.IP, UserAgent: m.UserAgent})
		}
		if err != nil {
			return err
		}
		return svc.auditAttempt(ctx, tx, ch.UserID, "success", "ok", "answers")
	})
	if err != nil {
		return session.Created{}, err
	}
	if !ok {
		svc.metrics.Login("backup", "failure")
		return session.Created{}, ErrLoginFailed
	}
	svc.metrics.Login("backup", "success")
	return out, nil
}

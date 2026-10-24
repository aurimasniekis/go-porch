package localauth

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/aurimasniekis/go-porch/internal/apperr"
	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/clock"
	"github.com/aurimasniekis/go-porch/internal/domain"
	"github.com/aurimasniekis/go-porch/internal/ids"
	"github.com/aurimasniekis/go-porch/internal/keyring"
	"github.com/aurimasniekis/go-porch/internal/obs/metrics"
	"github.com/aurimasniekis/go-porch/internal/session"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/store/db"
)

// ChallengeCookie carries the step-2 challenge after a correct password.
const ChallengeCookie = "__Host-porch_bchal"

// Policy configures lockout and throttling (ADR-0008).
type Policy struct {
	Threshold     int           // failed steps before a lock (default 1)
	Duration      time.Duration // first lock (default 6h)
	MaxDuration   time.Duration // escalation cap (default 48h)
	SourceLimit   int           // failed attempts per source per window (default 10)
	SourceWindow  time.Duration // (default 15m)
	CircuitLimit  int           // installation-wide failures per window before the circuit opens (default 100)
	CircuitWindow time.Duration // (default 1m)
	ChallengeTTL  time.Duration // step-2 validity (default 5m)
	// Disabled turns backup login off for everyone (explicit config flag; startup warns).
	Disabled bool
	Strength StrengthPolicy
	Params   Params
}

// DefaultPolicy matches ADR-0008.
func DefaultPolicy() Policy {
	return Policy{Threshold: 1, Duration: 6 * time.Hour, MaxDuration: 48 * time.Hour, SourceLimit: 10, SourceWindow: 15 * time.Minute,
		CircuitLimit: 100, CircuitWindow: time.Minute, ChallengeTTL: 5 * time.Minute, Strength: DefaultStrength, Params: DefaultParams}
}

// Errors. ErrLoginFailed is deliberately the same for unknown handles, wrong passwords, wrong answers and locks.
var (
	ErrLoginFailed = apperr.New(apperr.CodeUnauthorized, "invalid credentials, or backup login is temporarily unavailable for this account")
	ErrThrottled   = apperr.New(apperr.CodeRateLimited, "too many attempts from your network; try again later")
	ErrDisabled    = apperr.New(apperr.CodeUnavailable, "backup login is disabled on this installation")
	ErrNotEnrolled = apperr.New(apperr.CodeNotFound, "no backup credential enrolled")
)

// Service implements the backup login.
type Service struct {
	s        *store.Store
	kr       *keyring.Keyring
	audit    *audit.Writer
	sessions *session.Manager
	clock    clock.Clock
	policy   Policy
	metrics  *metrics.Metrics
	h        *hasher
}

// New returns the service.
func New(s *store.Store, kr *keyring.Keyring, a *audit.Writer, sessions *session.Manager, c clock.Clock, m *metrics.Metrics, p Policy) *Service {
	if c == nil {
		c = clock.System{}
	}
	return &Service{s: s, kr: kr, audit: a, sessions: sessions, clock: c, policy: p, metrics: m, h: newHasher(p.Params, 4)}
}

// Policy returns the effective policy.
func (svc *Service) Policy() Policy { return svc.policy }

func pwAAD(uid string) []byte   { return keyring.FieldAAD("backup_credentials", "password_enc", uid) }
func ansAAD(uid string) []byte  { return keyring.FieldAAD("backup_credentials", "answers_enc", uid) }
func titleAAD(id string) []byte { return keyring.FieldAAD("recovery_pairs", "title_enc", id) }

// EnrollParams describe a new or rotated credential.
type EnrollParams struct {
	Password string
	Pairs    []Pair
	Confirm  []string // the answers re-typed
}

// Enroll sets (or rotates) the caller's backup credential. Requires a step-up (recent authentication).
func (svc *Service) Enroll(ctx context.Context, p *session.Principal, in EnrollParams) (Estimate, error) {
	if err := svc.sessions.RequireStepUp(p); err != nil {
		return Estimate{}, err
	}
	u, err := svc.s.R().GetUser(ctx, p.UserID)
	if err != nil {
		return Estimate{}, err
	}
	inputs := []string{u.DisplayName, u.PrimaryEmail.String, u.BackupHandle.String}
	if at := strings.IndexByte(u.PrimaryEmail.String, '@'); at > 0 {
		inputs = append(inputs, u.PrimaryEmail.String[:at])
	}
	est, err := CheckEnrollment(svc.policy.Strength, in.Password, in.Pairs, in.Confirm, inputs)
	if err != nil {
		return est, err
	}
	pw, err := NormalizePassword(in.Password)
	if err != nil {
		return est, err
	}
	answers := make([]string, len(in.Pairs))
	for i, pr := range in.Pairs {
		answers[i] = pr.Answer
	}
	pwPHC, err := svc.h.hash(pw) // hashing outside the write transaction
	if err != nil {
		return est, err
	}
	ansPHC, err := svc.h.hash(answersInput(answers))
	if err != nil {
		return est, err
	}
	pwEnc, err := svc.kr.Seal(keyring.PurposeField, pwAAD(u.ID), []byte(pwPHC))
	if err != nil {
		return est, err
	}
	ansEnc, err := svc.kr.Seal(keyring.PurposeField, ansAAD(u.ID), []byte(ansPHC))
	if err != nil {
		return est, err
	}
	type sealedPair struct {
		id    string
		title []byte
	}
	sp := make([]sealedPair, len(in.Pairs))
	for i, pr := range in.Pairs {
		id := ids.New(ids.RecoveryPair)
		t, err := svc.kr.Seal(keyring.PurposeField, titleAAD(id), []byte(strings.TrimSpace(pr.Title)))
		if err != nil {
			return est, err
		}
		sp[i] = sealedPair{id: id, title: t}
	}
	err = svc.s.W().TxNamed(ctx, "localauth.enroll", func(tx *store.Tx) error {
		action := "backup_credential.enrolled"
		if _, err := tx.Q.GetBackupCredential(ctx, u.ID); err == nil {
			action = "backup_credential.rotated"
		}
		if err := tx.Q.UpsertBackupCredential(ctx, db.UpsertBackupCredentialParams{UserID: u.ID, PasswordEnc: pwEnc, AnswersEnc: ansEnc,
			PairCount: int64(len(sp)), EnrolledAt: tx.NowMicros(), RotatedAt: tx.NowMicros()}); err != nil {
			return err
		}
		if err := tx.Q.DeleteRecoveryPairs(ctx, u.ID); err != nil {
			return err
		}
		for i, s := range sp {
			if err := tx.Q.InsertRecoveryPair(ctx, db.InsertRecoveryPairParams{ID: s.id, UserID: u.ID, Position: int64(i), TitleEnc: s.title}); err != nil {
				return err
			}
		}
		if err := tx.Q.UpsertBackupLockout(ctx, db.UpsertBackupLockoutParams{UserID: u.ID, UpdatedAt: tx.NowMicros()}); err != nil {
			return err
		}
		_, err := svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorUser, ID: u.ID}, Action: action,
			Target: audit.Target{Type: "user", ID: u.ID}, Details: map[string]any{"pairs": len(sp), "estimate_bits": est.CombinedBitsEst}})
		return err
	})
	return est, err
}

// Status describes a user's backup credential.
type Status struct {
	Enrolled    bool       `json:"enrolled"`
	Pairs       int        `json:"pairs"`
	Titles      []string   `json:"titles,omitempty"`
	EnrolledAt  *time.Time `json:"enrolled_at,omitempty"`
	RotatedAt   *time.Time `json:"rotated_at,omitempty"`
	LockedUntil *time.Time `json:"locked_until,omitempty"`
	Handle      string     `json:"handle,omitempty"`
}

// StatusFor returns the user's credential status; withTitles unseals titles (only for the signed-in owner).
func (svc *Service) StatusFor(ctx context.Context, userID string, withTitles bool) (Status, error) {
	st := Status{}
	u, err := svc.s.R().GetUser(ctx, userID)
	if err != nil {
		return st, err
	}
	st.Handle = u.BackupHandle.String
	c, err := svc.s.R().GetBackupCredential(ctx, userID)
	if errors.Is(err, sql.ErrNoRows) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	st.Enrolled, st.Pairs = true, int(c.PairCount)
	e, r := domain.FromMicros(c.EnrolledAt), domain.FromMicros(c.RotatedAt)
	st.EnrolledAt, st.RotatedAt = &e, &r
	if l, err := svc.s.R().GetBackupLockout(ctx, userID); err == nil && l.LockedUntil > svc.clock.Now().UnixMicro() {
		t := domain.FromMicros(l.LockedUntil)
		st.LockedUntil = &t
	}
	if withTitles {
		st.Titles, err = svc.titles(ctx, svc.s.R(), userID)
	}
	return st, err
}

func (svc *Service) titles(ctx context.Context, q *db.Queries, userID string) ([]string, error) {
	rows, err := q.ListRecoveryPairs(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		t, err := svc.kr.Open(keyring.PurposeField, titleAAD(r.ID), r.TitleEnc)
		if err != nil {
			return nil, err
		}
		out = append(out, string(t))
	}
	return out, nil
}

// SetHandle sets the optional backup login handle (when set, the email no longer works as backup identifier).
func (svc *Service) SetHandle(ctx context.Context, p *session.Principal, handle string) error {
	if err := svc.sessions.RequireStepUp(p); err != nil {
		return err
	}
	handle = strings.ToLower(strings.TrimSpace(handle))
	if handle != "" && (!domain.ValidSlug(handle) || len(handle) < 4 || strings.Contains(handle, "@")) {
		return apperr.New(apperr.CodeInvalid, "handle must be 4..63 lowercase letters, digits or inner hyphens")
	}
	return svc.s.W().TxNamed(ctx, "localauth.set_handle", func(tx *store.Tx) error {
		_, err := tx.Q.SetBackupHandle(ctx, db.SetBackupHandleParams{BackupHandle: domain.NullStr(handle), UpdatedAt: tx.NowMicros(), ID: p.UserID})
		if store.IsConstraint(err) {
			return apperr.New(apperr.CodeAlreadyExists, "handle is taken")
		}
		if err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorUser, ID: p.UserID}, Action: "backup_credential.handle_changed",
			Target: audit.Target{Type: "user", ID: p.UserID}, Details: map[string]any{"has_handle": handle != ""}})
		return err
	})
}

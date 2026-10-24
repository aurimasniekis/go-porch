// Package setup bootstraps the first installation owner. A setup token can only be issued on the host
// (`porch admin setup-token`, which needs the data-directory lock and the KEK); consuming it creates the owner and a
// short setup session. Consumption runs in one BEGIN IMMEDIATE transaction guarded by "no operator exists", so two
// concurrent consumers can never both succeed (ADR-0003, M1 acceptance).
package setup

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
	"github.com/aurimasniekis/go-porch/internal/keyring"
	"github.com/aurimasniekis/go-porch/internal/session"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/store/db"
)

// TokenPrefix marks setup tokens so they are recognisable in logs and secret scanners.
const TokenPrefix = "porch_setup_"

// Errors. Invalid, expired and consumed tokens share one message.
var (
	ErrAlreadySetUp = apperr.New(apperr.CodeConflict, "setup already completed")
	ErrBadToken     = apperr.New(apperr.CodeUnauthorized, "invalid or expired setup token")
)

// Service issues and consumes setup tokens.
type Service struct {
	s        *store.Store
	kr       *keyring.Keyring
	audit    *audit.Writer
	users    *identity.Service
	sessions *session.Manager
}

// New returns a service.
func New(s *store.Store, kr *keyring.Keyring, a *audit.Writer, users *identity.Service, sessions *session.Manager) *Service {
	return &Service{s: s, kr: kr, audit: a, users: users, sessions: sessions}
}

func (svc *Service) macs(token string) ([][]byte, error) {
	return svc.kr.MACAll(keyring.PurposeToken, []byte("porch/setup/v1|"+token))
}

// Issue creates a single-use setup token valid for ttl. It refuses once an operator exists.
func (svc *Service) Issue(ctx context.Context, ttl time.Duration) (string, time.Time, error) {
	secret, err := session.RandomToken()
	if err != nil {
		return "", time.Time{}, err
	}
	token := TokenPrefix + secret
	mac, err := svc.kr.MAC(keyring.PurposeToken, []byte("porch/setup/v1|"+token))
	if err != nil {
		return "", time.Time{}, err
	}
	var exp time.Time
	err = svc.s.W().TxNamed(ctx, "setup.issue", func(tx *store.Tx) error {
		n, err := tx.Q.CountOperators(ctx)
		if err != nil {
			return err
		}
		if n > 0 {
			return ErrAlreadySetUp
		}
		exp = tx.Now.Add(ttl)
		id := ids.New(ids.SetupToken)
		if err := tx.Q.InsertSetupToken(ctx, db.InsertSetupTokenParams{ID: id, Mac: mac, CreatedAt: tx.NowMicros(), ExpiresAt: exp.UnixMicro()}); err != nil {
			return err
		}
		_, err = svc.audit.Append(ctx, tx, audit.Event{Actor: audit.CLI, Action: "setup.token_issued", Target: audit.Target{Type: "setup_token", ID: id},
			Details: map[string]any{"expires_at": exp.UTC().Format(time.RFC3339)}})
		return err
	})
	return token, exp, err
}

// ConsumeParams describe the first owner.
type ConsumeParams struct {
	Token       string
	DisplayName string
	Email       string
	IP          string
	UserAgent   string
}

// Result is the created owner and setup session.
type Result struct {
	User    identity.User
	Session session.Created
}

// Consume validates the token, creates the first owner and a setup session.
func (svc *Service) Consume(ctx context.Context, p ConsumeParams) (Result, error) {
	if !strings.HasPrefix(p.Token, TokenPrefix) || len(p.Token) > 128 {
		return Result{}, ErrBadToken
	}
	macs, err := svc.macs(p.Token)
	if err != nil {
		return Result{}, err
	}
	var res Result
	err = svc.s.W().TxNamed(ctx, "setup.consume", func(tx *store.Tx) error {
		n, err := tx.Q.CountOperators(ctx)
		if err != nil {
			return err
		}
		if n > 0 {
			return ErrAlreadySetUp
		}
		var tok db.SetupToken
		found := false
		for _, m := range macs {
			if tok, err = tx.Q.GetSetupTokenByMAC(ctx, m); err == nil {
				found = true
				break
			} else if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
		}
		if !found || tok.ConsumedAt.Valid || !tx.Now.Before(domain.FromMicros(tok.ExpiresAt)) {
			return ErrBadToken
		}
		ch := domain.Change{Actor: audit.Actor{Type: audit.ActorUser}, ManagedBy: domain.ManagedUI}
		u, err := svc.users.CreateTx(ctx, tx, ch, identity.CreateParams{DisplayName: p.DisplayName, PrimaryEmail: p.Email, EmailSource: "setup"})
		if err != nil {
			return err
		}
		ch.Actor.ID = u.ID
		if rows, err := tx.Q.ConsumeSetupToken(ctx, db.ConsumeSetupTokenParams{ConsumedAt: domain.NullMicros(&tx.Now),
			ConsumedBy: domain.NullStr(u.ID), ID: tok.ID}); err != nil {
			return err
		} else if rows != 1 {
			return ErrBadToken
		}
		if err := svc.users.GrantOperatorRoleTx(ctx, tx, ch, u.ID, identity.RoleOwner, "setup"); err != nil {
			return err
		}
		if _, err := tx.Q.MarkSetupCompleted(ctx, db.MarkSetupCompletedParams{SetupCompletedAt: domain.NullMicros(&tx.Now), UpdatedAt: tx.NowMicros()}); err != nil {
			return err
		}
		if _, err := svc.audit.Append(ctx, tx, audit.Event{Actor: ch.Actor, Action: "setup.completed", AuthMethod: session.MethodSetup,
			Target: audit.Target{Type: "user", ID: u.ID}}); err != nil {
			return err
		}
		c, err := svc.sessions.CreateTx(ctx, tx, session.NewParams{UserID: u.ID, Method: session.MethodSetup, IP: p.IP, UserAgent: p.UserAgent})
		if err != nil {
			return err
		}
		res = Result{User: u, Session: c}
		return nil
	})
	return res, err
}

// Completed reports whether the first owner exists.
func (svc *Service) Completed(ctx context.Context) (bool, error) {
	n, err := svc.s.R().CountOperators(ctx)
	return n > 0, err
}

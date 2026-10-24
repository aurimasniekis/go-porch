package mgmtapi

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/aurimasniekis/go-porch/internal/apperr"
	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/identity"
	"github.com/aurimasniekis/go-porch/internal/installation"
	"github.com/aurimasniekis/go-porch/internal/store"
)

// InstallationInfo describes the installation.
type InstallationInfo struct {
	ID               string     `json:"id"`
	Version          string     `json:"version"`
	SecurityEpoch    int64      `json:"security_epoch"`
	SetupCompletedAt *time.Time `json:"setup_completed_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
}

// Operator is a user with installation roles.
type Operator struct {
	UserID      string    `json:"user_id"`
	DisplayName string    `json:"display_name"`
	Email       string    `json:"email,omitempty"`
	Role        string    `json:"role"`
	Source      string    `json:"source"`
	CreatedAt   time.Time `json:"created_at"`
}

// OperatorGrant gives a user an installation role.
type OperatorGrant struct {
	UserID string `json:"user_id" minLength:"1" maxLength:"64"`
	Role   string `json:"role" enum:"owner,admin,auditor"`
}

// AuditVerification is the result of verifying the audit hash chain.
type AuditVerification struct {
	Events   int64  `json:"events"`
	OK       bool   `json:"ok"`
	BrokenAt int64  `json:"broken_at,omitempty"`
	Problem  string `json:"problem,omitempty"`
}

func registerInstallation(api huma.API, d *Deps) {
	tags := []string{"installation"}
	huma.Register(api, huma.Operation{OperationID: "get-installation", Method: http.MethodGet, Path: "/installation",
		Summary: "Installation status", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*struct{ Body InstallationInfo }, error) {
			if _, err := requireOperator(ctx, identity.RoleOwner, identity.RoleAdmin, identity.RoleAuditor); err != nil {
				return nil, err
			}
			info, err := installation.Get(ctx, d.Store.R())
			if err != nil {
				return nil, d.fail("installation", err)
			}
			return &struct{ Body InstallationInfo }{Body: InstallationInfo{ID: info.ID, Version: d.Version, SecurityEpoch: info.SecurityEpoch,
				SetupCompletedAt: info.SetupCompletedAt, CreatedAt: info.CreatedAt}}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "list-operators", Method: http.MethodGet, Path: "/installation/operators",
		Summary: "Users with installation roles", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*struct{ Body []Operator }, error) {
			if _, err := requireOperator(ctx, identity.RoleOwner, identity.RoleAdmin, identity.RoleAuditor); err != nil {
				return nil, err
			}
			rows, err := d.Store.R().ListOperators(ctx)
			if err != nil {
				return nil, d.fail("operators", err)
			}
			out := make([]Operator, 0, len(rows))
			for _, r := range rows {
				out = append(out, Operator{UserID: r.UserID, DisplayName: r.DisplayName, Email: r.PrimaryEmail.String, Role: r.Role, Source: r.Source,
					CreatedAt: time.UnixMicro(r.CreatedAt).UTC()})
			}
			return &struct{ Body []Operator }{Body: out}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "grant-operator-role", Method: http.MethodPost, Path: "/installation/operators",
		DefaultStatus: http.StatusNoContent, Summary: "Give a user an installation role (owner only; needs a recent sign-in)", Tags: tags,
		Security: sessionSecurity},
		func(ctx context.Context, in *struct{ Body OperatorGrant }) (*struct{}, error) {
			if _, err := requireOperator(ctx, identity.RoleOwner); err != nil {
				return nil, err
			}
			if err := d.stepUp(ctx); err != nil {
				return nil, err
			}
			err := d.Store.W().TxNamed(ctx, "installation.grant_role", func(tx *store.Tx) error {
				if _, err := tx.Q.GetUser(ctx, in.Body.UserID); err != nil {
					return apperr.New(apperr.CodeNotFound, "user not found")
				}
				return d.Users.GrantOperatorRoleTx(ctx, tx, change(ctx, ""), in.Body.UserID, in.Body.Role, "manual")
			})
			if err != nil {
				return nil, d.fail("grant-operator-role", err)
			}
			return &struct{}{}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "revoke-operator-role", Method: http.MethodDelete, Path: "/installation/operators/{user}/{role}",
		DefaultStatus: http.StatusNoContent, Summary: "Remove an installation role (owner only; needs a recent sign-in; the last owner stays)",
		Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			User string `path:"user" maxLength:"64"`
			Role string `path:"role" enum:"owner,admin,auditor"`
		}) (*struct{}, error) {
			if _, err := requireOperator(ctx, identity.RoleOwner); err != nil {
				return nil, err
			}
			if err := d.stepUp(ctx); err != nil {
				return nil, err
			}
			err := d.Store.W().TxNamed(ctx, "installation.revoke_role", func(tx *store.Tx) error {
				return d.Users.RevokeOperatorRoleTx(ctx, tx, change(ctx, ""), in.User, in.Role)
			})
			if err != nil {
				return nil, d.fail("revoke-operator-role", err)
			}
			return &struct{}{}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "verify-audit-chain", Method: http.MethodGet, Path: "/installation/audit/verify",
		Summary: "Verify the audit log hash chain", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*struct{ Body AuditVerification }, error) {
			if _, err := requireOperator(ctx, identity.RoleOwner, identity.RoleAdmin, identity.RoleAuditor); err != nil {
				return nil, err
			}
			res, err := audit.Verify(ctx, d.Store.R())
			if err != nil {
				return nil, d.fail("audit-verify", err)
			}
			return &struct{ Body AuditVerification }{Body: AuditVerification{Events: res.Events, OK: res.OK, BrokenAt: res.BrokenAt, Problem: res.Problem}}, nil
		})
}

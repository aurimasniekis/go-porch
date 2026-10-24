package mgmtapi

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/identity"
	"github.com/aurimasniekis/go-porch/internal/installation"
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

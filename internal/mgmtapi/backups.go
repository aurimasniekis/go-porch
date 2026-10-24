package mgmtapi

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/aurimasniekis/go-porch/internal/apperr"
	"github.com/aurimasniekis/go-porch/internal/backup"
	"github.com/aurimasniekis/go-porch/internal/identity"
)

// BackupStatus describes the backup configuration and recent runs.
type BackupStatus struct {
	Enabled         bool         `json:"enabled"`
	IntervalSeconds int64        `json:"interval_seconds"`
	VerifyKey       string       `json:"verify_key,omitempty" doc:"Ed25519 key that verifies this installation's backups; store it with the age identity."`
	Runs            []backup.Run `json:"runs"`
}

func registerBackups(api huma.API, d *Deps) {
	tags := []string{"backups"}
	huma.Register(api, huma.Operation{OperationID: "get-backups", Method: http.MethodGet, Path: "/installation/backups",
		Summary: "Backup configuration and recent runs (owner, admin or auditor)", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*struct{ Body BackupStatus }, error) {
			if _, err := requireOperator(ctx, identity.RoleOwner, identity.RoleAdmin, identity.RoleAuditor); err != nil {
				return nil, err
			}
			out := BackupStatus{Enabled: d.BackupEnabled, IntervalSeconds: int64(d.BackupInterval.Seconds()), Runs: []backup.Run{}}
			if d.Backups == nil {
				return &struct{ Body BackupStatus }{Body: out}, nil
			}
			if out.Enabled {
				k, err := d.Backups.VerifyKey()
				if err != nil {
					return nil, d.fail("backups", err)
				}
				out.VerifyKey = k
			}
			runs, err := d.Backups.Runs(ctx, 20)
			if err != nil {
				return nil, d.fail("backups", err)
			}
			out.Runs = runs
			return &struct{ Body BackupStatus }{Body: out}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "run-backup", Method: http.MethodPost, Path: "/installation/backups",
		DefaultStatus: http.StatusCreated, Summary: "Take a backup now (owner or admin)", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*struct{ Body backup.Run }, error) {
			if _, err := requireOperator(ctx, identity.RoleOwner, identity.RoleAdmin); err != nil {
				return nil, err
			}
			if d.Backups == nil || !d.BackupEnabled {
				return nil, problem(http.StatusConflict, apperr.CodeConflict, "backups are not configured (backup.enabled)", nil)
			}
			run, err := d.Backups.Run(ctx, "manual", change(ctx, "").Actor)
			if err != nil {
				return nil, problem(http.StatusBadGateway, "backup_failed", "backup failed: "+run.Error, nil)
			}
			return &struct{ Body backup.Run }{Body: run}, nil
		})
}

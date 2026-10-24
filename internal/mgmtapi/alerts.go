package mgmtapi

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/aurimasniekis/go-porch/internal/apperr"
	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/domain"
	"github.com/aurimasniekis/go-porch/internal/identity"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/store/db"
)

// Alert is a persistent operator alert.
type Alert struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	Severity  string    `json:"severity" enum:"info,warning,critical"`
	Message   string    `json:"message"`
	TargetID  string    `json:"target_id,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

func registerAlerts(api huma.API, d *Deps) {
	tags := []string{"installation"}
	huma.Register(api, huma.Operation{OperationID: "list-alerts", Method: http.MethodGet, Path: "/installation/alerts",
		Summary: "Open operator alerts", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*struct{ Body []Alert }, error) {
			if _, err := requireOperator(ctx, identity.RoleOwner, identity.RoleAdmin, identity.RoleAuditor); err != nil {
				return nil, err
			}
			rows, err := d.Store.R().ListOpenAlerts(ctx)
			if err != nil {
				return nil, d.fail("alerts", err)
			}
			out := make([]Alert, 0, len(rows))
			for _, r := range rows {
				out = append(out, Alert{ID: r.ID, Kind: r.Kind, Severity: r.Severity, Message: r.Message, TargetID: r.TargetID.String,
					CreatedAt: domain.FromMicros(r.CreatedAt)})
			}
			return &struct{ Body []Alert }{Body: out}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "acknowledge-alert", Method: http.MethodPost, Path: "/installation/alerts/{alert}/ack",
		DefaultStatus: http.StatusNoContent, Summary: "Acknowledge an alert", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			Alert string `path:"alert" maxLength:"64"`
		}) (*struct{}, error) {
			p, err := requireOperator(ctx, identity.RoleOwner, identity.RoleAdmin)
			if err != nil {
				return nil, err
			}
			err = d.Store.W().TxNamed(ctx, "alerts.ack", func(tx *store.Tx) error {
				n, err := tx.Q.AcknowledgeAlert(ctx, db.AcknowledgeAlertParams{AcknowledgedAt: domain.NullMicros(&tx.Now),
					AcknowledgedBy: domain.NullStr(p.UserID), ID: in.Alert})
				if err != nil {
					return err
				}
				if n == 0 {
					return apperr.New(apperr.CodeNotFound, "alert not found or already acknowledged")
				}
				_, err = d.Audit.Append(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorUser, ID: p.UserID}, Action: "alert.acknowledged",
					Target: audit.Target{Type: "alert", ID: in.Alert}})
				return err
			})
			if err != nil {
				return nil, d.fail("ack-alert", err)
			}
			return &struct{}{}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "unlock-backup-login", Method: http.MethodPost, Path: "/users/{user}/backup-lockout/unlock",
		DefaultStatus: http.StatusNoContent, Summary: "Clear a user's backup-login lockout (owner/admin, needs a recent sign-in)",
		Description: "There is deliberately no API to lock a user (ADR-0008).", Tags: []string{"users"}, Security: sessionSecurity},
		func(ctx context.Context, in *UserRef) (*struct{}, error) {
			p, err := requireOperator(ctx, identity.RoleOwner, identity.RoleAdmin)
			if err != nil {
				return nil, err
			}
			if err := d.stepUp(ctx); err != nil {
				return nil, err
			}
			if err := d.Local.Unlock(ctx, audit.Actor{Type: audit.ActorUser, ID: p.UserID}, in.User); err != nil {
				return nil, d.fail("unlock", err)
			}
			return &struct{}{}, nil
		})
}

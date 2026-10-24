package mgmtapi

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/aurimasniekis/go-porch/internal/apperr"
	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/authz"
	"github.com/aurimasniekis/go-porch/internal/identity"
	"github.com/aurimasniekis/go-porch/internal/keyring"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/store/db"
)

// AuditEvent is one audit record. Sensitive details are sealed at rest and never returned by the API.
type AuditEvent struct {
	ID              string         `json:"id"`
	Seq             int64          `json:"seq"`
	At              time.Time      `json:"at"`
	RequestID       string         `json:"request_id,omitempty"`
	ActorType       string         `json:"actor_type"`
	ActorID         string         `json:"actor_id,omitempty"`
	ActorName       string         `json:"actor_name,omitempty"`
	TenantID        string         `json:"tenant_id,omitempty"`
	Action          string         `json:"action"`
	TargetType      string         `json:"target_type,omitempty"`
	TargetID        string         `json:"target_id,omitempty"`
	Outcome         string         `json:"outcome" enum:"success,failure,denied"`
	ReasonCode      string         `json:"reason_code,omitempty"`
	SourceIP        string         `json:"source_ip,omitempty"`
	AuthMethod      string         `json:"auth_method,omitempty"`
	Details         map[string]any `json:"details,omitempty"`
	SealedDetails   bool           `json:"sealed_details" doc:"The event has encrypted details (readable only with host access)."`
	ChainHashPrefix string         `json:"chain_hash_prefix" doc:"First bytes of the event's chain hash (hex), for cross-checking exports."`
}

// AuditPage is one page of audit events, newest first.
type AuditPage struct {
	Items      []AuditEvent `json:"items"`
	NextCursor string       `json:"next_cursor,omitempty"`
}

// AuditQuery filters the audit log.
type AuditQuery struct {
	Actor   string    `query:"actor" maxLength:"64" doc:"Actor ID."`
	Target  string    `query:"target" maxLength:"64" doc:"Target ID."`
	Action  string    `query:"action" maxLength:"64" doc:"Action prefix, e.g. role. or oidc.token_issued."`
	Outcome string    `query:"outcome" enum:"success,failure,denied" required:"false"`
	Since   time.Time `query:"since" required:"false"`
	Until   time.Time `query:"until" required:"false"`
	Limit   int       `query:"limit" minimum:"1" maximum:"200" default:"50"`
	Cursor  string    `query:"cursor" maxLength:"20" doc:"Opaque cursor from next_cursor."`
}

var actionPrefixRE = regexp.MustCompile(`^[a-z_.]{1,64}$`)

func optStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (d *Deps) searchAudit(ctx context.Context, tenantID string, q AuditQuery) (AuditPage, error) {
	if q.Action != "" && !actionPrefixRE.MatchString(q.Action) {
		return AuditPage{}, problem(http.StatusUnprocessableEntity, apperr.CodeInvalid, "action must be lowercase letters, dots or underscores", nil)
	}
	before := int64(1<<63 - 1)
	if q.Cursor != "" {
		n, err := strconv.ParseInt(q.Cursor, 10, 64)
		if err != nil || n <= 0 {
			return AuditPage{}, problem(http.StatusBadRequest, apperr.CodeInvalid, "invalid cursor", nil)
		}
		before = n
	}
	until := int64(1<<63 - 1)
	if !q.Until.IsZero() {
		until = q.Until.UnixMicro()
	}
	var since int64
	if !q.Since.IsZero() {
		since = q.Since.UnixMicro()
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 50
	}
	rows, err := d.Store.R().SearchAuditEvents(ctx, db.SearchAuditEventsParams{BeforeSeq: before, TenantID: optStr(tenantID), ActorID: optStr(q.Actor),
		TargetID: optStr(q.Target), ActionPrefix: optStr(q.Action), Outcome: optStr(q.Outcome), Since: since, Until: until, Lim: int64(limit) + 1})
	if err != nil {
		return AuditPage{}, d.fail("audit-search", err)
	}
	out := AuditPage{Items: make([]AuditEvent, 0, len(rows))}
	if len(rows) > limit {
		rows = rows[:limit]
		out.NextCursor = strconv.FormatInt(rows[len(rows)-1].Seq, 10)
	}
	names := map[string]string{}
	for _, r := range rows {
		rec := audit.DecodeRecord(r)
		ev := AuditEvent{ID: rec.ID, Seq: rec.Seq, At: time.UnixMicro(rec.At).UTC(), RequestID: rec.RequestID, ActorType: rec.ActorType,
			ActorID: rec.ActorID, TenantID: rec.TenantID, Action: rec.Action, TargetType: rec.TargetType, TargetID: rec.TargetID, Outcome: rec.Outcome,
			ReasonCode: rec.ReasonCode, SourceIP: rec.SourceIP, AuthMethod: rec.AuthMethod, Details: rec.Details, SealedDetails: rec.HasSensitive}
		if len(r.Hash) >= 6 {
			ev.ChainHashPrefix = hexPrefix(r.Hash[:6])
		}
		if ev.ActorID != "" && (ev.ActorType == audit.ActorUser || ev.ActorType == "operator") {
			if n, ok := names[ev.ActorID]; ok {
				ev.ActorName = n
			} else if u, err := d.Store.R().GetUser(ctx, ev.ActorID); err == nil {
				names[ev.ActorID], ev.ActorName = u.DisplayName, u.DisplayName
			}
		}
		out.Items = append(out.Items, ev)
	}
	return out, nil
}

func hexPrefix(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}

// AdminSession is an active browser session (installation view).
type AdminSession struct {
	ID         string    `json:"id"`
	UserID     string    `json:"user_id"`
	UserName   string    `json:"user_name"`
	UserEmail  string    `json:"user_email,omitempty"`
	TenantID   string    `json:"tenant_id,omitempty"`
	Method     string    `json:"method"`
	AuthTime   time.Time `json:"auth_time"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	IP         string    `json:"ip,omitempty"`
	UserAgent  string    `json:"user_agent,omitempty"`
	Current    bool      `json:"current"`
}

// SystemHealth summarises the installation for operators.
type SystemHealth struct {
	Version        string                  `json:"version"`
	StartedAt      time.Time               `json:"started_at"`
	Ready          bool                    `json:"ready"`
	ReadyError     string                  `json:"ready_error,omitempty"`
	Storage        store.HealthStatus      `json:"storage"`
	DBBytes        int64                   `json:"db_bytes"`
	WALBytes       int64                   `json:"wal_bytes"`
	Keyring        []keyring.PurposeStatus `json:"keyring"`
	OutboxPending  int64                   `json:"outbox_pending"`
	OutboxDead     int64                   `json:"outbox_dead"`
	OutboxOldest   *time.Time              `json:"outbox_oldest_pending_at,omitempty"`
	OpenAlerts     int                     `json:"open_alerts"`
	AuditEvents    int64                   `json:"audit_events"`
	Tenants        int64                   `json:"tenants"`
	Users          int64                   `json:"users"`
	ActiveSessions int64                   `json:"active_sessions"`
	Backups        BackupHealth            `json:"backups"`
	Checks         []SystemCheck           `json:"checks"`
}

// BackupHealth reports backup status (backups arrive in M6).
type BackupHealth struct {
	Configured bool       `json:"configured"`
	LastAt     *time.Time `json:"last_at,omitempty"`
	LastOK     bool       `json:"last_ok"`
}

// SystemCheck is one named health check.
type SystemCheck struct {
	Name   string `json:"name"`
	Status string `json:"status" enum:"ok,warning,critical"`
	Detail string `json:"detail,omitempty"`
}

func registerOps(api huma.API, d *Deps) {
	tags := []string{"operations"}
	huma.Register(api, huma.Operation{OperationID: "search-audit", Method: http.MethodGet, Path: "/audit",
		Summary: "Search the installation audit log (owner, admin or auditor)", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			AuditQuery
			Tenant string `query:"tenant" maxLength:"64" doc:"Tenant ID."`
		}) (*struct{ Body AuditPage }, error) {
			if _, err := requireOperator(ctx, identity.RoleOwner, identity.RoleAdmin, identity.RoleAuditor); err != nil {
				return nil, err
			}
			page, err := d.searchAudit(ctx, in.Tenant, in.AuditQuery)
			if err != nil {
				return nil, err
			}
			return &struct{ Body AuditPage }{Body: page}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "search-tenant-audit", Method: http.MethodGet, Path: "/tenants/{tenant}/audit",
		Summary: "Search a tenant's audit events (audit:read)", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			TenantRef
			AuditQuery
		}) (*struct{ Body AuditPage }, error) {
			sc, err := d.tenantAdmin(ctx, in.Tenant, authz.PermAuditRead)
			if err != nil {
				return nil, err
			}
			page, err := d.searchAudit(ctx, sc.TenantID(), in.AuditQuery)
			if err != nil {
				return nil, err
			}
			return &struct{ Body AuditPage }{Body: page}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "list-sessions", Method: http.MethodGet, Path: "/sessions",
		Summary: "Active browser sessions across the installation (owner or admin)", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			User  string `query:"user" maxLength:"64" doc:"Only this user's sessions."`
			Limit int    `query:"limit" minimum:"1" maximum:"500" default:"200"`
		}) (*struct{ Body []AdminSession }, error) {
			p, err := requireOperator(ctx, identity.RoleOwner, identity.RoleAdmin)
			if err != nil {
				return nil, err
			}
			limit := in.Limit
			if limit <= 0 {
				limit = 200
			}
			rows, err := d.Store.R().ListActiveSessions(ctx, db.ListActiveSessionsParams{Now: d.now().UnixMicro(), UserID: optStr(in.User), Lim: int64(limit)})
			if err != nil {
				return nil, d.fail("list-sessions", err)
			}
			out := make([]AdminSession, 0, len(rows))
			for _, r := range rows {
				out = append(out, AdminSession{ID: r.ID, UserID: r.UserID, UserName: r.DisplayName, UserEmail: r.PrimaryEmail.String,
					TenantID: r.TenantID.String, Method: r.Method, AuthTime: time.UnixMicro(r.AuthTime).UTC(), CreatedAt: time.UnixMicro(r.CreatedAt).UTC(),
					LastSeenAt: time.UnixMicro(r.LastSeenAt).UTC(), ExpiresAt: time.UnixMicro(r.AbsoluteExpiresAt).UTC(), IP: r.Ip, UserAgent: r.UserAgent,
					Current: r.ID == p.SessionID})
			}
			return &struct{ Body []AdminSession }{Body: out}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "revoke-session", Method: http.MethodDelete, Path: "/sessions/{session}",
		DefaultStatus: http.StatusNoContent, Summary: "End a browser session (owner or admin)", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			Session string `path:"session" maxLength:"64"`
		}) (*struct{}, error) {
			if _, err := requireOperator(ctx, identity.RoleOwner, identity.RoleAdmin); err != nil {
				return nil, err
			}
			err := d.Store.W().TxNamed(ctx, "session.admin_revoke", func(tx *store.Tx) error {
				row, err := tx.Q.GetSession(ctx, in.Session)
				if errors.Is(err, sql.ErrNoRows) || (err == nil && row.RevokedAt.Valid) {
					return apperr.New(apperr.CodeNotFound, "session not found")
				}
				if err != nil {
					return err
				}
				if err := d.Sessions.RevokeTx(ctx, tx, row.ID, "admin"); err != nil {
					return err
				}
				_, err = d.Audit.Append(ctx, tx, audit.Event{Actor: change(ctx, "").Actor, Action: "session.revoked_by_admin",
					Target: audit.Target{Type: "session", ID: row.ID}, Details: map[string]any{"user_id": row.UserID}})
				return err
			})
			if err != nil {
				return nil, d.fail("revoke-session", err)
			}
			return &struct{}{}, nil
		})
	huma.Register(api, huma.Operation{OperationID: "revoke-user-sessions", Method: http.MethodPost, Path: "/users/{user}/revoke-sessions",
		DefaultStatus: http.StatusNoContent, Summary: "End every session of a user (owner or admin; needs a recent sign-in)", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			User string `path:"user" maxLength:"64"`
		}) (*struct{}, error) {
			if _, err := requireOperator(ctx, identity.RoleOwner, identity.RoleAdmin); err != nil {
				return nil, err
			}
			if err := d.stepUp(ctx); err != nil {
				return nil, err
			}
			err := d.Store.W().TxNamed(ctx, "session.admin_revoke_user", func(tx *store.Tx) error {
				if _, err := tx.Q.GetUser(ctx, in.User); err != nil {
					return apperr.New(apperr.CodeNotFound, "user not found")
				}
				n, err := tx.Q.RevokeUserSessions(ctx, db.RevokeUserSessionsParams{RevokedAt: sql.NullInt64{Int64: tx.NowMicros(), Valid: true},
					RevokeReason: sql.NullString{String: "admin", Valid: true}, UserID: in.User})
				if err != nil {
					return err
				}
				_, err = d.Audit.Append(ctx, tx, audit.Event{Actor: change(ctx, "").Actor, Action: "session.user_revoked_by_admin",
					Target: audit.Target{Type: "user", ID: in.User}, Details: map[string]any{"sessions": n}})
				return err
			})
			if err != nil {
				return nil, d.fail("revoke-user-sessions", err)
			}
			return &struct{}{}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "get-system-health", Method: http.MethodGet, Path: "/installation/health",
		Summary: "System health (owner, admin or auditor)", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*struct{ Body SystemHealth }, error) {
			if _, err := requireOperator(ctx, identity.RoleOwner, identity.RoleAdmin, identity.RoleAuditor); err != nil {
				return nil, err
			}
			h, err := d.systemHealth(ctx)
			if err != nil {
				return nil, d.fail("health", err)
			}
			return &struct{ Body SystemHealth }{Body: h}, nil
		})
}

func (d *Deps) systemHealth(ctx context.Context) (SystemHealth, error) {
	q := d.Store.R()
	h := SystemHealth{Version: d.Version, StartedAt: d.StartedAt, Storage: d.Store.Health().Status(), Checks: []SystemCheck{}}
	h.DBBytes, h.WALBytes = d.Store.Sizes()
	if d.Ready != nil {
		if err := d.Ready(ctx); err != nil {
			h.ReadyError = err.Error()
		} else {
			h.Ready = true
		}
	}
	if d.Keyring != nil {
		h.Keyring = d.Keyring.Status()
	}
	ob, err := q.CountOutbox(ctx)
	if err != nil {
		return h, err
	}
	h.OutboxPending, h.OutboxDead = toInt(ob.Pending), toInt(ob.Dead)
	if oldest := toInt(ob.OldestPendingAt); oldest > 0 {
		t := time.UnixMicro(oldest).UTC()
		h.OutboxOldest = &t
	}
	alerts, err := q.ListOpenAlerts(ctx)
	if err != nil {
		return h, err
	}
	h.OpenAlerts = len(alerts)
	if h.AuditEvents, err = q.CountAuditEvents(ctx); err != nil {
		return h, err
	}
	if h.Tenants, err = q.CountTenants(ctx); err != nil {
		return h, err
	}
	if h.Users, err = q.CountUsers(ctx); err != nil {
		return h, err
	}
	if h.ActiveSessions, err = q.CountActiveSessions(ctx, d.now().UnixMicro()); err != nil {
		return h, err
	}
	add := func(name, status, detail string) {
		h.Checks = append(h.Checks, SystemCheck{Name: name, Status: status, Detail: detail})
	}
	switch h.Storage.State {
	case store.HealthOK:
		add("storage", "ok", "")
	case store.HealthDegraded:
		add("storage", "warning", h.Storage.Reason)
	default:
		add("storage", "critical", h.Storage.Reason)
	}
	if h.Ready {
		add("readiness", "ok", "")
	} else {
		add("readiness", "critical", h.ReadyError)
	}
	switch {
	case h.OutboxDead > 0:
		add("events", "warning", strconv.FormatInt(h.OutboxDead, 10)+" events dead-lettered")
	case h.OutboxOldest != nil && d.now().Sub(*h.OutboxOldest) > 15*time.Minute:
		add("events", "warning", "oldest pending event is older than 15 minutes (is the event relay configured?)")
	default:
		add("events", "ok", "")
	}
	if h.OpenAlerts > 0 {
		add("alerts", "warning", strconv.Itoa(h.OpenAlerts)+" open alerts")
	} else {
		add("alerts", "ok", "")
	}
	add("backups", "warning", "backups are not configured (milestone M6)")
	return h, nil
}

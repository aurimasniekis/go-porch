// Package outbox records domain events in the same write transaction as the change they describe (ADR-0019). A relay
// publishes them to pulse later; publishing never blocks or fails a request.
package outbox

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/aurimasniekis/go-porch/internal/ids"
	"github.com/aurimasniekis/go-porch/internal/obs/redact"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/store/db"
)

// Event is one domain event. Payload must contain only non-secret fields; keys that look secret are rejected.
type Event struct {
	// Area, Entity and Action name the event: type porch.<area>.<entity>_<action>.v1, subject
	// evt.porch.<area>.<entity>.<action>.
	Area, Entity, Action string
	TenantID             string
	Payload              map[string]any
}

var segment = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// Type returns the CloudEvents type, e.g. porch.tenancy.tenant_created.v1.
func (e Event) Type() string { return "porch." + e.Area + "." + e.Entity + "_" + e.Action + ".v1" }

// Subject returns the NATS subject, e.g. evt.porch.tenancy.tenant.created.
func (e Event) Subject() string { return "evt.porch." + e.Area + "." + e.Entity + "." + e.Action }

// Enqueue stores ev inside tx and returns its stable ID (the event ID consumers deduplicate on).
func Enqueue(ctx context.Context, tx *store.Tx, ev Event) (string, error) {
	for _, s := range []string{ev.Area, ev.Entity, ev.Action} {
		if !segment.MatchString(s) {
			return "", fmt.Errorf("outbox: invalid event name segment %q", s)
		}
	}
	for k := range ev.Payload {
		if redact.IsSensitiveKey(k) {
			return "", fmt.Errorf("outbox: sensitive key %q in event payload", k)
		}
	}
	payload := ev.Payload
	if payload == nil {
		payload = map[string]any{}
	}
	if ev.TenantID != "" {
		payload["tenant_id"] = ev.TenantID
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	id := ids.New(ids.Outbox)
	err = tx.Q.InsertOutbox(ctx, db.InsertOutboxParams{
		ID: id, Type: ev.Type(), Subject: ev.Subject(), TenantID: nullStr(ev.TenantID), PayloadJson: string(b),
		CreatedAt: tx.NowMicros(), NextAttemptAt: tx.NowMicros(),
	})
	return id, err
}

func nullStr(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

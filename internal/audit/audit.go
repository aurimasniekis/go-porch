// Adapted from HallPass internal/audit/audit.go (Apache-2.0).

// Package audit writes the append-only, hash-chained audit log (ADR-0019).
//
// Every security-relevant action appends an event inside the same write transaction as the change it describes,
// so the audit trail and the state can never disagree. Each row stores hash = SHA-256(prev_hash || canonical row),
// which makes deletion, reordering or modification inside the database detectable by Verify. A party able to rewrite
// the whole chain (with database write access) is out of scope here; see external anchoring.
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/aurimasniekis/go-porch/internal/ids"
	"github.com/aurimasniekis/go-porch/internal/keyring"
	"github.com/aurimasniekis/go-porch/internal/obs/redact"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/store/db"
)

// Actor types.
const (
	ActorUser           = "user"
	ActorOperator       = "operator"
	ActorServiceAccount = "service_account"
	ActorAutomation     = "automation"
	ActorSystem         = "system"
	ActorCLI            = "cli"
	ActorClient         = "client"
)

// Outcomes.
const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
	OutcomeDenied  = "denied"
)

// Actor identifies who performed an action.
type Actor struct {
	Type string
	ID   string
}

// System is the actor for automatic actions (expiry, reconciliation, jobs).
var System = Actor{Type: ActorSystem, ID: "porch"}

// CLI is the actor for host-side administrative commands.
var CLI = Actor{Type: ActorCLI, ID: "porch-cli"}

// Target identifies what an action applied to.
type Target struct {
	Type string
	ID   string
}

// Event is one audit record (schema v1).
type Event struct {
	Actor      Actor
	TenantID   string
	Action     string // dotted, e.g. "tenant.created"
	Target     Target
	Outcome    string
	ReasonCode string // stable machine-readable reason for failures and denials
	SourceIP   string // trusted client IP (from the proxy-aware resolver), never a raw header
	AuthMethod string
	RequestID  string
	// Details are non-sensitive structured fields stored in plaintext. Keys that look sensitive (see redact) are
	// rejected: put such values in Sensitive.
	Details map[string]any
	// Sensitive details (free text, reasons) are sealed with the field key.
	Sensitive map[string]any
}

// Record is a stored audit event as returned to readers and sinks.
type Record struct {
	ID           string         `json:"id"`
	Seq          int64          `json:"seq"`
	At           int64          `json:"at"`
	RequestID    string         `json:"request_id,omitempty"`
	ActorType    string         `json:"actor_type"`
	ActorID      string         `json:"actor_id,omitempty"`
	TenantID     string         `json:"tenant_id,omitempty"`
	Action       string         `json:"action"`
	TargetType   string         `json:"target_type,omitempty"`
	TargetID     string         `json:"target_id,omitempty"`
	Outcome      string         `json:"outcome"`
	ReasonCode   string         `json:"reason_code,omitempty"`
	SourceIP     string         `json:"source_ip,omitempty"`
	AuthMethod   string         `json:"auth_method,omitempty"`
	Details      map[string]any `json:"details,omitempty"`
	HasSensitive bool           `json:"has_sensitive,omitempty"`
}

// Sink receives committed audit records (e.g. a JSON-lines file for SIEM ingestion).
type Sink interface {
	Write(Record) error
}

// Writer appends audit events.
type Writer struct {
	kr   *keyring.Keyring
	mu   sync.RWMutex
	sink Sink
}

// NewWriter returns a writer. kr may be nil only if events never carry sensitive details.
func NewWriter(kr *keyring.Keyring) *Writer { return &Writer{kr: kr} }

// SetSink attaches a sink that receives every record after its transaction commits.
func (w *Writer) SetSink(s Sink) {
	w.mu.Lock()
	w.sink = s
	w.mu.Unlock()
}

// GenesisHash is the prev_hash of the first event.
var GenesisHash = make([]byte, sha256.Size)

// ErrSensitiveDetail means a plaintext detail key names a secret-like value.
var ErrSensitiveDetail = errors.New("audit: sensitive key in plaintext details")

// Append writes ev inside tx and returns its ID. An error must abort the caller's transaction: a mutation without its
// audit record never commits.
func (w *Writer) Append(ctx context.Context, tx *store.Tx, ev Event) (string, error) {
	if ev.Action == "" || ev.Actor.Type == "" {
		return "", errors.New("audit: action and actor type are required")
	}
	if ev.Outcome == "" {
		ev.Outcome = OutcomeSuccess
	}
	for k := range ev.Details {
		if redact.IsSensitiveKey(k) {
			return "", fmt.Errorf("%w: %q", ErrSensitiveDetail, k)
		}
	}
	m := MetaFrom(ctx)
	if ev.SourceIP == "" {
		ev.SourceIP = m.SourceIP
	}
	if ev.RequestID == "" {
		ev.RequestID = m.RequestID
	}
	if ev.AuthMethod == "" {
		ev.AuthMethod = m.AuthMethod
	}
	details, err := canonicalJSON(ev.Details)
	if err != nil {
		return "", fmt.Errorf("audit details: %w", err)
	}
	id := ids.New(ids.Audit)
	var enc []byte
	if len(ev.Sensitive) > 0 {
		if w.kr == nil {
			return "", errors.New("audit: sensitive details require a keyring")
		}
		pt, err := canonicalJSON(ev.Sensitive)
		if err != nil {
			return "", err
		}
		if enc, err = w.kr.Seal(keyring.PurposeField, keyring.FieldAAD("audit_events", "details_enc", id), []byte(pt)); err != nil {
			return "", err
		}
	}
	seq := int64(1)
	prev := GenesisHash
	last, err := tx.Q.LastAuditEvent(ctx)
	switch {
	case err == nil:
		seq, prev = last.Seq+1, last.Hash
	case !errors.Is(err, sql.ErrNoRows):
		return "", err
	}
	rec := Record{ID: id, Seq: seq, At: tx.NowMicros(), RequestID: ev.RequestID, ActorType: ev.Actor.Type, ActorID: ev.Actor.ID,
		TenantID: ev.TenantID, Action: ev.Action, TargetType: ev.Target.Type, TargetID: ev.Target.ID, Outcome: ev.Outcome,
		ReasonCode: ev.ReasonCode, SourceIP: ev.SourceIP, AuthMethod: ev.AuthMethod, Details: ev.Details, HasSensitive: enc != nil}
	hash := chainHash(prev, rowFields(rec, details, enc))
	err = tx.Q.InsertAuditEvent(ctx, db.InsertAuditEventParams{
		ID: id, Seq: seq, At: rec.At, RequestID: nullStr(rec.RequestID), ActorType: rec.ActorType, ActorID: nullStr(rec.ActorID),
		TenantID: nullStr(rec.TenantID), Action: rec.Action, TargetType: nullStr(rec.TargetType), TargetID: nullStr(rec.TargetID),
		Outcome: rec.Outcome, ReasonCode: nullStr(rec.ReasonCode), SourceIp: nullStr(rec.SourceIP), AuthMethod: nullStr(rec.AuthMethod),
		DetailsJson: details, DetailsEnc: enc, PrevHash: prev, Hash: hash,
	})
	if err != nil {
		return "", err
	}
	w.mu.RLock()
	sink := w.sink
	w.mu.RUnlock()
	if sink != nil {
		tx.AfterCommit(func() { _ = sink.Write(rec) })
	}
	return id, nil
}

func nullStr(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

// canonicalJSON renders m with sorted keys (encoding/json sorts map keys); nil → "{}".
func canonicalJSON(m map[string]any) (string, error) {
	if len(m) == 0 {
		return "{}", nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// rowFields length-prefixes every field so that no two distinct rows serialize identically.
func rowFields(r Record, details string, enc []byte) []byte {
	var buf bytes.Buffer
	writeField := func(b []byte) {
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(b)))
		buf.Write(l[:])
		buf.Write(b)
	}
	var n [8]byte
	writeField([]byte("porch/audit/v1"))
	writeField([]byte(r.ID))
	binary.BigEndian.PutUint64(n[:], uint64(r.Seq)) //nolint:gosec // positive by CHECK
	writeField(n[:])
	binary.BigEndian.PutUint64(n[:], uint64(r.At)) //nolint:gosec // timestamps are positive
	writeField(n[:])
	for _, s := range []string{r.RequestID, r.ActorType, r.ActorID, r.TenantID, r.Action, r.TargetType, r.TargetID, r.Outcome,
		r.ReasonCode, r.SourceIP, r.AuthMethod, details} {
		writeField([]byte(s))
	}
	writeField(enc)
	return buf.Bytes()
}

func chainHash(prev, fields []byte) []byte {
	h := sha256.New()
	h.Write(prev)
	h.Write(fields)
	return h.Sum(nil)
}

// VerifyResult summarizes a chain verification.
type VerifyResult struct {
	Events   int64  `json:"events"`
	OK       bool   `json:"ok"`
	BrokenAt int64  `json:"broken_at,omitempty"`
	Problem  string `json:"problem,omitempty"`
	HeadHash []byte `json:"head_hash,omitempty"`
}

// Verify walks the whole chain in sequence order and reports the first inconsistency (ADR-0019).
func Verify(ctx context.Context, q *db.Queries) (VerifyResult, error) {
	const page = 1000
	res := VerifyResult{OK: true}
	prev := GenesisHash
	var after, expectSeq int64 = 0, 1
	for {
		rows, err := q.AuditEventsFrom(ctx, db.AuditEventsFromParams{Seq: after, Limit: page})
		if err != nil {
			return res, err
		}
		for _, r := range rows {
			res.Events++
			switch {
			case r.Seq != expectSeq:
				return fail(res, r.Seq, fmt.Sprintf("sequence gap: expected %d, found %d (events deleted)", expectSeq, r.Seq)), nil
			case !bytes.Equal(r.PrevHash, prev):
				return fail(res, r.Seq, "prev_hash does not match the previous event (events reordered or deleted)"), nil
			}
			want := chainHash(prev, rowFields(DecodeRecord(r), r.DetailsJson, r.DetailsEnc))
			if !bytes.Equal(want, r.Hash) {
				return fail(res, r.Seq, "hash mismatch (event modified)"), nil
			}
			prev, after = r.Hash, r.Seq
			expectSeq++
		}
		if len(rows) < page {
			res.HeadHash = prev
			return res, nil
		}
	}
}

func fail(res VerifyResult, seq int64, problem string) VerifyResult {
	res.OK, res.BrokenAt, res.Problem = false, seq, problem
	return res
}

// DecodeRecord converts a stored row to a Record (without decrypting sensitive details).
func DecodeRecord(r db.AuditEvent) Record {
	rec := Record{
		ID: r.ID, Seq: r.Seq, At: r.At, RequestID: r.RequestID.String, ActorType: r.ActorType, ActorID: r.ActorID.String,
		TenantID: r.TenantID.String, Action: r.Action, TargetType: r.TargetType.String, TargetID: r.TargetID.String,
		Outcome: r.Outcome, ReasonCode: r.ReasonCode.String, SourceIP: r.SourceIp.String, AuthMethod: r.AuthMethod.String,
		HasSensitive: len(r.DetailsEnc) > 0,
	}
	if r.DetailsJson != "" && r.DetailsJson != "{}" {
		_ = json.Unmarshal([]byte(r.DetailsJson), &rec.Details)
	}
	return rec
}

// OpenSensitive decrypts the sensitive details of a stored event.
func (w *Writer) OpenSensitive(r db.AuditEvent) (map[string]any, error) {
	if len(r.DetailsEnc) == 0 {
		return nil, nil
	}
	pt, err := w.kr.Open(keyring.PurposeField, keyring.FieldAAD("audit_events", "details_enc", r.ID), r.DetailsEnc)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(pt, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// JSONSink writes one ECS-aligned JSON object per line (for OpenSearch / Elastic ingestion).
type JSONSink struct {
	mu sync.Mutex
	w  io.Writer
}

// NewJSONSink returns a sink writing to w.
func NewJSONSink(w io.Writer) *JSONSink { return &JSONSink{w: w} }

// ECS renders r with Elastic Common Schema field names; Porch-specific fields live under "porch".
func ECS(r Record) map[string]any {
	outcome := r.Outcome
	if outcome == OutcomeDenied {
		outcome = "failure"
	}
	ev := map[string]any{
		"@timestamp": time.UnixMicro(r.At).UTC().Format(time.RFC3339Nano),
		"ecs":        map[string]any{"version": "8.11.0"},
		"event": map[string]any{
			"id": r.ID, "kind": "event", "category": []string{"iam"}, "action": r.Action, "outcome": outcome,
			"sequence": r.Seq, "dataset": "porch.audit",
		},
		"porch": map[string]any{
			"audit": map[string]any{"schema": 1, "outcome": r.Outcome, "reason_code": r.ReasonCode, "auth_method": r.AuthMethod,
				"target": map[string]any{"type": r.TargetType, "id": r.TargetID}, "details": r.Details, "has_sensitive": r.HasSensitive},
			"tenant": map[string]any{"id": r.TenantID},
		},
		"user": map[string]any{"id": r.ActorID},
	}
	if r.ActorType != "" {
		ev["porch"].(map[string]any)["actor"] = map[string]any{"type": r.ActorType}
	}
	if r.SourceIP != "" {
		ev["source"] = map[string]any{"ip": r.SourceIP}
	}
	if r.RequestID != "" {
		ev["http"] = map[string]any{"request": map[string]any{"id": r.RequestID}}
	}
	return ev
}

// Write implements Sink.
func (s *JSONSink) Write(r Record) error {
	b, err := json.Marshal(ECS(r))
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.w.Write(append(b, '\n'))
	return err
}

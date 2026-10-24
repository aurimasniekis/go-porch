// Package domain holds small types shared by Porch's domain services: who made a change (provenance), cursor
// pagination and identifier validation.
package domain

import (
	"database/sql"
	"encoding/base64"
	"regexp"
	"strings"
	"time"

	"github.com/aurimasniekis/go-porch/internal/apperr"
	"github.com/aurimasniekis/go-porch/internal/audit"
)

// Managed-by values (ADR-0016). Provenance is informational, not a security boundary.
const (
	ManagedUI        = "ui"
	ManagedAPI       = "api"
	ManagedTerraform = "terraform"
	ManagedSystem    = "system"
)

// Change describes who is making a mutation and through which channel.
type Change struct {
	Actor     audit.Actor
	ManagedBy string
}

// ChangedBy renders the actor for last_changed_by columns ("user:usr_…").
func (c Change) ChangedBy() string {
	if c.Actor.ID == "" {
		return c.Actor.Type
	}
	return c.Actor.Type + ":" + c.Actor.ID
}

// Managed returns ManagedBy, defaulting to api.
func (c Change) Managed() string {
	switch c.ManagedBy {
	case ManagedUI, ManagedAPI, ManagedTerraform, ManagedSystem:
		return c.ManagedBy
	}
	return ManagedAPI
}

// SystemChange is a change made by Porch itself.
var SystemChange = Change{Actor: audit.System, ManagedBy: ManagedSystem}

// Page requests one page of a list ordered by ID.
type Page struct {
	Limit int
	After string // decoded cursor: last ID of the previous page
}

// MaxPageSize bounds list responses.
const MaxPageSize = 200

// ParsePage validates limit and an opaque cursor.
func ParsePage(limit int, cursor string) (Page, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > MaxPageSize {
		limit = MaxPageSize
	}
	p := Page{Limit: limit}
	if cursor != "" {
		b, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil || len(b) == 0 || len(b) > 64 {
			return p, apperr.New(apperr.CodeInvalid, "invalid cursor")
		}
		p.After = string(b)
	}
	return p, nil
}

// NextCursor returns the cursor for the page after lastID, or "" when the page was not full.
func NextCursor(n, limit int, lastID string) string {
	if n < limit || lastID == "" {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString([]byte(lastID))
}

var slugRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidSlug reports whether s is a DNS-label-like slug (lowercase, digits, inner hyphens, ≤ 63).
func ValidSlug(s string) bool { return slugRE.MatchString(s) }

// CleanName trims a display name and checks its length (1..200 runes) and absence of control characters.
func CleanName(field, s string, v *apperr.Validation) string {
	s = strings.TrimSpace(s)
	n := len([]rune(s))
	if n == 0 || n > 200 {
		v.Add(field, "must be 1..200 characters")
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			v.Add(field, "must not contain control characters")
			break
		}
	}
	return s
}

// NullStr converts "" to NULL.
func NullStr(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

// NullMicros converts a nil time to NULL.
func NullMicros(t *time.Time) sql.NullInt64 {
	if t == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: t.UnixMicro(), Valid: true}
}

// FromMicros converts persisted microseconds to UTC time.
func FromMicros(us int64) time.Time { return time.UnixMicro(us).UTC() }

// OptMicros converts a nullable column to *time.Time.
func OptMicros(n sql.NullInt64) *time.Time {
	if !n.Valid {
		return nil
	}
	t := FromMicros(n.Int64)
	return &t
}

// IfMatch compares an expected version (0 = unconditional) with the current one.
func IfMatch(expected, current int64) error {
	if expected != 0 && expected != current {
		return apperr.New(apperr.CodePrecondition, "resource was changed (version %d, you sent %d); reload and retry", current, expected)
	}
	return nil
}

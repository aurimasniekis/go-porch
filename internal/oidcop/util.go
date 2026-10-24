package oidcop

import (
	"database/sql"
	"encoding/json"
	"time"
)

func sqlMicros(t time.Time) sql.NullInt64 { return sql.NullInt64{Int64: t.UnixMicro(), Valid: true} }

func jsonList(s string) []string {
	var out []string
	_ = json.Unmarshal([]byte(s), &out)
	if out == nil {
		out = []string{}
	}
	return out
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

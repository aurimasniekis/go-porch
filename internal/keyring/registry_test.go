package keyring_test

import (
	"context"
	"strings"
	"testing"

	"github.com/aurimasniekis/go-porch/internal/keyring"
	"github.com/aurimasniekis/go-porch/internal/store/storetest"
)

// Every *_enc column in the schema must be in keyring.Columns, so rotation, retirement and backups never miss one
// (fixes HallPass SR-36/37).
func TestSealedColumnRegistryComplete(t *testing.T) {
	s := storetest.Open(t)
	ctx := context.Background()
	registered := map[string]bool{}
	for _, c := range keyring.Columns {
		registered[c.Table+"."+c.BlobColumn] = true
	}
	rows, err := s.ReadDB().QueryContext(ctx, `SELECT m.name, p.name FROM sqlite_master m JOIN pragma_table_info(m.name) p
		WHERE m.type = 'table' AND p.name LIKE '%\_enc' ESCAPE '\'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var table, col string
		if err := rows.Scan(&table, &col); err != nil {
			t.Fatal(err)
		}
		n++
		if !registered[table+"."+col] {
			t.Errorf("sealed column %s.%s is not registered in keyring.Columns", table, col)
		}
		delete(registered, table+"."+col)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for k := range registered {
		if !strings.Contains(k, ".") {
			continue
		}
		t.Errorf("keyring.Columns lists %s which does not exist in the schema", k)
	}
	if n == 0 {
		t.Fatal("no sealed columns found; query broken?")
	}
}

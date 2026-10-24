package mgmtapi

import (
	"net/http"
	"regexp"
	"testing"

	"github.com/danielgtaylor/huma/v2"
)

// Every {param} in a path must be a declared path parameter. Huma silently ignores fields of unexported embedded
// structs, which once left /tenants/{tenant}/members unbound; this test keeps that from regressing.
func TestPathParamsBound(t *testing.T) {
	api := New(http.NewServeMux(), &Deps{Version: "test"})
	re := regexp.MustCompile(`\{([^}]+)\}`)
	for path, item := range api.OpenAPI().Paths {
		for _, op := range []*huma.Operation{item.Get, item.Post, item.Put, item.Patch, item.Delete} {
			if op == nil {
				continue
			}
			declared := map[string]bool{}
			for _, p := range op.Parameters {
				if p.In == "path" {
					declared[p.Name] = true
				}
			}
			for _, m := range re.FindAllStringSubmatch(path, -1) {
				if !declared[m[1]] {
					t.Errorf("%s %s: path parameter %q not bound", op.OperationID, path, m[1])
				}
			}
		}
	}
}

// Every operation except the explicitly public ones requires the session scheme.
func TestOperationsRequireAuth(t *testing.T) {
	public := map[string]bool{"get-setup-status": true, "complete-setup": true}
	api := New(http.NewServeMux(), &Deps{Version: "test"})
	for path, item := range api.OpenAPI().Paths {
		for _, op := range []*huma.Operation{item.Get, item.Post, item.Put, item.Patch, item.Delete} {
			if op == nil {
				continue
			}
			if !public[op.OperationID] && len(op.Security) == 0 {
				t.Errorf("%s %s has no security requirement", op.OperationID, path)
			}
		}
	}
}

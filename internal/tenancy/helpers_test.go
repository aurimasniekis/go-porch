package tenancy_test

import (
	"testing"

	"github.com/aurimasniekis/go-porch/internal/domain"
)

func mustPage(t *testing.T) domain.Page {
	t.Helper()
	p, err := domain.ParsePage(100, "")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

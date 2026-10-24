// Adapted from HallPass internal/keyring/keyringtest/keyringtest.go (Apache-2.0).

// Package keyringtest loads a keyring with a random KEK for tests.
package keyringtest

import (
	"context"
	"testing"

	"github.com/aurimasniekis/go-porch/internal/keyring"
	"github.com/aurimasniekis/go-porch/internal/store"
)

// Load returns a keyring for s with a freshly generated KEK.
func Load(t testing.TB, s *store.Store) *keyring.Keyring {
	t.Helper()
	k, err := keyring.GenerateKEK()
	if err != nil {
		t.Fatal(err)
	}
	w, err := keyring.NewLocalKEK(k)
	if err != nil {
		t.Fatal(err)
	}
	kr, err := keyring.Load(context.Background(), s, w)
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

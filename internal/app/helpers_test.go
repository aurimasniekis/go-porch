package app_test

import "github.com/aurimasniekis/go-porch/internal/identity"

type identityCreate = identity.CreateParams

func userStatus(s string) identity.UpdateParams { return identity.UpdateParams{Status: &s} }

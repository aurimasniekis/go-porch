package session_test

import (
	"time"

	"github.com/aurimasniekis/go-porch/internal/tenancy"
)

func tenancyIdle(d time.Duration) tenancy.UpdateParams { return tenancy.UpdateParams{SessionIdle: &d} }

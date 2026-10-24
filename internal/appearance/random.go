package appearance

import (
	"crypto/rand"
	"math/big"
)

// randN returns a uniform integer in [0, n) from crypto/rand (the repository bans math/rand outright).
func randN(n int) int {
	if n <= 1 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(v.Int64())
}

// shuffle permutes s in place (Fisher–Yates).
func shuffle[T any](s []T) {
	for i := len(s) - 1; i > 0; i-- {
		j := randN(i + 1)
		s[i], s[j] = s[j], s[i]
	}
}

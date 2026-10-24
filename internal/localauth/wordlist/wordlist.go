// Package wordlist embeds the EFF Large Wordlist for Passphrases (CC BY 3.0 US, Electronic Frontier Foundation; see
// NOTICE) and draws random words with crypto/rand for the optional "suggest random words" action (ADR-0009).
package wordlist

import (
	"crypto/rand"
	_ "embed"
	"math/big"
	"strings"
	"sync"
)

//go:embed eff_large_wordlist.txt
var raw string

var (
	once  sync.Once
	words []string
)

// Words returns the 7776 words.
func Words() []string {
	once.Do(func() {
		for line := range strings.SplitSeq(strings.TrimSpace(raw), "\n") {
			if _, w, ok := strings.Cut(strings.TrimSpace(line), "\t"); ok {
				words = append(words, w)
			}
		}
	})
	return words
}

// Random returns n uniformly random words.
func Random(n int) ([]string, error) {
	ws := Words()
	out := make([]string, n)
	limit := big.NewInt(int64(len(ws)))
	for i := range n {
		k, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return nil, err
		}
		out[i] = ws[k.Int64()]
	}
	return out, nil
}

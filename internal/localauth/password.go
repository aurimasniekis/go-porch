// Package localauth implements the local backup login (ADR-0008, ADR-0009): a password plus user-defined titled
// recovery answers, verified in two steps with a shared, atomically reserved lockout budget, per-source and
// installation-wide throttles, offline recovery links and owner/CLI unlock.
package localauth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"unicode"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"

	"github.com/aurimasniekis/go-porch/internal/apperr"
)

// Adapted from HallPass internal/opauth/password.go (Apache-2.0).

// MaxSecretBytes bounds normalized secrets; longer input is rejected, never truncated.
const MaxSecretBytes = 1024

// Params are Argon2id parameters.
type Params struct {
	Memory  uint32 // KiB
	Time    uint32
	Threads uint8
	KeyLen  uint32
	SaltLen int
}

// DefaultParams: m=64 MiB, t=3, p=2 (ADR-0008).
var DefaultParams = Params{Memory: 64 * 1024, Time: 3, Threads: 2, KeyLen: 32, SaltLen: 16}

// NormalizePassword applies NFKC and enforces length bounds.
func NormalizePassword(pw string) ([]byte, error) {
	if len(pw) > 4*MaxSecretBytes {
		return nil, apperr.New(apperr.CodeInvalid, "password must be at most %d bytes", MaxSecretBytes)
	}
	n := norm.NFKC.String(pw)
	if strings.ContainsRune(n, 0) {
		return nil, apperr.New(apperr.CodeInvalid, "password must not contain NUL characters")
	}
	if len(n) > MaxSecretBytes {
		return nil, apperr.New(apperr.CodeInvalid, "password must be at most %d bytes", MaxSecretBytes)
	}
	return []byte(n), nil
}

// CanonicalAnswer normalizes a recovery answer: NFKC, lowercase, punctuation and symbols removed, whitespace
// collapsed. "  Biscuit, the Dog! " and "biscuit the dog" are equal.
func CanonicalAnswer(a string) string {
	a = strings.ToLower(norm.NFKC.String(a))
	var b strings.Builder
	space := false
	for _, r := range a {
		switch {
		case unicode.IsSpace(r):
			space = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r) || unicode.IsControl(r):
		default:
			if space && b.Len() > 0 {
				b.WriteByte(' ')
			}
			space = false
			b.WriteRune(r)
		}
	}
	return b.String()
}

// answersInput length-prefixes every canonical answer so no two different answer lists hash the same input.
func answersInput(answers []string) []byte {
	var out []byte
	out = append(out, "porch/answers/v1"...)
	for _, a := range answers {
		c := CanonicalAnswer(a)
		out = binary.BigEndian.AppendUint32(out, uint32(len(c))) //nolint:gosec // bounded by MaxSecretBytes
		out = append(out, c...)
	}
	return out
}

// Hash returns a PHC-format Argon2id hash.
func Hash(secret []byte, p Params) (string, error) {
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey(secret, salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.Memory, p.Time, p.Threads, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

var errBadHash = errors.New("malformed password hash")

// Verify checks secret against a PHC hash in constant time.
func Verify(secret []byte, phc string) (bool, error) {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return false, errBadHash
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil || m == 0 || t == 0 || p == 0 || m > 4*1024*1024 || t > 100 {
		return false, errBadHash
	}
	enc := base64.RawStdEncoding
	salt, err := enc.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return false, errBadHash
	}
	want, err := enc.DecodeString(parts[5])
	if err != nil || len(want) < 16 || len(want) > 64 {
		return false, errBadHash
	}
	got := argon2.IDKey(secret, salt, t, m, p, uint32(len(want))) //nolint:gosec // bounded above
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// hasher bounds concurrent Argon2id evaluations (each uses 64 MiB) and keeps a dummy hash per parameter set so unknown
// or locked accounts cost the same time as real ones.
type hasher struct {
	calls  atomic.Int64 // Argon2id evaluations (tests assert equal work per path)
	params Params
	sem    chan struct{}
	once   sync.Once
	dummy  string
}

func newHasher(p Params, concurrency int) *hasher {
	if concurrency <= 0 {
		concurrency = 4
	}
	return &hasher{params: p, sem: make(chan struct{}, concurrency)}
}

func (h *hasher) hash(secret []byte) (string, error) {
	h.sem <- struct{}{}
	defer func() { <-h.sem }()
	return Hash(secret, h.params)
}

func (h *hasher) verify(secret []byte, phc string) bool {
	h.calls.Add(1)
	h.sem <- struct{}{}
	defer func() { <-h.sem }()
	ok, err := Verify(secret, phc)
	return err == nil && ok
}

// burn performs one verification against a dummy hash (timing equalisation).
func (h *hasher) burn() {
	h.once.Do(func() {
		d, err := Hash([]byte("porch-dummy-secret-for-timing"), h.params)
		if err != nil {
			panic(err)
		}
		h.dummy = d
	})
	h.verify([]byte("not-the-dummy"), h.dummy)
}

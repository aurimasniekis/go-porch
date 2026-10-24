// Adapted from Pulse internal/backup/crypto.go (Apache-2.0, © Aurimas Niekis).

package backup

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"github.com/klauspost/compress/s2"
)

// ParseRecipients parses age X25519 recipients (age1…), one per entry; # comments are ignored.
func ParseRecipients(entries []string) ([]age.Recipient, error) {
	var out []age.Recipient
	for _, e := range entries {
		for _, line := range strings.FieldsFunc(e, func(r rune) bool { return r == '\n' || r == ',' }) {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			r, err := age.ParseX25519Recipient(line)
			if err != nil {
				return nil, fmt.Errorf("backup: age recipient %q: %w", line, err)
			}
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("backup: no age recipients")
	}
	return out, nil
}

// ParseIdentities parses age identities (AGE-SECRET-KEY-1…), as in an age-keygen file.
func ParseIdentities(s string) ([]age.Identity, error) {
	ids, err := age.ParseIdentities(strings.NewReader(s))
	if err != nil {
		return nil, errors.New("backup: invalid age identity file")
	}
	return ids, nil
}

// GenerateIdentity returns a new identity file (age-keygen format) and its recipient.
func GenerateIdentity() (identityFile, recipient string, err error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return "", "", err
	}
	r := id.Recipient().String()
	return "# public key: " + r + "\n" + id.String() + "\n", r, nil
}

// ErrDecrypt means the identity does not match or the object was modified.
var ErrDecrypt = errors.New("backup: cannot decrypt (wrong identity or damaged object)")

// seal compresses (S2) and encrypts an object to the recipients; open reverses it.
func seal(rs []age.Recipient, plain []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, rs...)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(s2.EncodeBetter(nil, plain)); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func open(ids []age.Identity, cipher []byte) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(cipher), ids...)
	if err != nil {
		return nil, ErrDecrypt
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, ErrDecrypt
	}
	out, err := s2.Decode(nil, b)
	if err != nil {
		return nil, ErrDecrypt
	}
	return out, nil
}

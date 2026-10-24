package oidcop

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/ids"
	"github.com/aurimasniekis/go-porch/internal/keyring"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/store/db"
)

// Supported signing algorithms (ADR-0014). ES256 is the default; RS256 is offered for clients that need it.
const (
	AlgES256 = "ES256"
	AlgRS256 = "RS256"
)

// Keys manages OIDC signing keys: private keys sealed with the keyring signing purpose, one active key per algorithm,
// rotated keys kept in the JWKS (state retiring) until every token they signed has expired.
type Keys struct {
	s     *store.Store
	kr    *keyring.Keyring
	audit *audit.Writer
	// RSABits is the RSA modulus size (default 3072).
	RSABits int

	mu     sync.RWMutex
	active map[string]*signingKey // alg → key
	public []jose.JSONWebKey      // every non-retired key
}

type signingKey struct {
	kid  string
	alg  string
	priv crypto.Signer
}

// NewKeys returns a key manager; call Load before use.
func NewKeys(s *store.Store, kr *keyring.Keyring, a *audit.Writer) *Keys {
	return &Keys{s: s, kr: kr, audit: a, RSABits: 3072}
}

func aad(kid string) []byte { return keyring.FieldAAD("signing_keys", "private_enc", kid) }

func (k *Keys) generate(alg string) (crypto.Signer, error) {
	switch alg {
	case AlgES256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case AlgRS256:
		return rsa.GenerateKey(rand.Reader, k.RSABits)
	}
	return nil, fmt.Errorf("unsupported alg %s", alg)
}

// insertTx stores a fresh active key for alg.
func (k *Keys) insertTx(ctx context.Context, tx *store.Tx, alg string, priv crypto.Signer) (string, error) {
	kid := ids.New(ids.SigningKey)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", err
	}
	sealed, err := k.kr.Seal(keyring.PurposeSigning, aad(kid), der)
	if err != nil {
		return "", err
	}
	pub, err := json.Marshal(jose.JSONWebKey{Key: priv.Public(), KeyID: kid, Algorithm: alg, Use: "sig"})
	if err != nil {
		return "", err
	}
	return kid, tx.Q.InsertSigningKey(ctx, db.InsertSigningKeyParams{ID: kid, Alg: alg, PrivateEnc: sealed, PublicJwk: string(pub), CreatedAt: tx.NowMicros()})
}

// Load ensures an active key per algorithm exists (generating outside the transaction) and loads the key set.
func (k *Keys) Load(ctx context.Context) error {
	for _, alg := range []string{AlgES256, AlgRS256} {
		if _, err := k.s.R().GetActiveSigningKey(ctx, alg); err == nil {
			continue
		}
		priv, err := k.generate(alg)
		if err != nil {
			return err
		}
		err = k.s.W().TxNamed(ctx, "oidc.keys_init", func(tx *store.Tx) error {
			if _, err := tx.Q.GetActiveSigningKey(ctx, alg); err == nil {
				return nil // created concurrently
			}
			kid, err := k.insertTx(ctx, tx, alg, priv)
			if err != nil {
				return err
			}
			_, err = k.audit.Append(ctx, tx, audit.Event{Actor: audit.System, Action: "oidc.signing_key_created", Target: audit.Target{Type: "signing_key", ID: kid},
				Details: map[string]any{"alg": alg}})
			return err
		})
		if err != nil {
			return err
		}
	}
	return k.reload(ctx)
}

func (k *Keys) reload(ctx context.Context) error {
	rows, err := k.s.R().ListSigningKeys(ctx)
	if err != nil {
		return err
	}
	active := map[string]*signingKey{}
	public := make([]jose.JSONWebKey, 0, len(rows))
	for _, r := range rows {
		var jwk jose.JSONWebKey
		if err := json.Unmarshal([]byte(r.PublicJwk), &jwk); err != nil {
			return fmt.Errorf("signing key %s: %w", r.ID, err)
		}
		public = append(public, jwk)
		if r.State != "active" {
			continue
		}
		der, err := k.kr.Open(keyring.PurposeSigning, aad(r.ID), r.PrivateEnc)
		if err != nil {
			return fmt.Errorf("unseal signing key %s: %w", r.ID, err)
		}
		pk, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return err
		}
		signer, ok := pk.(crypto.Signer)
		if !ok {
			return errors.New("signing key is not a signer")
		}
		active[r.Alg] = &signingKey{kid: r.ID, alg: r.Alg, priv: signer}
	}
	k.mu.Lock()
	k.active, k.public = active, public
	k.mu.Unlock()
	return nil
}

// JWKS returns the public keys (active and retiring).
func (k *Keys) JWKS() jose.JSONWebKeySet {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return jose.JSONWebKeySet{Keys: append([]jose.JSONWebKey(nil), k.public...)}
}

// Sign signs claims with the active key of alg; typ is the JOSE header type ("JWT", "at+jwt").
func (k *Keys) Sign(alg, typ string, claims any) (string, error) {
	k.mu.RLock()
	key := k.active[alg]
	k.mu.RUnlock()
	if key == nil {
		return "", fmt.Errorf("no active %s signing key", alg)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.SignatureAlgorithm(alg), Key: jose.JSONWebKey{Key: key.priv, KeyID: key.kid}},
		(&jose.SignerOptions{}).WithType(jose.ContentType(typ)))
	if err != nil {
		return "", err
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}

// Verify checks a compact JWS against the key set (any algorithm Porch issues) and returns its payload and header type.
func (k *Keys) Verify(token string) ([]byte, string, error) {
	obj, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256, jose.RS256})
	if err != nil {
		return nil, "", err
	}
	if len(obj.Signatures) != 1 {
		return nil, "", errors.New("unexpected signature count")
	}
	h := obj.Signatures[0].Header
	set := k.JWKS()
	keys := set.Key(h.KeyID)
	if len(keys) == 0 {
		return nil, "", errors.New("unknown key id")
	}
	payload, err := obj.Verify(keys[0])
	if err != nil {
		return nil, "", err
	}
	typ, _ := h.ExtraHeaders[jose.HeaderType].(string)
	return payload, typ, nil
}

// Rotate creates a new active key for alg; the previous one stays published (retiring) for overlap, then retires.
func (k *Keys) Rotate(ctx context.Context, actor audit.Actor, alg string, overlap time.Duration) (string, error) {
	priv, err := k.generate(alg)
	if err != nil {
		return "", err
	}
	var kid string
	err = k.s.W().TxNamed(ctx, "oidc.keys_rotate", func(tx *store.Tx) error {
		cur, err := tx.Q.GetActiveSigningKey(ctx, alg)
		if err == nil {
			if _, err := tx.Q.SetSigningKeyRetiring(ctx, db.SetSigningKeyRetiringParams{RetireAfter: sqlMicros(tx.Now.Add(overlap)), ID: cur.ID}); err != nil {
				return err
			}
		}
		if kid, err = k.insertTx(ctx, tx, alg, priv); err != nil {
			return err
		}
		_, err = k.audit.Append(ctx, tx, audit.Event{Actor: actor, Action: "oidc.signing_key_rotated", Target: audit.Target{Type: "signing_key", ID: kid},
			Details: map[string]any{"alg": alg, "previous": cur.ID, "overlap_seconds": int64(overlap / time.Second)}})
		return err
	})
	if err != nil {
		return "", err
	}
	return kid, k.reload(ctx)
}

// RetireExpired removes retiring keys whose overlap has passed from the key set.
func (k *Keys) RetireExpired(ctx context.Context) (int64, error) {
	var n int64
	err := k.s.W().TxNamed(ctx, "oidc.keys_retire", func(tx *store.Tx) error {
		var err error
		n, err = tx.Q.RetireSigningKeys(ctx, db.RetireSigningKeysParams{RetiredAt: sqlMicros(tx.Now), RetireAfter: sqlMicros(tx.Now)})
		return err
	})
	if err != nil || n == 0 {
		return n, err
	}
	return n, k.reload(ctx)
}

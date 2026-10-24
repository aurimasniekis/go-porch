package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
)

// signingAlgs are the algorithms Porch signs ID and access tokens with.
var signingAlgs = []jose.SignatureAlgorithm{jose.ES256, jose.RS256}

// check is one validation step shown next to a decoded access token.
type check struct {
	Name   string
	OK     bool
	Detail string
}

// accessTokenView is how the page shows the access token.
type accessTokenView struct {
	// JWT is false for opaque (non-JWT) access tokens; then only Length is set.
	JWT    bool
	Length int
	// Verified is true only when every check passed.
	Verified bool
	Header   string
	Claims   string
	Checks   []check
	// Porch is the namespaced "porch" claim ({v, tenant, roles?, groups?}) of a verified token.
	Porch map[string]any
}

// inspectAccessToken decodes an RFC 9068 JWT access token and verifies it: signature against keys (Porch's JWKS), the
// at+jwt type, issuer, audience and expiry. Anything that is not a JWT is reported as opaque rather than an error.
func inspectAccessToken(ctx context.Context, keys oidc.KeySet, issuer, audience string, now time.Time, raw string) accessTokenView {
	v := accessTokenView{Length: len(raw)}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return v
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return v
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}
	if json.Unmarshal(headerJSON, &header) != nil || header.Alg == "" {
		return v
	}
	v.JWT = true
	v.Header = prettyJSON(headerJSON)

	payload, sigErr := verifyJWS(ctx, keys, raw)
	sig := check{Name: "Signature verified against Porch JWKS", OK: sigErr == nil, Detail: fmt.Sprintf("alg %s, kid %q", header.Alg, header.Kid)}
	if sigErr != nil {
		sig.Detail = sigErr.Error()
		// Show what the token claims, clearly marked as unverified.
		payload, err = base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			payload = nil
		}
	}
	v.Checks = append(v.Checks, sig)
	typ := strings.ToLower(header.Typ)
	v.Checks = append(v.Checks, check{Name: "Header typ is at+jwt (RFC 9068)", OK: typ == "at+jwt" || typ == "application/at+jwt",
		Detail: fmt.Sprintf("typ %q", header.Typ)})

	var claims struct {
		Iss   string          `json:"iss"`
		Aud   json.RawMessage `json:"aud"`
		Exp   *json.Number    `json:"exp"`
		Porch map[string]any  `json:"porch"`
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	if payload == nil || dec.Decode(&claims) != nil {
		v.Checks = append(v.Checks, check{Name: "Claims are a JSON object", Detail: "payload is not valid JSON"})
		return v
	}
	v.Claims = prettyJSON(payload)
	v.Checks = append(v.Checks, check{Name: "iss is the Porch issuer", OK: claims.Iss == issuer, Detail: fmt.Sprintf("iss %q", claims.Iss)})
	aud := audiences(claims.Aud)
	v.Checks = append(v.Checks, check{Name: "aud contains " + audience, OK: slices.Contains(aud, audience), Detail: fmt.Sprintf("aud %q", aud)})
	expCheck := check{Name: "Not expired", Detail: "no exp claim"}
	if claims.Exp != nil {
		if exp, err := claims.Exp.Int64(); err == nil {
			t := time.Unix(exp, 0)
			expCheck.OK = now.Before(t)
			expCheck.Detail = "exp " + t.UTC().Format(time.RFC3339)
		}
	}
	v.Checks = append(v.Checks, expCheck)

	v.Verified = true
	for _, c := range v.Checks {
		v.Verified = v.Verified && c.OK
	}
	if v.Verified {
		v.Porch = claims.Porch
	}
	return v
}

// verifyJWS checks the algorithm against the allow-list and then the signature against the key set.
func verifyJWS(ctx context.Context, keys oidc.KeySet, raw string) ([]byte, error) {
	if _, err := jose.ParseSigned(raw, signingAlgs); err != nil {
		return nil, fmt.Errorf("not an ES256/RS256 compact JWS: %w", err)
	}
	payload, err := keys.VerifySignature(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}
	return payload, nil
}

// audiences accepts the string and array forms of aud.
func audiences(raw json.RawMessage) []string {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		return many
	}
	return nil
}

// prettyJSON indents a JSON document, keeping numbers exactly as issued.
func prettyJSON(b []byte) string {
	var out bytes.Buffer
	if err := json.Indent(&out, b, "", "  "); err != nil {
		return string(b)
	}
	return out.String()
}

// tenantLabel renders porch.tenant as "slug (id)".
func tenantLabel(porch map[string]any) string {
	t, ok := porch["tenant"].(map[string]any)
	if !ok {
		return ""
	}
	slug, _ := t["slug"].(string)
	id, _ := t["id"].(string)
	switch {
	case slug != "" && id != "":
		return slug + " (" + id + ")"
	case slug != "":
		return slug
	default:
		return id
	}
}

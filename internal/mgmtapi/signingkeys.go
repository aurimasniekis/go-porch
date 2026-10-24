package mgmtapi

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/domain"
	"github.com/aurimasniekis/go-porch/internal/identity"
)

// SigningKey is a public OIDC signing key.
type SigningKey struct {
	KID         string     `json:"kid"`
	Alg         string     `json:"alg"`
	State       string     `json:"state" enum:"active,retiring,retired"`
	CreatedAt   time.Time  `json:"created_at"`
	RetireAfter *time.Time `json:"retire_after,omitempty"`
}

// RotateKeyRequest rotates one algorithm's key.
type RotateKeyRequest struct {
	Alg            string `json:"alg" enum:"ES256,RS256"`
	OverlapSeconds int64  `json:"overlap_seconds,omitempty" minimum:"0" maximum:"2592000" doc:"How long the old key stays published (default 24h)."`
}

func registerSigningKeys(api huma.API, d *Deps) {
	tags := []string{"installation"}
	huma.Register(api, huma.Operation{OperationID: "list-signing-keys", Method: http.MethodGet, Path: "/installation/signing-keys",
		Summary: "OIDC signing keys", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*struct{ Body []SigningKey }, error) {
			if _, err := requireOperator(ctx, identity.RoleOwner, identity.RoleAdmin, identity.RoleAuditor); err != nil {
				return nil, err
			}
			rows, err := d.Store.R().ListAllSigningKeys(ctx)
			if err != nil {
				return nil, d.fail("signing-keys", err)
			}
			out := make([]SigningKey, 0, len(rows))
			for _, r := range rows {
				out = append(out, SigningKey{KID: r.ID, Alg: r.Alg, State: r.State, CreatedAt: domain.FromMicros(r.CreatedAt), RetireAfter: domain.OptMicros(r.RetireAfter)})
			}
			return &struct{ Body []SigningKey }{Body: out}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "rotate-signing-key", Method: http.MethodPost, Path: "/installation/signing-keys/rotate",
		Summary: "Rotate an OIDC signing key (owner, needs a recent sign-in)", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct{ Body RotateKeyRequest }) (*struct{ Body SigningKey }, error) {
			p, err := requireOperator(ctx, identity.RoleOwner)
			if err != nil {
				return nil, err
			}
			if err := d.stepUp(ctx); err != nil {
				return nil, err
			}
			overlap := time.Duration(in.Body.OverlapSeconds) * time.Second
			if overlap == 0 {
				overlap = 24 * time.Hour
			}
			kid, err := d.OP.Signing.Rotate(ctx, audit.Actor{Type: audit.ActorUser, ID: p.UserID}, in.Body.Alg, overlap)
			if err != nil {
				return nil, d.fail("rotate-key", err)
			}
			return &struct{ Body SigningKey }{Body: SigningKey{KID: kid, Alg: in.Body.Alg, State: "active", CreatedAt: d.now().UTC()}}, nil
		})
}

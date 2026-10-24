package mgmtapi

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/aurimasniekis/go-porch/internal/localauth"
	"github.com/aurimasniekis/go-porch/internal/localauth/wordlist"
)

// BackupCredentialStatus describes the caller's backup login.
type BackupCredentialStatus struct {
	Enrolled    bool       `json:"enrolled"`
	Pairs       int        `json:"pairs"`
	Titles      []string   `json:"titles"`
	EnrolledAt  *time.Time `json:"enrolled_at,omitempty"`
	RotatedAt   *time.Time `json:"rotated_at,omitempty"`
	LockedUntil *time.Time `json:"locked_until,omitempty"`
	Handle      string     `json:"handle,omitempty"`
	MinPairs    int        `json:"min_pairs"`
	MaxPairs    int        `json:"max_pairs"`
}

// RecoveryPair is a title and its answer.
type RecoveryPair struct {
	Title  string `json:"title" minLength:"1" maxLength:"120" doc:"Your own hint, like a security question."`
	Answer string `json:"answer" minLength:"1" maxLength:"200"`
}

// EnrollBackupRequest sets or rotates the backup credential.
type EnrollBackupRequest struct {
	Password string         `json:"password" minLength:"1" maxLength:"1024"`
	Pairs    []RecoveryPair `json:"pairs" minItems:"3" maxItems:"12"`
	Confirm  []string       `json:"confirm" minItems:"3" maxItems:"12" doc:"Every answer typed again, in order."`
}

// StrengthEstimate reports the accepted credential's estimated strength.
type StrengthEstimate struct {
	PasswordScore int     `json:"password_score"`
	CombinedBits  float64 `json:"combined_bits_estimate"`
	Note          string  `json:"note"`
}

// HandleRequest sets the optional backup login handle.
type HandleRequest struct {
	Handle string `json:"handle" maxLength:"63" doc:"Empty removes the handle (email works again)."`
}

// LinkedIdentity is an upstream account linked to the caller.
type LinkedIdentity struct {
	ID           string     `json:"id"`
	ProviderSlug string     `json:"provider_slug"`
	ProviderName string     `json:"provider_name"`
	Email        string     `json:"email,omitempty"`
	HD           string     `json:"hd,omitempty"`
	LinkedAt     time.Time  `json:"linked_at"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
}

func registerAccount(api huma.API, d *Deps) {
	tags := []string{"account"}
	huma.Register(api, huma.Operation{OperationID: "get-backup-credential", Method: http.MethodGet, Path: "/me/backup-credential",
		Summary: "Your backup login status and recovery titles", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*struct{ Body BackupCredentialStatus }, error) {
			st, err := d.Local.StatusFor(ctx, Principal(ctx).UserID, true)
			if err != nil {
				return nil, d.fail("backup-status", err)
			}
			pol := d.Local.Policy().Strength
			titles := st.Titles
			if titles == nil {
				titles = []string{}
			}
			return &struct{ Body BackupCredentialStatus }{Body: BackupCredentialStatus{Enrolled: st.Enrolled, Pairs: st.Pairs, Titles: titles,
				EnrolledAt: st.EnrolledAt, RotatedAt: st.RotatedAt, LockedUntil: st.LockedUntil, Handle: st.Handle,
				MinPairs: pol.MinPairs, MaxPairs: pol.MaxPairs}}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "put-backup-credential", Method: http.MethodPut, Path: "/me/backup-credential",
		Summary: "Enroll or rotate your backup login (needs a recent sign-in)", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct{ Body EnrollBackupRequest }) (*struct{ Body StrengthEstimate }, error) {
			if err := d.stepUp(ctx); err != nil {
				return nil, err
			}
			pairs := make([]localauth.Pair, len(in.Body.Pairs))
			for i, p := range in.Body.Pairs {
				pairs[i] = localauth.Pair{Title: p.Title, Answer: p.Answer}
			}
			est, err := d.Local.Enroll(ctx, Principal(ctx), localauth.EnrollParams{Password: in.Body.Password, Pairs: pairs, Confirm: in.Body.Confirm})
			if err != nil {
				return nil, d.fail("backup-enroll", err)
			}
			return &struct{ Body StrengthEstimate }{Body: StrengthEstimate{PasswordScore: est.PasswordScore, CombinedBits: est.CombinedBitsEst, Note: est.Note}}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "put-backup-handle", Method: http.MethodPut, Path: "/me/backup-handle",
		Summary: "Set an optional backup login handle (needs a recent sign-in)", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct{ Body HandleRequest }) (*struct{}, error) {
			if err := d.stepUp(ctx); err != nil {
				return nil, err
			}
			if err := d.Local.SetHandle(ctx, Principal(ctx), in.Body.Handle); err != nil {
				return nil, d.fail("backup-handle", err)
			}
			return &struct{}{}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "suggest-words", Method: http.MethodGet, Path: "/me/suggest-words",
		Summary: "Random words from the EFF large wordlist (optional help for recovery answers)", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			Count int `query:"count" minimum:"1" maximum:"12" default:"3"`
		}) (*struct{ Body []string }, error) {
			ws, err := wordlist.Random(in.Count)
			if err != nil {
				return nil, d.fail("suggest-words", err)
			}
			return &struct{ Body []string }{Body: ws}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "list-my-identities", Method: http.MethodGet, Path: "/me/identities",
		Summary: "Upstream accounts linked to you", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*struct{ Body []LinkedIdentity }, error) {
			rows, err := d.Store.R().ListUserIdentities(ctx, Principal(ctx).UserID)
			if err != nil {
				return nil, d.fail("identities", err)
			}
			out := make([]LinkedIdentity, 0, len(rows))
			for _, r := range rows {
				li := LinkedIdentity{ID: r.ID, ProviderSlug: r.ProviderSlug, ProviderName: r.ProviderName, Email: r.Email.String, HD: r.Hd.String,
					LinkedAt: time.UnixMicro(r.LinkedAt).UTC()}
				if r.LastLoginAt.Valid {
					t := time.UnixMicro(r.LastLoginAt.Int64).UTC()
					li.LastLoginAt = &t
				}
				out = append(out, li)
			}
			return &struct{ Body []LinkedIdentity }{Body: out}, nil
		})
}

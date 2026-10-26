package mgmtapi

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/aurimasniekis/go-porch/internal/authz"
	"github.com/aurimasniekis/go-porch/internal/idp"
)

// DomainRule is a domain enrollment rule.
type DomainRule struct {
	ID            string    `json:"id"`
	Domain        string    `json:"domain"`
	TenantID      string    `json:"tenant_id"`
	ProviderID    string    `json:"provider_id"`
	EvidenceKind  string    `json:"evidence_kind" enum:"workspace_hd,verified_email" doc:"workspace_hd = validated Google hd claim; verified_email is weaker."`
	Mode          string    `json:"mode" enum:"invite_only,jit"`
	Version       int64     `json:"version"`
	ManagedBy     string    `json:"managed_by"`
	LastChangedBy string    `json:"last_changed_by,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func ruleDTO(r idp.DomainRule) DomainRule {
	return DomainRule{ID: r.ID, Domain: r.Domain, TenantID: r.TenantID, ProviderID: r.ProviderID, EvidenceKind: r.EvidenceKind, Mode: r.Mode,
		Version: r.Version, ManagedBy: r.ManagedBy, LastChangedBy: r.LastChangedBy, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
}

// CreateDomainRuleRequest adds a rule.
type CreateDomainRuleRequest struct {
	Domain       string `json:"domain" minLength:"3" maxLength:"253"`
	ProviderID   string `json:"provider_id" minLength:"1" maxLength:"64"`
	EvidenceKind string `json:"evidence_kind" enum:"workspace_hd,verified_email"`
	Mode         string `json:"mode" enum:"invite_only,jit"`
}

// Invite is a pending invitation.
type Invite struct {
	ID         string     `json:"id"`
	TenantID   string     `json:"tenant_id"`
	Email      string     `json:"email"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	ConsumedAt *time.Time `json:"consumed_at,omitempty"`
}

// CreateInviteRequest invites an email address.
type CreateInviteRequest struct {
	Email        string `json:"email" minLength:"3" maxLength:"254"`
	ValidSeconds int64  `json:"valid_seconds,omitempty" minimum:"0" maximum:"2592000" doc:"Default 7 days."`
}

func registerDomainRules(api huma.API, d *Deps) {
	tags := []string{"enrollment"}
	huma.Register(api, huma.Operation{OperationID: "list-domain-rules", Method: http.MethodGet, Path: "/tenants/{tenant}/domain-rules",
		Summary: "Domain enrollment rules of a tenant", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *TenantRef) (*struct{ Body []DomainRule }, error) {
			sc, err := d.tenantReader(ctx, in.Tenant)
			if err != nil {
				return nil, err
			}
			rs, err := d.IDP.Rules(ctx, sc)
			if err != nil {
				return nil, d.fail("list-rules", err)
			}
			out := make([]DomainRule, 0, len(rs))
			for _, r := range rs {
				out = append(out, ruleDTO(r))
			}
			return &struct{ Body []DomainRule }{Body: out}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "create-domain-rule", Method: http.MethodPost, Path: "/tenants/{tenant}/domain-rules",
		DefaultStatus: http.StatusCreated, Summary: "Enroll a domain into a tenant (needs a recent sign-in)", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			TenantRef
			ManagedBy
			Body CreateDomainRuleRequest
		}) (*struct {
			ETag string `header:"ETag"`
			Body DomainRule
		}, error) {
			sc, err := d.operatorScope(ctx, in.Tenant)
			if err != nil {
				return nil, err
			}
			if err := d.stepUp(ctx); err != nil {
				return nil, err
			}
			r, err := d.IDP.CreateRule(ctx, change(ctx, in.ManagedBy.ManagedBy), sc, idp.RuleParams{Domain: in.Body.Domain, ProviderID: in.Body.ProviderID,
				EvidenceKind: in.Body.EvidenceKind, Mode: in.Body.Mode})
			if err != nil {
				return nil, d.fail("create-rule", err)
			}
			return &struct {
				ETag string `header:"ETag"`
				Body DomainRule
			}{ETag: etag(r.Version), Body: ruleDTO(r)}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "delete-domain-rule", Method: http.MethodDelete, Path: "/tenants/{tenant}/domain-rules/{rule}",
		DefaultStatus: http.StatusNoContent, Summary: "Delete a rule and the memberships derived from it (needs a recent sign-in)", Tags: tags,
		Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			TenantRef
			ManagedBy
			IfMatch
			Rule string `path:"rule" maxLength:"64"`
		}) (*struct{}, error) {
			sc, err := d.operatorScope(ctx, in.Tenant)
			if err != nil {
				return nil, err
			}
			if err := d.stepUp(ctx); err != nil {
				return nil, err
			}
			v, err := in.Version()
			if err != nil {
				return nil, err
			}
			if err := d.IDP.DeleteRule(ctx, change(ctx, in.ManagedBy.ManagedBy), sc, in.Rule, v); err != nil {
				return nil, d.fail("delete-rule", err)
			}
			return &struct{}{}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "list-invites", Method: http.MethodGet, Path: "/tenants/{tenant}/invites",
		Summary: "Invitations of a tenant", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *TenantRef) (*struct{ Body []Invite }, error) {
			sc, err := d.tenantReader(ctx, in.Tenant, authz.PermInviteRead, authz.PermInviteManage)
			if err != nil {
				return nil, err
			}
			is, err := d.IDP.Invites(ctx, sc)
			if err != nil {
				return nil, d.fail("list-invites", err)
			}
			out := make([]Invite, 0, len(is))
			for _, i := range is {
				out = append(out, Invite{ID: i.ID, TenantID: i.TenantID, Email: i.Email, CreatedAt: i.CreatedAt, ExpiresAt: i.ExpiresAt, ConsumedAt: i.ConsumedAt})
			}
			return &struct{ Body []Invite }{Body: out}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "create-invite", Method: http.MethodPost, Path: "/tenants/{tenant}/invites",
		DefaultStatus: http.StatusCreated, Summary: "Invite an email address (accepted only with a matching verified upstream email)", Tags: tags,
		Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			TenantRef
			ManagedBy
			Body CreateInviteRequest
		}) (*struct{ Body Invite }, error) {
			sc, err := d.tenantAdmin(ctx, in.Tenant, authz.PermInviteManage)
			if err != nil {
				return nil, err
			}
			i, err := d.IDP.CreateInvite(ctx, change(ctx, in.ManagedBy.ManagedBy), sc, in.Body.Email, time.Duration(in.Body.ValidSeconds)*time.Second)
			if err != nil {
				return nil, d.fail("create-invite", err)
			}
			return &struct{ Body Invite }{Body: Invite{ID: i.ID, TenantID: i.TenantID, Email: i.Email, CreatedAt: i.CreatedAt, ExpiresAt: i.ExpiresAt}}, nil
		})

	huma.Register(api, huma.Operation{OperationID: "delete-invite", Method: http.MethodDelete, Path: "/tenants/{tenant}/invites/{invite}",
		DefaultStatus: http.StatusNoContent, Summary: "Revoke an invitation", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			TenantRef
			Invite string `path:"invite" maxLength:"64"`
		}) (*struct{}, error) {
			sc, err := d.tenantAdmin(ctx, in.Tenant, authz.PermInviteManage)
			if err != nil {
				return nil, err
			}
			if err := d.IDP.DeleteInvite(ctx, change(ctx, ""), sc, in.Invite); err != nil {
				return nil, d.fail("delete-invite", err)
			}
			return &struct{}{}, nil
		})
}

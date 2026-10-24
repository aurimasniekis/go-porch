package authz

import (
	"context"
	"encoding/json"
	"time"

	"github.com/aurimasniekis/go-porch/internal/apperr"
	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/domain"
	"github.com/aurimasniekis/go-porch/internal/ids"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/store/db"
	"github.com/aurimasniekis/go-porch/internal/tenancy"
)

// ResourceDef is a tenant resource (scope target for assignments; parents form a hierarchy).
type ResourceDef struct {
	ID         string            `json:"id"`
	Type       string            `json:"type"`
	Slug       string            `json:"slug"`
	Name       string            `json:"name"`
	ParentID   string            `json:"parent_id,omitempty"`
	Attributes map[string]string `json:"attributes"`
	Version    int64             `json:"version"`
	ManagedBy  string            `json:"managed_by"`
	UpdatedAt  time.Time         `json:"updated_at"`
}

// ResourceParams create or update a resource.
type ResourceParams struct {
	Type, Slug, Name, ParentID string
	Attributes                 map[string]string
	IfVersion                  int64
}

func validateAttrs(attrs map[string]string, v *apperr.Validation) {
	if len(attrs) > 50 {
		v.Add("attributes", "at most 50 attributes")
	}
	for k, val := range attrs {
		if !domain.ValidSlug(k) && !regexpType(k) {
			v.Add("attributes", "%q is not a valid attribute key", k)
		}
		if len(val) > 512 {
			v.Add("attributes", "%q is longer than 512 bytes", k)
		}
	}
}

// CreateResource adds a resource. Type "app" is reserved (applications are resources implicitly).
func (a *Admin) CreateResource(ctx context.Context, ch domain.Change, sc tenancy.Scope, p ResourceParams) (ResourceDef, error) {
	var v apperr.Validation
	if !regexpType(p.Type) || p.Type == "app" || p.Type == "tenant" {
		v.Add("type", "must be a lowercase identifier other than app or tenant")
	}
	if !domain.ValidSlug(p.Slug) {
		v.Add("slug", "must be lowercase letters, digits or inner hyphens")
	}
	p.Name = domain.CleanName("name", p.Name, &v)
	validateAttrs(p.Attributes, &v)
	if err := v.Err(); err != nil {
		return ResourceDef{}, err
	}
	if p.Attributes == nil {
		p.Attributes = map[string]string{}
	}
	attrs, _ := json.Marshal(p.Attributes)
	id := ids.New(ids.Resource)
	err := a.change(ctx, "authz.create_resource", ch, sc, audit.Event{Action: "resource.created", Target: audit.Target{Type: "resource", ID: id},
		Details: map[string]any{"type": p.Type, "slug": p.Slug}}, func(tx *store.Tx) error {
		if p.ParentID != "" {
			parent, err := tx.Q.GetResource(ctx, db.GetResourceParams{TenantID: sc.TenantID(), ID: p.ParentID})
			if err != nil {
				return apperr.New(apperr.CodeInvalid, "parent_id: unknown resource in this tenant")
			}
			depth := 1
			for pp := parent.ParentID; pp.Valid; depth++ {
				if depth >= MaxDepth {
					return apperr.New(apperr.CodeInvalid, "resource nesting would exceed %d levels", MaxDepth)
				}
				r, err := tx.Q.GetResource(ctx, db.GetResourceParams{TenantID: sc.TenantID(), ID: pp.String})
				if err != nil {
					break
				}
				pp = r.ParentID
			}
		}
		err := tx.Q.InsertResource(ctx, db.InsertResourceParams{ID: id, TenantID: sc.TenantID(), Type: p.Type, Slug: p.Slug, Name: p.Name,
			ParentID: domain.NullStr(p.ParentID), AttributesJson: string(attrs), ManagedBy: ch.Managed(), LastChangedBy: domain.NullStr(ch.ChangedBy()),
			CreatedAt: tx.NowMicros(), UpdatedAt: tx.NowMicros()})
		if store.IsConstraint(err) {
			return apperr.New(apperr.CodeAlreadyExists, "%s %q exists", p.Type, p.Slug)
		}
		return err
	})
	if err != nil {
		return ResourceDef{}, err
	}
	return a.GetResource(ctx, sc, id)
}

// UpdateResource changes name and attributes.
func (a *Admin) UpdateResource(ctx context.Context, ch domain.Change, sc tenancy.Scope, id string, p ResourceParams) (ResourceDef, error) {
	var v apperr.Validation
	p.Name = domain.CleanName("name", p.Name, &v)
	validateAttrs(p.Attributes, &v)
	if err := v.Err(); err != nil {
		return ResourceDef{}, err
	}
	if p.Attributes == nil {
		p.Attributes = map[string]string{}
	}
	attrs, _ := json.Marshal(p.Attributes)
	err := a.change(ctx, "authz.update_resource", ch, sc, audit.Event{Action: "resource.updated", Target: audit.Target{Type: "resource", ID: id}},
		func(tx *store.Tx) error {
			r, err := tx.Q.GetResource(ctx, db.GetResourceParams{TenantID: sc.TenantID(), ID: id})
			if err != nil {
				return ErrNotFound
			}
			if err := domain.IfMatch(p.IfVersion, r.Version); err != nil {
				return err
			}
			_, err = tx.Q.UpdateResource(ctx, db.UpdateResourceParams{Name: p.Name, AttributesJson: string(attrs), ManagedBy: ch.Managed(),
				LastChangedBy: domain.NullStr(ch.ChangedBy()), UpdatedAt: tx.NowMicros(), TenantID: sc.TenantID(), ID: id, Version: r.Version})
			return err
		})
	if err != nil {
		return ResourceDef{}, err
	}
	return a.GetResource(ctx, sc, id)
}

// DeleteResource removes a resource, its children and assignments scoped to it.
func (a *Admin) DeleteResource(ctx context.Context, ch domain.Change, sc tenancy.Scope, id string, ifVersion int64) error {
	return a.change(ctx, "authz.delete_resource", ch, sc, audit.Event{Action: "resource.deleted", Target: audit.Target{Type: "resource", ID: id}},
		func(tx *store.Tx) error {
			if r, err := tx.Q.GetResource(ctx, db.GetResourceParams{TenantID: sc.TenantID(), ID: id}); err == nil {
				if err := domain.IfMatch(ifVersion, r.Version); err != nil {
					return err
				}
			}
			// Child resources go with their parent (FK cascade), so their scoped assignments go too.
			if _, err := tx.SQL.ExecContext(ctx, `WITH RECURSIVE sub(id) AS (
  SELECT ? UNION SELECT r.id FROM resources r JOIN sub ON r.parent_id = sub.id WHERE r.tenant_id = ?)
DELETE FROM role_assignments WHERE tenant_id = ? AND scope_type = 'resource' AND scope_resource_id IN (SELECT id FROM sub)`,
				id, sc.TenantID(), sc.TenantID()); err != nil {
				return err
			}
			n, err := tx.Q.DeleteResource(ctx, db.DeleteResourceParams{TenantID: sc.TenantID(), ID: id})
			if err == nil && n == 0 {
				return ErrNotFound
			}
			return err
		})
}

// Resources lists resources.
func (a *Admin) Resources(ctx context.Context, sc tenancy.Scope) ([]ResourceDef, error) {
	if !sc.Valid() {
		return nil, tenancy.ErrNoAccess
	}
	rows, err := a.s.R().ListResources(ctx, sc.TenantID())
	if err != nil {
		return nil, err
	}
	out := make([]ResourceDef, 0, len(rows))
	for _, r := range rows {
		attrs := map[string]string{}
		_ = json.Unmarshal([]byte(r.AttributesJson), &attrs)
		out = append(out, ResourceDef{ID: r.ID, Type: r.Type, Slug: r.Slug, Name: r.Name, ParentID: r.ParentID.String, Attributes: attrs,
			Version: r.Version, ManagedBy: r.ManagedBy, UpdatedAt: domain.FromMicros(r.UpdatedAt)})
	}
	return out, nil
}

// GetResource returns one resource.
func (a *Admin) GetResource(ctx context.Context, sc tenancy.Scope, id string) (ResourceDef, error) {
	rs, err := a.Resources(ctx, sc)
	if err != nil {
		return ResourceDef{}, err
	}
	for _, r := range rs {
		if r.ID == id {
			return r, nil
		}
	}
	return ResourceDef{}, ErrNotFound
}

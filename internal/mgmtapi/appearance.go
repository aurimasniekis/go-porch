package mgmtapi

import (
	"context"
	"encoding/base64"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/aurimasniekis/go-porch/internal/appearance"
	"github.com/aurimasniekis/go-porch/internal/apperr"
	"github.com/aurimasniekis/go-porch/internal/apps"
	"github.com/aurimasniekis/go-porch/internal/authz"
	"github.com/aurimasniekis/go-porch/internal/identity"
)

// PublicAppearance is what the sign-in page and launcher need before anyone is signed in.
type PublicAppearance struct {
	Title      string            `json:"title"`
	Background *appearance.Image `json:"background" doc:"The background to show now, with its credit; null when backgrounds are off or not fetched yet."`
}

// AppearanceSettings configures the user-facing pages (ADR-0045).
type AppearanceSettings struct {
	Title      string             `json:"title" maxLength:"80" doc:"Shown on the sign-in page (\"Welcome to …\")."`
	Background BackgroundSettings `json:"background"`
	Images     []appearance.Image `json:"images,omitempty" readOnly:"true" doc:"The background images Porch currently holds."`
}

// BackgroundSettings selects where backgrounds come from.
type BackgroundSettings struct {
	Source   string   `json:"source" enum:"none,wikimedia,picsum" doc:"wikimedia: Wikimedia Commons (pick a category or files); picsum: Lorem Picsum photos from Unsplash (random, or photo IDs)."`
	Category string   `json:"category,omitempty" maxLength:"200" doc:"wikimedia: Commons category, e.g. \"Featured pictures of landscapes\"."`
	Files    []string `json:"files" maxItems:"12" doc:"wikimedia: file names (File:…); picsum: photo IDs. Empty = a random selection."`
	Rotation string   `json:"rotation" enum:"visit,daily" doc:"visit: a random image on every page load; daily: one image per day."`
	Count    int      `json:"count" minimum:"1" maximum:"12" doc:"How many images to keep."`
	Refresh  string   `json:"refresh" enum:"never,daily,weekly" doc:"How often Porch picks a new random selection."`
}

func settingsDTO(s appearance.Settings, imgs []appearance.Image) AppearanceSettings {
	b := s.Background
	return AppearanceSettings{Title: s.Title, Images: imgs, Background: BackgroundSettings{Source: b.Source, Category: b.Category, Files: b.Files,
		Rotation: b.Rotation, Count: b.Count, Refresh: b.Refresh}}
}

func (d *Deps) appearanceOut(ctx context.Context, s appearance.Settings) (*struct{ Body AppearanceSettings }, error) {
	imgs, err := d.Appearance.Backgrounds(ctx)
	if err != nil {
		return nil, d.fail("appearance", err)
	}
	return &struct{ Body AppearanceSettings }{Body: settingsDTO(s, imgs)}, nil
}

func registerAppearance(api huma.API, d *Deps) {
	huma.Register(api, huma.Operation{OperationID: "get-public-appearance", Method: http.MethodGet, Path: "/appearance",
		Summary: "Title and background for the sign-in page", Tags: []string{"auth"}},
		func(ctx context.Context, _ *struct{}) (*struct{ Body PublicAppearance }, error) {
			s, err := d.Appearance.Settings(ctx)
			if err != nil {
				return nil, d.fail("appearance", err)
			}
			bg, err := d.Appearance.Current(ctx)
			if err != nil {
				return nil, d.fail("appearance", err)
			}
			return &struct{ Body PublicAppearance }{Body: PublicAppearance{Title: s.Title, Background: bg}}, nil
		})

	tags := []string{"installation"}
	huma.Register(api, huma.Operation{OperationID: "get-appearance", Method: http.MethodGet, Path: "/installation/appearance",
		Summary: "Appearance settings and the current background images", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*struct{ Body AppearanceSettings }, error) {
			if _, err := requireOperator(ctx, identity.RoleOwner, identity.RoleAdmin, identity.RoleAuditor); err != nil {
				return nil, err
			}
			s, err := d.Appearance.Settings(ctx)
			if err != nil {
				return nil, d.fail("appearance", err)
			}
			return d.appearanceOut(ctx, s)
		})

	huma.Register(api, huma.Operation{OperationID: "update-appearance", Method: http.MethodPut, Path: "/installation/appearance",
		Summary: "Change the appearance; a changed background source fetches new images", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, in *struct{ Body AppearanceSettings }) (*struct{ Body AppearanceSettings }, error) {
			if _, err := requireOperator(ctx, identity.RoleOwner, identity.RoleAdmin); err != nil {
				return nil, err
			}
			old, err := d.Appearance.Settings(ctx)
			if err != nil {
				return nil, d.fail("appearance", err)
			}
			b := in.Body.Background
			s, err := d.Appearance.Update(ctx, change(ctx, ""), appearance.Settings{Title: in.Body.Title, Background: appearance.Background{
				Source: b.Source, Category: b.Category, Files: b.Files, Rotation: b.Rotation, Count: b.Count, Refresh: b.Refresh}})
			if err != nil {
				return nil, d.fail("appearance", err)
			}
			ob, nb := old.Background, s.Background
			changed := ob.Source != nb.Source || ob.Category != nb.Category || ob.Count != nb.Count || len(ob.Files) != len(nb.Files)
			for i := 0; !changed && i < len(nb.Files); i++ {
				changed = ob.Files[i] != nb.Files[i]
			}
			if changed && nb.Source != appearance.SourceNone {
				if _, err := d.Appearance.Refresh(ctx, change(ctx, "")); err != nil {
					return nil, d.fail("appearance", err) // the settings are saved; the old images stay until a refresh works
				}
			}
			return d.appearanceOut(ctx, s)
		})

	huma.Register(api, huma.Operation{OperationID: "refresh-appearance", Method: http.MethodPost, Path: "/installation/appearance/refresh",
		Summary: "Fetch a new selection of background images now", Tags: tags, Security: sessionSecurity},
		func(ctx context.Context, _ *struct{}) (*struct{ Body AppearanceSettings }, error) {
			if _, err := requireOperator(ctx, identity.RoleOwner, identity.RoleAdmin); err != nil {
				return nil, err
			}
			if _, err := d.Appearance.Refresh(ctx, change(ctx, "")); err != nil {
				return nil, d.fail("appearance", err)
			}
			s, err := d.Appearance.Settings(ctx)
			if err != nil {
				return nil, d.fail("appearance", err)
			}
			return d.appearanceOut(ctx, s)
		})

	huma.Register(api, huma.Operation{OperationID: "upload-application-icon", Method: http.MethodPut, Path: "/tenants/{tenant}/applications/{app}/icon",
		Summary: "Upload an application icon", Tags: []string{"applications"}, Security: sessionSecurity},
		func(ctx context.Context, in *struct {
			AppRef
			ManagedBy
			IfMatch
			Body IconUpload
		}) (*struct {
			ETag string `header:"ETag"`
			Body Application
		}, error) {
			sc, err := d.tenantAdmin(ctx, in.Tenant, authz.PermAppManage)
			if err != nil {
				return nil, err
			}
			v, err := in.Version()
			if err != nil {
				return nil, err
			}
			raw, err := base64.StdEncoding.DecodeString(in.Body.ContentBase64)
			if err != nil || len(raw) > 512<<10 {
				return nil, d.fail("app-icon", apperr.New(apperr.CodeInvalid, "content_base64 must be base64 of an image of at most 512 KiB"))
			}
			e, err := appearance.EncodeIcon(raw)
			if err != nil {
				return nil, d.fail("app-icon", apperr.Wrap(apperr.CodeInvalid, err, "%v", err))
			}
			a, c, err := d.Apps.Update(ctx, change(ctx, in.ManagedBy.ManagedBy), sc, in.App, apps.UpdateParams{
				Icon: &apps.Icon{Source: appearance.IconUpload, Image: &e}, IfVersion: v})
			if err != nil {
				return nil, d.fail("app-icon", err)
			}
			return &struct {
				ETag string `header:"ETag"`
				Body Application
			}{ETag: etag(a.Version), Body: d.appDTO(a, c)}, nil
		})
}

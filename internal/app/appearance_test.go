package app_test

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/png"
	"net/http"
	"strings"
	"testing"
)

// Application icons and launcher groups through the API (ADR-0045): an uploaded icon is re-encoded, served from
// /media with immutable caching and a sandboxing CSP, and shown in the launcher with the application's group.
func TestApplicationIconsAndLauncherGroups(t *testing.T) {
	a := newApp(t)
	owner := setupOwner(t, a)
	expect(t, owner.do(http.MethodPost, "/api/v1/tenants", map[string]string{"slug": "smith", "name": "Smith"}, nil), http.StatusCreated)
	app := decode[map[string]any](t, owner.do(http.MethodPost, "/api/v1/tenants/smith/applications", map[string]any{"slug": "photos",
		"name": "Photos", "kind": "forward_auth", "hosts": []string{"photos.smith.example"}, "group": "  Media  "}, nil))
	if app["group"] != "Media" || app["icon_url"] != "" {
		t.Fatalf("created: %v", app)
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, image.NewNRGBA(image.Rect(0, 0, 600, 300)))
	up := decode[map[string]any](t, owner.do(http.MethodPut, "/api/v1/tenants/smith/applications/photos/icon",
		map[string]string{"content_base64": base64.StdEncoding.EncodeToString(buf.Bytes())}, nil))
	iconURL, _ := up["icon_url"].(string)
	if up["icon_source"] != "upload" || !strings.HasPrefix(iconURL, "/media/") || up["group"] != "Media" {
		t.Fatalf("after upload: %v", up)
	}
	// Not an image: refused, nothing stored.
	rec := owner.do(http.MethodPut, "/api/v1/tenants/smith/applications/photos/icon",
		map[string]string{"content_base64": base64.StdEncoding.EncodeToString([]byte("<svg onload=alert(1)></svg>"))}, nil)
	expect(t, rec, http.StatusUnprocessableEntity)

	img := owner.do(http.MethodGet, iconURL, nil, nil)
	expect(t, img, http.StatusOK)
	h := img.Header()
	if h.Get("Content-Type") != "image/png" || !strings.Contains(h.Get("Cache-Control"), "immutable") ||
		h.Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(h.Get("Content-Security-Policy"), "sandbox") {
		t.Fatalf("media headers: %v", h)
	}
	if cfg, _, err := image.DecodeConfig(img.Body); err != nil || cfg.Width != 256 || cfg.Height != 128 {
		t.Fatalf("served icon: %v %v", cfg, err)
	}
	expect(t, owner.do(http.MethodGet, "/media/"+strings.Repeat("0", 64), nil, nil), http.StatusNotFound)
	expect(t, owner.do(http.MethodGet, "/media/..%2f..%2fetc", nil, nil), http.StatusNotFound)

	// The launcher carries the icon and group; members without app:manage cannot change icons.
	ada, _ := memberClient(t, a, owner, "smith", "Ada")
	apps := decode[[]map[string]any](t, ada.do(http.MethodGet, "/api/v1/me/apps", nil, nil))
	if len(apps) != 1 || apps[0]["icon_url"] != iconURL || apps[0]["group"] != "Media" {
		t.Fatalf("launcher: %v", apps)
	}
	// Tenant administration hides the tenant from members who cannot administer it (404, not 403).
	expect(t, ada.do(http.MethodPut, "/api/v1/tenants/smith/applications/photos/icon",
		map[string]string{"content_base64": base64.StdEncoding.EncodeToString(buf.Bytes())}, nil), http.StatusNotFound)

	// An SVG upload stays SVG, without its script, behind the same headers.
	svg := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 8 8" onload="alert(1)"><script>alert(1)</script><path d="M0 0h8v8z"/></svg>`
	sv := decode[map[string]any](t, owner.do(http.MethodPut, "/api/v1/tenants/smith/applications/photos/icon",
		map[string]string{"content_base64": base64.StdEncoding.EncodeToString([]byte(svg))}, nil))
	svgRec := owner.do(http.MethodGet, sv["icon_url"].(string), nil, nil)
	expect(t, svgRec, http.StatusOK)
	if svgRec.Header().Get("Content-Type") != "image/svg+xml" || !strings.Contains(svgRec.Header().Get("Content-Security-Policy"), "sandbox") ||
		strings.Contains(svgRec.Body.String(), "alert") || !strings.Contains(svgRec.Body.String(), `<path d="M0 0h8v8z">`) {
		t.Fatalf("svg icon: %v %s", svgRec.Header(), svgRec.Body.String())
	}

	// Removing the icon keeps the group.
	rm := decode[map[string]any](t, owner.do(http.MethodPatch, "/api/v1/tenants/smith/applications/photos",
		map[string]any{"icon": map[string]string{"source": ""}}, nil))
	if rm["icon_url"] != "" || rm["icon_source"] != "" || rm["group"] != "Media" {
		t.Fatalf("after removal: %v", rm)
	}

	// The sign-in page's appearance is public; backgrounds are off until an operator picks a source.
	pub := decode[map[string]any](t, (&client{t: t, h: a.PublicHandler(), remote: "198.51.100.9:1"}).do(http.MethodGet, "/api/v1/appearance", nil, nil))
	if pub["title"] != "Porch" || pub["background"] != nil {
		t.Fatalf("public appearance: %v", pub)
	}
	expect(t, ada.do(http.MethodPut, "/api/v1/installation/appearance", map[string]any{"title": "Ours",
		"background": map[string]any{"source": "none", "files": []string{}, "rotation": "visit", "count": 3, "refresh": "never"}}, nil), http.StatusForbidden)
	set := decode[map[string]any](t, owner.do(http.MethodPut, "/api/v1/installation/appearance", map[string]any{"title": "Smith family",
		"background": map[string]any{"source": "none", "files": []string{}, "rotation": "visit", "count": 3, "refresh": "never"}}, nil))
	if set["title"] != "Smith family" {
		t.Fatalf("settings: %v", set)
	}
}

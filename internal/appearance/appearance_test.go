package appearance_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aurimasniekis/go-porch/internal/appearance"
	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/domain"
	"github.com/aurimasniekis/go-porch/internal/testenv"
)

func pngOf(w, h int) []byte {
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for x := 0; x < w; x++ {
		img.Set(x, 0, color.NRGBA{R: 200, A: 255})
	}
	var b bytes.Buffer
	_ = png.Encode(&b, img)
	return b.Bytes()
}

func jpegOf(w, h int) []byte {
	var b bytes.Buffer
	_ = jpeg.Encode(&b, image.NewRGBA(image.Rect(0, 0, w, h)), nil)
	return b.Bytes()
}

// bombPNG is a valid PNG header claiming 100000×100000 pixels: it must be refused before any pixel is decoded.
func bombPNG() []byte {
	b := pngOf(1, 1)
	// IHDR data starts at byte 16 (8 signature + 4 length + 4 type); CRC covers type+data (bytes 12..28).
	binary.BigEndian.PutUint32(b[16:], 100000)
	binary.BigEndian.PutUint32(b[20:], 100000)
	binary.BigEndian.PutUint32(b[29:], crc32.ChecksumIEEE(b[12:29]))
	return b
}

func TestEncodeIconAndBackground(t *testing.T) {
	e, err := appearance.EncodeIcon(pngOf(1024, 512))
	if err != nil {
		t.Fatal(err)
	}
	if e.ContentType != "image/png" || e.Width != 256 || e.Height != 128 || len(e.ID) != 64 {
		t.Fatalf("icon: %+v", e)
	}
	if _, err := appearance.EncodeIcon([]byte("<svg onload=alert(1)>")); !errors.Is(err, appearance.ErrImage) {
		t.Fatalf("non-image accepted: %v", err)
	}
	if _, err := appearance.EncodeIcon([]byte("<html><script>alert(1)</script></html>")); !errors.Is(err, appearance.ErrImage) {
		t.Fatalf("html accepted: %v", err)
	}
	if _, err := appearance.EncodeIcon(bombPNG()); !errors.Is(err, appearance.ErrImage) || !strings.Contains(err.Error(), "pixels") {
		t.Fatalf("decompression bomb not refused by its header: %v", err)
	}
	bg, err := appearance.EncodeBackground(jpegOf(4000, 2000))
	if err != nil {
		t.Fatal(err)
	}
	if bg.ContentType != "image/jpeg" || bg.Width != 2560 || bg.Height != 1280 {
		t.Fatalf("background: %dx%d %s", bg.Width, bg.Height, bg.ContentType)
	}
	if _, err := appearance.EncodeBackground(jpegOf(600, 900)); !errors.Is(err, appearance.ErrImage) {
		t.Fatalf("portrait background accepted: %v", err)
	}
	if _, err := appearance.EncodeBackground(jpegOf(2560, 400)); !errors.Is(err, appearance.ErrImage) {
		t.Fatalf("panorama background accepted: %v", err)
	}
}

// fakeSources serves a Wikimedia Commons API, Picsum and dashboard-icons over TLS.
func fakeSources(t *testing.T) (*httptest.Server, *int) {
	t.Helper()
	listed := 0
	mux := http.NewServeMux()
	var base string
	mux.HandleFunc("/w/api.php", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "" {
			http.Error(w, "user agent required", http.StatusForbidden)
			return
		}
		q := r.URL.Query()
		if q.Get("list") == "categorymembers" {
			listed++
			if q.Get("cmtitle") != "Category:Featured pictures of landscapes" {
				_, _ = w.Write([]byte(`{"query":{"categorymembers":[]}}`))
				return
			}
			_, _ = w.Write([]byte(`{"query":{"categorymembers":[{"title":"File:Lake.jpg"},{"title":"File:Tower.jpg"},{"title":"File:Map.svg"}]}}`))
			return
		}
		pages := map[string]any{}
		for i, title := range strings.Split(q.Get("titles"), "|") {
			w, h := 4000, 2500
			if title == "File:Tower.jpg" {
				w, h = 2000, 3000 // portrait: skipped
			}
			pages[fmt.Sprint(i)] = map[string]any{"title": title, "imageinfo": []any{map[string]any{
				"thumburl": base + "/img/" + strings.TrimPrefix(title, "File:"), "descriptionurl": "https://commons.example/wiki/" + title,
				"mime": "image/jpeg", "width": w, "height": h, "extmetadata": map[string]any{
					"Artist":                   map[string]string{"value": `<a href="//commons.wikimedia.org/wiki/User:Anna">Anna &amp; Co</a> <script>x</script>`},
					"LicenseShortName":         map[string]string{"value": "CC BY-SA 4.0"},
					"LicenseUrl":               map[string]string{"value": "https://creativecommons.org/licenses/by-sa/4.0"},
					"ObjectName":               map[string]string{"value": "Lake at dawn"},
					"CommonsMetadataExtension": map[string]any{"value": 1.2}}}}}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"query": map[string]any{"pages": pages}})
	})
	mux.HandleFunc("/img/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "Tower.jpg") {
			_, _ = w.Write(jpegOf(200, 300))
			return
		}
		_, _ = w.Write(jpegOf(3000, 1800))
	})
	mux.HandleFunc("/id/{id}/info", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"id":%q,"author":"Bo","width":5000,"height":3333,"url":"https://unsplash.com/photos/x"}`, r.PathValue("id"))
	})
	mux.HandleFunc("/id/{id}/2560/1600.jpg", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(jpegOf(2560, 1600)) })
	mux.HandleFunc("/png/grafana.png", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(pngOf(512, 512)) })
	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)
	base = ts.URL
	return ts, &listed
}

func newService(t *testing.T, ts *httptest.Server) (*appearance.Service, *testenv.Env) {
	e := testenv.New(t)
	f := &appearance.Fetcher{Client: ts.Client(), UserAgent: "porch-test", WikimediaAPI: ts.URL + "/w/api.php", PicsumAPI: ts.URL,
		DashboardIcons: ts.URL}
	return appearance.New(e.Store, e.Audit, f, e.Clock, nil), e
}

var admin = domain.Change{Actor: audit.System}

func TestWikimediaBackgrounds(t *testing.T) {
	ts, _ := fakeSources(t)
	svc, e := newService(t, ts)
	ctx := context.Background()
	if bg, _ := svc.Current(ctx); bg != nil {
		t.Fatal("backgrounds are on by default")
	}
	s, err := svc.Update(ctx, admin, appearance.Settings{Title: "Smith family", Background: appearance.Background{
		Providers: []appearance.Provider{{Source: appearance.SourceWikimedia}}, Rotation: appearance.RotateDaily, Count: 3}})
	if err != nil {
		t.Fatal(err)
	}
	if s.Background.Providers[0].Category != appearance.DefaultCategory {
		t.Fatalf("category default: %q", s.Background.Providers[0].Category)
	}
	imgs, err := svc.Refresh(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	if len(imgs) != 1 { // Tower.jpg is portrait, Map.svg is not a JPEG
		t.Fatalf("pool: %+v", imgs)
	}
	got := imgs[0]
	if got.Author != "Anna & Co x" || got.License != "CC BY-SA 4.0" || got.Title != "Lake at dawn" || got.Width != 2560 ||
		!strings.HasPrefix(got.SourceURL, "https://commons.example/") || got.URL != "/media/"+got.ID {
		t.Fatalf("credit or image: %+v", got)
	}
	cur, err := svc.Current(ctx)
	if err != nil || cur == nil || cur.ID != got.ID {
		t.Fatalf("current: %+v %v", cur, err)
	}
	ct, data, err := svc.Media(ctx, got.ID)
	if err != nil || ct != "image/jpeg" || !bytes.HasPrefix(data, []byte{0xff, 0xd8}) {
		t.Fatalf("media: %s %v", ct, err)
	}
	if svc.RefreshDue(ctx) {
		t.Fatal("refresh due right after a refresh")
	}
	e.Clock.Advance(8 * 24 * time.Hour)
	if !svc.RefreshDue(ctx) {
		t.Fatal("weekly refresh not due after 8 days")
	}
	// Turning backgrounds off (no providers) removes the pool.
	if _, err := svc.Update(ctx, admin, appearance.Settings{Background: appearance.Background{}}); err != nil {
		t.Fatal(err)
	}
	if left, _ := svc.Backgrounds(ctx); len(left) != 0 {
		t.Fatalf("pool kept after source none: %d", len(left))
	}
}

func TestPicsumAndNamedFilesAndValidation(t *testing.T) {
	ts, listed := fakeSources(t)
	svc, _ := newService(t, ts)
	ctx := context.Background()
	if _, err := svc.Update(ctx, admin, appearance.Settings{Background: appearance.Background{Providers: []appearance.Provider{
		{Source: appearance.SourcePicsum, Files: []string{"1015", "1016"}}}}}); err != nil {
		t.Fatal(err)
	}
	imgs, err := svc.Refresh(ctx, admin)
	if err != nil || len(imgs) != 1 { // both IDs serve the same bytes: one stored image
		t.Fatalf("picsum: %+v %v", imgs, err)
	}
	if imgs[0].Author != "Bo" || imgs[0].License != "Unsplash License" {
		t.Fatalf("picsum credit: %+v", imgs[0])
	}
	if _, err := svc.Update(ctx, admin, appearance.Settings{Background: appearance.Background{Providers: []appearance.Provider{
		{Source: appearance.SourcePicsum, Files: []string{"../etc"}}}}}); err != nil {
		t.Fatal(err) // syntactically a name; refused by the fetcher below
	}
	if _, err := svc.Refresh(ctx, admin); err == nil {
		t.Fatal("non-numeric picsum ID fetched")
	}
	// Named Commons files skip the category listing.
	before := *listed
	if _, err := svc.Update(ctx, admin, appearance.Settings{Background: appearance.Background{Providers: []appearance.Provider{
		{Source: appearance.SourceWikimedia, Files: []string{"Lake.jpg"}}}}}); err != nil {
		t.Fatal(err)
	}
	if imgs, err := svc.Refresh(ctx, admin); err != nil || len(imgs) != 1 || *listed != before {
		t.Fatalf("named file: %+v %v (category listed %d times)", imgs, err, *listed-before)
	}
	for _, bad := range []appearance.Settings{
		{Background: appearance.Background{Providers: []appearance.Provider{{Source: "flickr"}}}},
		{Background: appearance.Background{Providers: []appearance.Provider{{Source: appearance.SourceWikimedia, Category: "a|b"}}}},
		{Background: appearance.Background{Providers: []appearance.Provider{{Source: appearance.SourceWikimedia}}, Count: 50}},
		{Background: appearance.Background{Providers: []appearance.Provider{{Source: appearance.SourceURL}}}},
		{Background: appearance.Background{Providers: []appearance.Provider{{Source: appearance.SourceURL, Files: []string{"http://x.example/a.jpg"}}}}},
		{Title: strings.Repeat("x", 81)},
	} {
		if _, err := svc.Update(ctx, admin, bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestFetchIcon(t *testing.T) {
	ts, _ := fakeSources(t)
	svc, _ := newService(t, ts)
	ctx := context.Background()
	e, err := svc.FetchIcon(ctx, appearance.IconDashboardIcons, "grafana")
	if err != nil || e.Width != 256 {
		t.Fatalf("dashboard icon: %+v %v", e, err)
	}
	if _, err := svc.FetchIcon(ctx, appearance.IconDashboardIcons, "../../etc/passwd"); err == nil {
		t.Fatal("path in icon name accepted")
	}
	if _, err := svc.FetchIcon(ctx, appearance.IconURL, "http://example.com/x.png"); err == nil {
		t.Fatal("plain-http icon URL accepted")
	}
	if _, err := svc.FetchIcon(ctx, appearance.IconURL, ts.URL+"/png/grafana.png"); err != nil {
		t.Fatal(err)
	}
}

func TestSanitizeSVG(t *testing.T) {
	logo := `<?xml version="1.0"?><!-- logo --><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 10 10" onload="alert(1)">
<defs><linearGradient id="a"><stop offset="0" stop-color="#FFF100"/></linearGradient><style>.c{fill:url(#a)}</style></defs>
<script>alert(1)</script>
<foreignObject><div xmlns="http://www.w3.org/1999/xhtml"><iframe src="https://evil.example"/></div></foreignObject>
<a href="javascript:alert(1)"><path d="M0 0"/></a>
<image href="https://tracker.example/pixel.png"/>
<use xlink:href="#a"/><use href="https://evil.example/x.svg#a"/>
<path class="c" d="M0 0h10v10z" fill="url(#a)" style="fill:url(https://evil.example/x)" onclick="alert(1)"/>
<rect width="5" height="5" fill="url( 'javascript:alert(1)')"/>
</svg>`
	e, err := appearance.EncodeIcon([]byte(logo))
	if err != nil {
		t.Fatal(err)
	}
	out := string(e.Data)
	if e.ContentType != "image/svg+xml" || !strings.HasPrefix(out, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10">`) {
		t.Fatalf("sanitized: %s", out)
	}
	for _, bad := range []string{"script", "alert", "onload", "onclick", "foreignObject", "iframe", "evil.example", "tracker", "javascript", "<a", "<image"} {
		if strings.Contains(out, bad) {
			t.Errorf("%q survived: %s", bad, out)
		}
	}
	for _, good := range []string{`<use href="#a">`, `fill="url(#a)"`, `.c{fill:url(#a)}`, `<stop offset="0" stop-color="#FFF100">`, `d="M0 0h10v10z"`} {
		if !strings.Contains(out, good) {
			t.Errorf("%q lost: %s", good, out)
		}
	}
	for name, doc := range map[string]string{
		"doctype entities": `<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;">]><svg xmlns="http://www.w3.org/2000/svg">&b;</svg>`,
		"external style":   `<svg xmlns="http://www.w3.org/2000/svg"><style>@import url(https://evil.example/x.css);</style></svg>`,
		"not svg":          `<html><svg></svg></html>`,
		"truncated":        `<svg xmlns="http://www.w3.org/2000/svg"><g>`,
	} {
		if _, err := appearance.SanitizeSVG([]byte(doc)); !errors.Is(err, appearance.ErrImage) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
}

func TestTheSVGAndDashboardSVG(t *testing.T) {
	mux := http.NewServeMux()
	svg := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M0 0h24v24H0z"/></svg>`
	mux.HandleFunc("/thesvg/github/mono.svg", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(svg)) })
	mux.HandleFunc("/dash/svg/jellyfin.svg", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(svg)) })
	mux.HandleFunc("/dash/png/legacy.png", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(pngOf(64, 64)) })
	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)
	e := testenv.New(t)
	svc := appearance.New(e.Store, e.Audit, &appearance.Fetcher{Client: ts.Client(), UserAgent: "porch-test", TheSVGBase: ts.URL + "/thesvg",
		DashboardIcons: ts.URL + "/dash"}, e.Clock, nil)
	ctx := context.Background()
	if got, err := svc.FetchIcon(ctx, appearance.IconTheSVG, "github/mono"); err != nil || got.ContentType != "image/svg+xml" {
		t.Fatalf("thesvg: %+v %v", got, err)
	}
	if got, err := svc.FetchIcon(ctx, appearance.IconDashboardIcons, "jellyfin"); err != nil || got.ContentType != "image/svg+xml" {
		t.Fatalf("dashboard svg: %+v %v", got, err)
	}
	if got, err := svc.FetchIcon(ctx, appearance.IconDashboardIcons, "legacy"); err != nil || got.ContentType != "image/png" {
		t.Fatalf("dashboard png fallback: %+v %v", got, err)
	}
	for _, bad := range []string{"../x", "GitHub", "a/b/c", "github/../../x"} {
		if _, err := svc.FetchIcon(ctx, appearance.IconTheSVG, bad); err == nil {
			t.Errorf("thesvg ref %q accepted", bad)
		}
	}
}

// Several providers fill one pool in turn; a failing provider leaves its share to the others.
func TestMixedProviders(t *testing.T) {
	ts, _ := fakeSources(t)
	svc, _ := newService(t, ts)
	ctx := context.Background()
	if _, err := svc.Update(ctx, admin, appearance.Settings{Background: appearance.Background{Count: 3, Providers: []appearance.Provider{
		{Source: appearance.SourceWikimedia, Category: "Featured pictures of landscapes"},
		{Source: appearance.SourceWikimedia, Category: "Empty category"}, // lists nothing: its share goes to the others
		{Source: appearance.SourcePicsum, Files: []string{"1015"}},
		{Source: appearance.SourceURL, Files: []string{ts.URL + "/img/Own.jpg"}},
	}}}); err != nil {
		t.Fatal(err)
	}
	imgs, err := svc.Refresh(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	from := map[string]bool{}
	for _, i := range imgs {
		switch {
		case i.License == "CC BY-SA 4.0":
			from["wikimedia"] = true
		case i.License == "Unsplash License":
			from["picsum"] = true
		case i.Title == "Own.jpg":
			from["url"] = true
		}
	}
	// The fake Commons and URL images have the same bytes, so the pool de-duplicates them: two distinct images.
	if len(imgs) != 2 || !from["picsum"] || (!from["wikimedia"] && !from["url"]) {
		t.Fatalf("mixed pool: %+v", imgs)
	}
}

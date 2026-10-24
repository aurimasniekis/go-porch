package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/aurimasniekis/go-porch/internal/httpx"
)

var files = fstest.MapFS{
	"index.html":   {Data: []byte(`<!doctype html><html><head><link rel="stylesheet" href="/assets/a.css"><script type="module" src="/assets/a.js"></script></head><body></body></html>`)},
	"assets/a.js":  {Data: []byte("console.log(1)")},
	"assets/a.css": {Data: []byte("body{}")},
	"favicon.svg":  {Data: []byte("<svg/>")},
}

func serve(path string, hook Hook) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	httpx.SecurityHeaders(false, Handler(files, hook)).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestIndexNonceMatchesCSP(t *testing.T) {
	rec := serve("/account", nil)
	csp := rec.Header().Get("Content-Security-Policy")
	i := strings.Index(csp, "'nonce-")
	nonce := csp[i+7 : strings.Index(csp[i+7:], "'")+i+7]
	body := rec.Body.String()
	for _, want := range []string{`<script nonce="` + nonce + `"`, `<link nonce="` + nonce + `" rel="stylesheet"`, `<meta name="porch-csp-nonce" content="` + nonce + `">`} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %s in %s", want, body)
		}
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("index cacheable")
	}
	if serve("/account", nil).Body.String() == body {
		t.Fatal("nonce reused across requests")
	}
}

func TestAssets(t *testing.T) {
	if rec := serve("/assets/a.js", nil); rec.Code != 200 || !strings.Contains(rec.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("asset %d %v", rec.Code, rec.Header())
	}
	if rec := serve("/assets/missing.js", nil); rec.Code != 404 {
		t.Fatalf("missing asset %d", rec.Code)
	}
	if rec := serve("/favicon.svg", nil); rec.Code != 200 {
		t.Fatal("favicon")
	}
}

func TestHookCanRedirect(t *testing.T) {
	rec := serve("/apps", func(w http.ResponseWriter, r *http.Request) bool {
		http.Redirect(w, r, "/login/google?intent=recheck", http.StatusFound)
		return true
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("code %d", rec.Code)
	}
}

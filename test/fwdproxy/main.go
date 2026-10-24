// Command fwdproxy is a minimal reverse proxy that behaves like Caddy's forward_auth in front of a "whoami" backend:
// it strips client-supplied X-Porch-* / Remote-* headers, routes /.porch/* to Porch preserving the Host header, asks
// Porch's /outpost/auth for every other request and relays its redirects. TEST ONLY (browser e2e); the demo stack
// uses real Caddy.
package main

import (
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
	"time"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:9998", "listen address")
	porchURL := flag.String("porch", "http://127.0.0.1:8080", "Porch base URL (reachable from this proxy)")
	flag.Parse()
	pu, err := url.Parse(*porchURL)
	if err != nil {
		log.Fatal(err)
	}
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	rp := &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) {
		pr.SetURL(pu)
		pr.Out.Host = pr.In.Host
	}}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k := range r.Header {
			lk := strings.ToLower(k)
			if strings.HasPrefix(lk, "x-porch-") || strings.HasPrefix(lk, "remote-") {
				r.Header.Del(k)
			}
		}
		if strings.HasPrefix(r.URL.Path, "/.porch/") {
			rp.ServeHTTP(w, r)
			return
		}
		req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, pu.String()+"/outpost/auth", nil)
		req.Header.Set("X-Forwarded-Method", r.Method)
		req.Header.Set("X-Forwarded-Proto", "http")
		req.Header.Set("X-Forwarded-Host", r.Host)
		req.Header.Set("X-Forwarded-Uri", r.URL.RequestURI())
		for _, c := range r.Cookies() {
			req.AddCookie(c)
		}
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			for k, v := range resp.Header {
				w.Header()[k] = v
			}
			w.WriteHeader(resp.StatusCode)
			_, _ = io.Copy(w, resp.Body)
			return
		}
		var keys []string
		for k := range resp.Header {
			if strings.HasPrefix(strings.ToLower(k), "x-porch-") {
				r.Header[k] = resp.Header[k]
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, "<!doctype html><html lang=\"en\"><head><title>whoami</title></head><body><main><h1>whoami</h1><p>%s %s</p><dl>",
			html.EscapeString(r.Method), html.EscapeString(r.URL.RequestURI()))
		for _, k := range keys {
			_, _ = fmt.Fprintf(w, "<dt>%s</dt><dd>%s</dd>", html.EscapeString(k), html.EscapeString(r.Header.Get(k)))
		}
		_, _ = fmt.Fprint(w, "</dl></main></body></html>")
	})
	srv := &http.Server{Addr: *listen, Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second}
	log.Printf("fwdproxy (TEST ONLY) on %s → %s", *listen, pu)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

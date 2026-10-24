package netguard

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestAllowed(t *testing.T) {
	g, _ := New(nil)
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "192.168.1.1", "172.16.0.1", "169.254.169.254", "::1", "fe80::1", "fd00::1",
		"100.64.1.1", "0.0.0.0", "::ffff:127.0.0.1", "64:ff9b::a00:1"} {
		if g.Allowed(netip.MustParseAddr(s)) {
			t.Errorf("%s allowed", s)
		}
	}
	for _, s := range []string{"142.250.74.110", "2a00:1450:4001::200e", "8.8.8.8"} {
		if !g.Allowed(netip.MustParseAddr(s)) {
			t.Errorf("%s blocked", s)
		}
	}
	g2, _ := New([]string{"127.0.0.1/32"})
	if !g2.Allowed(netip.MustParseAddr("127.0.0.1")) || g2.Allowed(netip.MustParseAddr("127.0.0.2")) {
		t.Fatal("allowlist wrong")
	}
}

func TestClientRefusesLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	g, _ := New(nil)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	_, err := g.Client(5 * time.Second).Do(req)
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("got %v", err)
	}
	g2, _ := New([]string{"127.0.0.0/8"})
	resp, err := g2.Client(5 * time.Second).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

// Security review L9: IPv6 forms that embed IPv4 addresses must not reach internal hosts.
func TestEmbeddedIPv4Blocked(t *testing.T) {
	g, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"::7f00:1", "::a00:1", "2002:7f00:1::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2", "64:ff9b:1::a00:1",
		"fec0::1", "::ffff:0:a00:1"} {
		if g.Allowed(netip.MustParseAddr(s)) {
			t.Errorf("%s allowed", s)
		}
	}
	if !g.Allowed(netip.MustParseAddr("2606:4700:4700::1111")) {
		t.Error("public IPv6 refused")
	}
}

func TestAddRootCAs(t *testing.T) {
	g, _ := New(nil)
	if err := g.AddRootCAs([]byte("not a certificate")); err == nil {
		t.Fatal("garbage accepted as CA")
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer srv.Close()
	pem := pemCert(srv.Certificate().Raw)
	g, _ = New([]string{"127.0.0.0/8"})
	if _, err := g.Client(5 * time.Second).Get(srv.URL); err == nil { //nolint:noctx // test
		t.Fatal("untrusted test CA accepted")
	}
	if err := g.AddRootCAs(pem); err != nil {
		t.Fatal(err)
	}
	resp, err := g.Client(5 * time.Second).Get(srv.URL) //nolint:noctx // test
	if err != nil {
		t.Fatalf("trusted extra CA: %v", err)
	}
	resp.Body.Close()
}

func pemCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

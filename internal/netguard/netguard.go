// Package netguard builds outbound HTTP clients that refuse to connect to internal addresses (SSRF guard for upstream
// OIDC discovery, token exchange, S3 and directory APIs). The check runs on the resolved IP at dial time, so DNS
// rebinding cannot bypass it; redirects are re-checked by the same dialer.
package netguard

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// ErrBlocked means the destination address is not allowed.
var ErrBlocked = errors.New("outbound connection to an internal address refused")

// Guard decides which destination addresses are allowed.
type Guard struct {
	allow []netip.Prefix
}

// New returns a guard that additionally allows the given CIDRs (e.g. a LAN MinIO or a test IdP on 127.0.0.1/32).
func New(allowCIDRs []string) (*Guard, error) {
	g := &Guard{}
	for _, s := range allowCIDRs {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("outbound allow %q: %w", s, err)
		}
		g.allow = append(g.allow, p.Masked())
	}
	return g, nil
}

// Allowed reports whether a may be dialed.
func (g *Guard) Allowed(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range g.allow {
		if p.Contains(a) {
			return true
		}
	}
	if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast() ||
		a.IsUnspecified() || a.IsInterfaceLocalMulticast() {
		return false
	}
	for _, p := range blocked {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// blocked are special-purpose ranges not covered by netip's predicates.
var blocked = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"), // NAT64 can reach IPv4 internals
	netip.MustParsePrefix("fc00::/7"),
}

func (g *Guard) control(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return err
	}
	if !g.Allowed(a) {
		return fmt.Errorf("%w: %s", ErrBlocked, a)
	}
	return nil
}

// Client returns an HTTP client using the guard, with conservative timeouts.
func (g *Guard) Client(timeout time.Duration) *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: g.control}
	tr := &http.Transport{
		Proxy:                 nil, // never route through an environment proxy that could reach internals
		DialContext:           d.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          20,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
	}
	return &http.Client{Timeout: timeout, Transport: tr, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		return nil
	}}
}

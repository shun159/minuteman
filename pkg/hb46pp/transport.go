package hb46pp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"
)

// httpTimeout bounds one whole provisioning HTTP exchange (dial, TLS,
// request, response body). Generous, since the caller's ctx can always
// cut it shorter.
const httpTimeout = 30 * time.Second

// resolver is the subset of *net.Resolver this package performs lookups
// through; it's an interface so tests can substitute a fake without a
// live DNS server.
type resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// newResolver returns a resolver dialed against servers (in order,
// first reachable wins), or the system resolver if servers is empty --
// the same policy as pkg/aftrdiscovery's AFTR-name resolution.
func newResolver(servers []netip.Addr) resolver {
	if len(servers) == 0 {
		return net.DefaultResolver
	}
	return &net.Resolver{PreferGo: true, Dial: dialServers(servers)}
}

// dialServers returns a net.Resolver.Dial function that tries each of
// servers in order on port 53, ignoring the address the resolver itself
// would have used, and falling back to the next server on dial failure.
// (Mirrors pkg/aftrdiscovery's unexported helper of the same name.)
func dialServers(servers []netip.Addr) func(ctx context.Context, network, _ string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		var lastErr error
		var d net.Dialer
		for _, s := range servers {
			conn, err := d.DialContext(ctx, network, net.JoinHostPort(s.String(), "53"))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, fmt.Errorf("dialing DNS servers %v: %w", servers, lastErr)
	}
}

// newHTTPClient returns an http.Client for provisioning requests: the
// spec requires the server be accessed over IPv6 only, so the dialer
// resolves the URL host to AAAA records via res (never A) and dials
// tcp6 exclusively. TLS uses normal certificate validation unless
// validateCert is false -- the discovery TXT record's t=a, which the
// spec permits for an https URL too, not just http (see
// ServerInfo.ValidateCert) -- in which case verification is skipped, as
// the VNE itself requested via that record.
func newHTTPClient(res resolver, validateCert bool) *http.Client {
	var d net.Dialer
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if ip, err := netip.ParseAddr(host); err == nil {
			if !ip.Is6() || ip.Is4In6() {
				return nil, fmt.Errorf("hb46pp: provisioning server address %s is not IPv6 (the spec requires IPv6-only access)", host)
			}
			return d.DialContext(ctx, "tcp6", addr)
		}

		addrs, err := res.LookupNetIP(ctx, "ip6", host)
		if err != nil {
			return nil, fmt.Errorf("hb46pp: resolving provisioning server %q: %w", host, err)
		}
		var lastErr error
		for _, a := range addrs {
			conn, err := d.DialContext(ctx, "tcp6", net.JoinHostPort(a.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("no AAAA records")
		}
		return nil, fmt.Errorf("hb46pp: dialing provisioning server %q: %w", host, lastErr)
	}

	transport := &http.Transport{DialContext: dial}
	if !validateCert {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // t=a explicitly requests this, see ServerInfo.ValidateCert
	}

	return &http.Client{
		Transport: transport,
		Timeout:   httpTimeout,
		// The spec (§3.3) defines only one redirect: a 307 to another
		// provisioning server. http.Client's default policy also
		// follows 301/302/303/308, which this protocol doesn't define
		// a meaning for; disable it here so fetchProvisioning's own
		// loop -- which knows about only 307 -- is the sole redirect
		// handling.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

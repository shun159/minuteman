// Package hb46pp implements the client side of HB46PP, the
// JAIPA-standardized "HTTP-Based IPv4 over IPv6 Provisioning Protocol"
// (https://github.com/v6pc/v6mig-prov/blob/master/spec.md, protocol
// version v6mig-1): a DNS TXT lookup on the well-known domain 4over6.info
// locates the VNE's provisioning server, and an HTTP(S) GET to it returns
// a JSON document describing which IPv4-over-IPv6 migration technologies
// the VNE supports and their parameters.
//
// Like pkg/aftrdiscovery, this package runs entirely in-process (stdlib
// resolver and HTTP client, no external processes) and is
// discovery-mechanism logic only: what to do with the returned parameters
// is the caller's policy decision.
package hb46pp

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"time"
)

// Config configures a Discover call.
type Config struct {
	// Client identifies the CPE in the provisioning request's query
	// parameters.
	Client ClientInfo

	// DNSServers, if non-empty, are used (in order, first reachable
	// wins) for every DNS lookup Discover performs -- the discovery TXT
	// record, the provisioning server's AAAA record, and the AFTR
	// name's AAAA record. The spec expects these to be the VNE's own
	// resolvers (typically learned via DHCPv6 OPTION_DNS_SERVERS or RA
	// RDNSS), since the 4over6.info TXT answer is VNE-specific. If
	// empty, the system resolver is used.
	DNSServers []netip.Addr

	// resolver and httpClient override the DNS resolver and HTTP client
	// built from DNSServers; they exist for tests.
	resolver   resolver
	httpClient *http.Client
}

// Result is the outcome of a successful Discover call.
type Result struct {
	// Provisioning is the full decoded provisioning response, including
	// parameters for any technology the VNE returned.
	Provisioning *Provisioning

	// Server is the provisioning server the response came from, as
	// located via the discovery TXT record.
	Server ServerInfo

	// AFTRName and AFTRAddr carry the DS-Lite parameters when the
	// response includes them: AFTRName is the dslite.aftr value as
	// given (a DNS name or an IPv6 address literal), AFTRAddr its
	// resolved address. Both are zero when Provisioning.DSLite is nil
	// -- the VNE not offering DS-Lite is not a Discover-level error,
	// since the caller may have requested several capabilities.
	AFTRName string
	AFTRAddr netip.Addr

	// RefreshInterval is how long the response is valid for: the ttl
	// field if present (capped at the spec's 7-day maximum), otherwise
	// a random duration in the spec's 20-24h default window. Reported,
	// not acted on -- periodic re-provisioning is a caller-level policy
	// decision, same as aftrdiscovery.Result.RefreshInterval.
	RefreshInterval time.Duration
}

// Discover performs one full HB46PP provisioning exchange: TXT lookup on
// 4over6.info, HTTP(S) GET against the provisioning server it names
// (IPv6-only, as the spec requires), and JSON decoding, plus resolving
// the DS-Lite AFTR name to an address when the response carries one.
//
// It is single-shot: on failure the caller decides whether and when to
// retry (RetryDelay maps an error to the spec's backoff window).
// ErrNotProvisioned in the error chain means the VNE (as seen through
// the configured resolvers) doesn't offer HB46PP at all.
func Discover(ctx context.Context, cfg Config) (*Result, error) {
	res := cfg.resolver
	if res == nil {
		res = newResolver(cfg.DNSServers)
	}

	server, err := lookupServer(ctx, res)
	if err != nil {
		return nil, err
	}

	reqURL, err := requestURL(server.URL, cfg.Client)
	if err != nil {
		return nil, err
	}

	client := cfg.httpClient
	if client == nil {
		client = newHTTPClient(res)
	}
	prov, err := fetchProvisioning(ctx, client, reqURL)
	if err != nil {
		return nil, err
	}

	result := &Result{
		Provisioning:    prov,
		Server:          *server,
		RefreshInterval: prov.RefreshInterval(),
	}
	if prov.DSLite != nil {
		result.AFTRName = prov.DSLite.AFTR
		result.AFTRAddr, err = resolveAFTR(ctx, res, prov.DSLite.AFTR)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

// resolveAFTR turns a dslite.aftr value -- "DNS name or IPv6 address"
// per the spec -- into an IPv6 address, resolving via res when it isn't
// already a literal. If the name resolves to multiple addresses, the
// first is used (the spec does not specify a selection policy; same
// stance as aftrdiscovery).
func resolveAFTR(ctx context.Context, res resolver, aftr string) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(aftr); err == nil {
		if !addr.Is6() || addr.Is4In6() {
			return netip.Addr{}, fmt.Errorf("hb46pp: dslite.aftr %q is not an IPv6 address", aftr)
		}
		return addr, nil
	}

	addrs, err := res.LookupNetIP(ctx, "ip6", aftr)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("hb46pp: resolving dslite.aftr %q: %w", aftr, err)
	}
	if len(addrs) == 0 {
		return netip.Addr{}, fmt.Errorf("hb46pp: dslite.aftr %q resolved to no addresses", aftr)
	}
	return addrs[0], nil
}

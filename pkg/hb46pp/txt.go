package hb46pp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// discoveryDomain is the well-known FQDN whose TXT record locates the
// VNE's provisioning server (spec §3.1). The answer is VNE-specific:
// each VNE serves its own record from its own full-service resolvers,
// which is why Config.DNSServers should be the WAN-learned resolvers,
// not a public one.
const discoveryDomain = "4over6.info"

// txtVersion is the protocol version this package implements; TXT
// records with any other v= value are ignored.
const txtVersion = "v6mig-1"

// ErrNotProvisioned means the discovery TXT lookup found no v6mig-1
// record -- NXDOMAIN, NODATA, or only records this package can't parse.
// It signals that the VNE (as seen through the configured resolvers)
// doesn't offer HB46PP, as opposed to a transient DNS/HTTP failure; the
// spec's retry backoff for it is correspondingly long (see RetryDelay).
var ErrNotProvisioned = errors.New("hb46pp: no " + txtVersion + " TXT record on " + discoveryDomain)

// ServerInfo is a provisioning server location parsed from a discovery
// TXT record.
type ServerInfo struct {
	// URL is the provisioning server URL (the record's url= field).
	URL string

	// ValidateCert reflects the record's t= field: t=b (true) requires
	// an https URL with normal certificate validation. t=a (false)
	// means no certificate validation, which the spec (§3.2) allows for
	// either a plain-http URL or an https URL accessed without
	// verifying its certificate -- the latter is threaded through to
	// newHTTPClient as InsecureSkipVerify.
	ValidateCert bool
}

// lookupServer queries discoveryDomain's TXT records via res and returns
// the first one that parses as a v6mig-1 provisioning record.
func lookupServer(ctx context.Context, res resolver) (*ServerInfo, error) {
	records, err := res.LookupTXT(ctx, discoveryDomain)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return nil, fmt.Errorf("%w: %v", ErrNotProvisioned, err)
		}
		return nil, fmt.Errorf("hb46pp: TXT lookup on %s: %w", discoveryDomain, err)
	}

	var lastErr error
	for _, rec := range records {
		info, err := parseTXTRecord(rec)
		if err == nil {
			return info, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotProvisioned, lastErr)
	}
	return nil, ErrNotProvisioned
}

// parseTXTRecord parses one discovery TXT record: space-separated
// key=value fields, e.g.
//
//	v=v6mig-1 url=https://vne.example.jp/rule.cgi t=b
//
// v, url and t are required; unknown keys are ignored per the spec. The
// t= field is validated against the URL scheme: t=b requires https
// (§3.2's certificate-validated options); t=a permits either http or
// https (§3.2's two no-validation options) -- the spec's only
// directional rule is that a plain-http URL MUST be paired with t=a,
// not that t=a implies http.
func parseTXTRecord(record string) (*ServerInfo, error) {
	kv := make(map[string]string)
	for _, field := range strings.Fields(record) {
		k, v, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		if _, dup := kv[k]; !dup {
			kv[k] = v
		}
	}

	if v := kv["v"]; v != txtVersion {
		return nil, fmt.Errorf("hb46pp: TXT record version %q, want %q", v, txtVersion)
	}
	rawURL := kv["url"]
	if rawURL == "" {
		return nil, errors.New("hb46pp: TXT record has no url= field")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("hb46pp: TXT record url %q: %w", rawURL, err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("hb46pp: TXT record url %q has no host", rawURL)
	}

	switch kv["t"] {
	case "a":
		if u.Scheme != "http" && u.Scheme != "https" {
			return nil, fmt.Errorf("hb46pp: TXT record has t=a (no certificate validation) but a %s url; t=a requires http or https", u.Scheme)
		}
		return &ServerInfo{URL: rawURL, ValidateCert: false}, nil
	case "b":
		if u.Scheme != "https" {
			return nil, fmt.Errorf("hb46pp: TXT record has t=b (certificate validation) but a %s url; t=b requires https", u.Scheme)
		}
		return &ServerInfo{URL: rawURL, ValidateCert: true}, nil
	default:
		return nil, fmt.Errorf("hb46pp: TXT record t=%q, want \"a\" or \"b\"", kv["t"])
	}
}

package hb46pp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"time"
)

// maxTTLSeconds is the spec's cap on the ttl field: 604800 seconds (7
// days).
const maxTTLSeconds = 604800

// defaultRefreshMin/Max bound the spec's re-query default when the
// response carries no ttl: a random duration in [20h, 24h].
const (
	defaultRefreshMin = 20 * time.Hour
	defaultRefreshMax = 24 * time.Hour
)

// maxResponseBytes bounds how large a provisioning response body may be;
// fetchProvisioning rejects anything over this rather than silently
// decoding just its first maxResponseBytes. The spec's per-field size
// limits put a legitimate response nowhere near this.
const maxResponseBytes = 1 << 20

// maxRedirects bounds how many spec-defined 307 forwards fetchProvisioning
// follows, guarding against a redirect loop between misconfigured servers.
const maxRedirects = 5

// Provisioning is a decoded provisioning response body (spec §3.3): the
// VNE's order-ranked list of supported migration technologies plus
// per-technology parameters. Only DS-Lite's parameters get a decoded
// struct here, since that's the only technology minuteman implements;
// the other technologies' parameter objects (map_e, map_t, lw4o6,
// 464xlat, ipip) are preserved raw so a future implementation can add
// its typed struct without re-fetching.
type Provisioning struct {
	EnablerName string `json:"enabler_name"` // VNE name (required)
	ServiceName string `json:"service_name"` // service name (required)
	ISPName     string `json:"isp_name"`     // optional
	Token       string `json:"token"`        // optional; echo in the next request's token parameter
	Auth        string `json:"auth"`         // optional: "req", "bad" or "ok"
	IPv6Mostly  bool   `json:"ipv6_mostly"`  // optional

	// TTL is the response's validity in seconds; nil when absent. Use
	// RefreshInterval instead of reading this directly -- it applies
	// the spec's cap and no-ttl default.
	TTL *int64 `json:"ttl"`

	// Order ranks the returned technologies most-preferred first, e.g.
	// ["map_e", "dslite"] (required).
	Order []string `json:"order"`

	// DSLite carries the DS-Lite parameters, nil when the VNE didn't
	// return any.
	DSLite *DSLiteParams `json:"dslite"`

	// MAPE, MAPT, LW4o6, XLAT464 and IPIP are the raw parameter objects
	// for technologies this project doesn't implement yet.
	MAPE    json.RawMessage `json:"map_e"`
	MAPT    json.RawMessage `json:"map_t"`
	LW4o6   json.RawMessage `json:"lw4o6"`
	XLAT464 json.RawMessage `json:"464xlat"`
	IPIP    json.RawMessage `json:"ipip"`
}

// DSLiteParams is the dslite technology parameter object.
type DSLiteParams struct {
	// AFTR is the AFTR's DNS name or IPv6 address literal.
	AFTR string `json:"aftr"`
}

// RefreshInterval returns how long p is valid for: the ttl field capped
// at the spec's 7-day maximum, or -- when ttl is absent or nonsensical
// -- a random duration in the spec's default 20-24h window (random so a
// fleet of CPEs that provisioned together doesn't re-query together).
func (p *Provisioning) RefreshInterval() time.Duration {
	if p.TTL != nil && *p.TTL > 0 {
		return time.Duration(min(*p.TTL, maxTTLSeconds)) * time.Second
	}
	return defaultRefreshMin + time.Duration(rand.Float64()*float64(defaultRefreshMax-defaultRefreshMin))
}

// fetchProvisioning GETs reqURL and decodes the JSON response, following
// only the spec's 307-to-another-server rule (§3.3) -- newHTTPClient
// disables http.Client's own broader redirect-following (which also
// treats 301/302/303/308 as redirects, a meaning this protocol doesn't
// define) via CheckRedirect, so this loop is the only redirect handling
// that happens. requireHTTPS, when true (the discovery TXT record's
// t=b), rejects a redirect target that isn't https -- a certificate-
// validated connection method shouldn't silently downgrade partway
// through. 403/404 get a specific error since the spec assigns them a
// meaning (the server doesn't recognize the request's source address as
// one of its subscribers).
func fetchProvisioning(ctx context.Context, client *http.Client, reqURL string, requireHTTPS bool) (*Provisioning, error) {
	for range maxRedirects + 1 {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, fmt.Errorf("hb46pp: building request: %w", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("hb46pp: provisioning request: %w", err)
		}

		if resp.StatusCode == http.StatusTemporaryRedirect {
			next, err := resp.Location()
			resp.Body.Close()
			if err != nil {
				return nil, fmt.Errorf("hb46pp: 307 response has no usable Location: %w", err)
			}
			if requireHTTPS && next.Scheme != "https" {
				return nil, fmt.Errorf("hb46pp: 307 redirected from a validated https server to a %s url, refusing", next.Scheme)
			}
			reqURL = next.String()
			continue
		}

		switch resp.StatusCode {
		case http.StatusOK:
			defer resp.Body.Close()
			body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
			if err != nil {
				return nil, fmt.Errorf("hb46pp: reading provisioning response: %w", err)
			}
			if len(body) > maxResponseBytes {
				return nil, fmt.Errorf("hb46pp: provisioning response exceeds %d bytes", maxResponseBytes)
			}
			return decodeProvisioning(bytes.NewReader(body))
		case http.StatusForbidden, http.StatusNotFound:
			resp.Body.Close()
			return nil, fmt.Errorf("hb46pp: provisioning server returned %s (it does not recognize this source address as a subscriber)", resp.Status)
		default:
			resp.Body.Close()
			return nil, fmt.Errorf("hb46pp: provisioning server returned %s", resp.Status)
		}
	}
	return nil, fmt.Errorf("hb46pp: too many 307 redirects (>%d)", maxRedirects)
}

// decodeProvisioning decodes and validates one provisioning response
// body: enabler_name and order (spec §3.4) must be present, and the auth
// field, if present, must not report an authentication failure.
// service_name is not required here even though the spec doesn't mark it
// option -- the same section says non-NGN services must omit it,
// so it's only unconditionally present for NGN deployments. order: []
// (a non-nil, empty slice -- json.Unmarshal distinguishes this from the
// field being absent, which leaves Order nil) is spec-valid too: it's
// how a server says no migration technology is available for this
// client, not a malformed response. Any non-whitespace data after the
// JSON object is rejected, so a technically-oversized response can't
// masquerade as a smaller, well-formed one just because its first
// maxResponseBytes happen to contain a complete, valid object.
func decodeProvisioning(r io.Reader) (*Provisioning, error) {
	dec := json.NewDecoder(r)
	var p Provisioning
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("hb46pp: decoding provisioning response: %w", err)
	}
	if err := dec.Decode(new(struct{})); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("hb46pp: provisioning response has trailing data after the JSON object")
	}
	if p.EnablerName == "" {
		return nil, fmt.Errorf("hb46pp: provisioning response is missing enabler_name")
	}
	if p.Order == nil {
		return nil, fmt.Errorf("hb46pp: provisioning response is missing order")
	}
	if p.Auth == "bad" {
		return nil, fmt.Errorf("hb46pp: provisioning server reported auth=bad (authentication failed)")
	}
	return &p, nil
}

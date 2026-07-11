package hb46pp

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// ClientInfo carries the CPE-identifying query parameters of a
// provisioning request (spec §3.2). VendorID, Product, Version and at
// least one capability are required by the spec; Token is optional.
//
// The spec also defines optional user/pass parameters for
// VNE-authenticated service; this package doesn't send them (minuteman
// has no credential store), which per the spec's auth field semantics
// just means the server may withhold auth-gated extras.
type ClientInfo struct {
	// VendorID is the CPE vendor's OUI as 6 hex digits, optionally
	// followed by "-" and an alphanumeric/underscore suffix (max 24
	// chars), e.g. "acde48-v6pc_swg_hgw".
	VendorID string

	// Product names the CPE product: ASCII alphanumerics, hyphen,
	// underscore, max 32 chars.
	Product string

	// Version is the CPE firmware version: digits and underscores only
	// (no periods), max 32 chars, e.g. "1_32".
	Version string

	// Capabilities lists the migration technologies the CPE supports,
	// each one of "464xlat", "dslite", "ipip", "lw4o6", "map_e",
	// "map_t"; sent comma-joined as the capability parameter.
	Capabilities []string

	// Token, if non-empty, is the token value from a previous
	// provisioning response, echoed back so the server can correlate
	// requests from the same CPE across sessions. 64 hex chars.
	Token string
}

var (
	vendorIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{6}(-[0-9A-Za-z_]{1,24})?$`)
	productPattern  = regexp.MustCompile(`^[0-9A-Za-z_-]{1,32}$`)
	versionPattern  = regexp.MustCompile(`^[0-9_]{1,32}$`)
	tokenPattern    = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
)

// knownCapabilities is the closed set of capability values the spec
// defines.
var knownCapabilities = map[string]bool{
	"464xlat": true,
	"dslite":  true,
	"ipip":    true,
	"lw4o6":   true,
	"map_e":   true,
	"map_t":   true,
}

func (c ClientInfo) validate() error {
	if !vendorIDPattern.MatchString(c.VendorID) {
		return fmt.Errorf("hb46pp: vendorid %q: want 6 hex digits optionally followed by -suffix (alphanumeric/underscore, max 24 chars)", c.VendorID)
	}
	if !productPattern.MatchString(c.Product) {
		return fmt.Errorf("hb46pp: product %q: want alphanumeric/hyphen/underscore, 1-32 chars", c.Product)
	}
	if !versionPattern.MatchString(c.Version) {
		return fmt.Errorf("hb46pp: version %q: want digits/underscores only, 1-32 chars", c.Version)
	}
	if len(c.Capabilities) == 0 {
		return errors.New("hb46pp: at least one capability is required")
	}
	for _, capability := range c.Capabilities {
		if !knownCapabilities[capability] {
			return fmt.Errorf("hb46pp: unknown capability %q", capability)
		}
	}
	if c.Token != "" && !tokenPattern.MatchString(c.Token) {
		return fmt.Errorf("hb46pp: token %q: want 64 hex chars", c.Token)
	}
	return nil
}

// requestURL appends c's query parameters to the provisioning server URL
// from the discovery TXT record. Parameters are emitted in the spec's
// example order (vendorid, product, version, capability, token) rather
// than url.Values' alphabetical order, to look like the requests real
// deployed servers were tested against.
func requestURL(base string, c ClientInfo) (string, error) {
	if err := c.validate(); err != nil {
		return "", err
	}

	var q strings.Builder
	add := func(key, value string) {
		if q.Len() > 0 {
			q.WriteByte('&')
		}
		q.WriteString(key)
		q.WriteByte('=')
		q.WriteString(url.QueryEscape(value))
	}
	add("vendorid", c.VendorID)
	add("product", c.Product)
	add("version", c.Version)
	add("capability", strings.Join(c.Capabilities, ","))
	if c.Token != "" {
		add("token", c.Token)
	}

	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + q.String(), nil
}

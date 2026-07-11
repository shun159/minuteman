package hb46pp

import (
	"strings"
	"testing"
)

func validClient() ClientInfo {
	return ClientInfo{
		VendorID:     "acde48-v6pc_swg_hgw",
		Product:      "V6MIG-ROUTER",
		Version:      "1_32",
		Capabilities: []string{"dslite"},
	}
}

func TestRequestURL(t *testing.T) {
	got, err := requestURL("https://vne.example.jp/rule.cgi", ClientInfo{
		VendorID:     "acde48",
		Product:      "ROUTER",
		Version:      "1_32",
		Capabilities: []string{"map_e", "dslite"},
	})
	if err != nil {
		t.Fatalf("requestURL: %v", err)
	}
	want := "https://vne.example.jp/rule.cgi?vendorid=acde48&product=ROUTER&version=1_32&capability=map_e%2Cdslite"
	if got != want {
		t.Fatalf("requestURL = %q, want %q", got, want)
	}
}

func TestRequestURLWithToken(t *testing.T) {
	c := validClient()
	c.Token = strings.Repeat("ab", 32)
	got, err := requestURL("https://vne.example.jp/rule.cgi", c)
	if err != nil {
		t.Fatalf("requestURL: %v", err)
	}
	if !strings.HasSuffix(got, "&token="+c.Token) {
		t.Fatalf("requestURL = %q, want trailing token parameter", got)
	}
}

func TestRequestURLBaseWithExistingQuery(t *testing.T) {
	got, err := requestURL("https://vne.example.jp/rule.cgi?plan=home", validClient())
	if err != nil {
		t.Fatalf("requestURL: %v", err)
	}
	if !strings.HasPrefix(got, "https://vne.example.jp/rule.cgi?plan=home&vendorid=") {
		t.Fatalf("requestURL = %q, want parameters appended with &", got)
	}
}

func TestClientInfoValidate(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ClientInfo)
	}{
		{"bad vendorid OUI", func(c *ClientInfo) { c.VendorID = "zzzzzz" }},
		{"vendorid suffix too long", func(c *ClientInfo) { c.VendorID = "acde48-" + strings.Repeat("a", 25) }},
		{"empty vendorid", func(c *ClientInfo) { c.VendorID = "" }},
		{"product with period", func(c *ClientInfo) { c.Product = "router.v2" }},
		{"version with period", func(c *ClientInfo) { c.Version = "1.32" }},
		{"no capabilities", func(c *ClientInfo) { c.Capabilities = nil }},
		{"unknown capability", func(c *ClientInfo) { c.Capabilities = []string{"gre"} }},
		{"short token", func(c *ClientInfo) { c.Token = "abcd" }},
		{"non-hex token", func(c *ClientInfo) { c.Token = strings.Repeat("zz", 32) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validClient()
			tt.mutate(&c)
			if err := c.validate(); err == nil {
				t.Fatalf("validate(%+v) = nil, want error", c)
			}
		})
	}

	if err := validClient().validate(); err != nil {
		t.Fatalf("validate(valid client): %v", err)
	}
}

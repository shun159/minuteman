package hb46pp

import (
	"strings"
	"testing"
	"time"
)

// specExampleJSON is the spec §3.3 example response, verbatim.
const specExampleJSON = `{
  "enabler_name": "A VNE",
  "service_name": "Highspeed 4over6",
  "isp_name": "ISP-A",
  "ttl": 86400,
  "token": "640756965820d3b9025b6941f9590af6802830ba58663fe8f043dc92b576f17a",
  "auth": "ok",
  "order": [ "map_e", "dslite" ],
  "ipv6_mostly": true,
  "dslite": {
    "aftr": "aftr.example.net"
  }
}`

func TestDecodeProvisioningSpecExample(t *testing.T) {
	p, err := decodeProvisioning(strings.NewReader(specExampleJSON))
	if err != nil {
		t.Fatalf("decodeProvisioning: %v", err)
	}
	if p.EnablerName != "A VNE" || p.ServiceName != "Highspeed 4over6" || p.ISPName != "ISP-A" {
		t.Fatalf("names = %q/%q/%q", p.EnablerName, p.ServiceName, p.ISPName)
	}
	if p.TTL == nil || *p.TTL != 86400 {
		t.Fatalf("TTL = %v, want 86400", p.TTL)
	}
	if len(p.Order) != 2 || p.Order[0] != "map_e" || p.Order[1] != "dslite" {
		t.Fatalf("Order = %v", p.Order)
	}
	if p.DSLite == nil || p.DSLite.AFTR != "aftr.example.net" {
		t.Fatalf("DSLite = %+v, want aftr.example.net", p.DSLite)
	}
	if !p.IPv6Mostly || p.Auth != "ok" {
		t.Fatalf("IPv6Mostly/Auth = %v/%q", p.IPv6Mostly, p.Auth)
	}
	if got := p.RefreshInterval(); got != 86400*time.Second {
		t.Fatalf("RefreshInterval = %v, want 24h", got)
	}
}

func TestDecodeProvisioningRequiredFields(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"missing enabler_name", `{"service_name":"s","order":["dslite"]}`},
		{"missing order", `{"enabler_name":"e","service_name":"s"}`},
		{"auth failed", `{"enabler_name":"e","service_name":"s","order":["dslite"],"auth":"bad"}`},
		{"not json", `<html></html>`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := decodeProvisioning(strings.NewReader(tt.body)); err == nil {
				t.Fatalf("decodeProvisioning(%s) = nil error, want error", tt.body)
			}
		})
	}
}

func TestDecodeProvisioningServiceNameOptional(t *testing.T) {
	// Spec §3.4: non-NGN services must omit service_name entirely.
	p, err := decodeProvisioning(strings.NewReader(`{"enabler_name":"e","order":["dslite"]}`))
	if err != nil {
		t.Fatalf("decodeProvisioning with no service_name: %v", err)
	}
	if p.ServiceName != "" {
		t.Fatalf("ServiceName = %q, want empty", p.ServiceName)
	}
}

func TestDecodeProvisioningTrailingWhitespaceIsValid(t *testing.T) {
	// A trailing newline is common server padding, not trailing data.
	_, err := decodeProvisioning(strings.NewReader(specExampleJSON + "\n"))
	if err != nil {
		t.Fatalf("decodeProvisioning with trailing newline: %v", err)
	}
}

func TestDecodeProvisioningRejectsTrailingData(t *testing.T) {
	_, err := decodeProvisioning(strings.NewReader(specExampleJSON + `{"enabler_name":"e2","service_name":"s2","order":[]}`))
	if err == nil {
		t.Fatal("decodeProvisioning with two concatenated JSON objects: want error, got nil")
	}
}

func TestDecodeProvisioningEmptyOrderIsValid(t *testing.T) {
	// Spec §3.3: order: [] is how a server says no method is available
	// for this client -- a normal response, not a protocol error.
	p, err := decodeProvisioning(strings.NewReader(`{"enabler_name":"e","service_name":"s","order":[]}`))
	if err != nil {
		t.Fatalf("decodeProvisioning with order:[]: %v", err)
	}
	if p.Order == nil || len(p.Order) != 0 {
		t.Fatalf("Order = %#v, want a non-nil empty slice", p.Order)
	}
	if p.DSLite != nil {
		t.Fatalf("DSLite = %+v, want nil", p.DSLite)
	}
}

func TestRefreshInterval(t *testing.T) {
	ttl := func(v int64) *int64 { return &v }

	// Present TTL is used as-is (in seconds).
	p := &Provisioning{TTL: ttl(3600)}
	if got := p.RefreshInterval(); got != time.Hour {
		t.Fatalf("RefreshInterval(ttl=3600) = %v, want 1h", got)
	}

	// Over-cap TTL is clamped to the spec's 7-day maximum.
	p = &Provisioning{TTL: ttl(10 * maxTTLSeconds)}
	if got := p.RefreshInterval(); got != maxTTLSeconds*time.Second {
		t.Fatalf("RefreshInterval(huge ttl) = %v, want 7d cap", got)
	}

	// Absent or non-positive TTL falls into the random 20-24h default.
	for _, p := range []*Provisioning{{}, {TTL: ttl(0)}, {TTL: ttl(-5)}} {
		got := p.RefreshInterval()
		if got < defaultRefreshMin || got > defaultRefreshMax {
			t.Fatalf("RefreshInterval(ttl=%v) = %v, want within [20h, 24h]", p.TTL, got)
		}
	}
}

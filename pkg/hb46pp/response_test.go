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
		{"missing service_name", `{"enabler_name":"e","order":["dslite"]}`},
		{"missing order", `{"enabler_name":"e","service_name":"s"}`},
		{"empty order", `{"enabler_name":"e","service_name":"s","order":[]}`},
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

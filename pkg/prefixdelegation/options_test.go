package prefixdelegation

import (
	"net/netip"
	"testing"
	"time"

	"github.com/shun159/miniteman/pkg/dhcpv6"
)

func TestIAPDOptionRoundTrip(t *testing.T) {
	want := IAPD{
		IAID: [4]byte{0, 0, 0, 1},
		T1:   1800 * time.Second,
		T2:   2880 * time.Second,
		Prefixes: []IAPrefix{
			{
				PreferredLifetime: 3600 * time.Second,
				ValidLifetime:     7200 * time.Second,
				Prefix:            netip.MustParsePrefix("2001:db8:1234:5600::/56"),
			},
		},
	}

	got, err := ParseIAPD(IAPDOption(want))
	if err != nil {
		t.Fatalf("ParseIAPD: %v", err)
	}
	if got.IAID != want.IAID {
		t.Errorf("IAID = %v, want %v", got.IAID, want.IAID)
	}
	if got.T1 != want.T1 || got.T2 != want.T2 {
		t.Errorf("T1/T2 = %v/%v, want %v/%v", got.T1, got.T2, want.T1, want.T2)
	}
	if len(got.Prefixes) != 1 {
		t.Fatalf("got %d prefixes, want 1", len(got.Prefixes))
	}
	gp, wp := got.Prefixes[0], want.Prefixes[0]
	if gp.Prefix != wp.Prefix {
		t.Errorf("Prefix = %v, want %v", gp.Prefix, wp.Prefix)
	}
	if gp.PreferredLifetime != wp.PreferredLifetime || gp.ValidLifetime != wp.ValidLifetime {
		t.Errorf("lifetimes = %v/%v, want %v/%v", gp.PreferredLifetime, gp.ValidLifetime, wp.PreferredLifetime, wp.ValidLifetime)
	}
}

func TestNewIAPDOptionHasNoPrefixes(t *testing.T) {
	got, err := ParseIAPD(NewIAPDOption([4]byte{0, 0, 0, 1}))
	if err != nil {
		t.Fatalf("ParseIAPD: %v", err)
	}
	if len(got.Prefixes) != 0 {
		t.Errorf("got %d prefixes, want 0", len(got.Prefixes))
	}
	if got.T1 != 0 || got.T2 != 0 {
		t.Errorf("T1/T2 = %v/%v, want 0/0", got.T1, got.T2)
	}
}

func TestParseIAPDStatusCode(t *testing.T) {
	statusOpt := dhcpv6.Option{
		Code: dhcpv6.OptionStatusCode,
		Data: append([]byte{0x00, byte(StatusNoPrefixAvail)}, "sorry"...),
	}
	iapdData := make([]byte, 12)
	iapdData = append(iapdData, byte(statusOpt.Code>>8), byte(statusOpt.Code), 0, byte(len(statusOpt.Data)))
	iapdData = append(iapdData, statusOpt.Data...)

	got, err := ParseIAPD(dhcpv6.Option{Code: dhcpv6.OptionIAPD, Data: iapdData})
	if err != nil {
		t.Fatalf("ParseIAPD: %v", err)
	}
	if got.StatusCode == nil {
		t.Fatal("StatusCode = nil, want non-nil")
	}
	if got.StatusCode.Code != StatusNoPrefixAvail {
		t.Errorf("StatusCode.Code = %d, want %d", got.StatusCode.Code, StatusNoPrefixAvail)
	}
	if got.StatusCode.Message != "sorry" {
		t.Errorf("StatusCode.Message = %q, want %q", got.StatusCode.Message, "sorry")
	}
}

func TestParseIAPDMalformed(t *testing.T) {
	cases := []struct {
		name string
		opt  dhcpv6.Option
	}{
		{"too short", dhcpv6.Option{Code: dhcpv6.OptionIAPD, Data: []byte{0, 0, 0, 1, 0, 0}}},
		{
			"truncated IAPREFIX suboption",
			dhcpv6.Option{Code: dhcpv6.OptionIAPD, Data: append(
				make([]byte, 12),
				// suboption header claims 25 bytes of IAPREFIX data, provides none
				byte(dhcpv6.OptionIAPrefix>>8), byte(dhcpv6.OptionIAPrefix), 0x00, 0x19,
			)},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParseIAPD(c.opt); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestParseIAPrefixOutOfRangeLength(t *testing.T) {
	data := make([]byte, 25)
	data[8] = 200 // prefix length > 128
	if _, err := parseIAPrefix(data); err == nil {
		t.Fatal("expected error for out-of-range prefix length, got nil")
	}
}

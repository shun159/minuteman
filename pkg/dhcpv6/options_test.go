package dhcpv6

import (
	"net"
	"testing"
	"time"
)

func TestOptionsMarshalParseRoundTrip(t *testing.T) {
	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	duid := NewDUIDLL(HardwareTypeEthernet, mac)

	want := Options{
		NewClientIDOption(duid),
		NewORO(OptionDNSServers, OptionAFTRName),
		NewElapsedTimeOption(2500 * time.Millisecond),
	}

	got, err := parseOptions(want.Marshal())
	if err != nil {
		t.Fatalf("parseOptions: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d options, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Code != want[i].Code {
			t.Errorf("option %d: code = %d, want %d", i, got[i].Code, want[i].Code)
		}
		if string(got[i].Data) != string(want[i].Data) {
			t.Errorf("option %d: data = %x, want %x", i, got[i].Data, want[i].Data)
		}
	}
}

func TestParseOptionsTruncated(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"short header", []byte{0x00, 0x01, 0x00}},
		{"length exceeds buffer", []byte{0x00, 0x01, 0x00, 0x05, 0xaa}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := parseOptions(c.data); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestNewElapsedTimeOptionSaturates(t *testing.T) {
	opt := NewElapsedTimeOption(1 * time.Hour)
	if len(opt.Data) != 2 {
		t.Fatalf("elapsed time option data length = %d, want 2", len(opt.Data))
	}
	if opt.Data[0] != 0xff || opt.Data[1] != 0xff {
		t.Fatalf("elapsed time = %x, want saturated 0xffff", opt.Data)
	}
}

func TestOptionsExtractors(t *testing.T) {
	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	duid := NewDUIDLL(HardwareTypeEthernet, mac)

	refreshData := []byte{0x00, 0x00, 0x0e, 0x10} // 3600 seconds
	opts := Options{
		NewClientIDOption(duid),
		{Code: OptionServerID, Data: []byte{0x00, 0x01, 0xde, 0xad}},
		{Code: OptionInformationRefreshTime, Data: refreshData},
	}

	if got, ok := opts.ClientID(); !ok || string(got) != string(duid) {
		t.Errorf("ClientID() = %x, %v; want %x, true", got, ok, duid)
	}
	if _, ok := opts.ServerID(); !ok {
		t.Error("ServerID() ok = false, want true")
	}
	refresh, ok := opts.InformationRefreshTime()
	if !ok || refresh != 3600*time.Second {
		t.Errorf("InformationRefreshTime() = %v, %v; want 3600s, true", refresh, ok)
	}
}

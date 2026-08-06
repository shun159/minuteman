package datapath

import "testing"

func TestAutoTCPMSSClamp(t *testing.T) {
	tests := []struct {
		name string
		mtu  int
		want uint32
	}{
		// The ordinary Ethernet case: 1500 - 40 (outer IPv6) - 40 (IPv4 + TCP)
		// is the 1420 every DS-Lite CPE ends up advertising.
		{name: "ethernet", mtu: 1500, want: 1420},
		// A softwire path MTU learned from an ICMPv6 Packet Too Big, which the
		// datapath floors at IPv6's own 1280 minimum (RFC 8201 §4).
		{name: "learned narrow path", mtu: 1400, want: 1320},
		{name: "ipv6 minimum", mtu: 1280, want: 1200},
		// Below RFC 1122 §4.2.2.6's 536 the clamp does more harm than the
		// fragmentation it avoids, so it turns itself off instead.
		{name: "just above the floor", mtu: 616, want: 536},
		{name: "at the floor", mtu: 615, want: 0},
		{name: "degenerate", mtu: 0, want: 0},
		{name: "negative", mtu: -1, want: 0},
	}

	for _, tt := range tests {
		if got := autoTCPMSSClamp(tt.mtu); got != tt.want {
			t.Errorf("%s: autoTCPMSSClamp(%d) = %d, want %d", tt.name, tt.mtu, got, tt.want)
		}
	}
}

func TestResolveMSSClamp(t *testing.T) {
	var l Loader

	if got := l.resolveMSSClamp(TCPMSSClampAuto, 1500); got != 1420 {
		t.Errorf("auto policy: got %d, want 1420", got)
	}
	if !l.mssClampAuto {
		t.Error("auto policy: mssClampAuto not recorded, so SetSoftwireMTU would never re-derive it")
	}

	// A pinned value must survive a later SetSoftwireMTU, which is exactly what
	// mssClampAuto being false expresses.
	if got := l.resolveMSSClamp(1300, 1500); got != 1300 {
		t.Errorf("explicit policy: got %d, want 1300", got)
	}
	if l.mssClampAuto {
		t.Error("explicit policy: mssClampAuto still set, a learned path MTU would overwrite the pinned value")
	}

	if got := l.resolveMSSClamp(0, 1500); got != 0 {
		t.Errorf("off policy: got %d, want 0", got)
	}
}

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/shun159/miniteman/pkg/datapath"
	"github.com/shun159/miniteman/pkg/ethtool"
)

// The commands themselves can't be run here -- both read live kernel state (a
// bpffs pin, a netlink link dump) -- so what's covered is the tree's shape and
// the pure output formatting.

func TestRootCommandTree(t *testing.T) {
	root := newRootCmd()

	stats, _, err := root.Find([]string{"stats"})
	if err != nil {
		t.Fatalf("finding `stats`: %v", err)
	}
	// Persistent rather than local, so the subcommands below inherit it.
	if stats.PersistentFlags().Lookup("json") == nil {
		t.Error("`stats` has no persistent --json flag")
	}

	// The alias matters as much as the name: `stats iface` is what the flag it
	// replaced was called.
	for _, name := range []string{"interfaces", "iface", "ifaces"} {
		cmd, _, err := root.Find([]string{"stats", name})
		if err != nil {
			t.Fatalf("finding `stats %s`: %v", name, err)
		}
		if cmd.Name() != "interfaces" {
			t.Errorf("`stats %s` resolved to %q, want interfaces", name, cmd.Name())
		}
		// --json is declared once, on the parent, so it must reach here too.
		if cmd.InheritedFlags().Lookup("json") == nil {
			t.Errorf("`stats %s` does not inherit --json", name)
		}
	}
}

func TestNormalizeLegacyArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			// The forms documented before the stats commands moved to cobra.
			name: "go-flag long options gain the second dash",
			args: []string{"stats", "-json"},
			want: []string{"stats", "--json"},
		},
		{
			name: "with a value attached",
			args: []string{"stats", "-json=true"},
			want: []string{"stats", "--json=true"},
		},
		{
			name: "already double-dashed is left alone",
			args: []string{"stats", "--json"},
			want: []string{"stats", "--json"},
		},
		{
			// -h is a real pflag shorthand; rewriting it would be wrong.
			name: "single-character shorthands are left alone",
			args: []string{"stats", "-h"},
			want: []string{"stats", "-h"},
		},
		{
			name: "subcommands and bare words are left alone",
			args: []string{"stats", "interfaces"},
			want: []string{"stats", "interfaces"},
		},
		{
			name: "nothing that only looks flag-like",
			args: []string{"stats", "-5"},
			want: []string{"stats", "-5"},
		},
		{
			name: "rewriting stops at the end-of-flags terminator",
			args: []string{"stats", "-json", "--", "-json"},
			want: []string{"stats", "--json", "--", "-json"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeLegacyArgs(tt.args)
			if len(got) != len(tt.want) {
				t.Fatalf("normalizeLegacyArgs(%q) = %q, want %q", tt.args, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("normalizeLegacyArgs(%q) = %q, want %q", tt.args, got, tt.want)
				}
			}
		})
	}
}

func TestLegacyIfaceFlagStillParses(t *testing.T) {
	// `stats -iface` was the spelling before `stats interfaces` existed. It
	// stays accepted (hidden and deprecated) so a script written against it
	// keeps working -- and hidden means help must not advertise it.
	root := newRootCmd()
	stats, _, err := root.Find([]string{"stats"})
	if err != nil {
		t.Fatalf("finding `stats`: %v", err)
	}
	f := stats.Flags().Lookup("iface")
	if f == nil {
		t.Fatal("`stats` no longer accepts the legacy --iface flag")
	}
	if !f.Hidden || f.Deprecated == "" {
		t.Errorf("--iface should be hidden and deprecated, got hidden=%v deprecated=%q", f.Hidden, f.Deprecated)
	}
}

func TestLegacyStatsOutputEmbedsCounters(t *testing.T) {
	// The deprecated combined JSON keeps its old shape: counters as top-level
	// fields (jq .DecapMartian) with Interfaces alongside them.
	var buf bytes.Buffer
	out := legacyStatsOutput{
		Stats:      datapath.Stats{DecapMartian: 7},
		Interfaces: []ifaceStats{{Name: "eth0", Role: "wan"}},
	}
	if err := encodeJSON(&buf, out); err != nil {
		t.Fatalf("encodeJSON: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if decoded["DecapMartian"] != float64(7) {
		t.Errorf("DecapMartian = %v, want it as a top-level field", decoded["DecapMartian"])
	}
	if _, ok := decoded["Interfaces"]; !ok {
		t.Error("Interfaces missing from the combined output")
	}
}

func TestPrintInterfaceStats(t *testing.T) {
	ifaces := []ifaceStats{
		{
			Name: "eth0", Ifindex: 2, Role: "wan", XDPProgID: 7,
			ordered: []ethtool.Stat{{Name: "rx_packets", Value: 12}, {Name: "xdp_redirect", Value: 3}},
		},
		{
			Name: "mm-frag0", Ifindex: 9, Role: "frag", XDPProgID: 11,
			Note: "driver exposes no statistics",
		},
	}

	var buf bytes.Buffer
	if err := printInterfaceStats(&buf, ifaces); err != nil {
		t.Fatalf("printInterfaceStats: %v", err)
	}
	got := buf.String()

	// Counters are indented under their interface's header, the way
	// `ethtool -S` prints them, with the interfaces separated by a blank line
	// and none before the first.
	want := "eth0 (ifindex 2, role wan, xdp prog id 7):\n" +
		"  rx_packets: 12\n" +
		"  xdp_redirect: 3\n" +
		"\n" +
		"mm-frag0 (ifindex 9, role frag, xdp prog id 11):\n" +
		"  driver exposes no statistics\n"
	if got != want {
		t.Errorf("printInterfaceStats output:\n%q\nwant:\n%q", got, want)
	}
}

func TestPrintInterfaceStatsEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := printInterfaceStats(&buf, nil); err != nil {
		t.Fatalf("printInterfaceStats: %v", err)
	}
	if got := buf.String(); !strings.HasPrefix(got, "No interfaces") {
		t.Errorf("printInterfaceStats(nil) = %q, want a no-interfaces line", got)
	}
}

func TestEncodeJSONEmptyInterfaces(t *testing.T) {
	// runStatsInterfaces normalises a nil result so consumers can iterate it
	// unconditionally; encoding nil directly would give them null.
	var buf bytes.Buffer
	if err := encodeJSON(&buf, []ifaceStats{}); err != nil {
		t.Fatalf("encodeJSON: %v", err)
	}
	var decoded []ifaceStats
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if decoded == nil {
		t.Errorf("encoded %q, want an empty array rather than null", buf.String())
	}
}

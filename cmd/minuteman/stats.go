package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/shun159/miniteman/pkg/datapath"
)

// statsOutput is what `minuteman stats -json` encodes. datapath.Stats is
// embedded rather than nested so its counters stay top-level JSON fields --
// `jq .DecapMartian` keeps working, and Interfaces (present only under
// -iface) is additive.
type statsOutput struct {
	datapath.Stats
	Interfaces []ifaceStats `json:",omitempty"`
}

// runStats implements the `minuteman stats` subcommand: read the stats map a
// running minuteman pinned to bpffs and print it, without touching the
// running process (needs the same root/CAP_BPF the daemon itself needs).
// With -iface it additionally reports each XDP-attached interface's driver
// counters, the equivalent of `ethtool -S` (see collectInterfaceStats).
func runStats(args []string) error {
	fs := flag.NewFlagSet("stats", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "print stats as JSON (field names match pkg/datapath's Stats struct)")
	withIfaces := fs.Bool("iface", false, "also report driver statistics (the `ethtool -S` counters) for every interface the datapath has XDP attached to")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		fs.Usage()
		return fmt.Errorf("stats: unexpected argument %q", fs.Arg(0))
	}

	stats, err := datapath.ReadPinnedStats()
	if err != nil {
		return err
	}
	out := statsOutput{Stats: stats}
	if *withIfaces {
		if out.Interfaces, err = collectInterfaceStats(); err != nil {
			return err
		}
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}

	// One `Name: value` line per counter, in the Stats struct's (= the C
	// enum's) order, so shell consumers can `awk '/^EncapFragSlow:/{print $2}'`.
	for _, c := range []struct {
		name  string
		value uint64
	}{
		{"Pass", stats.Pass},
		{"Drop", stats.Drop},
		{"Abort", stats.Abort},
		{"Encap", stats.Encap},
		{"Decap", stats.Decap},
		{"MTUDrop", stats.MTUDrop},
		{"NoConfig", stats.NoConfig},
		{"NoLANConfig", stats.NoLANConfig},
		{"Bypass", stats.Bypass},
		{"FIBSuccess", stats.FIBSuccess},
		{"FIBNoNeigh", stats.FIBNoNeigh},
		{"FIBFail", stats.FIBFail},
		{"FIBWrongIf", stats.FIBWrongIf},
		{"DecapPass", stats.DecapPass},
		{"DecapNotDSLite", stats.DecapNotDSLite},
		{"DecapBadPacket", stats.DecapBadPacket},
		{"DecapSlow", stats.DecapSlow},
		{"RedirectWAN", stats.RedirectWAN},
		{"RedirectLAN", stats.RedirectLAN},
		{"ICMPFragNeeded", stats.ICMPFragNeeded},
		{"ICMPTimeExceeded", stats.ICMPTimeExceeded},
		{"IPv6Fwd", stats.IPv6Fwd},
		{"IPv6Pass", stats.IPv6Pass},
		{"IPv6RSSRedirect", stats.IPv6RSSRedirect},
		{"ICMPRateLimited", stats.ICMPRateLimited},
		{"AffinityInsert", stats.AffinityInsert},
		{"AffinityInsertFail", stats.AffinityInsertFail},
		{"AffinityPinned", stats.AffinityPinned},
		{"EncapFragSlow", stats.EncapFragSlow},
		{"DecapFragSlow", stats.DecapFragSlow},
		{"DecapReasmPass", stats.DecapReasmPass},
		{"DecapMartian", stats.DecapMartian},
		{"EncapFragXDP", stats.EncapFragXDP},
		{"EncapFragSeg", stats.EncapFragSeg},
		{"TunnelICMPRelay", stats.TunnelICMPRelay},
		{"TunnelICMPPass", stats.TunnelICMPPass},
		{"TunnelICMPDrop", stats.TunnelICMPDrop},
		{"TunnelPMTU", stats.TunnelPMTU},
		{"MSSClamped", stats.MSSClamped},
	} {
		fmt.Printf("%s: %d\n", c.name, c.value)
	}

	if *withIfaces {
		printInterfaceStats(out.Interfaces)
	}
	return nil
}

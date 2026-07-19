package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/shun159/miniteman/pkg/datapath"
)

// runStats implements the `minuteman stats` subcommand: read the stats map a
// running minuteman pinned to bpffs and print it, without touching the
// running process (needs the same root/CAP_BPF the daemon itself needs).
func runStats(args []string) error {
	fs := flag.NewFlagSet("stats", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "print stats as JSON (field names match pkg/datapath's Stats struct)")
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

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(stats)
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
	} {
		fmt.Printf("%s: %d\n", c.name, c.value)
	}
	return nil
}

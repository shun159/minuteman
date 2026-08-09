package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/shun159/miniteman/pkg/datapath"
)

// newRootCmd builds the cobra command tree main() dispatches subcommands to.
// The root deliberately has no Run of its own: the daemon is still the
// flag-only invocation handled by run() and the stdlib flag package, so this
// tree exists to give the subcommands their proper "minuteman <cmd>" usage
// paths and to reject a mistyped one with something better than the daemon's
// "missing required flags".
//
// Errors are silenced here and reported by main's log.Fatal instead, so a
// failure is printed once; usage is silenced with them, since a runtime
// failure (no pinned map, no privileges) is not a usage problem and burying
// it under a flag list helps nobody.
func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "minuteman",
		Short: "DS-Lite (RFC 6333) B4 CPE gateway",
		Long: `minuteman attaches the DS-Lite (RFC 6333) XDP datapath to a WAN and one or
more LAN interfaces.

Running the gateway itself takes no subcommand -- it is the flag-only
invocation, so see 'minuteman -h' for the daemon's flags. The subcommands
below inspect an already-running instance.`,
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	// No `completion` command: only the subcommands below live in this tree,
	// so a generated script would silently complete nothing for the gateway's
	// own flags -- worse than offering no completion at all.
	root.CompletionOptions.DisableDefaultCmd = true
	root.AddCommand(newStatsCmd())
	return root
}

// newStatsCmd builds `minuteman stats`: the datapath's own packet counters at
// this level, each XDP-bound interface's driver counters under `interfaces`.
func newStatsCmd() *cobra.Command {
	var jsonOut, legacyIface bool

	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Print the running datapath's packet counters",
		Long: `Print the packet counters of the running datapath.

The counters are read from the stats map minuteman pinned to bpffs
(/sys/fs/bpf/minuteman/stats), so this never touches the running process --
but it needs the same root/CAP_BPF privileges the daemon does. Text output is
one "Name: value" line per counter, in the order the datapath's own enum
declares them, so shell consumers can awk a single one out.

Against a datapath running inside a network namespace, enter it with
'nsenter --net=...' rather than 'ip netns exec': the latter remounts /sys,
leaving the pin invisible.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if legacyIface {
				return runStatsWithInterfaces(cmd.OutOrStdout(), jsonOut)
			}
			return runStats(cmd.OutOrStdout(), jsonOut)
		},
	}
	// Persistent, so --json means the same thing at every level of the tree
	// rather than being re-declared per subcommand.
	cmd.PersistentFlags().BoolVar(&jsonOut, "json", false, "print as JSON (field names match pkg/datapath's Stats struct)")

	// The interface counters were a flag on `stats` before they were a
	// subcommand of it. Kept working, hidden and deprecated, with exactly the
	// output it used to produce (counters, then interfaces; under --json the
	// one object with Interfaces embedded) so a script written against it is
	// not silently given a different shape. MarkDeprecated both hides it from
	// help and prints the pointer to its replacement on use.
	cmd.Flags().BoolVar(&legacyIface, "iface", false, "also report each XDP-bound interface's driver statistics")
	_ = cmd.Flags().MarkDeprecated("iface", "use `minuteman stats interfaces` instead")

	cmd.AddCommand(newStatsInterfacesCmd(&jsonOut))
	return cmd
}

// newStatsInterfacesCmd builds `minuteman stats interfaces`. jsonOut points at
// the parent's persistent --json flag, which cobra has already parsed by the
// time RunE dereferences it.
func newStatsInterfacesCmd(jsonOut *bool) *cobra.Command {
	return &cobra.Command{
		Use:     "interfaces",
		Aliases: []string{"iface", "ifaces"},
		Short:   "Print driver statistics for every XDP-bound interface",
		Long: `Print the driver statistics -- the counters 'ethtool -S <iface>' reports --
for every interface the running datapath has an XDP program attached to,
labelled wan/lan/frag.

This is what tells "the datapath didn't handle it" apart from "the packet
never arrived", and it makes the softwire fragmenter's clone-and-trim visible
per companion veth (xdp_redirect on the pairs a packet needed, xdp_drops on
the ones it didn't).

The interface list comes from the kernel rather than from the daemon: a link
dump reports each device's attached XDP program id, and the ones referencing
the pinned stats map are this instance's. So it cannot drift from what is
really attached and it covers the companion veths no flag names -- but it must
run in the datapath's own network namespace to see them (the pin itself is on
the host's bpffs).

A driver that exposes no statistics, or a read that fails, is reported on that
interface's own line rather than failing the whole command.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runStatsInterfaces(cmd.OutOrStdout(), *jsonOut)
		},
	}
}

// runStats prints the datapath counters from the bpffs-pinned stats map.
func runStats(w io.Writer, jsonOut bool) error {
	stats, err := datapath.ReadPinnedStats()
	if err != nil {
		return err
	}

	if jsonOut {
		return encodeJSON(w, stats)
	}
	return printStats(w, stats)
}

// printStats writes the text form of the datapath counters. Split from
// runStats so the deprecated combined output prints the same counters it
// already read, rather than reading the map a second time.
func printStats(w io.Writer, stats datapath.Stats) error {
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
		if _, err := fmt.Fprintf(w, "%s: %d\n", c.name, c.value); err != nil {
			return err
		}
	}
	return nil
}

// legacyStatsOutput is what the deprecated `stats --iface --json` encodes:
// datapath.Stats embedded rather than nested, so its counters stay top-level
// fields (`jq .DecapMartian`) and Interfaces is additive. The undeprecated
// commands each encode one of the two halves directly instead.
type legacyStatsOutput struct {
	datapath.Stats
	Interfaces []ifaceStats `json:",omitempty"`
}

// runStatsWithInterfaces reproduces the pre-subcommand `stats -iface` output:
// the datapath counters followed by every XDP-bound interface's driver
// counters, or the single embedded JSON object under --json.
func runStatsWithInterfaces(w io.Writer, jsonOut bool) error {
	stats, err := datapath.ReadPinnedStats()
	if err != nil {
		return err
	}
	ifaces, err := collectInterfaceStats()
	if err != nil {
		return err
	}

	if jsonOut {
		return encodeJSON(w, legacyStatsOutput{Stats: stats, Interfaces: ifaces})
	}
	if err := printStats(w, stats); err != nil {
		return err
	}
	// The blank line the interface section used to be introduced by, now that
	// printInterfaceStats no longer leads with one of its own.
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	return printInterfaceStats(w, ifaces)
}

// runStatsInterfaces prints each XDP-bound interface's driver counters.
func runStatsInterfaces(w io.Writer, jsonOut bool) error {
	ifaces, err := collectInterfaceStats()
	if err != nil {
		return err
	}

	if jsonOut {
		// An empty result encodes as [] rather than null, so a consumer can
		// iterate it unconditionally.
		if ifaces == nil {
			ifaces = []ifaceStats{}
		}
		return encodeJSON(w, ifaces)
	}
	return printInterfaceStats(w, ifaces)
}

// encodeJSON writes v as indented JSON, the one output format both stats
// commands share.
func encodeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

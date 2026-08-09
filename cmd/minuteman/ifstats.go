package main

import (
	"errors"
	"fmt"
	"sort"

	"github.com/shun159/miniteman/pkg/datapath"
	"github.com/shun159/miniteman/pkg/ethtool"
	"github.com/shun159/miniteman/pkg/netlink"
)

// ifaceStats is one XDP-attached interface's driver statistics -- what
// `ethtool -S <iface>` prints -- alongside which part of the datapath is bound
// to it.
type ifaceStats struct {
	Name      string
	Ifindex   int
	Role      string
	XDPProgID uint32
	// Stats is keyed by driver counter name for JSON consumers (`jq
	// '.Interfaces[0].Stats.xdp_packets'`). The text output uses the ordered
	// slice below instead, so it can print counters in the order the driver
	// reports them -- drivers group related counters (per queue, per XDP
	// action) and alphabetising them scatters the groups.
	Stats map[string]uint64 `json:",omitempty"`
	// Note explains an empty Stats: a driver with no counters at all, or a
	// read that failed. Reported per interface rather than failing the whole
	// command, since the other interfaces' counters are still useful.
	Note string `json:",omitempty"`

	ordered []ethtool.Stat
}

// collectInterfaceStats finds every interface the running minuteman has an XDP
// program attached to and reads its driver statistics.
//
// The interface list is derived from the kernel, not from the daemon: a link
// dump gives each device's attached XDP program id, and pkg/datapath says which
// of those ids belong to the instance owning the pinned stats map. So `stats
// -iface` needs no cooperation from the running process beyond the pin it
// already publishes, and can't drift out of sync with what's actually attached
// (including the fragmenter's companion veths, which no flag names).
func collectInterfaceStats() ([]ifaceStats, error) {
	nl, err := netlink.Open()
	if err != nil {
		return nil, err
	}
	defer nl.Close()

	links, err := nl.Links()
	if err != nil {
		return nil, err
	}

	var progIDs []uint32
	for _, l := range links {
		if l.XDPProgID != 0 {
			progIDs = append(progIDs, l.XDPProgID)
		}
	}
	roles, err := datapath.XDPRoles(progIDs)
	if err != nil {
		return nil, err
	}

	var out []ifaceStats
	for _, l := range links {
		role, ok := roles[l.XDPProgID]
		if !ok {
			continue
		}

		is := ifaceStats{
			Name:      l.Name,
			Ifindex:   l.Index,
			Role:      string(role),
			XDPProgID: l.XDPProgID,
		}
		switch stats, err := ethtool.Stats(l.Name); {
		case errors.Is(err, ethtool.ErrNotSupported):
			is.Note = "driver exposes no statistics"
		case err != nil:
			is.Note = err.Error()
		default:
			is.ordered = stats
			is.Stats = make(map[string]uint64, len(stats))
			for _, s := range stats {
				is.Stats[s.Name] = s.Value
			}
		}
		out = append(out, is)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Ifindex < out[j].Ifindex })
	return out, nil
}

// printInterfaceStats writes the per-interface section of `minuteman stats
// -iface`'s text output, indented under a header line per interface the way
// `ethtool -S` prints its own.
func printInterfaceStats(ifaces []ifaceStats) {
	if len(ifaces) == 0 {
		fmt.Println("\nNo interfaces have minuteman XDP programs attached.")
		return
	}
	for _, i := range ifaces {
		fmt.Printf("\n%s (ifindex %d, role %s, xdp prog id %d):\n", i.Name, i.Ifindex, i.Role, i.XDPProgID)
		if i.Note != "" {
			fmt.Printf("  %s\n", i.Note)
			continue
		}
		for _, s := range i.ordered {
			fmt.Printf("  %s: %d\n", s.Name, s.Value)
		}
	}
}

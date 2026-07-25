package datapath

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// MaxSoftwireFrags mirrors MAX_SOFTWIRE_FRAGS in bpf/datapath.bpf.c: the
// number of frag_ports entries -- one companion veth pair, carrying one
// xdp_softwire_frag<i> program, per entry -- and so the most outer-IPv6
// fragments one oversized softwire packet can be carved into before the
// datapath falls back to the kernel ip6tnl.
const MaxSoftwireFrags = 4

// softwireFragOverhead is the per-fragment header overhead of an outer-IPv6
// softwire fragment: the outer IPv6 header (40) plus the Fragment extension
// header (8). The per-fragment payload (b4_config.frag_unit) is the WAN MTU
// less this, rounded down to the multiple of 8 fragment offsets require.
const softwireFragOverhead = 48

// softwireFragUnit derives the datapath's frag_unit from the WAN MTU: the
// largest multiple of 8 that fits a fragment in the WAN MTU after the outer
// headers (1500 -> 1448). Returns 0 (fragmentation disabled, ip6tnl fallback
// takes over) for a degenerate MTU.
func softwireFragUnit(wanMTU int) uint32 {
	if wanMTU <= softwireFragOverhead+8 {
		return 0
	}
	return uint32(wanMTU-softwireFragOverhead) &^ 7
}

// EnableSoftwireFrag wires up in-XDP softwire (outer IPv6) fragmentation
// against the companion veth pairs internal/fragpath created: it attaches
// pair i's xdp_softwire_frag<i> trimming program to that pair's B end
// (fwdIfaces[i]) -- which also activates the pair's NAPI, so it consumes XDP
// frames at all -- then points frag_ports entry i at the pair's A end
// (redirectIfindexes[i]). The datapath only engages the fragmenter once
// frag_ports resolves (see encap_fragment_outer's guard), so the
// attach-then-populate order here means it never broadcasts into a pair with
// no consumer.
func (l *Loader) EnableSoftwireFrag(redirectIfindexes [MaxSoftwireFrags]uint32, fwdIfaces [MaxSoftwireFrags]string) error {
	progs := [MaxSoftwireFrags]*ebpf.Program{
		l.objs.XdpSoftwireFrag0,
		l.objs.XdpSoftwireFrag1,
		l.objs.XdpSoftwireFrag2,
		l.objs.XdpSoftwireFrag3,
	}

	for i, prog := range progs {
		// A nil program here means MAX_SOFTWIRE_FRAGS in the BPF source grew
		// (adding xdp_softwire_frag<i> programs) without this list growing to
		// match: the array literal above is sized by MaxSoftwireFrags but its
		// elements are enumerated by hand, so the extra slots stay nil rather
		// than failing to compile. Fail fast instead of panicking in AttachXDP.
		if prog == nil {
			return fmt.Errorf("frag program slot %d is nil: the xdp_softwire_frag* list in frag.go is out of sync with MaxSoftwireFrags (%d)", i, MaxSoftwireFrags)
		}

		iface, err := net.InterfaceByName(fwdIfaces[i])
		if err != nil {
			return fmt.Errorf("looking up frag interface %q: %w", fwdIfaces[i], err)
		}
		lk, err := link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: iface.Index,
		})
		if err != nil {
			return fmt.Errorf("attaching XDP frag program %d to %q: %w", i, fwdIfaces[i], err)
		}
		l.fragLinks = append(l.fragLinks, lk)

		key := uint32(i)
		ifindex := redirectIfindexes[i]
		if err := l.objs.FragPorts.Put(&key, &ifindex); err != nil {
			return fmt.Errorf("populating frag_ports slot %d: %w", i, err)
		}
	}
	return nil
}

// Package fragpath manages the companion veth pairs the XDP datapath's
// softwire (outer IPv6) fragmentation bounces through (RFC 6333 §5.3).
//
// The datapath fragments an oversized softwire packet by broadcasting the
// whole encapsulated frame to the frag_ports DEVMAP -- one clone per possible
// fragment -- and letting an XDP program trim each clone down to fragment i
// (see encap_fragment_outer in bpf/datapath.bpf.c). Two kernel constraints
// shape where those clones can go:
//
//   - The devmap enqueue validates the *untrimmed* clone's length against the
//     target device's MTU before any program could trim it (is_valid_dst ->
//     xdp_ok_fwd_dev), and a frame that needs fragmenting by definition
//     exceeds the WAN MTU -- so the targets must be large-MTU devices, never
//     the WAN itself.
//   - Enqueued frames are batched per target *device* and a devmap entry's
//     egress program is taken from the batch's first enqueue, so entries
//     sharing one device cannot run distinct per-fragment programs.
//
// Hence one veth pair per fragment index: frag_ports entry i targets pair i's
// A end (mm-frag<i>), and pair i's B end (mm-frag<i>p) runs the
// xdp_softwire_frag<i> rx program (attached by pkg/datapath) that trims the
// clone to fragment i and redirects it out the real WAN. Attaching that
// program is also what activates the pair's NAPI so it consumes XDP frames at
// all.
//
// It mirrors internal/slowpath: one long-lived netlink socket, single-writer,
// fail-fast Ensure at startup, best-effort teardown on Close.
package fragpath

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/shun159/miniteman/pkg/datapath"
	"github.com/shun159/miniteman/pkg/netlink"
)

// NumPairs is one veth pair per possible fragment: frag_ports entry i
// broadcasts into pair i.
const NumPairs = datapath.MaxSoftwireFrags

// vethMTU is as large as a veth with single-buffer XDP attached allows: the
// attach requires MTU + headroom + skb_shared_info to fit one page (~3.5KB on
// 4K pages, ERANGE beyond it), so this sits safely under that ceiling. The
// fragments leaving the pairs are WAN-MTU-sized regardless; the MTU only
// bounds the oversized clones admitted *into* a pair.
const vethMTU = 3456

// MaxInnerLen is the largest inner IPv4 packet the pairs can carry a clone
// of: the devmap enqueue admits a clone only when its frame (inner + 14-byte
// Ethernet + 40-byte outer IPv6 + 8-byte Fragment header) fits vethMTU plus
// the Ethernet header, i.e. inner <= vethMTU - 48. The datapath is told this
// bound (b4_config.frag_max_inner) so anything larger falls back to the
// kernel ip6tnl instead of blackholing into a rejected broadcast.
const MaxInnerLen = vethMTU - 48

// redirectName/fwdName name pair i's ends: mm-frag<i> is the A end frag_ports
// broadcasts into, mm-frag<i>p its peer carrying the trimming program.
func redirectName(i int) string { return fmt.Sprintf("mm-frag%d", i) }
func fwdName(i int) string      { return fmt.Sprintf("mm-frag%dp", i) }

// Pairs owns the companion veth pairs. Not safe for concurrent use; the
// caller (cmd/minuteman startup) drives it from one goroutine.
type Pairs struct {
	sock              *netlink.Socket
	redirectIfindexes [NumPairs]uint32
}

// New opens the netlink socket the Pairs use for their lifetime. It does not
// create the devices yet -- call Ensure.
func New() (*Pairs, error) {
	sock, err := netlink.Open()
	if err != nil {
		return nil, err
	}
	return &Pairs{sock: sock}, nil
}

// Ensure creates the veth pairs and brings both ends of each up, replacing
// whatever a previous (crashed) run left behind. Fail-fast, like
// slowpath.Tunnel.Ensure: without the pairs the datapath's §5.3 fragmenter
// has nowhere to send its clones, and cmd/minuteman only enables it
// (b4_config.frag_unit) afterwards.
func (p *Pairs) Ensure() error {
	for i := range NumPairs {
		// Deleting the A end removes its peer with it; a stale B end without
		// an A (renamed/moved by an operator) is deleted separately too.
		for _, name := range []string{redirectName(i), fwdName(i)} {
			if ifi, err := net.InterfaceByName(name); err == nil {
				if err := p.sock.DelLink(ifi.Index); err != nil {
					return fmt.Errorf("fragpath: removing stale %s: %w", name, err)
				}
			}
		}

		if err := p.sock.AddVeth(redirectName(i), fwdName(i), vethMTU); err != nil {
			return fmt.Errorf("fragpath: creating veth pair %s/%s: %w", redirectName(i), fwdName(i), err)
		}

		for _, name := range []string{redirectName(i), fwdName(i)} {
			ifi, err := net.InterfaceByName(name)
			if err != nil {
				return fmt.Errorf("fragpath: resolving %s after create: %w", name, err)
			}
			if name == redirectName(i) {
				p.redirectIfindexes[i] = uint32(ifi.Index)
			}

			// The pairs carry only XDP frames the datapath itself puts there;
			// keep the kernel from chattering IPv6 (DAD/MLD) into them.
			// Best-effort: stray kernel packets are dropped by the trimming
			// program anyway.
			sysctl := "/proc/sys/net/ipv6/conf/" + name + "/disable_ipv6"
			if err := os.WriteFile(sysctl, []byte("1"), 0); err != nil {
				log.Printf("fragpath: disabling IPv6 on %s: %v", name, err)
			}

			if err := p.sock.SetLinkUp(ifi.Index); err != nil {
				return fmt.Errorf("fragpath: bringing %s up: %w", name, err)
			}
		}
	}
	return nil
}

// RedirectIfindexes returns the A ends' ifindexes in fragment order -- what
// the frag_ports DEVMAP entries point at. Valid after Ensure.
func (p *Pairs) RedirectIfindexes() [NumPairs]uint32 { return p.redirectIfindexes }

// FwdNames returns the B ends' device names in fragment order -- where
// pkg/datapath attaches the xdp_softwire_frag<i> programs.
func FwdNames() [NumPairs]string {
	var names [NumPairs]string
	for i := range names {
		names[i] = fwdName(i)
	}
	return names
}

// Close deletes the pairs (deleting an A end removes its peer too) and closes
// the netlink socket. Best-effort, matching slowpath.Tunnel.Close: a pair
// that outlives the process is replaced by the next run's Ensure.
func (p *Pairs) Close() error {
	for i, ifindex := range p.redirectIfindexes {
		if ifindex == 0 {
			continue
		}
		if err := p.sock.DelLink(int(ifindex)); err != nil {
			log.Printf("fragpath: removing %s on shutdown: %v", redirectName(i), err)
		}
	}
	return p.sock.Close()
}

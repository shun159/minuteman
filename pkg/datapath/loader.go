package datapath

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// Loader owns the loaded BPF objects and every XDP attachment made against
// them. Callers configure the datapath and attach it to interfaces through
// this type; nothing outside this package touches BPF maps or programs
// directly.
type Loader struct {
	objs bpfObjects

	wanLink    link.Link
	wanIfindex uint32
	lanLinks   map[uint32]link.Link
}

// Load compiles-in objects (embedded at build time by bpf2go) and loads them
// into the kernel. Call Close when done to detach and unload everything.
func Load() (*Loader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock rlimit: %w", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading BPF objects: %w", err)
	}

	return &Loader{
		objs:     objs,
		lanLinks: make(map[uint32]link.Link),
	}, nil
}

// Close detaches all XDP programs and unloads the BPF objects.
func (l *Loader) Close() error {
	if l.wanLink != nil {
		l.wanLink.Close()
	}
	for _, lk := range l.lanLinks {
		lk.Close()
	}
	return l.objs.Close()
}

// AttachWAN attaches the DS-Lite decap program (AFTR -> LAN direction) to
// the WAN-facing interface. Only one WAN interface is supported.
//
// It also enables the IPv4/IPv6 forwarding sysctls bpf_fib_lookup() needs
// (see configureWANSysctls) and re-enables RA acceptance on ifaceName, so
// callers don't need to configure this externally.
func (l *Loader) AttachWAN(ifaceName string) (ifindex uint32, err error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return 0, fmt.Errorf("looking up WAN interface %q: %w", ifaceName, err)
	}

	if err := configureWANSysctls(ifaceName); err != nil {
		return 0, fmt.Errorf("configuring sysctls for %q: %w", ifaceName, err)
	}

	lk, err := link.AttachXDP(link.XDPOptions{
		Program:   l.objs.XdpDsliteDecap,
		Interface: iface.Index,
	})
	if err != nil {
		return 0, fmt.Errorf("attaching XDP decap program to %q: %w", ifaceName, err)
	}

	if l.wanLink != nil {
		l.wanLink.Close()
	}
	l.wanLink = lk
	l.wanIfindex = uint32(iface.Index)
	return l.wanIfindex, nil
}

// AttachLAN attaches the DS-Lite encap program (LAN -> AFTR direction) to a
// LAN-facing interface. May be called once per LAN interface.
func (l *Loader) AttachLAN(ifaceName string) (ifindex uint32, err error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return 0, fmt.Errorf("looking up LAN interface %q: %w", ifaceName, err)
	}

	lk, err := link.AttachXDP(link.XDPOptions{
		Program:   l.objs.XdpDsliteEncap,
		Interface: iface.Index,
	})
	if err != nil {
		return 0, fmt.Errorf("attaching XDP encap program to %q: %w", ifaceName, err)
	}

	ifindexU32 := uint32(iface.Index)
	if old, ok := l.lanLinks[ifindexU32]; ok {
		old.Close()
	}
	l.lanLinks[ifindexU32] = lk
	return ifindexU32, nil
}

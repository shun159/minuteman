// Package ndppd runs pkg/ndproxy's RFC 4389 Neighbor Discovery proxy as a
// molecule supervision tree: a process owning the proxy's sockets and its
// state, and one owning the host routes a confirmed LAN host gets.
package ndppd

import (
	"context"
	"fmt"
	"log"
	"math/bits"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/shun159/miniteman/pkg/ndproxy"
	"github.com/shun159/molecule"
	"github.com/shun159/molecule/behaviours/genserver"
	"github.com/shun159/molecule/behaviours/supervisor"
	"github.com/shun159/molecule/net/socket"
	"github.com/shun159/molecule/proc"
	"golang.org/x/sys/unix"
)

// RoutesName is the name of the process owning the host routes.
const RoutesName molecule.Local = "ndppd routes"

// Routes installs and removes the /128 host route of a LAN host the proxy
// has confirmed, so the kernel forwards its traffic out the interface it
// was confirmed behind: internal/wanextend's HostRoutes.
type Routes interface {
	Install(target netip.Addr, iface string) error
	Remove(target netip.Addr, iface string)
	Close() error
}

// Config configures the proxy.
type Config struct {
	WAN  string   // where Neighbor Solicitations are answered
	LANs []string // where the hosts answered for live
	// OpenRoutes opens the host routes, on every start of their process.
	OpenRoutes func() (Routes, error)
}

// Spec is the supervision tree of the proxy:
//
//	ndppd (rest_for_one)
//	├── ndppd routes   genserver: the host routes, installed and removed by casts
//	└── ndppd proxy    genserver: the WAN and LAN sockets, and the proxy's state
//
// rest_for_one because the proxy tells the routes process what to do: a
// restarted routes process takes the proxy with it, which starts afresh,
// re-confirming hosts as the WAN asks for them.
func Spec(cfg Config) supervisor.Spec {
	return supervisor.Spec{
		Name:     molecule.Local("ndppd"),
		Strategy: supervisor.RestForOne,
		Children: []supervisor.ChildSpec{
			{ID: "ndppd routes", Start: genserver.Child(routes{open: cfg.OpenRoutes, logf: log.Printf}, molecule.WithName(RoutesName))},
			{ID: "ndppd proxy", Start: supervisor.StartFunc(cfg.startProxy)},
		},
	}
}

// ipv6Proto is ETH_P_IPV6 in network byte order, as AF_PACKET takes it.
var ipv6Proto = bits.ReverseBytes16(unix.ETH_P_IPV6)

// startProxy opens the proxy's sockets, owned by parent until the proxy
// owns them:
//
//   - the WAN's Neighbor Solicitations come in on an AF_PACKET socket, as a
//     raw ICMPv6 one never sees them (pkg/ndproxy's packet.go): NSFilter
//     attached before the bind, ALLMULTI so Solicited-Node multicast for
//     any target passes the NIC;
//   - the proxy's Advertisements go out on a raw ICMPv6 socket on the WAN,
//     filtered to nothing, as nothing is read from it;
//   - each LAN has a raw ICMPv6 socket, the probes going out on it and the
//     Advertisements coming back, filtered to those.
//
// Every raw socket is bound to its interface, both hop limits 255 (RFC
// 4861 §6.1.2).
func (cfg Config) startProxy(ctx context.Context, parent *proc.Self) (pid proc.PID, err error) {
	var opened []socket.Socket
	defer func() {
		if err != nil {
			for _, s := range opened {
				s.Close(context.Background(), parent)
			}
		}
	}()
	wan, err := net.InterfaceByName(cfg.WAN)
	if err != nil {
		return proc.PID{}, fmt.Errorf("ndppd: looking up %s: %w", cfg.WAN, err)
	}
	wanRX, err := socket.Open(parent, unix.AF_PACKET, unix.SOCK_DGRAM, int(ipv6Proto), func(fd int) error {
		prog := unix.SockFprog{Len: uint16(len(ndproxy.NSFilter)), Filter: &ndproxy.NSFilter[0]}
		if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog); err != nil {
			return fmt.Errorf("attaching NS filter: %w", err)
		}
		if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: ipv6Proto, Ifindex: wan.Index}); err != nil {
			return fmt.Errorf("binding: %w", err)
		}
		mreq := &unix.PacketMreq{Ifindex: int32(wan.Index), Type: unix.PACKET_MR_ALLMULTI}
		return unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, mreq)
	}, socket.Options{})
	if err != nil {
		return proc.PID{}, fmt.Errorf("ndppd: opening the WAN packet socket on %s: %w", cfg.WAN, err)
	}
	opened = append(opened, wanRX)
	wanTX, err := openICMPv6(parent, cfg.WAN)
	if err != nil {
		return proc.PID{}, err
	}
	opened = append(opened, wanTX)

	p := proxy{
		wanRX: wanRX, wanTX: wanTX, wanIndex: wan.Index, wanMAC: wan.HardwareAddr,
		now: time.Now, logf: log.Printf,
		send: func(s socket.Socket, to *syscall.SockaddrInet6, b []byte) molecule.Effect {
			return s.SendEffect(to, b)
		},
		arm: func(s socket.Socket) molecule.Effect { return s.SetActiveEffect(socket.Once) },
	}
	for _, name := range cfg.LANs {
		ifi, err := net.InterfaceByName(name)
		if err != nil {
			return proc.PID{}, fmt.Errorf("ndppd: looking up %s: %w", name, err)
		}
		s, err := openICMPv6(parent, name, ndproxy.AdvertisementType)
		if err != nil {
			return proc.PID{}, err
		}
		opened = append(opened, s)
		p.lans = append(p.lans, lan{name: name, index: ifi.Index, mac: ifi.HardwareAddr, sock: s})
	}

	pid, err = genserver.Child(p).StartLink(ctx, parent)
	if err != nil {
		return proc.PID{}, err
	}
	for _, s := range opened {
		if err = s.ControllingProcess(ctx, parent, pid); err != nil {
			break
		}
	}
	if err == nil {
		// Read: the WAN's Solicitations, the LANs' Advertisements.
		for _, s := range append([]socket.Socket{wanRX}, opened[2:]...) {
			if err = s.SetActive(ctx, parent, socket.Once); err != nil {
				break
			}
		}
	}
	if err != nil {
		parent.Exit(pid, proc.Kill)
		return proc.PID{}, err
	}
	return pid, nil
}

// openICMPv6 opens a raw ICMPv6 socket on iface, owned by parent, passing
// the ICMPv6 types given.
func openICMPv6(parent *proc.Self, iface string, types ...uint8) (socket.Socket, error) {
	s, err := socket.Open(parent, unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_ICMPV6, func(fd int) error {
		if err := unix.BindToDevice(fd, iface); err != nil {
			return fmt.Errorf("binding: %w", err)
		}
		for _, opt := range []int{unix.IPV6_MULTICAST_HOPS, unix.IPV6_UNICAST_HOPS} {
			if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, opt, 255); err != nil {
				return fmt.Errorf("setting hop limit: %w", err)
			}
		}
		return unix.SetsockoptICMPv6Filter(fd, unix.SOL_ICMPV6, ndproxy.ICMP6Filter, ndproxy.ICMPv6Filter(types...))
	}, socket.Options{})
	if err != nil {
		return socket.Socket{}, fmt.Errorf("ndppd: opening a raw ICMPv6 socket on %s: %w", iface, err)
	}
	return s, nil
}

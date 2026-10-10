// Package radvd sends Router Advertisements on minuteman's LAN interfaces,
// as a molecule supervision tree: one process per interface, owning its raw
// ICMPv6 socket, advertising the Config last given to it. The protocol --
// the RA itself, its timing -- is pkg/routeradvert's; this package is the
// process around it.
package radvd

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"syscall"

	"github.com/shun159/miniteman/pkg/routeradvert"
	"github.com/shun159/molecule"
	"github.com/shun159/molecule/behaviours/genserver"
	"github.com/shun159/molecule/behaviours/supervisor"
	"github.com/shun159/molecule/net/socket"
	"github.com/shun159/molecule/proc"
	"golang.org/x/sys/unix"
)

// Name is the name of the advertiser of iface.
func Name(iface string) molecule.Local { return molecule.Local("radvd " + iface) }

// Spec is the supervision tree of the advertisers of ifaces:
//
//	radvd (one_for_one)
//	├── radvd <iface>   genserver: the interface's raw ICMPv6 socket
//	└── ...
//
// An advertiser is idle until it is given a Config (Advertiser.Advertise).
// Each child's start opens its socket, so a failure fails the tree's start.
func Spec(ifaces []string) supervisor.Spec {
	var children []supervisor.ChildSpec
	for _, iface := range ifaces {
		children = append(children, supervisor.ChildSpec{
			ID:    "radvd " + iface,
			Start: supervisor.StartFunc(starter(iface)),
		})
	}
	return supervisor.Spec{Name: molecule.Local("radvd"), Strategy: supervisor.OneForOne, Children: children}
}

// Advertiser is a handle on the advertisers of a node, for the policies
// deciding what each interface advertises (internal/lanprefix,
// internal/wanextend). It may be used from any goroutine.
type Advertiser struct{ node *proc.Node }

// NewAdvertiser returns the handle on the advertisers of node.
func NewAdvertiser(node *proc.Node) Advertiser { return Advertiser{node: node} }

// Advertise makes cfg what iface advertises: from now, if it advertised
// nothing yet, or as soon as RFC 4861 allows another RA if it did and cfg
// differs -- in place, never withdrawing the router in between, as a restart
// would (RouterLifetime=0 is for shutdown). It does not wait.
func (a Advertiser) Advertise(iface string, cfg routeradvert.Config) {
	molecule.SendCast(a.node, Name(iface), advertise{cfg})
}

// starter starts the advertiser of iface, with its socket: raw ICMPv6,
// bound to iface, in the All-Routers group so multicast Solicitations reach
// it, both hop limits 255 (RFC 4861 §6.1.2 requires it on every NDP packet,
// so receivers can detect off-link spoofing), filtered to Router
// Solicitations.
func starter(iface string) supervisor.StartFunc {
	return func(ctx context.Context, parent *proc.Self) (proc.PID, error) {
		ifi, err := net.InterfaceByName(iface)
		if err != nil {
			return proc.PID{}, fmt.Errorf("radvd: looking up interface %s: %w", iface, err)
		}
		sock, err := socket.Open(parent, unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_ICMPV6, func(fd int) error {
			if err := unix.BindToDevice(fd, iface); err != nil {
				return fmt.Errorf("binding to %s: %w", iface, err)
			}
			mreq := &unix.IPv6Mreq{Multiaddr: routeradvert.AllRoutersMulticast.As16(), Interface: uint32(ifi.Index)}
			if err := unix.SetsockoptIPv6Mreq(fd, unix.IPPROTO_IPV6, unix.IPV6_JOIN_GROUP, mreq); err != nil {
				return fmt.Errorf("joining all-routers on %s: %w", iface, err)
			}
			for _, opt := range []int{unix.IPV6_MULTICAST_HOPS, unix.IPV6_UNICAST_HOPS} {
				if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, opt, 255); err != nil {
					return fmt.Errorf("setting hop limit on %s: %w", iface, err)
				}
			}
			return unix.SetsockoptICMPv6Filter(fd, unix.SOL_ICMPV6, routeradvert.ICMP6Filter, routeradvert.SolicitationFilter())
		}, socket.Options{})
		if err != nil {
			return proc.PID{}, fmt.Errorf("radvd: opening raw ICMPv6 socket on %s: %w", iface, err)
		}
		allNodes := &syscall.SockaddrInet6{Addr: routeradvert.AllNodesMulticast.As16(), ZoneId: uint32(ifi.Index)}
		a := advertiser{
			iface:  iface,
			mac:    ifi.HardwareAddr,
			seed:   [2]uint64{rand.Uint64(), rand.Uint64()},
			sendRA: func(b []byte) molecule.Effect { return sock.SendEffect(allNodes, b) },
			armRS:  sock.SetActiveEffect(socket.Once),
		}
		pid, err := genserver.Child(a, molecule.WithName(Name(iface))).StartLink(ctx, parent)
		if err == nil {
			if err = sock.ControllingProcess(ctx, parent, pid); err == nil {
				err = sock.SetActive(ctx, parent, socket.Once)
			}
			if err != nil {
				parent.Exit(pid, proc.Kill)
			}
		}
		if err != nil {
			sock.Close(context.Background(), parent)
			return proc.PID{}, err
		}
		return pid, nil
	}
}

// isTentative reports whether a send failed because the interface's
// link-local source is still DAD-tentative.
func isTentative(err error) bool { return errors.Is(err, unix.EADDRNOTAVAIL) }

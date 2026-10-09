// Package dhcpv6client runs the DHCPv6 exchanges of one interface in a
// molecule process owning its client socket, [link-local%iface]:546, for as
// long as it lives. The exchanges come from pkg/dhcpv6 through the Exchanger
// a Client is: pkg/aftrdiscovery's Information-Request, pkg/prefixdelegation's
// Solicit/Request/Renew/Rebind/Release.
//
// One process per interface is also what keeps them from colliding: the
// socket is bound once, and an exchange arriving while another runs waits
// its turn (a postponed event).
package dhcpv6client

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/shun159/miniteman/pkg/dhcpv6"
	"github.com/shun159/molecule"
	"github.com/shun159/molecule/behaviours/genstatem"
	"github.com/shun159/molecule/behaviours/supervisor"
	"github.com/shun159/molecule/net/genudp"
	"github.com/shun159/molecule/proc"
	"golang.org/x/sys/unix"
)

// bindRetries/bindRetryInterval bound how long a start waits out an
// EADDRNOTAVAIL binding the interface's link-local address: the kernel
// returns that while the address is DAD-tentative, as it briefly is after
// the link bounces -- a restart after AttachWAN, say.
const (
	bindRetries       = 10
	bindRetryInterval = time.Second
)

// Name is the name of the client process of iface.
func Name(iface string) molecule.Local { return molecule.Local("dhcpv6 client " + iface) }

// Config is a client's configuration.
type Config struct {
	// Iface is the interface the client runs on.
	Iface string

	// Tests set these, rather than deriving them from Iface: the address
	// to bind, the address to send to, and the client's DUID.
	bind     netip.AddrPort
	server   netip.AddrPort
	clientID dhcpv6.DUID
}

// ChildSpec is the child spec of the client of cfg.Iface, for a supervisor.
// Its start binds the socket, so that a supervisor's start fails, rather
// than the first exchange, on an interface with no usable link-local
// address.
func ChildSpec(cfg Config) supervisor.ChildSpec {
	return supervisor.ChildSpec{
		ID:    "dhcpv6 client " + cfg.Iface,
		Start: supervisor.StartFunc(cfg.start),
	}
}

func (cfg Config) start(ctx context.Context, parent *proc.Self) (proc.PID, error) {
	if err := cfg.resolve(); err != nil {
		return proc.PID{}, err
	}
	sock, err := cfg.open(ctx, parent)
	if err != nil {
		return proc.PID{}, err
	}
	var seed [16]byte
	rand.Read(seed[:])
	m := machine{
		sock:     sock,
		server:   cfg.server,
		clientID: cfg.clientID,
		seed:     [2]uint64{binary.LittleEndian.Uint64(seed[:8]), binary.LittleEndian.Uint64(seed[8:])},
	}
	pid, err := genstatem.Child(m, molecule.WithName(Name(cfg.Iface))).StartLink(ctx, parent)
	if err != nil {
		sock.Close(context.Background(), parent)
		return proc.PID{}, err
	}
	// The socket was the parent's until now, and passive: nothing was
	// delivered to it.
	if err := sock.ControllingProcess(ctx, parent, pid); err != nil {
		parent.Exit(pid, proc.Kill)
		sock.Close(context.Background(), parent)
		return proc.PID{}, err
	}
	return pid, nil
}

// resolve derives what tests do not set: the interface's link-local address
// on the client port, the servers' multicast address on it, and a DUID-LL
// of its MAC.
func (cfg *Config) resolve() error {
	if cfg.bind.IsValid() {
		return nil
	}
	iface, err := net.InterfaceByName(cfg.Iface)
	if err != nil {
		return fmt.Errorf("dhcpv6 client: looking up interface %s: %w", cfg.Iface, err)
	}
	lla, err := linkLocal(iface)
	if err != nil {
		return err
	}
	duid, err := dhcpv6.DUIDLLFromInterface(iface)
	if err != nil {
		return fmt.Errorf("dhcpv6 client: building client DUID: %w", err)
	}
	cfg.bind = netip.AddrPortFrom(lla.WithZone(cfg.Iface), dhcpv6.ClientPort)
	cfg.server = netip.AddrPortFrom(dhcpv6.AllRelayAgentsAndServers.WithZone(cfg.Iface), dhcpv6.ServerPort)
	cfg.clientID = duid
	return nil
}

// linkLocal returns iface's IPv6 link-local address.
func linkLocal(iface *net.Interface) (netip.Addr, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("dhcpv6 client: listing addresses on %s: %w", iface.Name, err)
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(ipn.IP); ok && ip.Is6() && !ip.Is4In6() && ip.IsLinkLocalUnicast() {
				return ip, nil
			}
		}
	}
	return netip.Addr{}, fmt.Errorf("dhcpv6 client: no IPv6 link-local address on %s", iface.Name)
}

// open binds the client socket, owned by parent until given to the client,
// waiting out a tentative address.
//
// The socket is bound, never connected: a connected socket only accepts
// datagrams from the address it is connected to, but the server's Reply is
// sent unicast from the server's own address, not from the multicast
// destination the request was sent to. Binding to a zone-qualified
// link-local address also fixes the outgoing interface for the multicast
// request: on Linux, binding to a link-local address sets the socket's
// bound device, which route lookups consult before IPV6_MULTICAST_IF.
func (cfg Config) open(ctx context.Context, parent *proc.Self) (genudp.Socket, error) {
	for attempt := 0; ; attempt++ {
		sock, err := genudp.Open(ctx, parent, cfg.bind.String(), genudp.Options{})
		if err == nil {
			return sock, nil
		}
		if !errors.Is(err, unix.EADDRNOTAVAIL) || attempt >= bindRetries {
			return genudp.Socket{}, fmt.Errorf("dhcpv6 client: binding %s: %w", cfg.bind, err)
		}
		select {
		case <-ctx.Done():
			return genudp.Socket{}, ctx.Err()
		case <-time.After(bindRetryInterval):
		}
	}
}

// Client is a handle on the client process of an interface, and the
// dhcpv6.Exchanger running exchanges there. It may be used from any
// goroutine.
type Client struct {
	node *proc.Node
	name molecule.Local
}

// NewClient returns the handle on the client of iface, on node.
func NewClient(node *proc.Node, iface string) Client {
	return Client{node: node, name: Name(iface)}
}

// Exchange runs x, after the exchanges before it, and returns its answer.
// When ctx is done first, the exchange is abandoned -- running or waiting its
// turn -- and Exchange returns ctx's error.
func (c Client) Exchange(ctx context.Context, x dhcpv6.Exchange) (*dhcpv6.Message, error) {
	id := c.node.MakeRef()
	p := molecule.Request[exchangeRep](c.node, c.name, exchangeReq{ID: id, X: x})
	select {
	case <-p.Done():
	case <-ctx.Done():
		p.Cancel()
		if _, err := p.Result(); errors.Is(err, molecule.ErrCancelled) {
			molecule.SendCast(c.node, c.name, cancelReq{ID: id})
			return nil, ctx.Err()
		}
	}
	rep, err := p.Result()
	if err != nil {
		return nil, fmt.Errorf("dhcpv6 client: %w", err)
	}
	return rep.Msg, rep.Err
}

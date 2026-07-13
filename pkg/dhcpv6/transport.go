package dhcpv6

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// clientPort and serverPort are the well-known DHCPv6 client/server UDP
// ports (RFC 3315 §5.2). clientPort is a privileged port; minuteman already
// requires root/CAP_NET_ADMIN to attach XDP programs, so binding to it adds
// no new privilege requirement.
const (
	clientPort = 546
	serverPort = 547
)

// wanLocks serializes DHCPv6 exchanges per WAN interface. Every exchange binds
// the same [link-local%iface]:546 via bindWAN with no SO_REUSEADDR, so two
// concurrent exchanges on one interface would collide with EADDRINUSE. A
// process that runs exchanges concurrently on one interface -- e.g.
// cmd/minuteman's long-lived DHCPv6-PD maintenance loop alongside its periodic
// AFTR re-discovery, both on the WAN -- relies on this lock to take turns.
var (
	wanLocksMu sync.Mutex
	wanLocks   = map[string]chan struct{}{}
)

// lockWAN acquires the per-interface DHCPv6 exchange lock for ifaceName,
// honoring ctx so a waiter blocked behind a long-running exchange still
// respects its own deadline/cancellation (a DHCPv6-PD Renew must be able to
// give up at T2 even if an AFTR re-discovery is holding the socket). The
// returned release must be called (typically deferred) once the exchange's
// socket is closed. A nil error means the lock was acquired.
func lockWAN(ctx context.Context, ifaceName string) (release func(), err error) {
	wanLocksMu.Lock()
	ch, ok := wanLocks[ifaceName]
	if !ok {
		ch = make(chan struct{}, 1)
		wanLocks[ifaceName] = ch
	}
	wanLocksMu.Unlock()

	select {
	case ch <- struct{}{}:
		return func() { <-ch }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// allDHCPRelayAgentsAndServers is the link-scoped multicast address DHCPv6
// clients send to (RFC 3315 §5.1).
const allDHCPRelayAgentsAndServers = "ff02::1:2"

// bindWAN opens a UDP6 socket bound to iface's link-local address on the
// DHCPv6 client port.
//
// This must be done with ListenUDP, never DialUDP: a connected socket only
// accepts datagrams from the address it's connected to, but the server's
// Reply is sent unicast from the server's own address, not from the
// multicast destination the request was sent to -- a connected socket would
// silently drop every reply. Binding to a zone-qualified link-local address
// also fixes the outgoing interface for the multicast request: on Linux,
// binding to a link-local address sets the socket's bound device, which
// route lookups consult before IPV6_MULTICAST_IF for all sends on that
// socket, so no explicit multicast-interface socket option is needed.
func bindWAN(iface *net.Interface) (*net.UDPConn, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("listing addresses on %s: %w", iface.Name, err)
	}

	var lla net.IP
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ipn.IP.To4() == nil && ipn.IP.IsLinkLocalUnicast() {
			lla = ipn.IP
			break
		}
	}
	if lla == nil {
		return nil, fmt.Errorf("no IPv6 link-local address on %s", iface.Name)
	}

	conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: lla, Port: clientPort, Zone: iface.Name})
	if err != nil {
		return nil, fmt.Errorf("binding to [%s%%%s]:%d: %w", lla, iface.Name, clientPort, err)
	}
	return conn, nil
}

// sendAndWait sends msg to dst and waits up to rt for a reply of type
// expectedType matching msg.XID, discarding any other traffic received in
// the meantime. It returns (nil, nil) on a plain timeout (the caller retries
// with a new RT), and returns promptly if ctx is cancelled while waiting.
func sendAndWait(ctx context.Context, conn *net.UDPConn, dst *net.UDPAddr, msg *Message, rt time.Duration, expectedType MessageType) (*Message, error) {
	b, err := msg.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("encoding message: %w", err)
	}
	if _, err := conn.WriteToUDP(b, dst); err != nil {
		return nil, fmt.Errorf("sending to %s: %w", dst, err)
	}

	deadline := time.Now().Add(rt)
	if err := conn.SetReadDeadline(deadline); err != nil {
		return nil, fmt.Errorf("setting read deadline: %w", err)
	}

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			conn.SetReadDeadline(time.Now())
		case <-stop:
		}
	}()

	buf := make([]byte, 65535)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return nil, nil
			}
			return nil, fmt.Errorf("reading reply: %w", err)
		}

		reply, err := ParseMessage(buf[:n])
		if err != nil {
			continue // malformed packet, not our reply -- keep waiting
		}
		if reply.Type != expectedType || reply.XID != msg.XID {
			continue
		}
		return reply, nil
	}
}

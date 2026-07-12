package dhcpv4

import (
	"encoding/binary"
	"net/netip"
	"time"
)

// InterfaceConfig is the DHCPv4 service configuration for one LAN interface.
type InterfaceConfig struct {
	Iface    string
	ServerIP netip.Addr   // the CPE's own IPv4 on this LAN: the DHCP server id and offered router
	Subnet   netip.Prefix // the LAN subnet addresses are carved from
	// DNSServers is offered in option 6. For DS-Lite this is normally the
	// CPE's own ServerIP (so LAN DNS goes to minuteman's -dns-proxy, which
	// forwards it over IPv6 rather than through the softwire); empty omits
	// the option (see cmd/minuteman: it declines to advertise a DNS server
	// that wouldn't actually answer).
	DNSServers []netip.Addr
	// MTU is offered in option 26. For DS-Lite this should be the WAN MTU
	// minus the 40-byte IPv4-in-IPv6 tunnel overhead, so LAN clients size
	// their packets to fit the softwire; 0 omits the option.
	MTU       uint16
	LeaseTime time.Duration
}

// handle turns one received request into the reply the server should send,
// or nil to stay silent. It is pure: the only state it mutates is pool, and
// it reads the clock only through now. The returned message's Flags/CIAddr/
// YIAddr/CHAddr are what packet.go's destination logic keys off.
func handle(cfg InterfaceConfig, pool *Pool, req *Message, now time.Time) *Message {
	if req.Op != OpBootRequest {
		return nil
	}
	// BOOTP relay (giaddr set) is out of this server's scope (see the package
	// doc): a relayed reply must go back to the relay agent on the server
	// port, which destination() doesn't do, so decline rather than mis-send.
	if req.GIAddr.IsValid() && !req.GIAddr.IsUnspecified() {
		return nil
	}
	mt, ok := req.Options.MessageType()
	if !ok {
		return nil
	}
	clientID := req.Options.ClientID(req.CHAddr)

	switch mt {
	case Discover:
		requested, _ := req.Options.RequestedIP()
		ip, ok := pool.Offer(clientID, requested, now)
		if !ok {
			return nil // pool exhausted; the client will retry
		}
		return buildReply(cfg, pool, req, Offer, ip)

	case Request:
		return handleRequest(cfg, pool, req, clientID, now)

	case Release:
		// RFC 2131 §4.4.6: RELEASE is unicast to the leasing server; ignore
		// one addressed elsewhere. Pool.Release re-checks ownership.
		if sid, ok := req.Options.ServerID(); ok && sid != cfg.ServerIP {
			return nil
		}
		pool.Release(clientID, req.CIAddr)
		return nil

	case Decline:
		// RFC 2131 §4.4.5: a DHCPDECLINE MUST carry the server identifier and
		// the declined address. Ignore ones not addressed to us; Pool.Decline
		// further ignores an address the client doesn't actually hold, so a
		// client can't poison the pool with addresses it was never leased.
		if sid, ok := req.Options.ServerID(); !ok || sid != cfg.ServerIP {
			return nil
		}
		if declined, ok := req.Options.RequestedIP(); ok {
			pool.Decline(clientID, declined, now)
		}
		return nil

	case Inform:
		// The client already has an (externally configured) address in
		// ciaddr and wants only configuration parameters — no lease, no
		// yiaddr (RFC 2131 §4.3.5).
		return buildInformAck(cfg, req)

	default:
		return nil // OFFER/ACK/NAK from a client is nonsensical
	}
}

// handleRequest implements RFC 2131 §4.3.2's three DHCPREQUEST substates,
// distinguished by which of server-identifier / requested-IP / ciaddr the
// client set.
func handleRequest(cfg InterfaceConfig, pool *Pool, req *Message, clientID string, now time.Time) *Message {
	reqIP, hasReqIP := req.Options.RequestedIP()

	// SELECTING: server-identifier present — the client is accepting one
	// server's offer.
	if sid, hasSID := req.Options.ServerID(); hasSID {
		if sid != cfg.ServerIP {
			pool.CancelOffer(clientID) // it chose another server; free our offer now
			return nil
		}
		if !hasReqIP {
			return nil // malformed SELECTING
		}
		bound, ok := pool.Binding(clientID, now)
		if !ok || bound != reqIP {
			return buildNAK(cfg, req) // we never offered this, or the offer lapsed
		}
		pool.Commit(clientID, reqIP, now)
		return buildReply(cfg, pool, req, ACK, reqIP)
	}

	// No server-identifier: INIT-REBOOT (requested-IP, ciaddr zero) or
	// RENEWING/REBINDING (ciaddr set). The address in question is the
	// requested-IP option or, absent it, ciaddr.
	target := reqIP
	if !hasReqIP {
		target = req.CIAddr
	}
	if !target.IsValid() || target.IsUnspecified() {
		return nil
	}

	bound, ok := pool.Binding(clientID, now)
	if !ok {
		// No record of this client. RFC 2131 §4.3.2 requires silence here so
		// independent DHCP servers on one segment coexist; the client times
		// out and falls back to DISCOVER, recovering its address through a
		// fresh lease (this server keeps no state across restarts, so a
		// returning client's INIT-REBOOT for its cached address is exactly
		// this "no record" case).
		return nil
	}
	if bound != target {
		return buildNAK(cfg, req) // the client insists on an address we didn't lease it
	}
	pool.Commit(clientID, target, now)
	return buildReply(cfg, pool, req, ACK, target)
}

// buildReply assembles an OFFER or ACK granting yip to the client, carrying
// the full lease + configuration option set.
func buildReply(cfg InterfaceConfig, pool *Pool, req *Message, mt MessageType, yip netip.Addr) *Message {
	m := baseReply(req)
	m.YIAddr = yip
	m.Options = append(Options{
		NewMessageType(mt),
		NewAddr(OptServerID, cfg.ServerIP),
		NewSeconds(OptLeaseTime, pool.LeaseDuration()),
		NewSeconds(OptRenewalTime, pool.LeaseDuration()/2),     // T1 = 50% (RFC 2131 §4.4.5)
		NewSeconds(OptRebindingTime, pool.LeaseDuration()*7/8), // T2 = 87.5%
	}, configOptions(cfg)...)
	return m
}

// buildInformAck assembles an ACK for a DHCPINFORM: configuration options
// only, no address grant and no lease timers.
func buildInformAck(cfg InterfaceConfig, req *Message) *Message {
	m := baseReply(req)
	m.CIAddr = req.CIAddr // echo the client's own address (RFC 2131 §4.3.5)
	m.Options = append(Options{
		NewMessageType(ACK),
		NewAddr(OptServerID, cfg.ServerIP),
	}, configOptions(cfg)...)
	return m
}

// buildNAK assembles a DHCPNAK, telling the client its requested address is
// unacceptable so it must restart from DISCOVER. A NAK is broadcast (RFC
// 2131 §4.3.2): the client's notion of its own address is exactly what's
// being rejected, so it may not be reachable by unicast.
func buildNAK(cfg InterfaceConfig, req *Message) *Message {
	m := baseReply(req)
	m.Flags |= flagBroadcast
	m.Options = Options{
		NewMessageType(NAK),
		NewAddr(OptServerID, cfg.ServerIP),
	}
	return m
}

// baseReply fills the BOOTP header fields common to every reply. siaddr
// (next bootstrap server) is deliberately left zero: it is not the server
// identifier (option 54 carries that), and setting it would advertise this
// CPE as a boot server it isn't (RFC 2131 §3.1, server message table).
func baseReply(req *Message) *Message {
	return &Message{
		Op:     OpBootReply,
		HType:  hardwareTypeEthernet,
		HLen:   6,
		XID:    req.XID,
		Flags:  req.Flags,  // echo the broadcast flag
		GIAddr: req.GIAddr, // echoed for form; giaddr!=0 requests are rejected in handle
		CHAddr: req.CHAddr,
	}
}

// configOptions is the shared network-configuration option set (subnet
// mask, router, broadcast, DNS, MTU) carried by every OFFER/ACK/INFORM-ACK.
func configOptions(cfg InterfaceConfig) Options {
	opts := Options{
		NewAddr(OptSubnetMask, subnetMask(cfg.Subnet.Bits())),
		NewAddr(OptRouter, cfg.ServerIP),
		NewAddr(OptBroadcastAddr, lastAddr(cfg.Subnet.Masked())),
	}
	if len(cfg.DNSServers) > 0 {
		opts = append(opts, NewAddrs(OptDNSServers, cfg.DNSServers))
	}
	if cfg.MTU != 0 {
		opts = append(opts, NewMTU(cfg.MTU))
	}
	return opts
}

// subnetMask returns the IPv4 netmask for a prefix length (e.g. 24 ->
// 255.255.255.0), encoded as an address for the option's 4-byte value.
func subnetMask(bits int) netip.Addr {
	var v uint32
	if bits > 0 {
		v = ^uint32(0) << (32 - bits)
	}
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], v)
	return netip.AddrFrom4(out)
}

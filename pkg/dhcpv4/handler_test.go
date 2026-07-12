package dhcpv4

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

func testConfig() (InterfaceConfig, *Pool) {
	cfg := InterfaceConfig{
		Iface:      "lan0",
		ServerIP:   netip.MustParseAddr("192.168.1.1"),
		Subnet:     netip.MustParsePrefix("192.168.1.0/24"),
		DNSServers: []netip.Addr{netip.MustParseAddr("192.168.1.1")},
		MTU:        1460,
		LeaseTime:  12 * time.Hour,
	}
	pool, _ := NewPool(cfg.Subnet, cfg.ServerIP, cfg.LeaseTime)
	return cfg, pool
}

func clientReq(mt MessageType, opts ...Option) *Message {
	mac, _ := net.ParseMAC("52:54:00:aa:bb:cc")
	return &Message{
		Op:      OpBootRequest,
		HType:   hardwareTypeEthernet,
		HLen:    6,
		XID:     0x1234,
		CHAddr:  mac,
		Options: append(Options{NewMessageType(mt)}, opts...),
	}
}

// doDORA runs a DISCOVER + SELECTING-REQUEST for the default client and
// returns the acquired address.
func doDORA(t *testing.T, cfg InterfaceConfig, pool *Pool, now time.Time) netip.Addr {
	t.Helper()
	offer := handle(cfg, pool, clientReq(Discover), now)
	if offer == nil {
		t.Fatal("no OFFER")
	}
	ack := handle(cfg, pool, clientReq(Request,
		NewAddr(OptServerID, cfg.ServerIP), NewAddr(OptRequestedIP, offer.YIAddr)), now)
	if ack == nil {
		t.Fatal("no ACK")
	}
	if mt, _ := ack.Options.MessageType(); mt != ACK {
		t.Fatalf("reply type = %v, want ACK", mt)
	}
	return ack.YIAddr
}

func TestHandleDiscoverProducesOffer(t *testing.T) {
	cfg, pool := testConfig()
	reply := handle(cfg, pool, clientReq(Discover), time.Now())
	if reply == nil {
		t.Fatal("DISCOVER produced no reply")
	}
	if mt, _ := reply.Options.MessageType(); mt != Offer {
		t.Fatalf("reply type = %v, want OFFER", mt)
	}
	if !cfg.Subnet.Contains(reply.YIAddr) || reply.YIAddr == cfg.ServerIP {
		t.Fatalf("offered address %v is not a usable pool address", reply.YIAddr)
	}
	for _, code := range []OptionCode{OptSubnetMask, OptRouter, OptDNSServers, OptInterfaceMTU, OptLeaseTime} {
		if _, ok := reply.Options.Get(code); !ok {
			t.Errorf("OFFER missing option %d", code)
		}
	}
}

func TestHandleFullDORA(t *testing.T) {
	cfg, pool := testConfig()
	now := time.Now()
	ip := doDORA(t, cfg, pool, now)
	if !cfg.Subnet.Contains(ip) {
		t.Fatalf("ACKed address %v not in subnet", ip)
	}
}

func TestHandleRequestForOtherServerCancelsOfferAndIsSilent(t *testing.T) {
	cfg, pool := testConfig()
	now := time.Now()
	offer := handle(cfg, pool, clientReq(Discover), now)

	req := clientReq(Request,
		NewAddr(OptServerID, netip.MustParseAddr("192.168.1.254")), // a different server
		NewAddr(OptRequestedIP, offer.YIAddr),
	)
	if reply := handle(cfg, pool, req, now); reply != nil {
		t.Fatalf("REQUEST selecting another server: want silence, got %v", reply)
	}
	// Our tentative offer must have been released immediately.
	if _, ok := pool.Binding("52:54:00:aa:bb:cc", now); ok {
		t.Fatal("offer not cancelled after the client selected another server")
	}
}

func TestHandleSelectingUnofferedAddressNAKs(t *testing.T) {
	cfg, pool := testConfig()
	now := time.Now()
	// A SELECTING REQUEST naming us but for an address we never offered this
	// client (no prior DISCOVER) must be NAKed.
	req := clientReq(Request,
		NewAddr(OptServerID, cfg.ServerIP),
		NewAddr(OptRequestedIP, netip.MustParseAddr("192.168.1.77")),
	)
	reply := handle(cfg, pool, req, now)
	if reply == nil {
		t.Fatal("SELECTING for an un-offered address produced no reply, want NAK")
	}
	if mt, _ := reply.Options.MessageType(); mt != NAK {
		t.Fatalf("reply type = %v, want NAK", mt)
	}
}

func TestHandleUnknownInitRebootIsSilent(t *testing.T) {
	cfg, pool := testConfig()
	// INIT-REBOOT (no server-id, requested-ip, ciaddr=0) from a client the
	// server has no record of MUST be silent (RFC 2131 §4.3.2) -- not an ACK
	// of a free address (the old, non-compliant behavior) and not a NAK.
	req := clientReq(Request, NewAddr(OptRequestedIP, netip.MustParseAddr("192.168.1.50")))
	if reply := handle(cfg, pool, req, time.Now()); reply != nil {
		t.Fatalf("unknown INIT-REBOOT: want silence, got %v", reply)
	}
}

func TestHandleInitRebootWrongAddressNAKs(t *testing.T) {
	cfg, pool := testConfig()
	now := time.Now()
	ip := doDORA(t, cfg, pool, now)

	// The client now (INIT-REBOOT) insists on a *different* address than the
	// one it holds -> NAK.
	wrong := netip.MustParseAddr("192.168.1.200")
	if wrong == ip {
		wrong = netip.MustParseAddr("192.168.1.201")
	}
	reply := handle(cfg, pool, clientReq(Request, NewAddr(OptRequestedIP, wrong)), now)
	if reply == nil {
		t.Fatal("INIT-REBOOT for the wrong held address produced no reply, want NAK")
	}
	if mt, _ := reply.Options.MessageType(); mt != NAK {
		t.Fatalf("reply type = %v, want NAK", mt)
	}
	if !reply.Broadcast() {
		t.Error("NAK must be broadcast")
	}
}

func TestHandleRenewingUsesCiaddr(t *testing.T) {
	cfg, pool := testConfig()
	now := time.Now()
	ip := doDORA(t, cfg, pool, now)

	renew := clientReq(Request) // no server-id, no requested-ip, ciaddr set
	renew.CIAddr = ip
	ack := handle(cfg, pool, renew, now.Add(6*time.Hour))
	if ack == nil {
		t.Fatal("RENEW produced no reply")
	}
	if mt, _ := ack.Options.MessageType(); mt != ACK {
		t.Fatalf("RENEW reply type = %v, want ACK", mt)
	}
	if ack.YIAddr != ip {
		t.Fatalf("RENEW yiaddr = %v, want %v", ack.YIAddr, ip)
	}
}

func TestHandleReleaseFreesLease(t *testing.T) {
	cfg, pool := testConfig()
	now := time.Now()
	ip := doDORA(t, cfg, pool, now)

	rel := clientReq(Release, NewAddr(OptServerID, cfg.ServerIP))
	rel.CIAddr = ip
	if reply := handle(cfg, pool, rel, now); reply != nil {
		t.Fatalf("RELEASE should get no reply, got %v", reply)
	}
	if _, ok := pool.Binding("52:54:00:aa:bb:cc", now); ok {
		t.Fatal("RELEASE did not free the lease")
	}
}

func TestHandleDeclineRequiresServerIDAndOwnership(t *testing.T) {
	cfg, pool := testConfig()
	now := time.Now()
	ip := doDORA(t, cfg, pool, now)

	// A DECLINE without a server identifier is ignored (no quarantine).
	handle(cfg, pool, clientReq(Decline, NewAddr(OptRequestedIP, ip)), now)
	if !pool.allocatable(ip, now) {
		t.Fatal("DECLINE without server-id quarantined the address anyway")
	}

	// A DECLINE naming another server is ignored.
	handle(cfg, pool, clientReq(Decline,
		NewAddr(OptServerID, netip.MustParseAddr("192.168.1.254")),
		NewAddr(OptRequestedIP, ip)), now)
	if !pool.allocatable(ip, now) {
		t.Fatal("DECLINE for another server quarantined the address anyway")
	}

	// A well-formed DECLINE from the owning client quarantines it.
	handle(cfg, pool, clientReq(Decline,
		NewAddr(OptServerID, cfg.ServerIP),
		NewAddr(OptRequestedIP, ip)), now)
	if pool.allocatable(ip, now) {
		t.Fatal("a valid DECLINE did not quarantine the address")
	}
}

func TestHandleRejectsRelayedRequest(t *testing.T) {
	cfg, pool := testConfig()
	req := clientReq(Discover)
	req.GIAddr = netip.MustParseAddr("10.0.0.1") // came via a BOOTP relay
	if reply := handle(cfg, pool, req, time.Now()); reply != nil {
		t.Fatalf("relayed (giaddr!=0) request: want silence (relay unsupported), got %v", reply)
	}
}

func TestRepliesLeaveSiaddrZero(t *testing.T) {
	cfg, pool := testConfig()
	now := time.Now()
	offer := handle(cfg, pool, clientReq(Discover), now)
	// siaddr (next bootstrap server) must be 0.0.0.0: it's not the server id,
	// and a non-zero value could make a PXE client treat this CPE as a boot
	// server.
	if offer.SIAddr.IsValid() && !offer.SIAddr.IsUnspecified() {
		t.Fatalf("OFFER siaddr = %v, want 0.0.0.0", offer.SIAddr)
	}
}

func TestHandleInformReturnsConfigWithoutLease(t *testing.T) {
	cfg, pool := testConfig()
	inform := clientReq(Inform)
	inform.CIAddr = netip.MustParseAddr("192.168.1.200")
	ack := handle(cfg, pool, inform, time.Now())
	if ack == nil {
		t.Fatal("INFORM produced no reply")
	}
	if mt, _ := ack.Options.MessageType(); mt != ACK {
		t.Fatalf("INFORM reply type = %v, want ACK", mt)
	}
	if ack.YIAddr.IsValid() && !ack.YIAddr.IsUnspecified() {
		t.Errorf("INFORM ACK must not assign an address, got yiaddr %v", ack.YIAddr)
	}
	if _, ok := ack.Options.Get(OptLeaseTime); ok {
		t.Error("INFORM ACK must not carry a lease time")
	}
	if _, ok := ack.Options.Get(OptRouter); !ok {
		t.Error("INFORM ACK should still carry config options like the router")
	}
}

func TestHandleIgnoresServerMessageTypes(t *testing.T) {
	cfg, pool := testConfig()
	if reply := handle(cfg, pool, clientReq(ACK), time.Now()); reply != nil {
		t.Errorf("a client sending ACK should be ignored, got %v", reply)
	}
}

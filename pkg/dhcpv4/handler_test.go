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
	// Config options must be present.
	for _, code := range []OptionCode{OptSubnetMask, OptRouter, OptDNSServers, OptInterfaceMTU, OptLeaseTime} {
		if _, ok := reply.Options.Get(code); !ok {
			t.Errorf("OFFER missing option %d", code)
		}
	}
}

func TestHandleFullDORA(t *testing.T) {
	cfg, pool := testConfig()
	now := time.Now()

	offer := handle(cfg, pool, clientReq(Discover), now)
	if offer == nil {
		t.Fatal("no OFFER")
	}
	// SELECTING REQUEST: option 54 = our server id, option 50 = offered addr.
	req := clientReq(Request,
		NewAddr(OptServerID, cfg.ServerIP),
		NewAddr(OptRequestedIP, offer.YIAddr),
	)
	ack := handle(cfg, pool, req, now)
	if ack == nil {
		t.Fatal("no ACK")
	}
	if mt, _ := ack.Options.MessageType(); mt != ACK {
		t.Fatalf("reply type = %v, want ACK", mt)
	}
	if ack.YIAddr != offer.YIAddr {
		t.Fatalf("ACK yiaddr = %v, want the offered %v", ack.YIAddr, offer.YIAddr)
	}
}

func TestHandleRequestForOtherServerIsSilent(t *testing.T) {
	cfg, pool := testConfig()
	req := clientReq(Request,
		NewAddr(OptServerID, netip.MustParseAddr("192.168.1.254")), // a different server
		NewAddr(OptRequestedIP, netip.MustParseAddr("192.168.1.50")),
	)
	if reply := handle(cfg, pool, req, time.Now()); reply != nil {
		t.Fatalf("REQUEST selecting another server: want silence, got %v", reply)
	}
}

func TestHandleRequestWrongAddressNAKs(t *testing.T) {
	cfg, pool := testConfig()
	// INIT-REBOOT for an address on the wrong subnet: no server id, option 50
	// out of our subnet -> NAK.
	req := clientReq(Request, NewAddr(OptRequestedIP, netip.MustParseAddr("10.9.9.9")))
	reply := handle(cfg, pool, req, time.Now())
	if reply == nil {
		t.Fatal("wrong-subnet REQUEST produced no reply, want NAK")
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
	// Establish a lease via DORA first.
	offer := handle(cfg, pool, clientReq(Discover), now)
	handle(cfg, pool, clientReq(Request,
		NewAddr(OptServerID, cfg.ServerIP), NewAddr(OptRequestedIP, offer.YIAddr)), now)

	// RENEWING: no option 50, no server id, ciaddr = current address.
	renew := clientReq(Request)
	renew.CIAddr = offer.YIAddr
	ack := handle(cfg, pool, renew, now.Add(6*time.Hour))
	if ack == nil {
		t.Fatal("RENEW produced no reply")
	}
	if mt, _ := ack.Options.MessageType(); mt != ACK {
		t.Fatalf("RENEW reply type = %v, want ACK", mt)
	}
	if ack.YIAddr != offer.YIAddr {
		t.Fatalf("RENEW yiaddr = %v, want %v", ack.YIAddr, offer.YIAddr)
	}
}

func TestHandleReleaseFreesLease(t *testing.T) {
	cfg, pool := testConfig()
	now := time.Now()
	offer := handle(cfg, pool, clientReq(Discover), now)
	handle(cfg, pool, clientReq(Request,
		NewAddr(OptServerID, cfg.ServerIP), NewAddr(OptRequestedIP, offer.YIAddr)), now)

	rel := clientReq(Release)
	rel.CIAddr = offer.YIAddr
	if reply := handle(cfg, pool, rel, now); reply != nil {
		t.Fatalf("RELEASE should get no reply, got %v", reply)
	}
	// The address is now free for a different client.
	other, _ := net.ParseMAC("52:54:00:dd:ee:ff")
	discover := clientReq(Discover)
	discover.CHAddr = other
	reoffer := handle(cfg, pool, discover, now)
	if reoffer.YIAddr != offer.YIAddr {
		t.Fatalf("released address not reused: got %v, want %v", reoffer.YIAddr, offer.YIAddr)
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

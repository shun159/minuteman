package dhcpv4server

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/shun159/miniteman/pkg/dhcpv4"
	"github.com/shun159/molecule/behaviours/supervisor"
	"github.com/shun159/molecule/proc"
)

var (
	serverIP = netip.MustParseAddr("192.168.1.1")
	clientHW = net.HardwareAddr{2, 0, 0, 0, 0, 9}
	cfg      = dhcpv4.InterfaceConfig{
		Iface:     "lan0",
		ServerIP:  serverIP,
		Subnet:    netip.MustParsePrefix("192.168.1.0/24"),
		LeaseTime: time.Hour,
	}
)

// request is msg as the packet socket delivers it: IPv4/UDP from the client
// port to the server port. Checksums are left zero: nothing on this side
// checks them.
func request(msg *dhcpv4.Message) []byte {
	payload := msg.Marshal()
	b := make([]byte, 28+len(payload))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	b[9] = syscall.IPPROTO_UDP
	copy(b[16:20], []byte{255, 255, 255, 255})
	binary.BigEndian.PutUint16(b[20:], 68)
	binary.BigEndian.PutUint16(b[22:], 67)
	binary.BigEndian.PutUint16(b[24:], uint16(8+len(payload)))
	copy(b[28:], payload)
	return b
}

func discover() *dhcpv4.Message {
	return &dhcpv4.Message{Op: dhcpv4.OpBootRequest, HType: 1, HLen: 6, XID: 0x1234, Flags: 0x8000, CHAddr: clientHW,
		Options: dhcpv4.Options{{Code: dhcpv4.OptMessageType, Data: []byte{byte(dhcpv4.Discover)}}}}
}

func newServer(t *testing.T) (server, *dhcpv4.Pool) {
	t.Helper()
	pool, err := dhcpv4.NewPool(cfg.Subnet, cfg.ServerIP, cfg.LeaseTime)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	return server{cfg: cfg, ifindex: 7, pool: pool, now: func() time.Time { return now }, logf: t.Logf}, pool
}

// A DISCOVER is offered an address, the reply framed to the broadcast
// link-layer address it asked for; the pool given is left as it was.
func TestAnswerDiscover(t *testing.T) {
	s, pool := newServer(t)
	next, to, frame := s.answer(pool, request(discover()))
	if frame == nil {
		t.Fatal("no reply to a DISCOVER")
	}
	ll, ok := to.(*syscall.SockaddrLinklayer)
	if !ok || ll.Ifindex != 7 || ll.Protocol != ipProto || !bytes.Equal(ll.Addr[:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) {
		t.Errorf("sent to %#v", to)
	}
	if !bytes.Equal(frame[12:16], serverIP.AsSlice()) {
		t.Errorf("reply from %v", frame[12:16])
	}
	reply, err := dhcpv4.Parse(frame[28:])
	if err != nil {
		t.Fatal(err)
	}
	if mt, _ := reply.Options.MessageType(); mt != dhcpv4.Offer || !cfg.Subnet.Contains(reply.YIAddr) {
		t.Errorf("reply %v offering %v", mt, reply.YIAddr)
	}
	if _, held := pool.Binding(string(clientHW), s.now()); held {
		t.Error("the pool given holds the offer")
	}
	if ip, held := next.Binding(string(clientHW), s.now()); !held || ip != reply.YIAddr {
		t.Errorf("the next pool holds %v %v, want %v", ip, held, reply.YIAddr)
	}
}

func TestAnswerNotDHCP(t *testing.T) {
	s, pool := newServer(t)
	packet := request(discover())
	packet[22], packet[23] = 0, 53 // to another port
	if next, to, frame := s.answer(pool, packet); next != pool || to != nil || frame != nil {
		t.Errorf("answered %v %v", to, frame)
	}
}

func TestSpecNoInterfaces(t *testing.T) {
	if _, err := Spec(nil); err == nil {
		t.Error("Spec without interfaces succeeded")
	}
}

// An invalid subnet fails the start, before any socket is opened.
func TestStartInvalidSubnet(t *testing.T) {
	bad := cfg
	bad.Subnet = netip.MustParsePrefix("2001:db8::/64")
	bad.ServerIP = netip.MustParseAddr("2001:db8::1")
	spec, err := Spec([]dhcpv4.InterfaceConfig{bad})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := supervisor.Start(t.Context(), proc.NewNode(""), spec); err == nil {
		t.Error("start with an IPv6 subnet succeeded")
	}
}

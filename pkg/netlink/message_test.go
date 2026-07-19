package netlink

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

func TestNlmsgAlign(t *testing.T) {
	cases := []struct{ in, want int }{
		{0, 0}, {1, 4}, {2, 4}, {3, 4}, {4, 4}, {5, 8}, {20, 20}, {21, 24},
	}
	for _, c := range cases {
		if got := nlmsgAlign(c.in); got != c.want {
			t.Errorf("nlmsgAlign(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestBuildAddrMessage(t *testing.T) {
	addr := netip.MustParseAddr("2001:db8:1234:5600::1")
	msg := buildAddrMessage(unix.RTM_NEWADDR, unix.NLM_F_REQUEST|unix.NLM_F_ACK, 42, 7, addr, 64)

	wantLen := uint32(unix.SizeofNlMsghdr + unix.SizeofIfAddrmsg + 2*(unix.SizeofRtAttr+16))
	if got := binary.NativeEndian.Uint32(msg[0:4]); got != wantLen {
		t.Errorf("nlmsghdr.Len = %d, want %d", got, wantLen)
	}
	if got := binary.NativeEndian.Uint16(msg[4:6]); got != unix.RTM_NEWADDR {
		t.Errorf("nlmsghdr.Type = %d, want RTM_NEWADDR", got)
	}
	if got := binary.NativeEndian.Uint16(msg[6:8]); got != unix.NLM_F_REQUEST|unix.NLM_F_ACK {
		t.Errorf("nlmsghdr.Flags = %#x, want %#x", got, unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	}
	if got := binary.NativeEndian.Uint32(msg[8:12]); got != 42 {
		t.Errorf("nlmsghdr.Seq = %d, want 42", got)
	}
	if len(msg) != int(wantLen) {
		t.Fatalf("len(msg) = %d, want %d", len(msg), wantLen)
	}

	ifa := msg[unix.SizeofNlMsghdr:]
	if ifa[0] != unix.AF_INET6 {
		t.Errorf("ifaddrmsg.Family = %d, want AF_INET6", ifa[0])
	}
	if ifa[1] != 64 {
		t.Errorf("ifaddrmsg.Prefixlen = %d, want 64", ifa[1])
	}
	if got := binary.NativeEndian.Uint32(ifa[4:8]); got != 7 {
		t.Errorf("ifaddrmsg.Index = %d, want 7", got)
	}

	attrs := ifa[unix.SizeofIfAddrmsg:]
	for i := range 2 {
		off := i * (unix.SizeofRtAttr + 16)
		attrLen := binary.NativeEndian.Uint16(attrs[off : off+2])
		attrType := binary.NativeEndian.Uint16(attrs[off+2 : off+4])
		if attrLen != unix.SizeofRtAttr+16 {
			t.Errorf("attr %d: Len = %d, want %d", i, attrLen, unix.SizeofRtAttr+16)
		}
		wantType := uint16(unix.IFA_LOCAL)
		if i == 1 {
			wantType = unix.IFA_ADDRESS
		}
		if attrType != wantType {
			t.Errorf("attr %d: Type = %d, want %d", i, attrType, wantType)
		}
		gotAddr, ok := netip.AddrFromSlice(attrs[off+unix.SizeofRtAttr : off+unix.SizeofRtAttr+16])
		if !ok || gotAddr != addr {
			t.Errorf("attr %d: address = %v, want %v", i, gotAddr, addr)
		}
	}
}

func TestBuildGetAddrMessage(t *testing.T) {
	msg := buildGetAddrMessage(9)

	if got := binary.NativeEndian.Uint16(msg[4:6]); got != unix.RTM_GETADDR {
		t.Errorf("nlmsghdr.Type = %d, want RTM_GETADDR", got)
	}
	wantFlags := uint16(unix.NLM_F_REQUEST | unix.NLM_F_DUMP)
	if got := binary.NativeEndian.Uint16(msg[6:8]); got != wantFlags {
		t.Errorf("nlmsghdr.Flags = %#x, want %#x", got, wantFlags)
	}
	ifa := msg[unix.SizeofNlMsghdr:]
	if ifa[0] != unix.AF_INET6 {
		t.Errorf("ifaddrmsg.Family = %d, want AF_INET6", ifa[0])
	}
	if len(msg) != unix.SizeofNlMsghdr+unix.SizeofIfAddrmsg {
		t.Fatalf("len(msg) = %d, want %d", len(msg), unix.SizeofNlMsghdr+unix.SizeofIfAddrmsg)
	}
}

func TestBuildRouteMessage(t *testing.T) {
	dst := netip.MustParsePrefix("2001:db8::1/128")
	msg := buildRouteMessage(unix.RTM_NEWROUTE, unix.NLM_F_REQUEST|unix.NLM_F_ACK, 3, 5, dst)

	if got := binary.NativeEndian.Uint16(msg[4:6]); got != unix.RTM_NEWROUTE {
		t.Errorf("nlmsghdr.Type = %d, want RTM_NEWROUTE", got)
	}

	rt := msg[unix.SizeofNlMsghdr:]
	if rt[0] != unix.AF_INET6 {
		t.Errorf("rtmsg.Family = %d, want AF_INET6", rt[0])
	}
	if rt[1] != 128 {
		t.Errorf("rtmsg.Dst_len = %d, want 128", rt[1])
	}
	if rt[4] != unix.RT_TABLE_MAIN {
		t.Errorf("rtmsg.Table = %d, want RT_TABLE_MAIN", rt[4])
	}
	if rt[6] != unix.RT_SCOPE_LINK {
		t.Errorf("rtmsg.Scope = %d, want RT_SCOPE_LINK", rt[6])
	}
	if rt[7] != unix.RTN_UNICAST {
		t.Errorf("rtmsg.Type = %d, want RTN_UNICAST", rt[7])
	}

	attrs := rt[unix.SizeofRtMsg:]
	dstAttrLen := binary.NativeEndian.Uint16(attrs[0:2])
	dstAttrType := binary.NativeEndian.Uint16(attrs[2:4])
	if dstAttrType != unix.RTA_DST || dstAttrLen != unix.SizeofRtAttr+16 {
		t.Fatalf("first attr = {len %d, type %d}, want {%d, RTA_DST}", dstAttrLen, dstAttrType, unix.SizeofRtAttr+16)
	}
	gotDst, ok := netip.AddrFromSlice(attrs[unix.SizeofRtAttr : unix.SizeofRtAttr+16])
	if !ok || gotDst != dst.Addr() {
		t.Errorf("RTA_DST = %v, want %v", gotDst, dst.Addr())
	}

	oifOff := nlmsgAlign(int(dstAttrLen))
	oifAttrLen := binary.NativeEndian.Uint16(attrs[oifOff : oifOff+2])
	oifAttrType := binary.NativeEndian.Uint16(attrs[oifOff+2 : oifOff+4])
	if oifAttrType != unix.RTA_OIF || oifAttrLen != unix.SizeofRtAttr+4 {
		t.Fatalf("second attr = {len %d, type %d}, want {%d, RTA_OIF}", oifAttrLen, oifAttrType, unix.SizeofRtAttr+4)
	}
	gotOif := binary.NativeEndian.Uint32(attrs[oifOff+unix.SizeofRtAttr : oifOff+unix.SizeofRtAttr+4])
	if gotOif != 5 {
		t.Errorf("RTA_OIF = %d, want 5", gotOif)
	}
}

func TestBuildRouteMessageIPv4Default(t *testing.T) {
	// The IPv4 default route internal/slowpath points at the companion ip6tnl:
	// family AF_INET, Dst_len 0, and NO RTA_DST (only RTA_OIF).
	dst := netip.MustParsePrefix("0.0.0.0/0")
	msg := buildRouteMessage(unix.RTM_NEWROUTE, unix.NLM_F_REQUEST|unix.NLM_F_ACK, 1, 12, dst)

	rt := msg[unix.SizeofNlMsghdr:]
	if rt[0] != unix.AF_INET {
		t.Errorf("rtmsg.Family = %d, want AF_INET", rt[0])
	}
	if rt[1] != 0 {
		t.Errorf("rtmsg.Dst_len = %d, want 0", rt[1])
	}

	attrs := rt[unix.SizeofRtMsg:]
	// The single attribute must be RTA_OIF -- a default route carries no RTA_DST.
	attrType := binary.NativeEndian.Uint16(attrs[2:4])
	attrLen := binary.NativeEndian.Uint16(attrs[0:2])
	if attrType != unix.RTA_OIF || attrLen != unix.SizeofRtAttr+4 {
		t.Fatalf("first attr = {len %d, type %d}, want {%d, RTA_OIF}", attrLen, attrType, unix.SizeofRtAttr+4)
	}
	if got := binary.NativeEndian.Uint32(attrs[unix.SizeofRtAttr : unix.SizeofRtAttr+4]); got != 12 {
		t.Errorf("RTA_OIF = %d, want 12", got)
	}
	// Exactly one attribute: rtmsg header + one RTA_OIF, nothing more.
	if len(attrs) != nlmsgAlign(int(attrLen)) {
		t.Errorf("route body has %d trailing attr bytes, want just RTA_OIF (%d)", len(attrs), nlmsgAlign(int(attrLen)))
	}
}

func TestBuildAddIP6TnlMessage(t *testing.T) {
	local := netip.MustParseAddr("fd00:1::2")
	remote := netip.MustParseAddr("fd00:2::2")
	flags := uint16(unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_EXCL)
	msg := buildAddIP6TnlMessage(7, flags, "mm-dslite0", local, remote, 1460)

	if got := binary.NativeEndian.Uint16(msg[4:6]); got != unix.RTM_NEWLINK {
		t.Errorf("nlmsghdr.Type = %d, want RTM_NEWLINK", got)
	}
	if got := binary.NativeEndian.Uint16(msg[6:8]); got != flags {
		t.Errorf("nlmsghdr.Flags = %#x, want %#x", got, flags)
	}
	if got := binary.NativeEndian.Uint32(msg[0:4]); int(got) != len(msg) {
		t.Errorf("nlmsghdr.Len = %d, want %d", got, len(msg))
	}

	ifi := msg[unix.SizeofNlMsghdr:]
	if ifi[0] != unix.AF_UNSPEC {
		t.Errorf("ifinfomsg.Family = %d, want AF_UNSPEC", ifi[0])
	}
	if got := binary.NativeEndian.Uint32(ifi[4:8]); got != 0 {
		t.Errorf("ifinfomsg.Index = %d, want 0 (kernel assigns on create)", got)
	}

	attrs := map[uint16][]byte{}
	walkAttrs(t, ifi[unix.SizeofIfInfomsg:], attrs)

	if name := attrs[unix.IFLA_IFNAME]; string(name) != "mm-dslite0\x00" {
		t.Errorf("IFLA_IFNAME = %q, want %q", name, "mm-dslite0\x00")
	}
	if mtu := attrs[unix.IFLA_MTU]; len(mtu) != 4 || binary.NativeEndian.Uint32(mtu) != 1460 {
		t.Errorf("IFLA_MTU = %v, want 1460", mtu)
	}

	linfo, ok := attrs[unix.IFLA_LINKINFO]
	if !ok {
		t.Fatal("IFLA_LINKINFO absent")
	}
	info := map[uint16][]byte{}
	walkAttrs(t, linfo, info)
	if kind := info[unix.IFLA_INFO_KIND]; string(kind) != "ip6tnl\x00" {
		t.Errorf("IFLA_INFO_KIND = %q, want %q", kind, "ip6tnl\x00")
	}

	data, ok := info[unix.IFLA_INFO_DATA]
	if !ok {
		t.Fatal("IFLA_INFO_DATA absent")
	}
	tun := map[uint16][]byte{}
	walkAttrs(t, data, tun)

	wantLocal := local.As16()
	if got := tun[iflaIPTunLocal]; !slices.Equal(got, wantLocal[:]) {
		t.Errorf("IFLA_IPTUN_LOCAL = %v, want %v", got, wantLocal)
	}
	wantRemote := remote.As16()
	if got := tun[iflaIPTunRemote]; !slices.Equal(got, wantRemote[:]) {
		t.Errorf("IFLA_IPTUN_REMOTE = %v, want %v", got, wantRemote)
	}
	if got := tun[iflaIPTunProto]; len(got) != 1 || got[0] != unix.IPPROTO_IPIP {
		t.Errorf("IFLA_IPTUN_PROTO = %v, want [%d]", got, unix.IPPROTO_IPIP)
	}
	if got := tun[iflaIPTunFlags]; len(got) != 4 || binary.NativeEndian.Uint32(got) != ip6TnlIgnEncapLimit {
		t.Errorf("IFLA_IPTUN_FLAGS = %v, want IGN_ENCAP_LIMIT (%#x)", got, ip6TnlIgnEncapLimit)
	}
}

func TestBuildChangeIP6TnlMessage(t *testing.T) {
	local := netip.MustParseAddr("fd00:1::9")
	remote := netip.MustParseAddr("fd00:2::2")
	msg := buildChangeIP6TnlMessage(4, 21, local, remote)

	if got := binary.NativeEndian.Uint16(msg[4:6]); got != unix.RTM_NEWLINK {
		t.Errorf("nlmsghdr.Type = %d, want RTM_NEWLINK", got)
	}
	// A changelink must NOT carry NLM_F_CREATE/NLM_F_EXCL: it targets an
	// existing device by index, and must fail rather than create if it's gone.
	flags := binary.NativeEndian.Uint16(msg[6:8])
	if flags&(unix.NLM_F_CREATE|unix.NLM_F_EXCL) != 0 {
		t.Errorf("flags = %#x, must not include NLM_F_CREATE/NLM_F_EXCL", flags)
	}

	ifi := msg[unix.SizeofNlMsghdr:]
	if got := binary.NativeEndian.Uint32(ifi[4:8]); got != 21 {
		t.Errorf("ifinfomsg.Index = %d, want 21", got)
	}
	// No IFLA_IFNAME on a changelink (identified by index), just IFLA_LINKINFO.
	attrs := map[uint16][]byte{}
	walkAttrs(t, ifi[unix.SizeofIfInfomsg:], attrs)
	if _, ok := attrs[unix.IFLA_IFNAME]; ok {
		t.Error("changelink unexpectedly carries IFLA_IFNAME")
	}
	if _, ok := attrs[unix.IFLA_LINKINFO]; !ok {
		t.Error("changelink missing IFLA_LINKINFO")
	}
}

func TestBuildSetLinkUpMessage(t *testing.T) {
	msg := buildSetLinkUpMessage(2, 21)
	if got := binary.NativeEndian.Uint16(msg[4:6]); got != unix.RTM_NEWLINK {
		t.Errorf("nlmsghdr.Type = %d, want RTM_NEWLINK", got)
	}
	ifi := msg[unix.SizeofNlMsghdr:]
	if got := binary.NativeEndian.Uint32(ifi[4:8]); got != 21 {
		t.Errorf("ifinfomsg.Index = %d, want 21", got)
	}
	if got := binary.NativeEndian.Uint32(ifi[8:12]); got&unix.IFF_UP == 0 {
		t.Errorf("ifinfomsg.Flags = %#x, want IFF_UP set", got)
	}
	if got := binary.NativeEndian.Uint32(ifi[12:16]); got&unix.IFF_UP == 0 {
		t.Errorf("ifinfomsg.Change = %#x, want IFF_UP set", got)
	}
}

func TestBuildDelLinkMessage(t *testing.T) {
	msg := buildDelLinkMessage(3, 21)
	if got := binary.NativeEndian.Uint16(msg[4:6]); got != unix.RTM_DELLINK {
		t.Errorf("nlmsghdr.Type = %d, want RTM_DELLINK", got)
	}
	ifi := msg[unix.SizeofNlMsghdr:]
	if got := binary.NativeEndian.Uint32(ifi[4:8]); got != 21 {
		t.Errorf("ifinfomsg.Index = %d, want 21", got)
	}
}

// walkAttrs decodes a run of netlink attributes into out{type: value}, following
// the same TLV+4-byte-alignment layout encodeRtAttr/encodeNestedAttr produce.
func walkAttrs(t *testing.T, buf []byte, out map[uint16][]byte) {
	t.Helper()
	for len(buf) >= unix.SizeofRtAttr {
		attrLen := binary.NativeEndian.Uint16(buf[0:2])
		attrType := binary.NativeEndian.Uint16(buf[2:4])
		if int(attrLen) < unix.SizeofRtAttr || int(attrLen) > len(buf) {
			t.Fatalf("walkAttrs: bad attr length %d (%d remaining)", attrLen, len(buf))
		}
		out[attrType] = buf[unix.SizeofRtAttr:attrLen]
		next := nlmsgAlign(int(attrLen))
		if next > len(buf) {
			break
		}
		buf = buf[next:]
	}
}

func TestBuildGetRouteMessage(t *testing.T) {
	dst := netip.MustParseAddr("2001:db8:aa::1")
	msg := buildGetRouteMessage(9, 4, dst)

	if got := binary.NativeEndian.Uint16(msg[4:6]); got != unix.RTM_GETROUTE {
		t.Errorf("nlmsghdr.Type = %d, want RTM_GETROUTE", got)
	}
	// A route *query* must not carry NLM_F_DUMP: it resolves the one route for
	// dst (running source selection), rather than listing the table.
	flags := binary.NativeEndian.Uint16(msg[6:8])
	if flags&unix.NLM_F_DUMP != 0 {
		t.Errorf("flags = %#x, must not include NLM_F_DUMP", flags)
	}
	if flags&unix.NLM_F_REQUEST == 0 {
		t.Errorf("flags = %#x, want NLM_F_REQUEST set", flags)
	}

	rt := msg[unix.SizeofNlMsghdr:]
	if rt[0] != unix.AF_INET6 {
		t.Errorf("rtmsg.Family = %d, want AF_INET6", rt[0])
	}
	if rt[1] != 128 {
		t.Errorf("rtmsg.Dst_len = %d, want 128 (a full address)", rt[1])
	}

	// RTA_DST then RTA_OIF, same layout the route builder is checked for.
	attrs := rt[unix.SizeofRtMsg:]
	dstAttrLen := binary.NativeEndian.Uint16(attrs[0:2])
	if binary.NativeEndian.Uint16(attrs[2:4]) != unix.RTA_DST {
		t.Fatal("first attr is not RTA_DST")
	}
	gotDst, ok := netip.AddrFromSlice(attrs[unix.SizeofRtAttr : unix.SizeofRtAttr+16])
	if !ok || gotDst != dst {
		t.Errorf("RTA_DST = %v, want %v", gotDst, dst)
	}
	oifOff := nlmsgAlign(int(dstAttrLen))
	if binary.NativeEndian.Uint16(attrs[oifOff+2:oifOff+4]) != unix.RTA_OIF {
		t.Fatal("second attr is not RTA_OIF")
	}
	if got := binary.NativeEndian.Uint32(attrs[oifOff+unix.SizeofRtAttr : oifOff+unix.SizeofRtAttr+4]); got != 4 {
		t.Errorf("RTA_OIF = %d, want 4", got)
	}
}

func TestParseRoutePrefsrc(t *testing.T) {
	prefsrc := netip.MustParseAddr("2001:db8:aa::10")

	// A synthetic RTM_NEWROUTE payload (rtmsg header + RTA_DST then RTA_PREFSRC),
	// which is the shape the kernel returns for a route-get. PREFSRC deliberately
	// isn't the first attribute, to check the walk finds it.
	dstAddr := netip.MustParseAddr("2001:db8:aa::1").As16()
	srcAddr := prefsrc.As16()
	payload := make([]byte, unix.SizeofRtMsg)
	payload[0] = unix.AF_INET6
	payload = append(payload, encodeRtAttr(unix.RTA_DST, dstAddr[:])...)
	payload = append(payload, encodeRtAttr(unix.RTA_PREFSRC, srcAddr[:])...)

	got, ok := parseRoutePrefsrc(payload)
	if !ok {
		t.Fatal("parseRoutePrefsrc returned ok=false for a reply carrying RTA_PREFSRC")
	}
	if got != prefsrc {
		t.Errorf("prefsrc = %v, want %v", got, prefsrc)
	}
}

func TestParseRoutePrefsrcAbsent(t *testing.T) {
	// An unreachable destination resolves to a route with no source: RTA_PREFSRC
	// is absent, so the caller must be told to retry rather than get a zero addr.
	dstAddr := netip.MustParseAddr("2001:db8:aa::1").As16()
	payload := make([]byte, unix.SizeofRtMsg)
	payload[0] = unix.AF_INET6
	payload = append(payload, encodeRtAttr(unix.RTA_DST, dstAddr[:])...)

	if _, ok := parseRoutePrefsrc(payload); ok {
		t.Error("parseRoutePrefsrc returned ok=true with no RTA_PREFSRC")
	}
}

func TestParseRoutePrefsrcWrongFamily(t *testing.T) {
	payload := make([]byte, unix.SizeofRtMsg)
	payload[0] = unix.AF_INET // not AF_INET6
	src := netip.MustParseAddr("192.0.2.1").As4()
	payload = append(payload, encodeRtAttr(unix.RTA_PREFSRC, src[:])...)

	if _, ok := parseRoutePrefsrc(payload); ok {
		t.Error("parseRoutePrefsrc accepted a non-AF_INET6 reply")
	}
}

func buildAckMessage(t *testing.T, seq uint32, errno int32) []byte {
	t.Helper()
	buf := make([]byte, unix.SizeofNlMsghdr+unix.SizeofNlMsgerr)
	binary.NativeEndian.PutUint32(buf[0:4], uint32(len(buf)))
	binary.NativeEndian.PutUint16(buf[4:6], unix.NLMSG_ERROR)
	binary.NativeEndian.PutUint32(buf[8:12], seq)
	binary.NativeEndian.PutUint32(buf[unix.SizeofNlMsghdr:], uint32(errno))
	return buf
}

func TestParseAckErrnoSuccess(t *testing.T) {
	ack := buildAckMessage(t, 5, 0)
	if err := parseAckErrno(ack, 5); err != nil {
		t.Fatalf("parseAckErrno: %v", err)
	}
}

func TestParseAckErrnoFailure(t *testing.T) {
	ack := buildAckMessage(t, 5, -int32(unix.EEXIST))
	if err := parseAckErrno(ack, 5); err == nil {
		t.Fatal("expected error for non-zero errno, got nil")
	}
}

func TestParseAckErrnoWrongSeq(t *testing.T) {
	ack := buildAckMessage(t, 5, 0)
	if err := parseAckErrno(ack, 6); err == nil {
		t.Fatal("expected error for mismatched sequence, got nil")
	}
}

func TestParseAckErrnoTooShort(t *testing.T) {
	if err := parseAckErrno([]byte{0, 1, 2}, 0); err == nil {
		t.Fatal("expected error for too-short ack, got nil")
	}
}

func TestWalkMessagesSingle(t *testing.T) {
	msg := buildAddrMessage(unix.RTM_NEWADDR, unix.NLM_F_REQUEST, 1, 2, netip.MustParseAddr("2001:db8::1"), 64)
	msgs, err := walkMessages(msg)
	if err != nil {
		t.Fatalf("walkMessages: %v", err)
	}
	if len(msgs) != 1 || msgs[0].Type != unix.RTM_NEWADDR {
		t.Fatalf("msgs = %+v, want one RTM_NEWADDR", msgs)
	}
}

func TestWalkMessagesMultiplePacked(t *testing.T) {
	m1 := buildAddrMessage(unix.RTM_NEWADDR, unix.NLM_F_REQUEST, 1, 2, netip.MustParseAddr("2001:db8::1"), 64)
	m2 := buildAckMessage(t, 1, 0)
	buf := slices.Concat(m1, m2)

	msgs, err := walkMessages(buf)
	if err != nil {
		t.Fatalf("walkMessages: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("len(msgs) = %d, want 2", len(msgs))
	}
	if msgs[0].Type != unix.RTM_NEWADDR || msgs[1].Type != unix.NLMSG_ERROR {
		t.Fatalf("msgs types = [%d, %d], want [RTM_NEWADDR, NLMSG_ERROR]", msgs[0].Type, msgs[1].Type)
	}
}

func TestWalkMessagesMalformedLength(t *testing.T) {
	buf := make([]byte, unix.SizeofNlMsghdr)
	binary.NativeEndian.PutUint32(buf[0:4], 0xffff) // claims far more than available
	if _, err := walkMessages(buf); err == nil {
		t.Fatal("expected error for a length exceeding the buffer, got nil")
	}
}

func TestParseIfAddrMsg(t *testing.T) {
	addr := netip.MustParseAddr("2001:db8:1234:5678::abcd")
	full := buildAddrMessage(unix.RTM_NEWADDR, unix.NLM_F_REQUEST, 1, 9, addr, 64)
	payload := full[unix.SizeofNlMsghdr:]

	t.Run("matching ifindex, global scope", func(t *testing.T) {
		got, ok := parseIfAddrMsg(payload, 9)
		if !ok {
			t.Fatal("parseIfAddrMsg: ok = false, want true")
		}
		want := netip.PrefixFrom(addr, 64)
		if got != want {
			t.Errorf("parseIfAddrMsg = %v, want %v", got, want)
		}
	})

	t.Run("wrong ifindex", func(t *testing.T) {
		if _, ok := parseIfAddrMsg(payload, 42); ok {
			t.Fatal("parseIfAddrMsg with mismatched ifindex: ok = true, want false")
		}
	})

	t.Run("link-local scope excluded", func(t *testing.T) {
		linkLocalPayload := slices.Clone(payload)
		linkLocalPayload[3] = unix.RT_SCOPE_LINK
		if _, ok := parseIfAddrMsg(linkLocalPayload, 9); ok {
			t.Fatal("parseIfAddrMsg with RT_SCOPE_LINK: ok = true, want false")
		}
	})

	t.Run("too short", func(t *testing.T) {
		if _, ok := parseIfAddrMsg([]byte{0, 1, 2}, 9); ok {
			t.Fatal("parseIfAddrMsg with truncated payload: ok = true, want false")
		}
	})
}

func TestIsNoRouteErrno(t *testing.T) {
	// parseAckErrno wraps the kernel errno with %w, so test through that shape
	// (not just the bare errno) to prove errors.Is unwraps it.
	wrap := func(e error) error { return fmt.Errorf("netlink: error: %w", e) }

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"ENETUNREACH is no-route", wrap(unix.ENETUNREACH), true},
		{"EHOSTUNREACH is no-route", wrap(unix.EHOSTUNREACH), true},
		{"ENETDOWN is no-route", wrap(unix.ENETDOWN), true},
		// A malformed-request / unexpected errno must NOT be treated as
		// "no route yet" -- it has to surface instead of looping forever.
		{"EINVAL is not no-route", wrap(unix.EINVAL), false},
		{"EPERM is not no-route", wrap(unix.EPERM), false},
		{"non-errno error is not no-route", fmt.Errorf("netlink: ack too short"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNoRouteErrno(tt.err); got != tt.want {
				t.Errorf("isNoRouteErrno(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

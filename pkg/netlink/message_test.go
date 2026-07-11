package netlink

import (
	"encoding/binary"
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

package lanprefix

import (
	"encoding/binary"
	"net/netip"
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

	// nlmsghdr
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

	// ifaddrmsg
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

	// IFA_LOCAL / IFA_ADDRESS attrs
	attrs := ifa[unix.SizeofIfAddrmsg:]
	for i := 0; i < 2; i++ {
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

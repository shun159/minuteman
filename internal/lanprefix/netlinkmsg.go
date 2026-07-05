package lanprefix

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

// nlmsgAlign rounds n up to the next multiple of NLMSG_ALIGNTO (4 bytes),
// the padding every netlink message and attribute is aligned to.
func nlmsgAlign(n int) int {
	const alignTo = unix.NLMSG_ALIGNTO
	return (n + alignTo - 1) &^ (alignTo - 1)
}

// encodeRtAttr encodes a single netlink route attribute (RTM_NEWADDR/
// RTM_DELADDR's IFA_* attributes are all plain TLVs in this format):
// a 4-byte unix.RtAttr header (length, type) followed by payload, padded up
// to a 4-byte boundary.
func encodeRtAttr(attrType uint16, payload []byte) []byte {
	rtaLen := unix.SizeofRtAttr + len(payload)
	buf := make([]byte, nlmsgAlign(rtaLen))
	binary.NativeEndian.PutUint16(buf[0:2], uint16(rtaLen))
	binary.NativeEndian.PutUint16(buf[2:4], attrType)
	copy(buf[unix.SizeofRtAttr:], payload)
	return buf
}

// buildAddrMessage builds a complete RTM_NEWADDR/RTM_DELADDR netlink
// request (RFC-less, but see rtnetlink(7)): an nlmsghdr, an ifaddrmsg, and
// IFA_LOCAL/IFA_ADDRESS attributes both set to addr -- matching what `ip
// addr add`/`ip addr del` sends for a non-point-to-point link, which is
// what every interface in this rig is.
func buildAddrMessage(rtmType uint16, flags uint16, seq uint32, ifindex int, addr netip.Addr, prefixLen int) []byte {
	addr16 := addr.As16()
	ifaAddr := encodeRtAttr(unix.IFA_ADDRESS, addr16[:])
	ifaLocal := encodeRtAttr(unix.IFA_LOCAL, addr16[:])

	ifa := unix.IfAddrmsg{
		Family:    unix.AF_INET6,
		Prefixlen: uint8(prefixLen),
		Index:     uint32(ifindex),
	}

	body := make([]byte, 0, unix.SizeofIfAddrmsg+len(ifaLocal)+len(ifaAddr))
	body = append(body, ifa.Family, ifa.Prefixlen, ifa.Flags, ifa.Scope)
	body = binary.NativeEndian.AppendUint32(body, ifa.Index)
	body = append(body, ifaLocal...)
	body = append(body, ifaAddr...)

	hdr := unix.NlMsghdr{
		Len:   uint32(unix.SizeofNlMsghdr + len(body)),
		Type:  rtmType,
		Flags: flags,
		Seq:   seq,
	}

	var buf bytes.Buffer
	buf.Grow(int(hdr.Len))
	binary.Write(&buf, binary.NativeEndian, &hdr)
	buf.Write(body)
	return buf.Bytes()
}

// parseAckErrno parses a netlink response as an NLMSG_ERROR (rtnetlink(7)'s
// ack format: the kernel acks every NLM_F_ACK request, successful or not,
// with an NLMSG_ERROR carrying errno 0 for success). Returns an error if b
// isn't a well-formed NLMSG_ERROR for wantSeq, or if the kernel reported a
// non-zero errno.
func parseAckErrno(b []byte, wantSeq uint32) error {
	if len(b) < unix.SizeofNlMsghdr+unix.SizeofNlMsgerr {
		return fmt.Errorf("lanprefix: netlink ack too short (%d bytes)", len(b))
	}

	var hdr unix.NlMsghdr
	hdr.Len = binary.NativeEndian.Uint32(b[0:4])
	hdr.Type = binary.NativeEndian.Uint16(b[4:6])
	hdr.Seq = binary.NativeEndian.Uint32(b[8:12])

	if hdr.Type != unix.NLMSG_ERROR {
		return fmt.Errorf("lanprefix: netlink response type %d, want NLMSG_ERROR", hdr.Type)
	}
	if hdr.Seq != wantSeq {
		return fmt.Errorf("lanprefix: netlink ack sequence %d, want %d", hdr.Seq, wantSeq)
	}

	errnoOff := unix.SizeofNlMsghdr
	errno := int32(binary.NativeEndian.Uint32(b[errnoOff : errnoOff+4]))
	if errno == 0 {
		return nil
	}
	return fmt.Errorf("lanprefix: netlink error: %w", syscall.Errno(-errno))
}

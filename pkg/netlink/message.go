package netlink

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

// encodeRtAttr encodes a single netlink route attribute (every RTM_*
// family's attributes are plain TLVs in this format): a 4-byte
// unix.RtAttr header (length, type) followed by payload, padded up to a
// 4-byte boundary.
func encodeRtAttr(attrType uint16, payload []byte) []byte {
	rtaLen := unix.SizeofRtAttr + len(payload)
	buf := make([]byte, nlmsgAlign(rtaLen))
	binary.NativeEndian.PutUint16(buf[0:2], uint16(rtaLen))
	binary.NativeEndian.PutUint16(buf[2:4], attrType)
	copy(buf[unix.SizeofRtAttr:], payload)
	return buf
}

// encodeNestedAttr encodes a container attribute (e.g. IFLA_LINKINFO) whose
// payload is itself a run of already-encoded child attributes. Because
// encodeRtAttr pads every attribute to a 4-byte boundary, the children can be
// concatenated as-is and the result stays aligned -- so this is just
// encodeRtAttr over the joined children.
func encodeNestedAttr(attrType uint16, children ...[]byte) []byte {
	var payload []byte
	for _, c := range children {
		payload = append(payload, c...)
	}
	return encodeRtAttr(attrType, payload)
}

// buildAddrMessage builds a complete RTM_NEWADDR/RTM_DELADDR netlink
// request (see rtnetlink(7)): an nlmsghdr, an ifaddrmsg, and IFA_LOCAL/
// IFA_ADDRESS attributes both set to addr -- matching what `ip addr add`/
// `ip addr del` sends for a non-point-to-point link, which is what every
// interface this package is used against is.
func buildAddrMessage(rtmType uint16, flags uint16, seq uint32, ifindex int, addr netip.Addr, prefixLen int) []byte {
	addr16 := addr.As16()
	ifaAddr := encodeRtAttr(unix.IFA_ADDRESS, addr16[:])
	ifaLocal := encodeRtAttr(unix.IFA_LOCAL, addr16[:])

	body := make([]byte, 0, unix.SizeofIfAddrmsg+len(ifaLocal)+len(ifaAddr))
	body = append(body, unix.AF_INET6, uint8(prefixLen), 0, 0)
	body = binary.NativeEndian.AppendUint32(body, uint32(ifindex))
	body = append(body, ifaLocal...)
	body = append(body, ifaAddr...)

	return buildMessage(rtmType, flags, seq, body)
}

// buildGetAddrMessage builds an RTM_GETADDR dump request for every AF_INET6
// address on the system -- the kernel dump doesn't reliably filter by
// ifindex in the request itself across kernel versions, so Addrs filters
// the results client-side instead (see parseIfAddrMsg).
func buildGetAddrMessage(seq uint32) []byte {
	body := make([]byte, unix.SizeofIfAddrmsg)
	body[0] = unix.AF_INET6
	return buildMessage(unix.RTM_GETADDR, unix.NLM_F_REQUEST|unix.NLM_F_DUMP, seq, body)
}

// buildRouteMessage builds a complete RTM_NEWROUTE/RTM_DELROUTE netlink
// request for a route to dst out ifindex, with no gateway (RTA_OIF only):
// scope RT_SCOPE_LINK and no RTA_GATEWAY, matching what `ip route add
// <dst> dev <iface>` sends for a directly-attached destination. The address
// family follows dst: an IPv4 prefix (Is4) is emitted as AF_INET with a
// 4-byte RTA_DST, everything else as AF_INET6 with a 16-byte one -- so the
// same builder serves both the IPv6 /128 host routes internal/wanextend
// installs and the IPv4 default route internal/slowpath points at the
// companion ip6tnl. A default route (Bits == 0) carries no RTA_DST at all:
// Dst_len 0 already means "all destinations", and omitting the attribute is
// what `ip route add default dev <iface>` sends.
func buildRouteMessage(rtmType uint16, flags uint16, seq uint32, ifindex int, dst netip.Prefix) []byte {
	family := uint8(unix.AF_INET6)
	dstBytes := func() []byte { a := dst.Addr().As16(); return a[:] }()
	if dst.Addr().Is4() {
		family = unix.AF_INET
		a := dst.Addr().As4()
		dstBytes = a[:]
	}

	oif := make([]byte, 4)
	binary.NativeEndian.PutUint32(oif, uint32(ifindex))
	rtaOif := encodeRtAttr(unix.RTA_OIF, oif)

	body := make([]byte, 0, unix.SizeofRtMsg+unix.SizeofRtAttr+len(dstBytes)+len(rtaOif))
	body = append(body,
		family,             // Family
		uint8(dst.Bits()),  // Dst_len
		0,                  // Src_len
		0,                  // Tos
		unix.RT_TABLE_MAIN, // Table
		unix.RTPROT_STATIC, // Protocol
		unix.RT_SCOPE_LINK, // Scope
		unix.RTN_UNICAST,   // Type
	)
	body = binary.NativeEndian.AppendUint32(body, 0) // Flags
	if dst.Bits() > 0 {
		body = append(body, encodeRtAttr(unix.RTA_DST, dstBytes)...)
	}
	body = append(body, rtaOif...)

	return buildMessage(rtmType, flags, seq, body)
}

// buildGetRouteMessage builds an RTM_GETROUTE request asking the kernel which
// route -- and, crucially, which source address -- it would use to reach dst
// out ifindex. This is the `ip route get <dst> oif <ifindex>` query: a single
// route resolution (no NLM_F_DUMP), so the kernel runs its full RFC 6724
// source-address selection and returns the chosen preferred source in
// RTA_PREFSRC. RTA_OIF constrains the lookup to the WAN interface so the answer
// is the source the softwire's own ip6tnl would pick toward the AFTR.
func buildGetRouteMessage(seq uint32, ifindex int, dst netip.Addr) []byte {
	dstAddr := dst.As16()
	rtaDst := encodeRtAttr(unix.RTA_DST, dstAddr[:])

	oif := make([]byte, 4)
	binary.NativeEndian.PutUint32(oif, uint32(ifindex))
	rtaOif := encodeRtAttr(unix.RTA_OIF, oif)

	body := make([]byte, 0, unix.SizeofRtMsg+len(rtaDst)+len(rtaOif))
	body = append(body,
		unix.AF_INET6, // Family
		128,           // Dst_len: a full address, not a prefix
		0,             // Src_len
		0,             // Tos
		0,             // Table (unset: the kernel resolves as for a real send)
		0,             // Protocol
		0,             // Scope (RT_SCOPE_UNIVERSE)
		unix.RTN_UNICAST,
	)
	body = binary.NativeEndian.AppendUint32(body, 0) // Flags
	body = append(body, rtaDst...)
	body = append(body, rtaOif...)

	return buildMessage(unix.RTM_GETROUTE, unix.NLM_F_REQUEST, seq, body)
}

// ip6tnl (RFC 6333 companion softwire device) rtnetlink attribute codes and
// flag, from <linux/if_tunnel.h>/<linux/ip6_tunnel.h>. golang.org/x/sys/unix
// doesn't export the IFLA_IPTUN_* enum, so -- as pkg/routeradvert vendors
// ICMP6_FILTER and bpf/uapi vendors the datapath's UAPI macros -- they're
// defined here.
const (
	iflaIPTunLocal  = 2 // IPv6 source (the B4 address)
	iflaIPTunRemote = 3 // IPv6 destination (the AFTR address)
	iflaIPTunFlags  = 8 // __u32 IP6_TNL_F_* flags
	iflaIPTunProto  = 9 // __u8 encapsulated L4 proto: IPPROTO_IPIP => "ipip6"

	// ip6TnlIgnEncapLimit is IP6_TNL_F_IGN_ENCAP_LIMIT: don't prepend an
	// RFC 2473 Tunnel-Encapsulation-Limit destination-options header. This is
	// `encaplimit none`, and it's mandatory here for the same reason the AFTR
	// simulator sets it (see test/netns/setup.sh): minuteman's XDP decap
	// expects the inner IPv4 immediately after the outer IPv6 header
	// (nexthdr == IPPROTO_IPIP), with no intervening extension header.
	ip6TnlIgnEncapLimit = 0x1
)

// buildIfInfoBody builds a 16-byte ifinfomsg with the given index/flags/change,
// the common header of every RTM_*LINK message this package builds.
func buildIfInfoBody(ifindex int, flags, change uint32) []byte {
	body := make([]byte, unix.SizeofIfInfomsg)
	body[0] = unix.AF_UNSPEC
	binary.NativeEndian.PutUint32(body[4:8], uint32(ifindex)) // Index
	binary.NativeEndian.PutUint32(body[8:12], flags)          // Flags
	binary.NativeEndian.PutUint32(body[12:16], change)        // Change
	return body
}

// buildIP6TnlLinkInfo builds the IFLA_LINKINFO attribute for an ip6tnl in
// ipip6 (IPv4-in-IPv6) mode with the given softwire endpoints:
// {IFLA_INFO_KIND="ip6tnl", IFLA_INFO_DATA{LOCAL, REMOTE, PROTO=IPPROTO_IPIP,
// FLAGS=IGN_ENCAP_LIMIT}}. Shared by create and change (changelink) requests.
func buildIP6TnlLinkInfo(local, remote netip.Addr) []byte {
	l := local.As16()
	r := remote.As16()

	flagsBuf := make([]byte, 4)
	binary.NativeEndian.PutUint32(flagsBuf, ip6TnlIgnEncapLimit)

	data := encodeNestedAttr(unix.IFLA_INFO_DATA,
		encodeRtAttr(iflaIPTunLocal, l[:]),
		encodeRtAttr(iflaIPTunRemote, r[:]),
		encodeRtAttr(iflaIPTunProto, []byte{unix.IPPROTO_IPIP}),
		encodeRtAttr(iflaIPTunFlags, flagsBuf),
	)
	kind := encodeRtAttr(unix.IFLA_INFO_KIND, []byte("ip6tnl\x00"))
	return encodeNestedAttr(unix.IFLA_LINKINFO, kind, data)
}

// buildAddIP6TnlMessage builds an RTM_NEWLINK request creating an ip6tnl named
// name with the given endpoints and MTU -- the rtnetlink equivalent of
// `ip link add name <name> type ip6tnl mode ipip6 local <local> remote
// <remote> encaplimit none mtu <mtu>`. The caller supplies NLM_F_CREATE|
// NLM_F_EXCL in flags.
func buildAddIP6TnlMessage(seq uint32, flags uint16, name string, local, remote netip.Addr, mtu int) []byte {
	mtuBuf := make([]byte, 4)
	binary.NativeEndian.PutUint32(mtuBuf, uint32(mtu))

	body := buildIfInfoBody(0, 0, 0)
	body = append(body, encodeRtAttr(unix.IFLA_IFNAME, []byte(name+"\x00"))...)
	body = append(body, encodeRtAttr(unix.IFLA_MTU, mtuBuf)...)
	body = append(body, buildIP6TnlLinkInfo(local, remote)...)
	return buildMessage(unix.RTM_NEWLINK, flags, seq, body)
}

// buildChangeIP6TnlMessage builds an RTM_NEWLINK request (changelink, no
// NLM_F_CREATE) repointing an existing ip6tnl identified by ifindex at new
// softwire endpoints -- so a WAN renumbering or AFTR migration updates the
// companion device in place, keeping the IPv4 default route that points at it.
func buildChangeIP6TnlMessage(seq uint32, ifindex int, local, remote netip.Addr) []byte {
	body := buildIfInfoBody(ifindex, 0, 0)
	body = append(body, buildIP6TnlLinkInfo(local, remote)...)
	return buildMessage(unix.RTM_NEWLINK, unix.NLM_F_REQUEST|unix.NLM_F_ACK, seq, body)
}

// buildSetLinkUpMessage builds an RTM_NEWLINK request setting ifindex IFF_UP.
func buildSetLinkUpMessage(seq uint32, ifindex int) []byte {
	body := buildIfInfoBody(ifindex, unix.IFF_UP, unix.IFF_UP)
	return buildMessage(unix.RTM_NEWLINK, unix.NLM_F_REQUEST|unix.NLM_F_ACK, seq, body)
}

// buildDelLinkMessage builds an RTM_DELLINK request deleting ifindex.
func buildDelLinkMessage(seq uint32, ifindex int) []byte {
	body := buildIfInfoBody(ifindex, 0, 0)
	return buildMessage(unix.RTM_DELLINK, unix.NLM_F_REQUEST|unix.NLM_F_ACK, seq, body)
}

// parseRoutePrefsrc parses an RTM_GETROUTE reply (rtmsg, header stripped) and
// returns its RTA_PREFSRC -- the source address the kernel would use for the
// queried destination. ok is false for a non-AF_INET6 reply or one without an
// RTA_PREFSRC (e.g. the destination is unreachable, or resolves to a route with
// no usable source on the constrained interface -- which at startup means the
// WAN's default route hasn't been (re)learned yet, so the caller retries).
func parseRoutePrefsrc(payload []byte) (netip.Addr, bool) {
	if len(payload) < unix.SizeofRtMsg {
		return netip.Addr{}, false
	}
	if payload[0] != unix.AF_INET6 {
		return netip.Addr{}, false
	}

	attrs := payload[unix.SizeofRtMsg:]
	for len(attrs) >= unix.SizeofRtAttr {
		attrLen := binary.NativeEndian.Uint16(attrs[0:2])
		attrType := binary.NativeEndian.Uint16(attrs[2:4])
		if int(attrLen) < unix.SizeofRtAttr || int(attrLen) > len(attrs) {
			break
		}
		if attrType == unix.RTA_PREFSRC {
			if addr, ok := netip.AddrFromSlice(attrs[unix.SizeofRtAttr:attrLen]); ok {
				return addr, true
			}
		}
		next := nlmsgAlign(int(attrLen))
		if next > len(attrs) {
			break
		}
		attrs = attrs[next:]
	}
	return netip.Addr{}, false
}

// buildMessage prepends an nlmsghdr to body.
func buildMessage(rtmType uint16, flags uint16, seq uint32, body []byte) []byte {
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

// rawMsg is one netlink message split out of a Recvfrom buffer, header
// included (Raw) so parseAckErrno can keep validating the header itself.
type rawMsg struct {
	Type uint16
	Raw  []byte
}

// walkMessages splits buf -- as returned by one Recvfrom call, which may
// pack several netlink messages together (e.g. a dump response) -- into
// individual rawMsgs.
func walkMessages(buf []byte) ([]rawMsg, error) {
	var msgs []rawMsg
	for len(buf) > 0 {
		if len(buf) < unix.SizeofNlMsghdr {
			return nil, fmt.Errorf("netlink: trailing %d bytes shorter than a message header", len(buf))
		}
		msgLen := binary.NativeEndian.Uint32(buf[0:4])
		msgType := binary.NativeEndian.Uint16(buf[4:6])
		if msgLen < unix.SizeofNlMsghdr || int(msgLen) > len(buf) {
			return nil, fmt.Errorf("netlink: malformed message length %d (%d bytes remaining)", msgLen, len(buf))
		}
		msgs = append(msgs, rawMsg{Type: msgType, Raw: buf[:msgLen]})
		buf = buf[min(nlmsgAlign(int(msgLen)), len(buf)):]
	}
	return msgs, nil
}

// parseIfAddrMsg parses an RTM_NEWADDR payload (ifaddrmsg, header
// stripped) for wantIfindex, returning the prefix built from its
// IFA_ADDRESS attribute (falling back to IFA_LOCAL -- see
// buildAddrMessage's comment on why this package always sets both when
// building its own requests, which a differently-behaved peer might not).
// ok is false for a message that isn't AF_INET6, isn't for wantIfindex,
// isn't global scope (RT_SCOPE_UNIVERSE -- skips link-local/host-scope
// addresses, irrelevant to WAN-prefix discovery), or carries neither
// attribute.
func parseIfAddrMsg(payload []byte, wantIfindex int) (netip.Prefix, bool) {
	if len(payload) < unix.SizeofIfAddrmsg {
		return netip.Prefix{}, false
	}
	family := payload[0]
	prefixLen := payload[1]
	scope := payload[3]
	ifindex := binary.NativeEndian.Uint32(payload[4:8])

	if family != unix.AF_INET6 || int(ifindex) != wantIfindex || scope != unix.RT_SCOPE_UNIVERSE {
		return netip.Prefix{}, false
	}

	var address, local netip.Addr
	attrs := payload[unix.SizeofIfAddrmsg:]
	for len(attrs) >= unix.SizeofRtAttr {
		attrLen := binary.NativeEndian.Uint16(attrs[0:2])
		attrType := binary.NativeEndian.Uint16(attrs[2:4])
		if int(attrLen) < unix.SizeofRtAttr || int(attrLen) > len(attrs) {
			break
		}
		value := attrs[unix.SizeofRtAttr:attrLen]
		switch attrType {
		case unix.IFA_ADDRESS:
			address, _ = netip.AddrFromSlice(value)
		case unix.IFA_LOCAL:
			local, _ = netip.AddrFromSlice(value)
		}

		next := nlmsgAlign(int(attrLen))
		if next > len(attrs) {
			break
		}
		attrs = attrs[next:]
	}

	addr := address
	if !addr.IsValid() {
		addr = local
	}
	if !addr.IsValid() {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, int(prefixLen)), true
}

// parseAckErrno parses a netlink response as an NLMSG_ERROR (rtnetlink(7)'s
// ack format: the kernel acks every NLM_F_ACK request, successful or not,
// with an NLMSG_ERROR carrying errno 0 for success). Returns an error if b
// isn't a well-formed NLMSG_ERROR for wantSeq, or if the kernel reported a
// non-zero errno.
func parseAckErrno(b []byte, wantSeq uint32) error {
	if len(b) < unix.SizeofNlMsghdr+unix.SizeofNlMsgerr {
		return fmt.Errorf("netlink: ack too short (%d bytes)", len(b))
	}

	msgType := binary.NativeEndian.Uint16(b[4:6])
	seq := binary.NativeEndian.Uint32(b[8:12])

	if msgType != unix.NLMSG_ERROR {
		return fmt.Errorf("netlink: response type %d, want NLMSG_ERROR", msgType)
	}
	if seq != wantSeq {
		return fmt.Errorf("netlink: ack sequence %d, want %d", seq, wantSeq)
	}

	errnoOff := unix.SizeofNlMsghdr
	errno := int32(binary.NativeEndian.Uint32(b[errnoOff : errnoOff+4]))
	if errno == 0 {
		return nil
	}
	return fmt.Errorf("netlink: error: %w", syscall.Errno(-errno))
}

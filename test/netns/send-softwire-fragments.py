#!/usr/bin/env python3
# Sends a fragmented DS-Lite softwire packet (RFC 6333) toward minuteman's B4,
# for the MM_SOFTWIRE_FRAG smoketest's decap-reassembly direction.
#
# A real Linux AFTR (the rig's mm-aftr) never emits outer-IPv6 fragments -- with
# its tunnel MTU it fragments the *inner* IPv4 instead -- so there's no natural
# way to exercise minuteman's fragmented-softwire XDP_PASS path (RFC 6333 5.3,
# STAT_DECAP_REASM_PASS) from the rig's own traffic. This crafts one by hand: an
# inner IPv4 ICMP echo request (public host -> LAN client) encapsulated in IPv6
# (AFTR -> B4, next header IPPROTO_IPIP) and split into two IPv6 fragments, sent
# raw from the ISP side to the CPE's WAN MAC. minuteman's decap must XDP_PASS
# both so the kernel reassembles them and the companion ip6tnl decapsulates the
# result, delivering the inner echo to the LAN client (which then replies).
#
# Other modes (see main()) craft the rest of the softwire traffic the rig can't
# produce naturally, including the ICMPv6 errors an intermediate IPv6 router on
# the B4<->AFTR path would send *about* a softwire packet (RFC 2473 §8): those
# quote a packet minuteman itself emitted, so no amount of real rig traffic
# produces one on demand.
#
# Stdlib only (no scapy), matching the rig's no-extra-dependency stance: the
# packet is built byte-for-byte with struct + a manual checksum.
import os
import socket
import struct
import sys

IPPROTO_IPIP = 4       # inner protocol carried by the softwire (RFC 6333)
IPPROTO_FRAGMENT = 44  # IPv6 fragment extension header
IPPROTO_ICMPV6 = 58

ICMPV6_DEST_UNREACH = 1
ICMPV6_PKT_TOOBIG = 2
ICMPV6_TIME_EXCEEDED = 3

IP_DF = 0x4000


def checksum16(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_inner_ipv4(
    src_ip: str, dst_ip: str, payload_len: int, ttl: int = 64, df: bool = False
) -> bytes:
    # ICMP echo request (type 8) with a payload big enough that the whole inner
    # packet spans two IPv6 fragments once encapsulated.
    icmp_id, icmp_seq = 0x4242, 1
    icmp_payload = b"F" * payload_len
    icmp = struct.pack("!BBHHH", 8, 0, 0, icmp_id, icmp_seq) + icmp_payload
    icmp_csum = checksum16(icmp)
    icmp = struct.pack("!BBHHH", 8, 0, icmp_csum, icmp_id, icmp_seq) + icmp_payload

    total_len = 20 + len(icmp)
    ihl_ver = (4 << 4) | 5
    frag_off = IP_DF if df else 0
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        ihl_ver, 0, total_len, 0x1234, frag_off, ttl, 1, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    ip_csum = checksum16(ip)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        ihl_ver, 0, total_len, 0x1234, frag_off, ttl, 1, ip_csum,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    return ip + icmp


def ipv6_header(src: str, dst: str, payload_len: int, next_hdr: int) -> bytes:
    return struct.pack(
        "!IHBB16s16s",
        6 << 28, payload_len, next_hdr, 64,
        socket.inet_pton(socket.AF_INET6, src),
        socket.inet_pton(socket.AF_INET6, dst),
    )


def icmpv6_checksum(src: str, dst: str, msg: bytes) -> int:
    # Unlike ICMPv4's, the ICMPv6 checksum covers the IPv6 pseudo-header
    # (RFC 4443 §2.3), so it can't be computed over the message alone.
    pseudo = (
        socket.inet_pton(socket.AF_INET6, src)
        + socket.inet_pton(socket.AF_INET6, dst)
        + struct.pack("!IBBBB", len(msg), 0, 0, 0, IPPROTO_ICMPV6)
    )
    return checksum16(pseudo + msg)


def build_tunnel_icmpv6(
    router6: str, b4_6: str, quoted_src: str, quoted_dst: str, icmp_type: int,
    code: int, extra: int, inner: bytes,
) -> bytes:
    """An ICMPv6 error *about a softwire packet*, as an intermediate IPv6 router
    on the B4<->AFTR path would send it: addressed to the B4, quoting the outer
    IPv6 header minuteman wrote (B4 -> AFTR, next header IPPROTO_IPIP) plus the
    inner IPv4 packet it carried. `extra` is the 32-bit word after type/code/
    checksum -- the MTU for Packet Too Big, unused (0) otherwise. quoted_src/
    quoted_dst are the quoted softwire's endpoints, separate from the B4 the
    error is addressed to so a deliberately bogus quote can be built too.
    """
    quoted = ipv6_header(quoted_src, quoted_dst, len(inner), IPPROTO_IPIP) + inner
    # RFC 4443: as much of the invoking packet as fits without exceeding the
    # minimum IPv6 MTU. Everything this script quotes is far below that.
    quoted = quoted[: 1280 - 40 - 8]

    msg = struct.pack("!BBHI", icmp_type, code, 0, extra) + quoted
    csum = icmpv6_checksum(router6, b4_6, msg)
    msg = struct.pack("!BBHI", icmp_type, code, csum, extra) + quoted
    return ipv6_header(router6, b4_6, len(msg), IPPROTO_ICMPV6) + msg


def frag_header(next_hdr: int, offset8: int, more: int, ident: int) -> bytes:
    # offset is in 8-byte units; low bit of the 16-bit field is the M flag.
    off_m = (offset8 << 3) | (more & 1)
    return struct.pack("!BBHI", next_hdr, 0, off_m, ident)


def main() -> None:
    dst_mac_s, src_mac_s, iface = sys.argv[1], sys.argv[2], sys.argv[3]
    aftr6 = sys.argv[4] if len(sys.argv) > 4 else "fd00:2::2"
    b4_6 = sys.argv[5] if len(sys.argv) > 5 else "fd00:1::2"
    # Optional 6th arg selects the mode:
    #   (default) "frag"    -> a fragmented softwire to a LAN client (reassembly path)
    #   "martian" <inner-dst> -> a whole softwire packet whose inner IPv4 destination
    #                            is off-LAN, to exercise the decap martian drop (the
    #                            softwire slow path's IPv4 default route must not turn
    #                            the B4 into a reflector -- STAT_DECAP_MARTIAN).
    #   "ttl1" -> a whole softwire packet to a LAN client with inner TTL=1, to
    #             exercise B4-originated ICMPv4 Time Exceeded on the decap path.
    #   "icmp6ptb" [mtu] [df|nodf]     -> ICMPv6 Packet Too Big about a softwire
    #   "icmp6texc" [df|nodf]          -> ICMPv6 Time Exceeded about a softwire
    #   "icmp6unreach" [code] [df|nodf]-> ICMPv6 Destination Unreachable ditto
    #   "icmp6bogus" [mtu]             -> a PtB whose quote is NOT this B4's
    #                                     softwire (spoof check: must be ignored)
    # The icmp6* modes come from an intermediate router (MM_ICMP6_SRC, default
    # the ISP's WAN address), not from the AFTR, and are the RFC 2473 §8 input.
    mode = sys.argv[6] if len(sys.argv) > 6 else "frag"

    dst_mac = bytes.fromhex(dst_mac_s.replace(":", ""))
    src_mac = bytes.fromhex(src_mac_s.replace(":", ""))
    eth = dst_mac + src_mac + struct.pack("!H", 0x86DD)

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((iface, 0))

    if mode in ("martian", "oversized"):
        inner_dst = sys.argv[7] if len(sys.argv) > 7 else "8.8.8.8"
        inner = build_inner_ipv4("203.0.113.2", inner_dst, 1372 if mode == "oversized" else 32, df=mode == "oversized")
        pkt = ipv6_header(aftr6, b4_6, len(inner), IPPROTO_IPIP) + inner
        s.send(eth + pkt)
        s.close()
        print(f"sent 1 softwire packet (inner dst {inner_dst}, off-LAN) to {dst_mac_s} via {iface}")
        return

    if mode == "ttl1":
        inner = build_inner_ipv4("203.0.113.2", "192.168.1.2", 32, ttl=1)
        pkt = ipv6_header(aftr6, b4_6, len(inner), IPPROTO_IPIP) + inner
        s.send(eth + pkt)
        s.close()
        print(f"sent 1 softwire packet (inner TTL=1) to {dst_mac_s} via {iface}")
        return

    if mode.startswith("icmp6"):
        router6 = os.environ.get("MM_ICMP6_SRC", "fd00:1::1")
        args = sys.argv[7:]

        def take_df(rest: list) -> bool:
            return not (rest and rest[0] == "nodf")

        if mode == "icmp6ptb" or mode == "icmp6bogus":
            mtu = int(args[0]) if args else 1400
            df = take_df(args[1:])
            icmp_type, code, extra = ICMPV6_PKT_TOOBIG, 0, mtu
            what = f"Packet Too Big (mtu {mtu})"
        elif mode == "icmp6texc":
            df = take_df(args)
            icmp_type, code, extra = ICMPV6_TIME_EXCEEDED, 0, 0
            what = "Time Exceeded"
        elif mode == "icmp6unreach":
            code = int(args[0]) if args else 0
            df = take_df(args[1:])
            icmp_type, extra = ICMPV6_DEST_UNREACH, 0
            what = f"Destination Unreachable (code {code})"
        else:
            raise SystemExit(f"unknown mode {mode}")

        # The quoted inner IPv4 is an *outbound* packet: LAN client -> public
        # host, i.e. exactly what the B4 encapsulated and what the relayed
        # ICMPv4 error must be addressed back to. It is deliberately big enough
        # that the quote hits build_tunnel_icmpv6's 1280-byte truncation, as a
        # real router's would: with a small quote the *kernel*'s own relay of a
        # Packet Too Big (which runs today, before minuteman handles these) does
        # not fire, so a small quote would make this injector test something no
        # real ICMPv6 error looks like.
        inner = build_inner_ipv4(os.environ.get("MM_QUOTED_SRC", "192.168.1.2"), "203.0.113.2", 1372, df=df)
        quoted_b4, quoted_aftr = b4_6, aftr6
        if mode == "icmp6bogus":
            # Quote a softwire between two addresses that are not this B4's:
            # nothing minuteman sent, so it must not be relayed or believed.
            quoted_b4, quoted_aftr = "2001:db8:dead::1", "2001:db8:dead::2"

        pkt = build_tunnel_icmpv6(
            router6, b4_6, quoted_b4, quoted_aftr, icmp_type, code, extra, inner
        )
        s.send(eth + pkt)
        s.close()
        print(
            f"sent ICMPv6 {what} from {router6} to {b4_6}, quoting a softwire "
            f"{quoted_b4} -> {quoted_aftr} (inner {'DF' if df else 'non-DF'}) "
            f"via {iface}"
        )
        return

    inner = build_inner_ipv4("203.0.113.2", "192.168.1.2", 1200)

    # Split the inner payload at an 8-byte boundary so both fragments are legal.
    split = 1024
    first, second = inner[:split], inner[split:]
    frag_id = 0xABCD

    frag1 = ipv6_header(aftr6, b4_6, 8 + len(first), IPPROTO_FRAGMENT) + \
        frag_header(IPPROTO_IPIP, 0, 1, frag_id) + first
    frag2 = ipv6_header(aftr6, b4_6, 8 + len(second), IPPROTO_FRAGMENT) + \
        frag_header(IPPROTO_IPIP, split // 8, 0, frag_id) + second

    s.send(eth + frag1)
    s.send(eth + frag2)
    s.close()
    print(f"sent 2 IPv6 fragments (inner {len(inner)}B IPv4 ICMP echo) to {dst_mac_s} via {iface}")


if __name__ == "__main__":
    main()

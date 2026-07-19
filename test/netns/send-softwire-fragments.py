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
# Stdlib only (no scapy), matching the rig's no-extra-dependency stance: the
# packet is built byte-for-byte with struct + a manual checksum.
import socket
import struct
import sys

IPPROTO_IPIP = 4       # inner protocol carried by the softwire (RFC 6333)
IPPROTO_FRAGMENT = 44  # IPv6 fragment extension header


def checksum16(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_inner_ipv4(src_ip: str, dst_ip: str, payload_len: int) -> bytes:
    # ICMP echo request (type 8) with a payload big enough that the whole inner
    # packet spans two IPv6 fragments once encapsulated.
    icmp_id, icmp_seq = 0x4242, 1
    icmp_payload = b"F" * payload_len
    icmp = struct.pack("!BBHHH", 8, 0, 0, icmp_id, icmp_seq) + icmp_payload
    icmp_csum = checksum16(icmp)
    icmp = struct.pack("!BBHHH", 8, 0, icmp_csum, icmp_id, icmp_seq) + icmp_payload

    total_len = 20 + len(icmp)
    ihl_ver = (4 << 4) | 5
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        ihl_ver, 0, total_len, 0x1234, 0, 64, 1, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    ip_csum = checksum16(ip)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        ihl_ver, 0, total_len, 0x1234, 0, 64, 1, ip_csum,
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
    mode = sys.argv[6] if len(sys.argv) > 6 else "frag"

    dst_mac = bytes.fromhex(dst_mac_s.replace(":", ""))
    src_mac = bytes.fromhex(src_mac_s.replace(":", ""))
    eth = dst_mac + src_mac + struct.pack("!H", 0x86DD)

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((iface, 0))

    if mode == "martian":
        inner_dst = sys.argv[7] if len(sys.argv) > 7 else "8.8.8.8"
        inner = build_inner_ipv4("203.0.113.2", inner_dst, 32)
        pkt = ipv6_header(aftr6, b4_6, len(inner), IPPROTO_IPIP) + inner
        s.send(eth + pkt)
        s.close()
        print(f"sent 1 softwire packet (inner dst {inner_dst}, off-LAN) to {dst_mac_s} via {iface}")
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

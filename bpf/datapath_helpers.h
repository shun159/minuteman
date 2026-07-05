#ifndef __DP_HELPERS__
#define __DP_HELPERS__

#include "vmlinux.h"
#include "uapi/linux/icmp.h"
#include "uapi/linux/if_ether.h"
#include "uapi/linux/ip.h"

#include <bpf/bpf_endian.h>
#include <sys/cdefs.h>

#ifndef IPPROTO_IPIP
#define IPPROTO_IPIP 4
#endif

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

#define s6_addr in6_u.u6_addr8
#define s6_addr32 in6_u.u6_addr32

#define OUTER_ETH_LEN 14
#define OUTER_IPV6_LEN (sizeof(struct ipv6hdr))
#define OUTER_HDR_LEN (OUTER_ETH_LEN + OUTER_IPV6_LEN)
#define TUNNEL_L3_OVERHEAD OUTER_IPV6_LEN
#define ICMPV4_MIN_MTU 68

struct vlan_hdr_min {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

struct ipv4_quote {
    struct iphdr iph;
    __u8 data[8];
};

#define ICMP_FRAG_QUOTE_LEN sizeof(struct ipv4_quote)

struct icmp_frag_needed {
    __u8 type;
    __u8 code;
    __u16 checksum;
    __u16 unused;
    __u16 next_mtu;
    struct ipv4_quote quote;
};

#define ICMP_FRAG_REPLY_L3_LEN (sizeof(struct iphdr) + sizeof(struct icmp_frag_needed))

static __always_inline __u16
checksum_fold32(__u32 csum)
{
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return (__u16)~csum;
}

static __always_inline __u16
icmp_checksum(const struct icmp_frag_needed *icmp)
{
    __u32 csum = 0;
    const __u16 *p = (const __u16 *)icmp;

#pragma unroll
    for (int i = 0; i < sizeof(*icmp) / 2; i++)
        csum += (__u32)p[i];

    return checksum_fold32(csum);
}

static __always_inline bool
ipv4_has_df(const struct iphdr *iph)
{
    return (iph->frag_off & bpf_htons(IP_DF)) != 0;
}

static __always_inline void
ipv4_checksum(struct iphdr *iph)
{
    iph->check = 0;

    __u32 acc = 0;
    __u16 *ipw = (__u16 *)iph;

#pragma unroll
    for (int i = 0; i < sizeof(struct iphdr) / 2; i++)
        acc += ipw[i];

    iph->check = checksum_fold32(acc);
}

static __always_inline void
decrease_ipv4_ttl(struct iphdr *iph)
{
    __u32 csum;

    csum = (__u32)iph->check + bpf_htons(0x0100);
    csum = (csum & 0xffff) + (csum >> 16);

    iph->check = (__sum16)csum;
    iph->ttl -= 1;
}

static __always_inline bool
ipv6_addr_equal(const struct in6_addr *a, const struct in6_addr *b)
{
    return a->s6_addr32[0] == b->s6_addr32[0] && a->s6_addr32[1] == b->s6_addr32[1] &&
           a->s6_addr32[2] == b->s6_addr32[2] && a->s6_addr32[3] == b->s6_addr32[3];
}

/*
 * Parses an Ethernet (+ up to one 802.1Q/802.1ad tag) + IPv4 header.
 * Returns 1 with l2_len_out/iph_out set on a well-formed IPv4 packet,
 * 0 if the packet should be passed through untouched (not IPv4, or an
 * IPv4 packet we don't handle), -1 if the packet is malformed and should
 * be dropped.
 */
static __always_inline int
parse_l2_ipv4(void *data, void *data_end, __u64 *l2_len_out, struct iphdr **iph_out)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    __u64 off = sizeof(*eth);
    __be16 proto = eth->h_proto;

#pragma clang loop unroll(full)
    for (int i = 0; i < 2; i++) {
        if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD)) {
            struct vlan_hdr_min *vh = data + off;
            if ((void *)(vh + 1) > data_end)
                return -1;
            proto = vh->h_vlan_encapsulated_proto;
            off += sizeof(*vh);
        }
    }

    if (proto != bpf_htons(ETH_P_IP))
        return 0;

    struct iphdr *iph = data + off;
    if ((void *)(iph + 1) > data_end)
        return -1;

    if (iph->version != 4 || iph->ihl != 5)
        return 0;

    __u16 tot_len = bpf_ntohs(iph->tot_len);
    if (tot_len < sizeof(*iph))
        return -1;

    if ((void *)iph + tot_len > data_end)
        return -1;

    *l2_len_out = off;
    *iph_out = iph;
    return 1;
}

/*
 * Parses a plain Ethernet + IPv6 header (no VLAN, no extension headers).
 * Same return convention as parse_l2_ipv4().
 */
static __always_inline int
parse_l2_ipv6(void *data, void *data_end, __u64 *l2_len_out, struct ipv6hdr **iph_out)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return 0;

    struct ipv6hdr *iph = data + sizeof(*eth);
    if ((void *)(iph + 1) > data_end)
        return -1;

    if (iph->version != 6)
        return 0;

    __u16 payload_len = bpf_ntohs(iph->payload_len);
    if ((void *)(iph + 1) + payload_len > data_end)
        return -1;

    *l2_len_out = sizeof(*eth);
    *iph_out = iph;
    return 1;
}

static __always_inline void
write_outer_ipv6(struct ipv6hdr *iph, const struct in6_addr *saddr,
                 const struct in6_addr *daddr, __u16 payload_len)
{
    iph->version = 6;
    iph->priority = 0;
    __builtin_memset(iph->flow_lbl, 0, sizeof(iph->flow_lbl));
    iph->payload_len = bpf_htons(payload_len);
    iph->nexthdr = IPPROTO_IPIP;
    iph->hop_limit = 64;
    iph->saddr = *saddr;
    iph->daddr = *daddr;
}

static __always_inline void
swap_eth_addrs(struct ethhdr *eth)
{
    __u8 old_src[ETH_ALEN];

    __builtin_memcpy(old_src, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, old_src, ETH_ALEN);
}

static __always_inline void
copy_ipv4_quote(struct ipv4_quote *quote, const struct iphdr *iph)
{
    __builtin_memcpy(quote, iph, sizeof(*quote));
}

static __always_inline void
build_icmp_frag_needed(struct icmp_frag_needed *msg, const struct ipv4_quote *quote,
                       __u16 next_mtu)
{
    __builtin_memset(msg, 0, sizeof(*msg));
    msg->type = ICMP_DEST_UNREACH;
    msg->code = ICMP_FRAG_NEEDED;
    msg->unused = 0;
    msg->next_mtu = bpf_htons(next_mtu);
    msg->quote = *quote;
    msg->checksum = 0;
    msg->checksum = icmp_checksum(msg);
}

/*
 * Writes an ICMPv4 "Fragmentation Needed" reply in place of the packet
 * currently at [eth, iph, icmp), addressed back to the quoted packet's
 * source, over a plain (untunneled) Ethernet+IPv4 frame. Used on the LAN
 * side, where no DS-Lite encapsulation is needed to reach the sender.
 */
static __always_inline void
write_plain_icmp_frag_needed(struct ethhdr *eth, struct iphdr *iph,
                             struct icmp_frag_needed *icmp,
                             const struct ipv4_quote *quote, __u32 icmp_src_ip_host_order,
                             __u16 next_mtu)
{
    struct icmp_frag_needed msg = {};

    swap_eth_addrs(eth);
    eth->h_proto = bpf_htons(ETH_P_IP);

    iph->version = 4;
    iph->ihl = 5;
    iph->tos = 0;
    iph->tot_len = bpf_htons((__u16)ICMP_FRAG_REPLY_L3_LEN);
    iph->id = 0;
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_ICMP;
    iph->saddr = bpf_htonl(icmp_src_ip_host_order);
    iph->daddr = quote->iph.saddr;
    ipv4_checksum(iph);

    build_icmp_frag_needed(&msg, quote, next_mtu);
    __builtin_memcpy(icmp, &msg, sizeof(msg));
}

/*
 * Writes an ICMPv4 "Fragmentation Needed" reply that is itself
 * re-encapsulated in a DS-Lite (IPv4-in-IPv6) tunnel frame, addressed back
 * through the AFTR to the original IPv4 sender. Used when the WAN-side path
 * MTU (after DS-Lite encap overhead) is too small for a packet arriving
 * from the LAN.
 */
static __always_inline void
write_dslite_icmp_frag_needed(struct ethhdr *eth, struct ipv6hdr *outer_iph,
                              struct iphdr *icmp_iph, struct icmp_frag_needed *icmp,
                              const struct ipv4_quote *quote,
                              const struct in6_addr *b4_addr,
                              const struct in6_addr *aftr_addr,
                              __u32 icmp_src_ip_host_order, __u16 next_mtu)
{
    struct icmp_frag_needed msg = {};

    swap_eth_addrs(eth);
    eth->h_proto = bpf_htons(ETH_P_IPV6);

    write_outer_ipv6(outer_iph, b4_addr, aftr_addr, (__u16)ICMP_FRAG_REPLY_L3_LEN);

    icmp_iph->version = 4;
    icmp_iph->ihl = 5;
    icmp_iph->tos = 0;
    icmp_iph->tot_len = bpf_htons((__u16)ICMP_FRAG_REPLY_L3_LEN);
    icmp_iph->id = 0;
    icmp_iph->frag_off = 0;
    icmp_iph->ttl = 64;
    icmp_iph->protocol = IPPROTO_ICMP;
    icmp_iph->saddr = bpf_htonl(icmp_src_ip_host_order);
    icmp_iph->daddr = quote->iph.saddr;
    ipv4_checksum(icmp_iph);

    build_icmp_frag_needed(&msg, quote, next_mtu);
    __builtin_memcpy(icmp, &msg, sizeof(msg));
}

// https://qiita.com/qiita_kuru/items/54e4d902c86e40663119#murmurhash3-finalizer
static __always_inline __u32
murmur_mix(__u32 x)
{
    x ^= x >> 16;
    x *= 0x7feb352d;
    x ^= x >> 15;
    x *= 0x846ca68b;
    x ^= x >> 16;
    return x;
}

struct l4_ports {
    __be16 sport;
    __be16 dport;
};

static __always_inline __u32
inner_ip4_hash(const struct iphdr *iph, void *data_end)
{
    __u32 h = 0;

    h ^= bpf_ntohl(iph->saddr);
    h ^= bpf_ntohl(iph->daddr);
    h ^= ((__u32)iph->protocol) << 16;

    if (iph->ihl != 5)
        return murmur_mix(h);

    struct l4_ports *ports = (struct l4_ports *)((__u8 *)iph + sizeof(*iph));
    if ((void *)(ports + 1) <= data_end) {
        if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
            h ^= ((__u32)bpf_ntohs(ports->sport) << 16);
            h ^= (__u32)bpf_ntohs(ports->dport);
        }
    }

    return murmur_mix(h);
}

#endif // __DP_HELPERS__

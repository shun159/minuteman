#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "datapath_helpers.h"

char LICENSE[] SEC("license") = "GPL";

#define MAX_LAN_PORTS 64
#define MAX_TX_PORTS 128
#define MAX_CPUS 256

#define CFG_KEY 0
#define FANOUT_KEY 0

#define CFG_F_FIB_LOOKUP (1U << 0)
#define CFG_F_CPU_FANOUT (1U << 1)

/*
 * DS-Lite (RFC 6333) B4 element configuration: our IPv6 B4 address and the
 * AFTR's IPv6 address form the IPv4-in-IPv6 softwire (nexthdr IPPROTO_IPIP).
 * src_mac/dst_mac are used only as a fallback when bpf_fib_lookup() can't
 * resolve the WAN next hop (e.g. no neighbor entry yet).
 */
struct b4_config {
    struct in6_addr b4_addr;
    struct in6_addr aftr_addr;
    __u8 src_mac[ETH_ALEN];
    __u8 dst_mac[ETH_ALEN];
    __u32 wan_ifindex;
    __u32 flags;
};

struct lan_config {
    __u32 gateway_ip; /* host byte order */
    __u16 inner_mtu;
    __u16 flags;
};

struct fanout_config {
    __u32 enabled;
    __u32 cpu_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct b4_config);
} b4_config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_LAN_PORTS);
    __type(key, __u32); /* LAN ifindex */
    __type(value, struct lan_config);
} lan_configs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct fanout_config);
} fanout_config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_CPUS);
    __type(key, __u32);
    __type(value, __u32);
} fanout_cpus SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
    __uint(max_entries, MAX_TX_PORTS);
    __type(key, __u32);   /* ifindex */
    __type(value, __u32); /* ifindex */
} tx_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CPUMAP);
    __uint(max_entries, MAX_CPUS);
    __type(key, __u32);
    __type(value, struct bpf_cpumap_val);
} cpu_map SEC(".maps");

enum stat_id {
    STAT_PASS = 0,
    STAT_DROP,
    STAT_ABORT,
    STAT_ENCAP,
    STAT_DECAP,
    STAT_MTU_DROP,
    STAT_NO_CONFIG,
    STAT_NO_LAN_CONFIG,
    STAT_BYPASS,
    STAT_FIB_SUCCESS,
    STAT_FIB_NO_NEIGH,
    STAT_FIB_FAIL,
    STAT_FIB_WRONG_IF,
    STAT_DECAP_PASS,
    STAT_DECAP_NOT_DSLITE,
    STAT_DECAP_BAD_PACKET,
    STAT_DECAP_SLOW,
    STAT_REDIRECT_WAN,
    STAT_REDIRECT_LAN,
    STAT_ICMP_FRAG_NEEDED,
    STAT_MAX,
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

static __always_inline void
increase_stats_count(__u32 idx)
{
    __u64 *v = bpf_map_lookup_elem(&stats, &idx);
    if (v)
        *v += 1;
}

static __always_inline struct b4_config *
get_b4_config(void)
{
    __u32 key = CFG_KEY;
    return bpf_map_lookup_elem(&b4_config_map, &key);
}

static __always_inline struct lan_config *
get_lan_config(__u32 ifindex)
{
    return bpf_map_lookup_elem(&lan_configs, &ifindex);
}

static __always_inline bool
is_local_gateway_dst(const struct lan_config *lan, const struct iphdr *iph)
{
    return lan->gateway_ip && iph->daddr == bpf_htonl(lan->gateway_ip);
}

/*
 * Non-unicast IPv4 destinations must never enter the DS-Lite softwire (it's a
 * point-to-point tunnel to a single AFTR): the limited broadcast address
 * 255.255.255.255 and the multicast range 224.0.0.0/4 are passed up the local
 * stack instead. This is what lets a LAN client's DHCP DISCOVER/REQUEST (sent
 * to the limited broadcast) reach minuteman's own in-process DHCPv4 server,
 * which listens via an AF_PACKET socket downstream of XDP -- without this the
 * encap path would wrap those broadcasts and redirect them out the WAN.
 * (Unicast DHCP renewals go straight to the gateway IP, already bypassed by
 * is_local_gateway_dst.)
 */
static __always_inline bool
is_non_unicast_dst(const struct iphdr *iph)
{
    __u32 daddr = bpf_ntohl(iph->daddr);
    return daddr == 0xffffffff || (daddr & 0xf0000000) == 0xe0000000;
}

static __always_inline bool
is_local_lan_route(struct xdp_md *ctx, struct iphdr *iph)
{
    struct bpf_fib_lookup fib = {};

    fib.family = AF_INET;
    fib.tos = iph->tos;
    fib.l4_protocol = iph->protocol;
    fib.tot_len = bpf_ntohs(iph->tot_len);
    fib.ipv4_src = iph->saddr;
    fib.ipv4_dst = iph->daddr;
    fib.ifindex = ctx->ingress_ifindex;

    int ret = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0);
    if (ret != BPF_FIB_LKUP_RET_SUCCESS)
        return false;

    return get_lan_config(fib.ifindex) != NULL;
}

static __always_inline int
redirect_to_ifindex(__u32 ifindex, __u32 stat)
{
    increase_stats_count(stat);
    return bpf_redirect_map(&tx_ports, ifindex, 0);
}

static __always_inline bool
lookup_aftr_nexthop(struct xdp_md *ctx, const struct b4_config *cfg, __u16 inner_len,
                    struct bpf_fib_lookup *fib)
{
    fib->family = AF_INET6;
    fib->l4_protocol = IPPROTO_IPIP;
    fib->tot_len = (__u16)(OUTER_IPV6_LEN + inner_len);
    __builtin_memcpy(fib->ipv6_src, &cfg->b4_addr, sizeof(fib->ipv6_src));
    __builtin_memcpy(fib->ipv6_dst, &cfg->aftr_addr, sizeof(fib->ipv6_dst));
    fib->ifindex = ctx->ingress_ifindex;

    int ret = bpf_fib_lookup(ctx, fib, sizeof(*fib), 0);

    if (ret == BPF_FIB_LKUP_RET_SUCCESS || ret == BPF_FIB_LKUP_RET_FRAG_NEEDED) {
        if (cfg->wan_ifindex && fib->ifindex != cfg->wan_ifindex) {
            increase_stats_count(STAT_FIB_WRONG_IF);
            return false;
        }
        if (ret == BPF_FIB_LKUP_RET_SUCCESS)
            increase_stats_count(STAT_FIB_SUCCESS);
        return true;
    }

    if (ret == BPF_FIB_LKUP_RET_NO_NEIGH)
        increase_stats_count(STAT_FIB_NO_NEIGH);
    else
        increase_stats_count(STAT_FIB_FAIL);
    return false;
}

static __always_inline void
write_outer_eth6(struct ethhdr *eth, const struct b4_config *cfg,
                 const struct bpf_fib_lookup *fib, bool fib_ok)
{
    if (fib_ok) {
        __builtin_memcpy(eth->h_dest, fib->dmac, ETH_ALEN);
        __builtin_memcpy(eth->h_source, fib->smac, ETH_ALEN);
    } else {
        __builtin_memcpy(eth->h_dest, cfg->dst_mac, ETH_ALEN);
        __builtin_memcpy(eth->h_source, cfg->src_mac, ETH_ALEN);
    }
    eth->h_proto = bpf_htons(ETH_P_IPV6);
}

static __always_inline int
check_dev_mtu(struct xdp_md *ctx, __u32 ifindex, __u32 l3_len, __u32 *mtu_out)
{
    __u32 mtu_len = l3_len;

    int ret = bpf_check_mtu(ctx, ifindex, &mtu_len, 0, 0);
    if (mtu_out)
        *mtu_out = mtu_len;

    if (ret == 0 || ret == BPF_MTU_CHK_RET_FRAG_NEEDED)
        return ret;

    increase_stats_count(STAT_ABORT);
    return ret;
}

static __always_inline int
maybe_redirect_to_cpu(struct xdp_md *ctx, const struct iphdr *inner_iph, void *data_end)
{
    __u32 key = FANOUT_KEY;

    struct fanout_config *cfg = bpf_map_lookup_elem(&fanout_config_map, &key);
    if (!cfg || !cfg->enabled || cfg->cpu_count == 0)
        return 0;

    __u32 h = inner_ip4_hash(inner_iph, data_end);
    __u32 idx = h % cfg->cpu_count;

    if (idx >= MAX_CPUS)
        return 0;

    __u32 *cpu = bpf_map_lookup_elem(&fanout_cpus, &idx);
    if (!cpu)
        return 0;

    return bpf_redirect_map(&cpu_map, *cpu, 0);
}

/*
 * Sends a plain (untunneled) ICMPv4 Fragmentation Needed reply straight back
 * out the LAN interface a packet arrived on. Used from the encap path: the
 * offending packet hasn't been tunneled yet, so its sender is directly
 * reachable on the ingress interface.
 */
static __always_inline int
send_plain_icmp_frag_needed(struct xdp_md *ctx, __u64 l2_len,
                            const struct iphdr *orig_iph, __u32 icmp_src_ip,
                            __u16 next_mtu)
{
    __u8 *data = (__u8 *)(long)ctx->data;
    __u8 *data_end = (__u8 *)(long)ctx->data_end;

    if (!icmp_src_ip) {
        increase_stats_count(STAT_MTU_DROP);
        return XDP_DROP;
    }

    if (l2_len < sizeof(struct ethhdr) || l2_len > 64) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }

    if (orig_iph->ihl != 5) {
        increase_stats_count(STAT_MTU_DROP);
        return XDP_DROP;
    }

    if (bpf_ntohs(orig_iph->tot_len) < ICMP_FRAG_QUOTE_LEN ||
        (void *)orig_iph + ICMP_FRAG_QUOTE_LEN > data_end) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }

    struct ipv4_quote quote = {};
    copy_ipv4_quote(&quote, orig_iph);

    __u32 new_len = (__u32)l2_len + (__u32)ICMP_FRAG_REPLY_L3_LEN;
    __u32 old_len = data_end - data;
    if (new_len > old_len) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }

    if (bpf_xdp_adjust_tail(ctx, (int)new_len - (int)old_len) < 0) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }

    data = (__u8 *)(long)ctx->data;
    data_end = (__u8 *)(long)ctx->data_end;

    struct ethhdr *eth = (struct ethhdr *)data;
    struct iphdr *iph = (struct iphdr *)(data + l2_len);
    struct icmp_frag_needed *icmp =
        (struct icmp_frag_needed *)(data + l2_len + sizeof(struct iphdr));

    if ((void *)(eth + 1) > data_end || (void *)(iph + 1) > data_end ||
        (void *)(icmp + 1) > data_end) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }

    write_plain_icmp_frag_needed(eth, iph, icmp, &quote, icmp_src_ip, next_mtu);

    increase_stats_count(STAT_MTU_DROP);
    increase_stats_count(STAT_ICMP_FRAG_NEEDED);
    return XDP_TX;
}

SEC("xdp")
int
xdp_dslite_encap(struct xdp_md *ctx)
{
    __u8 *data = (__u8 *)(long)ctx->data;
    __u8 *data_end = (__u8 *)(long)ctx->data_end;

    __u64 l2_len = 0;
    struct iphdr *inner_iph = 0;
    int parsed = parse_l2_ipv4(data, data_end, &l2_len, &inner_iph);
    if (parsed < 0) {
        increase_stats_count(STAT_DROP);
        return XDP_DROP;
    }
    if (parsed == 0) {
        increase_stats_count(STAT_PASS);
        return XDP_PASS;
    }

    struct b4_config *cfg = get_b4_config();
    if (!cfg) {
        increase_stats_count(STAT_NO_CONFIG);
        return XDP_PASS;
    }

    __u32 ingress_ifindex = ctx->ingress_ifindex;
    struct lan_config *lan = get_lan_config(ingress_ifindex);
    if (!lan) {
        increase_stats_count(STAT_NO_LAN_CONFIG);
        return XDP_PASS;
    }

    if (is_non_unicast_dst(inner_iph) || is_local_gateway_dst(lan, inner_iph) ||
        is_local_lan_route(ctx, inner_iph)) {
        increase_stats_count(STAT_BYPASS);
        return XDP_PASS;
    }

    __u16 inner_len = bpf_ntohs(inner_iph->tot_len);
    __u32 wan_mtu = 0;
    int ret =
        check_dev_mtu(ctx, cfg->wan_ifindex, TUNNEL_L3_OVERHEAD + inner_len, &wan_mtu);
    if (ret == BPF_MTU_CHK_RET_FRAG_NEEDED) {
        __u32 next_mtu =
            wan_mtu > TUNNEL_L3_OVERHEAD ? wan_mtu - TUNNEL_L3_OVERHEAD : ICMPV4_MIN_MTU;
        if (next_mtu < ICMPV4_MIN_MTU)
            next_mtu = ICMPV4_MIN_MTU;
        if (next_mtu > 0xffff)
            next_mtu = 0xffff;

        if (ipv4_has_df(inner_iph))
            return send_plain_icmp_frag_needed(ctx, l2_len, inner_iph, lan->gateway_ip,
                                               (__u16)next_mtu);

        increase_stats_count(STAT_MTU_DROP);
        return XDP_DROP;
    }
    if (ret != 0)
        return XDP_DROP;

    if (inner_iph->ttl <= 1) {
        increase_stats_count(STAT_PASS);
        return XDP_PASS;
    }

    struct bpf_fib_lookup fib = {};
    bool fib_ok = lookup_aftr_nexthop(ctx, cfg, inner_len, &fib);
    if (!fib_ok)
        return XDP_PASS;

    int delta = (int)l2_len - OUTER_HDR_LEN;
    if (bpf_xdp_adjust_head(ctx, delta) < 0) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }

    data = (__u8 *)(long)ctx->data;
    data_end = (__u8 *)(long)ctx->data_end;

    struct ethhdr *outer_eth = (struct ethhdr *)data;
    struct ipv6hdr *outer_iph = (struct ipv6hdr *)(data + OUTER_ETH_LEN);
    inner_iph = (struct iphdr *)(data + OUTER_HDR_LEN);

    if ((void *)(inner_iph + 1) > data_end) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }
    if ((void *)inner_iph + inner_len > data_end) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }

    write_outer_eth6(outer_eth, cfg, &fib, fib_ok);
    write_outer_ipv6(outer_iph, &cfg->b4_addr, &cfg->aftr_addr, inner_len);
    decrease_ipv4_ttl(inner_iph);

    increase_stats_count(STAT_ENCAP);
    return redirect_to_ifindex(cfg->wan_ifindex, STAT_REDIRECT_WAN);
}

static __always_inline bool
is_expected_dslite_peer(const struct b4_config *cfg, const struct ipv6hdr *outer_iph)
{
    return ipv6_addr_equal(&outer_iph->daddr, &cfg->b4_addr) &&
           ipv6_addr_equal(&outer_iph->saddr, &cfg->aftr_addr);
}

static __always_inline int
validate_dslite_ipv6(__u8 *data_end, const struct ipv6hdr *outer_iph,
                     struct iphdr **inner_out, __u16 *inner_len_out)
{
    struct iphdr *inner_iph = (struct iphdr *)((__u8 *)outer_iph + sizeof(*outer_iph));
    if ((void *)(inner_iph + 1) > data_end) {
        increase_stats_count(STAT_DECAP_BAD_PACKET);
        return XDP_DROP;
    }
    if (inner_iph->version != 4 || inner_iph->ihl != 5) {
        increase_stats_count(STAT_DECAP_BAD_PACKET);
        return XDP_PASS;
    }

    __u16 inner_len = bpf_ntohs(inner_iph->tot_len);
    if (inner_len < sizeof(*inner_iph)) {
        increase_stats_count(STAT_DECAP_BAD_PACKET);
        return XDP_DROP;
    }
    if ((void *)inner_iph + inner_len > data_end) {
        increase_stats_count(STAT_DECAP_BAD_PACKET);
        return XDP_DROP;
    }

    *inner_out = inner_iph;
    *inner_len_out = inner_len;
    return -1;
}

static __always_inline void
fill_inner_fib_params(struct bpf_fib_lookup *fib, const struct iphdr *inner_iph,
                      __u16 inner_len, __u32 ingress_ifindex)
{
    fib->family = AF_INET;
    fib->tos = inner_iph->tos;
    fib->l4_protocol = inner_iph->protocol;
    fib->tot_len = inner_len;
    fib->ipv4_src = inner_iph->saddr;
    fib->ipv4_dst = inner_iph->daddr;
    fib->ifindex = ingress_ifindex;
}

enum lan_lookup_result {
    LAN_LOOKUP_FAIL = 0,
    LAN_LOOKUP_OK = 1,
    LAN_LOOKUP_FRAG_NEEDED = 2,
};

static __always_inline int
lookup_lan_nexthop(struct xdp_md *ctx, const struct b4_config *cfg,
                   const struct iphdr *inner_iph, __u16 inner_len,
                   struct bpf_fib_lookup *fib, __u16 *mtu_out)
{
    fill_inner_fib_params(fib, inner_iph, inner_len, ctx->ingress_ifindex);

    int ret = bpf_fib_lookup(ctx, fib, sizeof(*fib), 0);
    if (ret == BPF_FIB_LKUP_RET_SUCCESS || ret == BPF_FIB_LKUP_RET_FRAG_NEEDED) {
        if (fib->ifindex == cfg->wan_ifindex) {
            increase_stats_count(STAT_FIB_WRONG_IF);
            return LAN_LOOKUP_FAIL;
        }
        if (!get_lan_config(fib->ifindex)) {
            increase_stats_count(STAT_NO_LAN_CONFIG);
            return LAN_LOOKUP_FAIL;
        }
        if (ret == BPF_FIB_LKUP_RET_SUCCESS) {
            increase_stats_count(STAT_FIB_SUCCESS);
            return LAN_LOOKUP_OK;
        }
        if (mtu_out)
            *mtu_out = fib->mtu_result;
        return LAN_LOOKUP_FRAG_NEEDED;
    }

    if (ret == BPF_FIB_LKUP_RET_NO_NEIGH)
        increase_stats_count(STAT_FIB_NO_NEIGH);
    else
        increase_stats_count(STAT_FIB_FAIL);

    return LAN_LOOKUP_FAIL;
}

static __always_inline int
finish_decap_slow_path(struct ethhdr *eth, const struct ethhdr *old_eth)
{
    *eth = *old_eth;
    eth->h_proto = bpf_htons(ETH_P_IP);
    increase_stats_count(STAT_DECAP_SLOW);
    return XDP_PASS;
}

/*
 * Sends an ICMPv4 Fragmentation Needed reply re-encapsulated in a DS-Lite
 * (IPv4-in-IPv6) frame, transmitted back out the WAN interface toward the
 * AFTR. Used from the decap path: the offending packet's original IPv4
 * sender is only reachable through the softwire.
 */
static __always_inline int
send_dslite_icmp_frag_needed(struct xdp_md *ctx, const struct b4_config *cfg,
                             const struct iphdr *inner_iph, __u32 icmp_src_ip,
                             __u16 next_mtu)
{
    __u8 *data = (__u8 *)(long)ctx->data;
    __u8 *data_end = (__u8 *)(long)ctx->data_end;

    if (!icmp_src_ip) {
        increase_stats_count(STAT_MTU_DROP);
        return XDP_DROP;
    }

    if (inner_iph->ihl != 5) {
        increase_stats_count(STAT_MTU_DROP);
        return XDP_DROP;
    }

    if (bpf_ntohs(inner_iph->tot_len) < ICMP_FRAG_QUOTE_LEN ||
        (void *)inner_iph + ICMP_FRAG_QUOTE_LEN > data_end) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }

    struct ipv4_quote quote = {};
    copy_ipv4_quote(&quote, inner_iph);

    __u32 new_len = OUTER_ETH_LEN + (__u32)OUTER_IPV6_LEN + (__u32)ICMP_FRAG_REPLY_L3_LEN;
    __u32 old_len = data_end - data;
    if (new_len > old_len) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }

    if (bpf_xdp_adjust_tail(ctx, (int)new_len - (int)old_len) < 0) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }

    data = (__u8 *)(long)ctx->data;
    data_end = (__u8 *)(long)ctx->data_end;

    struct ethhdr *eth = (struct ethhdr *)data;
    struct ipv6hdr *outer_iph = (struct ipv6hdr *)(data + OUTER_ETH_LEN);
    struct iphdr *icmp_iph = (struct iphdr *)(data + OUTER_HDR_LEN);
    struct icmp_frag_needed *icmp =
        (struct icmp_frag_needed *)(data + OUTER_HDR_LEN + sizeof(struct iphdr));

    if ((void *)(eth + 1) > data_end || (void *)(outer_iph + 1) > data_end ||
        (void *)(icmp_iph + 1) > data_end || (void *)(icmp + 1) > data_end) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }

    write_dslite_icmp_frag_needed(eth, outer_iph, icmp_iph, icmp, &quote, &cfg->b4_addr,
                                  &cfg->aftr_addr, icmp_src_ip, next_mtu);

    increase_stats_count(STAT_MTU_DROP);
    increase_stats_count(STAT_ICMP_FRAG_NEEDED);
    return XDP_TX;
}

static __always_inline int
handle_xdp_dslite_decap(struct xdp_md *ctx)
{
    increase_stats_count(STAT_DECAP);

    __u8 *data = (__u8 *)(long)ctx->data;
    __u8 *data_end = (__u8 *)(long)ctx->data_end;

    __u64 l2_len = 0;
    struct ipv6hdr *outer_iph = 0;
    int parsed = parse_l2_ipv6(data, data_end, &l2_len, &outer_iph);
    if (parsed < 0) {
        increase_stats_count(STAT_DROP);
        return XDP_DROP;
    }
    if (parsed == 0) {
        increase_stats_count(STAT_DECAP_PASS);
        return XDP_PASS;
    }

    struct b4_config *cfg = get_b4_config();
    if (!cfg) {
        increase_stats_count(STAT_NO_CONFIG);
        return XDP_PASS;
    }

    if (outer_iph->nexthdr != IPPROTO_IPIP) {
        increase_stats_count(STAT_DECAP_NOT_DSLITE);
        return XDP_PASS;
    }

    if (!is_expected_dslite_peer(cfg, outer_iph)) {
        increase_stats_count(STAT_DECAP_PASS);
        return XDP_PASS;
    }

    struct iphdr *inner_iph_pre = 0;
    __u16 inner_len = 0;
    int ret = validate_dslite_ipv6(data_end, outer_iph, &inner_iph_pre, &inner_len);
    if (ret != -1)
        return ret;

    if (inner_iph_pre->ttl <= 1) {
        increase_stats_count(STAT_DECAP_PASS);
        return XDP_PASS;
    }

    struct ethhdr old_eth = *(struct ethhdr *)data;

    struct bpf_fib_lookup fib = {};
    __u16 fib_mtu = 0;
    int lan_lookup =
        lookup_lan_nexthop(ctx, cfg, inner_iph_pre, inner_len, &fib, &fib_mtu);
    bool fast = lan_lookup == LAN_LOOKUP_OK;

    if (lan_lookup == LAN_LOOKUP_FRAG_NEEDED) {
        struct lan_config *out_lan = get_lan_config(fib.ifindex);
        if (!out_lan) {
            increase_stats_count(STAT_NO_LAN_CONFIG);
            return XDP_PASS;
        }

        __u32 next_mtu = fib_mtu;
        if (next_mtu < ICMPV4_MIN_MTU)
            next_mtu = ICMPV4_MIN_MTU;
        if (next_mtu > 0xffff)
            next_mtu = 0xffff;

        if (ipv4_has_df(inner_iph_pre))
            return send_dslite_icmp_frag_needed(ctx, cfg, inner_iph_pre,
                                                out_lan->gateway_ip, (__u16)next_mtu);

        increase_stats_count(STAT_MTU_DROP);
        return XDP_DROP;
    }

    if (fast) {
        __u32 lan_mtu = 0;
        ret = check_dev_mtu(ctx, fib.ifindex, inner_len, &lan_mtu);
        if (ret == BPF_MTU_CHK_RET_FRAG_NEEDED) {
            struct lan_config *out_lan = get_lan_config(fib.ifindex);
            if (!out_lan) {
                increase_stats_count(STAT_NO_LAN_CONFIG);
                return XDP_PASS;
            }

            __u32 next_mtu = lan_mtu;
            if (next_mtu < ICMPV4_MIN_MTU)
                next_mtu = ICMPV4_MIN_MTU;
            if (next_mtu > 0xffff)
                next_mtu = 0xffff;

            if (ipv4_has_df(inner_iph_pre))
                return send_dslite_icmp_frag_needed(ctx, cfg, inner_iph_pre,
                                                    out_lan->gateway_ip, (__u16)next_mtu);

            increase_stats_count(STAT_MTU_DROP);
            return XDP_DROP;
        }
        if (ret != 0)
            return XDP_DROP;
    }

    if (bpf_xdp_adjust_head(ctx, (int)OUTER_IPV6_LEN) < 0) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }

    data = (__u8 *)(long)ctx->data;
    data_end = (__u8 *)(long)ctx->data_end;

    struct ethhdr *eth = (struct ethhdr *)data;
    struct iphdr *inner_iph = (struct iphdr *)(data + OUTER_ETH_LEN);
    if ((void *)(eth + 1) > data_end) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }
    if ((void *)(inner_iph + 1) > data_end) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }
    if ((void *)inner_iph + inner_len > data_end) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }

    if (!fast)
        return finish_decap_slow_path(eth, &old_eth);

    __builtin_memcpy(eth->h_dest, fib.dmac, ETH_ALEN);
    __builtin_memcpy(eth->h_source, fib.smac, ETH_ALEN);
    eth->h_proto = bpf_htons(ETH_P_IP);

    if (inner_iph->ttl <= 1) {
        increase_stats_count(STAT_PASS);
        return XDP_PASS;
    }

    decrease_ipv4_ttl(inner_iph);

    return redirect_to_ifindex(fib.ifindex, STAT_REDIRECT_LAN);
}

SEC("xdp/cpumap")
int
xdp_dslite_decap_cpu(struct xdp_md *ctx)
{
    return handle_xdp_dslite_decap(ctx);
}

SEC("xdp")
int
xdp_dslite_decap(struct xdp_md *ctx)
{
    __u8 *data = (__u8 *)(long)ctx->data;
    __u8 *data_end = (__u8 *)(long)ctx->data_end;

    __u64 l2_len = 0;
    struct ipv6hdr *outer_iph = 0;
    int parsed = parse_l2_ipv6(data, data_end, &l2_len, &outer_iph);
    if (parsed < 0) {
        increase_stats_count(STAT_DROP);
        return XDP_DROP;
    }
    if (parsed == 0) {
        increase_stats_count(STAT_DECAP_PASS);
        return XDP_PASS;
    }

    struct b4_config *cfg = get_b4_config();
    if (!cfg)
        return XDP_PASS;

    if (outer_iph->nexthdr != IPPROTO_IPIP)
        return XDP_PASS;

    if (!is_expected_dslite_peer(cfg, outer_iph))
        return XDP_PASS;

    struct iphdr *inner_iph = 0;
    __u16 inner_len = 0;
    int ret = validate_dslite_ipv6(data_end, outer_iph, &inner_iph, &inner_len);
    if (ret != -1)
        return ret;

    int action = maybe_redirect_to_cpu(ctx, inner_iph, data_end);
    if (action)
        return action;

    return handle_xdp_dslite_decap(ctx);
}

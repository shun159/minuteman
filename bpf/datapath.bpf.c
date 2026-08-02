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
 * DS-Lite (RFC 6333) B4 element configuration. This is the effective config
 * for one packet: the WAN-global fields (src_mac/dst_mac, used only as a
 * fallback when bpf_fib_lookup() can't resolve the WAN next hop; wan_ifindex;
 * flags) come from b4_config_map, while b4_addr/aftr_addr -- the IPv4-in-IPv6
 * softwire endpoints (nexthdr IPPROTO_IPIP) -- come from the active (or, on
 * decap, the matched) next_hop slot and are overlaid per packet by
 * resolve_softwire(). The copy stored in b4_config_map leaves b4_addr/
 * aftr_addr zero; they're never read from there.
 */
struct b4_config {
    struct in6_addr b4_addr;
    struct in6_addr aftr_addr;
    __u8 src_mac[ETH_ALEN];
    __u8 dst_mac[ETH_ALEN];
    __u32 wan_ifindex;
    __u32 flags;
    /*
     * Per-fragment payload size for softwire (outer IPv6) fragmentation: the
     * largest multiple of 8 that fits the WAN MTU after the outer IPv6 +
     * Fragment headers (WAN MTU - 48, rounded down; 1500 -> 1448). Computed
     * by userspace; 0 means unset, which sends every oversized packet down
     * the kernel ip6tnl fallback instead (see encap_fragment_outer).
     */
    __u32 frag_unit;
    /*
     * Largest inner IPv4 packet the fragmenter may take: the companion veth
     * pair (internal/fragpath) admits a broadcast clone only while the whole
     * encapsulated frame fits its MTU, and a bigger packet must fall back to
     * the ip6tnl rather than blackhole into a rejected enqueue.
     */
    __u32 frag_max_inner;
};

/*
 * One softwire endpoint pair (this B4's address + its AFTR's), swappable at
 * runtime for live AFTR re-discovery (RFC 4242 refresh / WAN-address change).
 * Userspace never mutates the slot the datapath is currently using: it writes
 * a *new* slot in full, then flips active_nh (a single __u32) to point at it.
 * bpf_map_update_elem on an ARRAY map copies the value in place (no RCU
 * replacement), so overwriting the live slot could be read half-updated; the
 * write-inactive-then-flip idiom avoids that. decap accepts any valid slot
 * (find_dslite_peer_nh), so a brief overlap during a switch still decaps
 * return traffic from both the old and new AFTR.
 */
struct next_hop {
    __u32 valid;
    struct in6_addr b4_addr;
    struct in6_addr aftr_addr;
};

/* Number of next_hop slots. Two is enough for one live switch at a time (the
 * old AFTR plus the new one); the array is sized to match in Go. */
#define NUM_NEXT_HOPS 2

struct lan_config {
    __u32 gateway_ip; /* host byte order */
    __u16 inner_mtu;
    __u16 flags;
};

/*
 * The softwire path MTU learned from an ICMPv6 Packet Too Big about one of our
 * own tunnel packets (RFC 2473 §6.7/§8), per next_hop slot -- the encap path's
 * own bpf_check_mtu only ever sees the *local* WAN device's MTU, so without
 * this a narrower link further along the B4<->AFTR path is invisible to it.
 *
 * The datapath only *learns* here; acting on it is split: encap clamps its
 * effective MTU against this value per packet, while the fragment size
 * (b4_config.frag_unit) and the companion ip6tnl's MTU are recomputed by
 * userspace, which polls this map. Deriving frag_unit in the datapath instead
 * would let encap_fragment_outer and the xdp_softwire_frag<i> programs read
 * two different units for one packet's clones (they read it at different
 * times) and emit a fragment set that can never reassemble.
 *
 * updated_ns == 0 means nothing learned. Userspace ages an entry out on its own
 * clock, restoring the device MTU when the narrow path stops being reported.
 */
struct tunnel_pmtu {
    __u32 mtu;
    __u32 pad;
    __u64 updated_ns;
};

/*
 * How long a learned softwire path MTU is trusted before a larger reading may
 * replace it -- 10 minutes, the same window the kernel gives its own IPv4 PMTU
 * cache entries (ip_rt_mtu_expires). Userspace uses the same figure to decide
 * when to hand the fragment size back to the WAN device's own MTU.
 */
#define TUNNEL_PMTU_EXPIRY_NS (600ULL * 1000000000ULL)

struct fanout_config {
    __u32 enabled;
    __u32 cpu_count;
};

/*
 * Software-RSS configuration for the native-IPv6 forwarding fastpath. Kept
 * entirely separate from the DS-Lite fanout_config above (and its cpu_map): the
 * DS-Lite CPU-fanout scaffold is dormant -- never enabled from userspace -- and
 * IPv6 software RSS must be independently switchable without waking it. Off by
 * default; enabled only when the NIC's hardware RSS can't spread flows itself.
 */
struct ipv6_rss_config {
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
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, NUM_NEXT_HOPS);
    __type(key, __u32); /* slot index */
    __type(value, struct next_hop);
} next_hops SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, NUM_NEXT_HOPS);
    __type(key, __u32); /* next_hop slot index */
    __type(value, struct tunnel_pmtu);
} tunnel_pmtus SEC(".maps");

/*
 * Migration control: one bit-packed __u32 that drives which next_hop slot a
 * softwire packet uses, and (during an AFTR migration) whether flow affinity
 * applies. Packing it into a single word keeps every state transition a single
 * atomic store -- the same reason active_nh (which this subsumes) was one word.
 * Each program loads it into a local exactly once per packet and never re-reads
 * it mid-packet, so the first and second halves of one packet can never see
 * different generations.
 *
 *   bits  0..7  active_slot  the slot encap uses by default
 *   bits  8..15 old_slot     during DRAINING, the slot pre-cutover flows pin to
 *   bits 16..23 state        MIG_STEADY / MIG_PRIMING / MIG_DRAINING
 *   bits 24..31 epoch        this migration's generation (see flow_affinity)
 */
#define MIG_STEADY 0
#define MIG_PRIMING 1
#define MIG_DRAINING 2

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32); /* packed: see MIG_* accessors */
} migration_ctrl SEC(".maps");

/*
 * Inner-IPv4 flow key for AFTR migration affinity. Ports are only meaningful
 * for unfragmented TCP/UDP; every fragment (the first one included) and every
 * portless protocol degrades to ports=0, so all of one datagram's fragments --
 * and successive datagrams of the same flow -- land on the same entry. Keying
 * fragments by IPv4 ID instead would keep a single datagram together but never
 * match across datagrams (a fresh ID each), destroying exactly the affinity
 * PRIMING recorded. The coarse shared entry merely pins same-pair fragmented
 * flows to one slot together: the value is only a generation stamp, so a
 * collision is fate-sharing, not corruption.
 *
 * The key is always in the *forward* (LAN -> Internet) orientation; the decap
 * path reverses the inner header's addresses/ports to reach the same key.
 */
struct flow_key {
    __u32 src;
    __u32 dst;
    __be16 sport;
    __be16 dport;
    __u8 proto;
    __u8 pad[3];
};

/*
 * epoch stamps which migration recorded this flow. A lookup only honours an
 * entry whose epoch matches the control word's, so leftovers from an earlier
 * migration are ignored (and deleted lazily by userspace) -- the flow table
 * never has to be drained to empty before the next migration can start.
 */
struct flow_affinity {
    __u64 last_seen_ns;
    __u32 epoch;
    __u32 pad;
};

#define MAX_FLOW_AFFINITY 65536

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FLOW_AFFINITY);
    __type(key, struct flow_key);
    __type(value, struct flow_affinity);
} flow_affinity_map SEC(".maps");

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

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ipv6_rss_config);
} ipv6_rss_config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_CPUS);
    __type(key, __u32);   /* fanout slot index */
    __type(value, __u32); /* target CPU id */
} ipv6_rss_cpus SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_CPUMAP);
    __uint(max_entries, MAX_CPUS);
    __type(key, __u32);
    __type(value, struct bpf_cpumap_val);
} cpu_map_v6 SEC(".maps");

/*
 * Maximum number of outer-IPv6 fragments the datapath can carve one oversized
 * softwire packet into -- the number of frag_ports entries, and of
 * xdp_softwire_frag* programs. 4 x frag_unit (1448 at WAN MTU 1500) covers any
 * inner packet a single-buffer XDP frame can carry; anything larger falls back
 * to the kernel ip6tnl slow path. Mirrored as maxSoftwireFrags in Go.
 */
#define MAX_SOFTWIRE_FRAGS 4

/*
 * Softwire fragmentation clone targets (RFC 6333 §5.3): entry i is the A end
 * of companion large-MTU veth pair i (internal/fragpath), whose B end runs
 * xdp_softwire_frag<i> as its rx XDP program. XDP can only emit one frame per
 * input frame, so encap_fragment_outer() builds the whole encapsulated packet
 * once (with a Fragment header) and bpf_redirect_map()s it here with
 * BPF_F_BROADCAST: the kernel clones the frame per entry, and pair i's
 * program trims its clone down to fragment i (or drops it when the packet
 * needs fewer than MAX_SOFTWIRE_FRAGS fragments) and redirects it out the
 * WAN.
 *
 * One device per fragment index is load-bearing, not decoration, twice over:
 *
 *   - The devmap enqueue validates the *untrimmed* clone's length against the
 *     target device's MTU before any trimming could happen (is_valid_dst ->
 *     xdp_ok_fwd_dev), and a frame that needs fragmenting by definition
 *     exceeds the WAN MTU -- so the targets must be large-MTU devices, never
 *     the WAN itself.
 *   - Per-entry devmap *egress programs* (bpf_devmap_val.bpf_prog) cannot
 *     express per-fragment behavior here: the kernel batches enqueued frames
 *     in one bulk queue per target device and runs only the first enqueue's
 *     program over the whole batch, so entries sharing one device would run
 *     one program over every clone. Distinct devices are what actually keeps
 *     the four programs distinct -- which is why the programs live on the
 *     pairs' B ends as plain rx XDP programs and the map holds plain
 *     ifindexes.
 */
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, MAX_SOFTWIRE_FRAGS);
    __type(key, __u32);
    __type(value, __u32); /* ifindex of pair i's A end */
} frag_ports SEC(".maps");

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
    STAT_IPV6_FWD,
    STAT_IPV6_PASS,
    STAT_IPV6_RSS_REDIRECT,
    STAT_ICMP_RATE_LIMITED,
    STAT_AFFINITY_INSERT,
    STAT_AFFINITY_INSERT_FAIL,
    STAT_AFFINITY_PINNED,
    /*
     * Softwire fragmentation slow path (RFC 6333 §5.3). XDP doesn't
     * reassemble; inbound fragmentation cases are handed to the kernel, where
     * a companion ip6tnl (local=B4, remote=AFTR) plus an IPv4 default route
     * do the work. Outbound, STAT_ENCAP_FRAG_SLOW is only the *fallback* for
     * what encap_fragment_outer()'s in-XDP outer-IPv6 fragmentation (the two
     * STAT_ENCAP_FRAG_XDP/SEG counters below) can't cover. Counted separately
     * so the netns rig can assert which path is actually exercised.
     */
    STAT_ENCAP_FRAG_SLOW,  /* oversized inner IPv4 the XDP fragmenter can't take:
                            * kernel ip6tnl fallback (inner-IPv4 fragmentation) */
    STAT_DECAP_FRAG_SLOW,  /* decapped inner too big for a non-DF LAN egress */
    STAT_DECAP_REASM_PASS, /* fragmented softwire IPv6: kernel reassembles + decaps */
    STAT_DECAP_MARTIAN,    /* decapped inner resolves off-LAN (would bounce): dropped */
    /*
     * In-XDP softwire fragmentation (RFC 6333 §5.3, errata 5847 -> RFC 2473
     * §7.2(b)): the oversized inner IPv4 is encapsulated whole and the outer
     * IPv6 is fragmented, DF bit ignored.
     */
    STAT_ENCAP_FRAG_XDP, /* oversized inner IPv4 outer-fragmented in XDP (per packet) */
    STAT_ENCAP_FRAG_SEG, /* outer-IPv6 fragments emitted by xdp_softwire_frag* */
    /*
     * Decap-side inner-TTL expiry answered in XDP with a softwire-encapsulated
     * ICMPv4 Time Exceeded (RFC 1812 §5.3.1). Appended here rather than next to
     * STAT_ICMP_FRAG_NEEDED on purpose: these ids are the keys of the bpffs-
     * pinned stats map, so inserting one mid-enum renumbers every counter after
     * it and breaks any observer (`minuteman stats`, bpftool) built against a
     * different revision. New counters go before STAT_MAX, never in the middle.
     */
    STAT_ICMP_TIME_EXCEEDED,
    /*
     * Tunnel ICMPv6 relay (RFC 2473 §8): an ICMPv6 error an intermediate router
     * on the B4<->AFTR path sent *about* a softwire packet, translated here into
     * an ICMPv4 error toward the LAN client whose packet it quoted.
     */
    STAT_TUNNEL_ICMP_RELAY, /* relayed to the LAN as an ICMPv4 error */
    STAT_TUNNEL_ICMP_PASS,  /* about our softwire, not relayable here: XDP_PASSed
                             * so the kernel's own ip6tnl gets its turn */
    STAT_TUNNEL_ICMP_DROP,  /* consumed here without a relay: the answer is
                             * something other than an ICMPv4 error (a non-DF
                             * Packet Too Big, whose answer is to fragment at the
                             * learned MTU), or RFC 1812 §4.3.2.7 forbids one */
    STAT_TUNNEL_PMTU,       /* softwire path MTU learned from a Packet Too Big */
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

/*
 * Rate limiting for datapath-originated ICMP errors (ICMPv6 Packet Too Big,
 * ICMPv4 Fragmentation Needed in both plain and softwire-tunneled form).
 * RFC 4443 SS2.4(f) makes rate-limiting originated ICMPv6 errors a MUST, and
 * RFC 1812 SS4.3.2.8 recommends the same for ICMPv4 -- and since these
 * replies are XDP_TX'd without ever entering the kernel stack, the kernel's
 * own icmp_ratelimit/ratemask sysctls never see them, so the datapath must
 * enforce its own limit or a line-rate stream of oversized packets yields a
 * line-rate stream of ICMP errors (a reflection primitive).
 *
 * One token bucket per CPU (PERCPU_ARRAY, so no cross-CPU atomics -- the
 * same reasoning as the stats map): ICMP_ERROR_RATE_PER_SEC sustained,
 * ICMP_ERROR_BURST burst, each per CPU. With hardware RSS (or the optional
 * software-RSS stage) spreading flows, the aggregate across N CPUs is
 * N * rate -- on a typical 4-16 CPU CPE that lands in the same range as the
 * kernel's own default global limit (icmp_msgs_per_sec = 1000). PMTUD needs
 * only a handful of errors per flow, so legitimate traffic never notices.
 */
#define ICMP_ERROR_RATE_PER_SEC 100
#define ICMP_ERROR_BURST 20
#define ICMP_ERROR_REFILL_INTERVAL_NS (1000000000ULL / ICMP_ERROR_RATE_PER_SEC)

struct icmp_rate_bucket {
    __u64 last_refill_ns;
    __u64 tokens;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct icmp_rate_bucket);
} icmp_error_rate SEC(".maps");

/*
 * Takes one token from this CPU's ICMP-error bucket, refilling it first
 * from the time elapsed since the last refill. Returns false when the
 * bucket is empty -- the caller must then drop the offending packet
 * *without* originating the ICMP error (mirroring what the kernel does
 * when its own ICMP rate limit trips). last_refill_ns advances by whole
 * refill intervals rather than jumping to now, so the sub-interval
 * remainder isn't lost to truncation. A zeroed bucket (map initial state)
 * computes a huge elapsed time on first use and clamps to a full burst,
 * so no explicit initialization is needed.
 */
static __always_inline bool
icmp_error_allowed(void)
{
    __u32 key = 0;
    struct icmp_rate_bucket *b = bpf_map_lookup_elem(&icmp_error_rate, &key);
    if (!b)
        return true;

    __u64 now = bpf_ktime_get_ns();
    __u64 refill = (now - b->last_refill_ns) / ICMP_ERROR_REFILL_INTERVAL_NS;
    if (refill > 0) {
        __u64 tokens = b->tokens + refill;
        b->tokens = tokens > ICMP_ERROR_BURST ? ICMP_ERROR_BURST : tokens;
        b->last_refill_ns += refill * ICMP_ERROR_REFILL_INTERVAL_NS;
    }
    if (b->tokens == 0)
        return false;
    b->tokens -= 1;
    return true;
}

static __always_inline struct b4_config *
get_b4_config(void)
{
    __u32 key = CFG_KEY;
    return bpf_map_lookup_elem(&b4_config_map, &key);
}

/* Loads the migration control word. Callers must do this exactly once per
 * packet and pass the local copy down (never re-look it up mid-packet). */
static __always_inline __u32
get_migration_ctrl(void)
{
    __u32 key = 0;
    __u32 *c = bpf_map_lookup_elem(&migration_ctrl, &key);
    return c ? *c : 0; /* unset == STEADY on slot 0 */
}

static __always_inline __u32
mig_active_slot(__u32 ctrl)
{
    return ctrl & 0xff;
}

static __always_inline __u32
mig_old_slot(__u32 ctrl)
{
    return (ctrl >> 8) & 0xff;
}

static __always_inline __u32
mig_state(__u32 ctrl)
{
    return (ctrl >> 16) & 0xff;
}

static __always_inline __u32
mig_epoch(__u32 ctrl)
{
    return (ctrl >> 24) & 0xff;
}

/*
 * Assembles the effective per-packet config: the WAN-global template from
 * b4_config_map overlaid with one next_hop slot's softwire addresses.
 * Returns false (caller passes to the kernel) if the global config isn't set
 * yet or nh is missing/invalid.
 */
static __always_inline bool
resolve_softwire(struct b4_config *out, const struct next_hop *nh)
{
    struct b4_config *g = get_b4_config();
    if (!g || !nh || !nh->valid)
        return false;
    *out = *g;
    out->b4_addr = nh->b4_addr;
    out->aftr_addr = nh->aftr_addr;
    return true;
}

static __always_inline struct next_hop *
get_next_hop(__u32 slot)
{
    return bpf_map_lookup_elem(&next_hops, &slot);
}

/*
 * Resolves against the slot the control word currently makes active. Used by
 * the native-IPv6 fastpath (which needs only this B4's own address as an ICMPv6
 * source and never touches an AFTR, so flow affinity doesn't apply to it) and
 * by any caller that has no inner flow to key on.
 */
static __always_inline bool
resolve_active_softwire(struct b4_config *out)
{
    return resolve_softwire(out, get_next_hop(mig_active_slot(get_migration_ctrl())));
}

/*
 * Builds the forward (LAN -> Internet) flow key for iph. reverse=true is for
 * the decap path, whose inner header runs Internet -> LAN: swapping its
 * addresses and ports yields the same key the encap path recorded, so both
 * directions of one flow share one entry (a download-heavy flow would otherwise
 * look idle to the drain GC, which only ever sees uplink packets).
 *
 * See struct flow_key for why fragments and portless protocols use ports=0.
 */
static __always_inline void
build_flow_key(struct flow_key *key, const struct iphdr *iph, void *data_end,
               bool reverse)
{
    __builtin_memset(key, 0, sizeof(*key));
    key->proto = iph->protocol;

    __be16 sport = 0, dport = 0;
    bool fragmented = (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET)) != 0;

    if (!fragmented && iph->ihl == 5 &&
        (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP)) {
        struct l4_ports *p = (struct l4_ports *)((__u8 *)iph + sizeof(*iph));
        if ((void *)(p + 1) <= data_end) {
            sport = p->sport;
            dport = p->dport;
        }
    }

    if (reverse) {
        key->src = iph->daddr;
        key->dst = iph->saddr;
        key->sport = dport;
        key->dport = sport;
    } else {
        key->src = iph->saddr;
        key->dst = iph->daddr;
        key->sport = sport;
        key->dport = dport;
    }
}

/*
 * Records or refreshes this flow's affinity entry during a migration, and
 * reports whether the flow predates the cutover (a current-epoch entry).
 *
 * PRIMING records every flow it sees while the *old* AFTR is still active --
 * that's the whole point: at cutover, a table miss can't distinguish a new flow
 * from a pre-existing flow's next packet (UDP/QUIC/ICMP have no start marker),
 * so the distinction has to be learned beforehand.
 *
 * Two details make the recording trustworthy enough to gate the cutover on:
 *
 *   - It is lookup-first, not a blind insert. A leftover stale-epoch entry on
 *     this key must be re-stamped, not inserted over; a blind insert would fail
 *     and leave a flow we *did* observe carrying the wrong epoch, so it would be
 *     misclassified as new at cutover.
 *   - The insert itself uses BPF_ANY, not BPF_NOEXIST. Two CPUs can both miss
 *     the lookup for the same flow and race to create it; with BPF_NOEXIST the
 *     loser gets EEXIST and would be counted as a failed recording even though
 *     the flow is, in fact, recorded -- and the control plane would abandon a
 *     perfectly good migration over it. With BPF_ANY the loser simply rewrites
 *     the same {epoch, now}, so a failure here means what the cutover gate needs
 *     it to mean: the table is genuinely full.
 *
 * DRAINING never creates an entry: a miss there means a flow that started after
 * the cutover, which belongs on the new AFTR and must not be pinned.
 */
static __always_inline struct flow_affinity *
touch_flow_affinity(__u32 ctrl, const struct iphdr *iph, void *data_end, bool reverse)
{
    struct flow_key key;
    build_flow_key(&key, iph, data_end, reverse);

    __u32 epoch = mig_epoch(ctrl);
    __u64 now = bpf_ktime_get_ns();

    struct flow_affinity *fa = bpf_map_lookup_elem(&flow_affinity_map, &key);
    if (fa) {
        if (mig_state(ctrl) == MIG_PRIMING)
            fa->epoch = epoch; /* re-stamp a leftover from an older migration */
        if (fa->epoch != epoch)
            return NULL; /* stale generation: as good as absent */
        fa->last_seen_ns = now;
        return fa;
    }

    if (mig_state(ctrl) != MIG_PRIMING)
        return NULL;

    struct flow_affinity nv = {.last_seen_ns = now, .epoch = epoch};
    if (bpf_map_update_elem(&flow_affinity_map, &key, &nv, BPF_ANY) < 0) {
        /* The table is full (BPF_ANY can't fail on a duplicate). The control
         * plane gates cutover on this counter: a flow we failed to record may be
         * pre-existing, and cutting over would move it to an AFTR holding no
         * state for it, so the migration is abandoned instead. */
        increase_stats_count(STAT_AFFINITY_INSERT_FAIL);
        return NULL;
    }
    increase_stats_count(STAT_AFFINITY_INSERT);
    return NULL; /* newly recorded: still the active (old) AFTR this packet */
}

/*
 * Picks the next_hop slot to encapsulate inner_iph into. In STEADY -- the
 * overwhelmingly common case -- this is just the active slot and costs nothing
 * beyond the control-word read that replaced the old active_nh read: no flow
 * parsing, no map lookup. Flow affinity only engages during a migration.
 */
static __always_inline __u32
pick_softwire_slot(__u32 ctrl, const struct iphdr *inner_iph, void *data_end)
{
    __u32 slot = mig_active_slot(ctrl);
    if (mig_state(ctrl) == MIG_STEADY)
        return slot;

    struct flow_affinity *fa = touch_flow_affinity(ctrl, inner_iph, data_end, false);

    if (mig_state(ctrl) == MIG_DRAINING && fa) {
        increase_stats_count(STAT_AFFINITY_PINNED);
        return mig_old_slot(ctrl);
    }
    return slot;
}

/*
 * Finds the valid next_hop slot whose (b4_addr, aftr_addr) matches the outer
 * IPv6 header's (daddr, saddr) -- i.e. the softwire this decapsulating packet
 * belongs to. Scanning all slots (not just the active one) lets return
 * traffic from a just-replaced AFTR keep decapping through a switch.
 */
static __always_inline struct next_hop *
find_dslite_peer_nh(const struct ipv6hdr *outer_iph)
{
#pragma unroll
    for (int i = 0; i < NUM_NEXT_HOPS; i++) {
        __u32 slot = i;
        struct next_hop *nh = bpf_map_lookup_elem(&next_hops, &slot);
        if (nh && nh->valid && ipv6_addr_equal(&outer_iph->daddr, &nh->b4_addr) &&
            ipv6_addr_equal(&outer_iph->saddr, &nh->aftr_addr))
            return nh;
    }
    return NULL;
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
 * The softwire path MTU learned for this slot, or 0 if nothing has been
 * learned or the reading has aged out (see tunnel_pmtus / learn_tunnel_pmtu).
 * Expiry is checked on read as well as on write so a path that widens again
 * stops constraining encap even if no further ICMPv6 error ever arrives.
 */
static __always_inline __u32
tunnel_pmtu_for(__u32 slot)
{
    struct tunnel_pmtu *e = bpf_map_lookup_elem(&tunnel_pmtus, &slot);
    if (!e || e->updated_ns == 0)
        return 0;
    if (bpf_ktime_get_ns() - e->updated_ns > TUNNEL_PMTU_EXPIRY_NS)
        return 0;
    return e->mtu;
}

/*
 * Softwire (outer IPv6) fragmentation for an oversized inner IPv4 packet, in
 * XDP (RFC 6333 §5.3). §5.3 -- clarified by errata 5847, which points at
 * RFC 2473 §7.2(b) and ignores the DF bit -- forbids fragmenting the inner
 * IPv4 packet: the B4 must encapsulate it whole and fragment the resulting
 * *outer IPv6* packet, whether or not the inner packet set DF. (This replaced
 * the earlier DF -> ICMPv4 Fragmentation Needed behavior here; an oversized
 * DF packet is now fragmented transparently instead of bouncing a PMTUD
 * signal. minuteman's primary MTU strategy is still the advertised WAN-40 LAN
 * MTU, so this path only carries traffic from clients that ignore it.)
 *
 * XDP emits exactly one frame per input frame, so the fragments are made by
 * cloning: the frame is encapsulated once -- outer Ethernet + IPv6
 * (nexthdr = Fragment) + Fragment header (offset 0, M=1, fresh random ID) --
 * and broadcast to frag_ports (the companion veth pairs' A ends; see that
 * map's comment for why it is one pair per fragment), where pair i's
 * xdp_softwire_frag<i> program (emit_softwire_fragment) trims its clone down
 * to fragment i and redirects it out the WAN. The Fragment header written
 * here before the broadcast is what every clone inherits, so all fragments
 * share one identification without any metadata passing.
 *
 * What the broadcast can't cover falls back to the kernel companion ip6tnl
 * exactly as before (XDP_PASS + STAT_ENCAP_FRAG_SLOW): no frag_unit
 * configured, more than MAX_SOFTWIRE_FRAGS fragments needed, or a device MTU
 * shrunk at runtime below the configured unit. That kernel path fragments the
 * inner IPv4 (non-DF) or answers Fragmentation Needed (DF) -- a reachability
 * fallback, not §5.3 conformance.
 */
static __always_inline int
encap_fragment_outer(struct xdp_md *ctx, __u64 l2_len, struct iphdr *inner_iph,
                     __u16 inner_len, const struct b4_config *cfg, __u32 wan_mtu)
{
    /* Expiring TTL: XDP_PASS so the kernel (which has the slow-path IPv4
     * default route) answers ICMPv4 Time Exceeded, as on the normal path. */
    if (inner_iph->ttl <= 1) {
        increase_stats_count(STAT_PASS);
        return XDP_PASS;
    }

    /* frag_ports must actually have somewhere to send the clones (userspace
     * populates it only once the companion veth pair is up); an unconfigured
     * map would make the broadcast a silent blackhole. */
    __u32 slot0 = 0;
    __u32 unit = cfg->frag_unit & ~7U;
    if (unit == 0 || inner_len > MAX_SOFTWIRE_FRAGS * unit ||
        inner_len > cfg->frag_max_inner ||
        unit + OUTER_IPV6_LEN + sizeof(struct frag_hdr) > wan_mtu ||
        !bpf_map_lookup_elem(&frag_ports, &slot0)) {
        increase_stats_count(STAT_ENCAP_FRAG_SLOW);
        return XDP_PASS;
    }

    /*
     * Resolve the WAN next hop for a *fragment-sized* packet (the largest
     * fragment: outer IPv6 + Fragment header + unit), never the whole
     * oversized one: bpf_fib_lookup returns FRAG_NEEDED early -- before
     * filling in ifindex/dmac/smac -- when tot_len exceeds the route MTU, so
     * looking up the full length here would leave the ingress ifindex echoed
     * back and trip the wrong-interface check. The fragments really are this
     * size, so this is also the honest question to ask the FIB.
     */
    struct bpf_fib_lookup fib = {};
    if (!lookup_aftr_nexthop(ctx, cfg, (__u16)(unit + sizeof(struct frag_hdr)), &fib))
        return XDP_PASS;

    int delta = (int)l2_len - (int)(OUTER_HDR_LEN + sizeof(struct frag_hdr));
    if (bpf_xdp_adjust_head(ctx, delta) < 0) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }

    __u8 *data = (__u8 *)(long)ctx->data;
    __u8 *data_end = (__u8 *)(long)ctx->data_end;

    struct ethhdr *outer_eth = (struct ethhdr *)data;
    struct ipv6hdr *outer_iph = (struct ipv6hdr *)(data + OUTER_ETH_LEN);
    struct frag_hdr *fh = (struct frag_hdr *)(data + OUTER_HDR_LEN);
    inner_iph = (struct iphdr *)(data + OUTER_HDR_LEN + sizeof(struct frag_hdr));

    if ((void *)(inner_iph + 1) > data_end || (void *)inner_iph + inner_len > data_end) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }

    write_outer_eth6(outer_eth, cfg, &fib, true);
    write_outer_ipv6(outer_iph, &cfg->b4_addr, &cfg->aftr_addr, IPPROTO_FRAGMENT,
                     (__u16)(inner_len + sizeof(struct frag_hdr)));
    fh->nexthdr = IPPROTO_IPIP;
    fh->reserved = 0;
    fh->frag_off = bpf_htons(1); /* offset 0, M=1 */
    fh->identification = bpf_get_prandom_u32();
    decrease_ipv4_ttl(inner_iph);

    increase_stats_count(STAT_ENCAP_FRAG_XDP);
    return bpf_redirect_map(&frag_ports, 0, BPF_F_BROADCAST);
}

/*
 * Trims one broadcast clone of encap_fragment_outer()'s encapsulated frame
 * down to outer-IPv6 fragment idx -- payload bytes [idx*unit, idx*unit +
 * unit) of the inner IPv4 packet, behind a copy of the original Ethernet +
 * IPv6 + Fragment headers with payload_len/frag_off/M rewritten -- and
 * redirects the result out the WAN. A clone beyond the last fragment (the
 * packet needed fewer than MAX_SOFTWIRE_FRAGS) is dropped, as is any stray
 * non-clone traffic the kernel puts on the pair. Runs as the rx XDP program
 * of companion veth pair idx's B end (which is also what activates the
 * pair's NAPI so it consumes XDP frames at all).
 */
static __always_inline int
emit_softwire_fragment(struct xdp_md *ctx, __u32 idx)
{
    __u8 *data = (__u8 *)(long)ctx->data;
    __u8 *data_end = (__u8 *)(long)ctx->data_end;

    __u64 l2_len = 0;
    struct ipv6hdr *ip6h = 0;
    if (parse_l2_ipv6(data, data_end, &l2_len, &ip6h) != 1 ||
        ip6h->nexthdr != IPPROTO_FRAGMENT) {
        /* Not a clone of ours: stray kernel chatter on the pair. */
        increase_stats_count(STAT_DROP);
        return XDP_DROP;
    }

    struct frag_hdr *fh = (struct frag_hdr *)(ip6h + 1);
    if ((void *)(fh + 1) > (void *)data_end) {
        increase_stats_count(STAT_DROP);
        return XDP_DROP;
    }

    __u16 plen = bpf_ntohs(ip6h->payload_len);
    if (plen < sizeof(*fh) + sizeof(struct iphdr)) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }
    __u32 total = plen - sizeof(*fh); /* inner IPv4 bytes to slice up */

    struct b4_config *g = get_b4_config();
    if (!g || !g->wan_ifindex) {
        increase_stats_count(STAT_NO_CONFIG);
        return XDP_DROP;
    }
    __u32 unit = g->frag_unit & ~7U;
    if (unit < 8 || unit > 0xffff) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }

    __u32 start = idx * unit;
    if (start >= total)
        return XDP_DROP; /* packet needs fewer fragments than clones */

    __u32 len = total - start;
    bool last = true;
    if (len > unit) {
        len = unit;
        last = false;
    }

    /* The headers survive the front trim below only as these stack copies. */
    struct ethhdr eth_copy = *(struct ethhdr *)data;
    struct ipv6hdr ip6_copy = *ip6h;
    struct frag_hdr fh_copy = *fh;

    /* Drop the payload of the preceding fragments off the front (the headers
     * go with it and are rewritten from the copies), then everything past
     * this fragment's slice off the tail. */
    if (start > 0 && bpf_xdp_adjust_head(ctx, (int)start) < 0) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }
    __u32 tail_trim = total - start - len;
    if (tail_trim > 0 && bpf_xdp_adjust_tail(ctx, -(int)tail_trim) < 0) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }

    data = (__u8 *)(long)ctx->data;
    data_end = (__u8 *)(long)ctx->data_end;

    struct ethhdr *eth = (struct ethhdr *)data;
    struct ipv6hdr *out6 = (struct ipv6hdr *)(data + OUTER_ETH_LEN);
    struct frag_hdr *outfh = (struct frag_hdr *)(data + OUTER_HDR_LEN);
    if ((void *)(outfh + 1) > (void *)data_end) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }

    *eth = eth_copy;
    ip6_copy.payload_len = bpf_htons((__u16)(len + sizeof(struct frag_hdr)));
    *out6 = ip6_copy;
    /* start is a multiple of 8, so (start/8) << 3 == start; bit 0 is M. */
    fh_copy.frag_off = bpf_htons((__u16)(start | (last ? 0 : 1)));
    *outfh = fh_copy;

    increase_stats_count(STAT_ENCAP_FRAG_SEG);
    return redirect_to_ifindex(g->wan_ifindex, STAT_REDIRECT_WAN);
}

/*
 * Sends an ICMPv6 "Packet Too Big" (RFC 4443 §3.2) reply straight back out the
 * interface the offending packet arrived on. Used from the native-IPv6
 * forwarding fastpath when the resolved egress link's MTU is too small: since
 * IPv6 is never softwire-tunneled, the original sender is directly reachable via
 * the ingress interface, so this is a plain (untunneled) reply, unlike
 * send_dslite_icmp_frag_needed's softwire-encapsulated IPv4 one.
 * src6 is the router's own routable source address for the reply; if it's
 * unset, the packet is handed to the kernel to originate the PtB instead.
 */
static __always_inline int
send_icmpv6_pkt_too_big(struct xdp_md *ctx, __u64 l2_len, const struct ipv6hdr *orig_ip6h,
                        const struct in6_addr *src6, __u32 mtu)
{
    __u8 *data = (__u8 *)(long)ctx->data;
    __u8 *data_end = (__u8 *)(long)ctx->data_end;

    if (ipv6_addr_is_unspecified(src6)) {
        increase_stats_count(STAT_IPV6_PASS);
        return XDP_PASS;
    }

    if (!icmp_error_allowed()) {
        increase_stats_count(STAT_MTU_DROP);
        increase_stats_count(STAT_ICMP_RATE_LIMITED);
        return XDP_DROP;
    }

    if (l2_len < sizeof(struct ethhdr) || l2_len > 64) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }

    if ((void *)orig_ip6h + ICMPV6_PTB_QUOTE_LEN > data_end) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }

    struct ipv6_quote quote = {};
    copy_ipv6_quote(&quote, orig_ip6h);

    if (mtu < IPV6_MIN_MTU)
        mtu = IPV6_MIN_MTU;

    __u32 new_len = (__u32)l2_len + (__u32)ICMPV6_PTB_REPLY_L3_LEN;
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
    struct ipv6hdr *iph = (struct ipv6hdr *)(data + l2_len);
    struct icmpv6_pkt_too_big *icmp =
        (struct icmpv6_pkt_too_big *)(data + l2_len + sizeof(struct ipv6hdr));

    if ((void *)(eth + 1) > data_end || (void *)(iph + 1) > data_end ||
        (void *)(icmp + 1) > data_end) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }

    write_icmpv6_pkt_too_big(eth, iph, icmp, &quote, src6, mtu);

    increase_stats_count(STAT_MTU_DROP);
    increase_stats_count(STAT_ICMP_FRAG_NEEDED);
    return XDP_TX;
}

/*
 * Native-IPv6 forwarding fastpath, shared by the LAN-ingress (encap) and
 * WAN-ingress (decap) programs and by the software-RSS cpumap stage. It is a
 * plain IPv6 router step: FIB-resolve the next hop, rewrite L2, decrement the
 * hop limit, and redirect out the egress interface -- doing in XDP what the
 * kernel slow path would otherwise do for every transit IPv6 packet. Anything
 * that isn't cleanly forwardable transit (local delivery to us, unresolved
 * neighbors, too-big packets, link-local/multicast) is handed back to the
 * kernel via XDP_PASS, so NDP/RA/DHCPv6/PMTUD all keep working unchanged.
 *
 * l2_len is ip6h's offset from the frame start (the L2 header length); the
 * frame is rewritten in place, with no bpf_xdp_adjust_head.
 */
static __always_inline int
handle_ipv6_forward(struct xdp_md *ctx, __u64 l2_len, struct ipv6hdr *ip6h,
                    const struct b4_config *cfg)
{
    if (!ipv6_is_forwardable(ip6h)) {
        increase_stats_count(STAT_IPV6_PASS);
        return XDP_PASS;
    }

    /* Let the kernel synthesize ICMPv6 Time Exceeded (mirrors the IPv4 path). */
    if (ip6h->hop_limit <= 1) {
        increase_stats_count(STAT_IPV6_PASS);
        return XDP_PASS;
    }

    struct bpf_fib_lookup fib = {};
    fib.family = AF_INET6;
    fib.l4_protocol = ip6h->nexthdr;
    fib.tot_len = (__u16)(sizeof(*ip6h) + bpf_ntohs(ip6h->payload_len));
    __builtin_memcpy(fib.ipv6_src, &ip6h->saddr, sizeof(fib.ipv6_src));
    __builtin_memcpy(fib.ipv6_dst, &ip6h->daddr, sizeof(fib.ipv6_dst));
    fib.ifindex = ctx->ingress_ifindex;

    int ret = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0);
    if (ret == BPF_FIB_LKUP_RET_FRAG_NEEDED) {
        /*
         * The egress link's MTU is too small: an IPv6 router never fragments,
         * so we originate ICMPv6 Packet Too Big ourselves rather than dropping
         * the packet -- now that IPv6 lives in the fastpath, PMTUD must be
         * served here, not by the kernel slow path we've bypassed.
         */
        return send_icmpv6_pkt_too_big(ctx, l2_len, ip6h, &cfg->b4_addr, fib.mtu_result);
    }
    if (ret != BPF_FIB_LKUP_RET_SUCCESS) {
        /*
         * NOT_FWDED (destined to one of our own addresses -> local delivery,
         * which keeps DHCPv6/dnsproxy/etc. working), NO_NEIGH (kernel resolves
         * ND, then later packets fast-path), FWD_DISABLED,
         * blackhole/unreachable/prohibit: all belong to the kernel slow path.
         */
        if (ret == BPF_FIB_LKUP_RET_NO_NEIGH)
            increase_stats_count(STAT_FIB_NO_NEIGH);
        else
            increase_stats_count(STAT_IPV6_PASS);
        return XDP_PASS;
    }

    /*
     * Egress must be a managed interface (registered in tx_ports) and distinct
     * from the ingress. The same-interface case -- e.g. ndproxy's shared /64
     * before wanextend installs its /128 host route -- is left to the kernel's
     * NDP/Redirect handling rather than hairpinned here.
     */
    if (fib.ifindex == ctx->ingress_ifindex) {
        increase_stats_count(STAT_IPV6_PASS);
        return XDP_PASS;
    }
    if (fib.ifindex != cfg->wan_ifindex && !get_lan_config(fib.ifindex)) {
        increase_stats_count(STAT_FIB_WRONG_IF);
        return XDP_PASS;
    }

    increase_stats_count(STAT_FIB_SUCCESS);

    __u8 *data = (__u8 *)(long)ctx->data;
    __u8 *data_end = (__u8 *)(long)ctx->data_end;

    struct ethhdr *eth = (struct ethhdr *)data;
    ip6h = (struct ipv6hdr *)(data + l2_len);
    if ((void *)(eth + 1) > data_end || (void *)(ip6h + 1) > data_end) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }

    __builtin_memcpy(eth->h_dest, fib.dmac, ETH_ALEN);
    __builtin_memcpy(eth->h_source, fib.smac, ETH_ALEN);
    /* h_proto stays ETH_P_IPV6. */
    decrease_ipv6_hoplimit(ip6h);

    return redirect_to_ifindex(fib.ifindex, STAT_IPV6_FWD);
}

/*
 * Optional software-RSS stage for native IPv6: when enabled, hash the flow and
 * bounce the packet to another CPU's cpu_map_v6 queue (running xdp_ipv6_fwd_cpu)
 * so forwarding work spreads across CPUs. Returns 0 -- forward inline on this
 * CPU -- when disabled, which is the default (hardware RSS, e.g. mlx4, spreads
 * flows already and makes this redundant overhead).
 */
static __always_inline int
maybe_redirect_ipv6_to_cpu(struct xdp_md *ctx, const struct ipv6hdr *ip6h, void *data_end)
{
    __u32 key = FANOUT_KEY;

    struct ipv6_rss_config *cfg = bpf_map_lookup_elem(&ipv6_rss_config_map, &key);
    if (!cfg || !cfg->enabled || cfg->cpu_count == 0)
        return 0;

    __u32 h = inner_ip6_hash(ip6h, data_end);
    __u32 idx = h % cfg->cpu_count;

    if (idx >= MAX_CPUS)
        return 0;

    __u32 *cpu = bpf_map_lookup_elem(&ipv6_rss_cpus, &idx);
    if (!cpu)
        return 0;

    increase_stats_count(STAT_IPV6_RSS_REDIRECT);
    return bpf_redirect_map(&cpu_map_v6, *cpu, 0);
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
        /*
         * Not IPv4. Native IPv6 gets the forwarding fastpath (LAN -> WAN, or
         * LAN -> LAN); anything else (ARP, VLAN-tagged IPv6, ...) is left to
         * the kernel.
         */
        __u64 l2_len6 = 0;
        struct ipv6hdr *ip6h = 0;
        if (parse_l2_ipv6(data, data_end, &l2_len6, &ip6h) == 1) {
            struct b4_config cfg6;
            if (!resolve_active_softwire(&cfg6)) {
                increase_stats_count(STAT_NO_CONFIG);
                return XDP_PASS;
            }
            int action = maybe_redirect_ipv6_to_cpu(ctx, ip6h, data_end);
            if (action)
                return action;
            return handle_ipv6_forward(ctx, l2_len6, ip6h, &cfg6);
        }
        increase_stats_count(STAT_PASS);
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

    /*
     * Only now, once this packet is known to be headed into the softwire, pick
     * its slot: the bypassed traffic above (LAN-local, broadcast/multicast,
     * DHCP) must never be recorded as a flow. pick_softwire_slot applies flow
     * affinity if an AFTR migration is in progress; in STEADY it's just the
     * active slot.
     */
    __u32 ctrl = get_migration_ctrl();
    __u32 slot = pick_softwire_slot(ctrl, inner_iph, data_end);

    struct b4_config cfg_storage;
    if (!resolve_softwire(&cfg_storage, get_next_hop(slot))) {
        increase_stats_count(STAT_NO_CONFIG);
        return XDP_PASS;
    }
    struct b4_config *cfg = &cfg_storage;

    __u16 inner_len = bpf_ntohs(inner_iph->tot_len);
    __u32 wan_mtu = 0;
    int ret =
        check_dev_mtu(ctx, cfg->wan_ifindex, TUNNEL_L3_OVERHEAD + inner_len, &wan_mtu);
    if (ret != 0 && ret != BPF_MTU_CHK_RET_FRAG_NEEDED)
        return XDP_DROP;

    /*
     * bpf_check_mtu only knows the local WAN device's MTU. A narrower link
     * further along the B4<->AFTR path shows up as an ICMPv6 Packet Too Big
     * about one of our own softwire packets, which the decap side records
     * (handle_tunnel_icmpv6 -> learn_tunnel_pmtu); honouring it here is what
     * keeps the packet from being sent at a size the path will only drop
     * again. The fragment *size* still comes from b4_config.frag_unit, which
     * userspace recomputes from the same reading -- until it does, an
     * oversized packet lands on the ip6tnl fallback rather than being
     * fragmented too big (see encap_fragment_outer's guard against frag_unit
     * exceeding the MTU passed here).
     */
    __u32 eff_mtu = wan_mtu;
    __u32 learned_mtu = tunnel_pmtu_for(slot);
    if (learned_mtu != 0 && learned_mtu < eff_mtu)
        eff_mtu = learned_mtu;

    if (ret == BPF_MTU_CHK_RET_FRAG_NEEDED || TUNNEL_L3_OVERHEAD + inner_len > eff_mtu)
        /*
         * Too big for the softwire once encapsulated: encapsulate whole and
         * fragment the *outer IPv6*, DF ignored (RFC 6333 §5.3 / errata 5847
         * -> RFC 2473 §7.2(b)); see encap_fragment_outer for the mechanism
         * and its ip6tnl fallback.
         */
        return encap_fragment_outer(ctx, l2_len, inner_iph, inner_len, cfg, eff_mtu);

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
    write_outer_ipv6(outer_iph, &cfg->b4_addr, &cfg->aftr_addr, IPPROTO_IPIP, inner_len);
    decrease_ipv4_ttl(inner_iph);

    increase_stats_count(STAT_ENCAP);
    return redirect_to_ifindex(cfg->wan_ifindex, STAT_REDIRECT_WAN);
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
    LAN_LOOKUP_DROP = 3,
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
            /*
             * The decapped inner IPv4 resolves to a forwarding egress that
             * isn't a managed LAN -- since the softwire slow path added an IPv4
             * default route via the companion ip6tnl, an unexpected inner
             * destination (not a LAN client, not local) now resolves straight
             * back into that tunnel. XDP_PASSing it would let the kernel
             * re-encapsulate it toward the AFTR (a reflection); drop it instead.
             * Local delivery to the CPE itself is BPF_FIB_LKUP_RET_NOT_FWDED, a
             * different branch below, so this never drops a packet meant for us.
             */
            increase_stats_count(STAT_DECAP_MARTIAN);
            return LAN_LOOKUP_DROP;
        }
        if (ret == BPF_FIB_LKUP_RET_SUCCESS) {
            increase_stats_count(STAT_FIB_SUCCESS);
            return LAN_LOOKUP_OK;
        }
        if (mtu_out)
            *mtu_out = fib->mtu_result;
        return LAN_LOOKUP_FRAG_NEEDED;
    }

    if (ret == BPF_FIB_LKUP_RET_NO_NEIGH) {
        /*
         * The route resolved but has no neighbor yet. For a managed LAN that's
         * a client not in the neighbor table -- XDP_PASS so the kernel resolves
         * ND and delivers. But the companion ip6tnl is a NOARP point-to-point
         * device, so the IPv4 default route through it can surface here too;
         * that (like the SUCCESS case above) is an off-LAN martian that must be
         * dropped, not passed into the kernel to bounce back through the tunnel.
         */
        if (fib->ifindex != cfg->wan_ifindex && get_lan_config(fib->ifindex)) {
            increase_stats_count(STAT_FIB_NO_NEIGH);
            return LAN_LOOKUP_FAIL;
        }
        increase_stats_count(STAT_DECAP_MARTIAN);
        return LAN_LOOKUP_DROP;
    }

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
                             const struct iphdr *inner_iph, __u16 next_mtu)
{
    __u8 *data = (__u8 *)(long)ctx->data;
    __u8 *data_end = (__u8 *)(long)ctx->data_end;

    if (inner_iph->ihl != 5) {
        increase_stats_count(STAT_MTU_DROP);
        return XDP_DROP;
    }

    if (!icmp_error_allowed()) {
        increase_stats_count(STAT_MTU_DROP);
        increase_stats_count(STAT_ICMP_RATE_LIMITED);
        return XDP_DROP;
    }

    if (bpf_ntohs(inner_iph->tot_len) < ICMP_FRAG_QUOTE_LEN ||
        (void *)inner_iph + ICMP_FRAG_QUOTE_LEN > data_end) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }

    struct ipv4_quote quote = {};
    copy_ipv4_quote(&quote, inner_iph);

    /* RFC 1812 §4.3.2.7: no ICMP error for a non-initial fragment, another
     * ICMP error, or a source that isn't a single host. The offending packet
     * is too big for the egress either way, so it is simply dropped. */
    if (!icmp_error_eligible(&quote)) {
        increase_stats_count(STAT_MTU_DROP);
        return XDP_DROP;
    }

    struct bpf_fib_lookup fib = {};
    if (!lookup_aftr_nexthop(ctx, cfg, ICMP_FRAG_REPLY_L3_LEN, &fib))
        return XDP_DROP;

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
                                  &cfg->aftr_addr, next_mtu);
    write_outer_eth6(eth, cfg, &fib, true);

    increase_stats_count(STAT_MTU_DROP);
    increase_stats_count(STAT_ICMP_FRAG_NEEDED);
    return redirect_to_ifindex(cfg->wan_ifindex, STAT_REDIRECT_WAN);
}

/*
 * Sends an ICMPv4 Time Exceeded (RFC 1812 §5.3.1) for a decapped inner packet
 * whose TTL expired at the B4, re-encapsulated back through the softwire: like
 * the Fragmentation Needed above, the original IPv4 sender is only reachable
 * via the AFTR. Sourced from the well-known B4 address 192.0.0.2 (RFC 6333
 * §5.7 / RFC 7335), not from a LAN gateway address.
 *
 * Every case this can't handle in XDP is XDP_PASSed rather than dropped: the
 * companion ip6tnl decapsulates the packet and the kernel's own IPv4
 * forwarding then originates the Time Exceeded, exactly as it already does for
 * the encap (outbound) direction. Only an unusable next hop or the ICMP rate
 * limiter drops.
 */
static __always_inline int
send_dslite_icmp_time_exceeded(struct xdp_md *ctx, const struct b4_config *cfg,
                               const struct iphdr *inner_iph)
{
    __u8 *data = (__u8 *)(long)ctx->data;
    __u8 *data_end = (__u8 *)(long)ctx->data_end;

    if (inner_iph->ihl != 5) {
        increase_stats_count(STAT_DECAP_PASS);
        return XDP_PASS;
    }

    if (bpf_ntohs(inner_iph->tot_len) < ICMP_FRAG_QUOTE_LEN ||
        (void *)inner_iph + ICMP_FRAG_QUOTE_LEN > data_end) {
        increase_stats_count(STAT_DECAP_PASS);
        return XDP_PASS;
    }

    struct ipv4_quote quote = {};
    copy_ipv4_quote(&quote, inner_iph);

    /* RFC 1812 §4.3.2.7: no ICMP error for a non-initial fragment, another
     * ICMP error, or a source that isn't a single host. */
    if (!icmp_error_eligible(&quote)) {
        increase_stats_count(STAT_DECAP_PASS);
        return XDP_PASS;
    }

    /*
     * The reply is a fixed 110 bytes, built by shrinking this frame in place;
     * a smaller offending packet (a bare TCP SYN from a TCP traceroute, say)
     * can't be rewritten into one, so it goes to the kernel instead of being
     * treated as a datapath bug.
     */
    __u32 new_len =
        OUTER_ETH_LEN + (__u32)OUTER_IPV6_LEN + (__u32)ICMP_TIME_EXCEEDED_REPLY_L3_LEN;
    __u32 old_len = data_end - data;
    if (new_len > old_len) {
        increase_stats_count(STAT_DECAP_PASS);
        return XDP_PASS;
    }

    if (!icmp_error_allowed()) {
        increase_stats_count(STAT_ICMP_RATE_LIMITED);
        return XDP_DROP;
    }

    struct bpf_fib_lookup fib = {};
    if (!lookup_aftr_nexthop(ctx, cfg, ICMP_TIME_EXCEEDED_REPLY_L3_LEN, &fib))
        return XDP_DROP;

    if (bpf_xdp_adjust_tail(ctx, (int)new_len - (int)old_len) < 0) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }

    data = (__u8 *)(long)ctx->data;
    data_end = (__u8 *)(long)ctx->data_end;

    struct ethhdr *eth = (struct ethhdr *)data;
    struct ipv6hdr *outer_iph = (struct ipv6hdr *)(data + OUTER_ETH_LEN);
    struct iphdr *icmp_iph = (struct iphdr *)(data + OUTER_HDR_LEN);
    struct icmp_time_exceeded *icmp =
        (struct icmp_time_exceeded *)(data + OUTER_HDR_LEN + sizeof(struct iphdr));

    if ((void *)(eth + 1) > data_end || (void *)(outer_iph + 1) > data_end ||
        (void *)(icmp_iph + 1) > data_end || (void *)(icmp + 1) > data_end) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }

    write_dslite_icmp_time_exceeded(eth, outer_iph, icmp_iph, icmp, &quote, &cfg->b4_addr,
                                    &cfg->aftr_addr);
    write_outer_eth6(eth, cfg, &fib, true);

    increase_stats_count(STAT_ICMP_TIME_EXCEEDED);
    return redirect_to_ifindex(cfg->wan_ifindex, STAT_REDIRECT_WAN);
}

/*
 * Returned by handle_tunnel_icmpv6 for a packet it decided isn't its business:
 * the caller then carries on with the branch it would have taken anyway (the
 * native-IPv6 fastpath), rather than this having to guess an XDP action for
 * every ICMPv6 packet that merely arrived on the WAN. Outside the XDP_* range
 * on purpose.
 */
#define TUNNEL_ICMP_NOT_MINE (-1)

/*
 * Records the softwire path MTU an ICMPv6 Packet Too Big reported for one of
 * our own tunnel packets. Floored at the IPv6 minimum MTU (RFC 8201 §4: a node
 * must not reduce its path MTU below 1280), which is also what makes a forged
 * PtB harmless -- the smallest MTU anyone can talk us into is one every IPv6
 * path must already support.
 *
 * A *smaller* MTU is always taken; a larger one only once the current reading
 * has aged out, so a single stale or forged large value can't undo a real
 * narrowing. Userspace ages entries on the same timescale (see tunnel_pmtus).
 */
static __always_inline void
learn_tunnel_pmtu(__u32 slot, __u32 mtu)
{
    if (mtu < IPV6_MIN_MTU)
        mtu = IPV6_MIN_MTU;

    struct tunnel_pmtu *e = bpf_map_lookup_elem(&tunnel_pmtus, &slot);
    if (!e)
        return;

    __u64 now = bpf_ktime_get_ns();
    if (e->updated_ns != 0 && mtu >= e->mtu &&
        now - e->updated_ns < TUNNEL_PMTU_EXPIRY_NS)
        return;

    e->mtu = mtu;
    e->updated_ns = now;
    increase_stats_count(STAT_TUNNEL_PMTU);
}

/*
 * The next_hop slot whose softwire the given quoted header describes -- i.e.
 * one of *our own* outbound tunnel packets (b4 -> aftr), the reverse of
 * find_dslite_peer_nh's inbound match. `error_dst` is the destination of the
 * ICMPv6 error carrying the quote, required to be that same slot's B4 address:
 * an error about our softwire that wasn't addressed to us isn't ours to act on.
 */
static __always_inline int
find_dslite_local_slot(const struct ipv6hdr *quoted, const struct in6_addr *error_dst)
{
#pragma unroll
    for (int i = 0; i < NUM_NEXT_HOPS; i++) {
        __u32 slot = i;
        struct next_hop *nh = bpf_map_lookup_elem(&next_hops, &slot);
        if (nh && nh->valid && ipv6_addr_equal(&quoted->saddr, &nh->b4_addr) &&
            ipv6_addr_equal(&quoted->daddr, &nh->aftr_addr) &&
            ipv6_addr_equal(error_dst, &nh->b4_addr))
            return i;
    }
    return -1;
}

/*
 * RFC 2473 §8: relays an ICMPv6 error an intermediate IPv6 router on the
 * B4<->AFTR path sent *about a softwire packet* into an ICMPv4 error toward the
 * LAN client whose packet it quoted. Without this the tunnel is opaque to the
 * error -- the IPv4 sender learns nothing, since the ICMPv6 error is addressed
 * to the B4, not to it. The encap path's own bpf_check_mtu only ever sees the
 * local WAN device's MTU, so a Packet Too Big from further along the path is
 * the *only* way a narrower link there becomes known; it is also recorded
 * (learn_tunnel_pmtu) whether or not it is relayed.
 *
 * The type mapping follows RFC 7915 §5.3's ICMPv6->ICMPv4 table. Packet Too Big
 * is relayed only for a DF quote: without DF the sender can't act on a
 * next-hop-MTU signal, and this B4 answers that case by fragmenting the outer
 * IPv6 at the learned MTU instead (RFC 6333 §5.3 / errata 5847 -> RFC 2473
 * §7.2(b), the same DF-ignoring stance encap_fragment_outer takes).
 *
 * Anything not matched here is left alone (TUNNEL_ICMP_NOT_MINE) or handed to
 * the kernel (XDP_PASS), never dropped silently: a plain ICMPv6 error addressed
 * to the CPE itself must still reach the local stack.
 */
static __always_inline int
handle_tunnel_icmpv6(struct xdp_md *ctx, __u64 l2_len, const struct ipv6hdr *ip6h,
                     __u8 *data_end)
{
    struct icmpv6_error_hdr *icmp6 = (struct icmpv6_error_hdr *)(ip6h + 1);
    if ((void *)(icmp6 + 1) > (void *)data_end)
        return TUNNEL_ICMP_NOT_MINE;

    if (icmp6->type != ICMPV6_DEST_UNREACH && icmp6->type != ICMPV6_PKT_TOOBIG &&
        icmp6->type != ICMPV6_TIME_EXCEED)
        return TUNNEL_ICMP_NOT_MINE;

    /* The invoking packet, as much of it as the sender quoted. */
    struct ipv6hdr *quoted = (struct ipv6hdr *)(icmp6 + 1);
    if ((void *)(quoted + 1) > (void *)data_end)
        return TUNNEL_ICMP_NOT_MINE;

    int slot = find_dslite_local_slot(quoted, &ip6h->daddr);
    if (slot < 0)
        return TUNNEL_ICMP_NOT_MINE;

    /*
     * Past this point the error is definitely about a softwire packet this B4
     * sent, so every remaining exit is a counted decision rather than a
     * fallthrough to the native-IPv6 path.
     */
    struct iphdr *inner = 0;
    if (quoted->nexthdr == IPPROTO_IPIP) {
        inner = (struct iphdr *)(quoted + 1);
    } else if (quoted->nexthdr == IPPROTO_FRAGMENT) {
        /*
         * The quote is one of our own outer-IPv6 fragments. Only the first
         * carries the inner IPv4 header; a later one has nothing to address a
         * relayed error to (and its arrival means the first was seen too).
         */
        struct frag_hdr *fh = (struct frag_hdr *)(quoted + 1);
        if ((void *)(fh + 1) > (void *)data_end) {
            increase_stats_count(STAT_TUNNEL_ICMP_PASS);
            return XDP_PASS;
        }
        if ((fh->frag_off & bpf_htons(0xfff8)) != 0 || fh->nexthdr != IPPROTO_IPIP) {
            increase_stats_count(STAT_TUNNEL_ICMP_PASS);
            return XDP_PASS;
        }
        inner = (struct iphdr *)(fh + 1);
    } else {
        increase_stats_count(STAT_TUNNEL_ICMP_PASS);
        return XDP_PASS;
    }

    if ((void *)inner + ICMP_FRAG_QUOTE_LEN > (void *)data_end || inner->version != 4 ||
        inner->ihl != 5) {
        /* Too little of the invoking packet quoted to build a reply from, or an
         * inner this datapath's fixed-size quote can't express (IPv4 options). */
        increase_stats_count(STAT_TUNNEL_ICMP_PASS);
        return XDP_PASS;
    }

    struct ipv4_quote quote = {};
    copy_ipv4_quote(&quote, inner);

    __u8 rel_type = 0, rel_code = 0;
    __u32 rel_extra = 0;
    bool relay = false;

    switch (icmp6->type) {
    case ICMPV6_PKT_TOOBIG: {
        __u32 ptb_mtu = bpf_ntohl(icmp6->extra);

        learn_tunnel_pmtu((__u32)slot, ptb_mtu);

        if (!ipv4_has_df(&quote.iph)) {
            /*
             * A sender that didn't set DF can't act on a next-hop MTU, and this
             * B4's answer for it is to fragment the outer IPv6 at the MTU just
             * learned rather than push the problem back (RFC 6333 §5.3 /
             * errata 5847 -> RFC 2473 §7.2(b)). Everything of value has been
             * taken from the error, so it is consumed here: XDP_PASSing it
             * would just let the kernel's own ip6tnl relay the very signal
             * minuteman deliberately isn't sending.
             */
            increase_stats_count(STAT_TUNNEL_ICMP_DROP);
            return XDP_DROP;
        }

        __u32 next_mtu = ptb_mtu > TUNNEL_L3_OVERHEAD ? ptb_mtu - TUNNEL_L3_OVERHEAD : 0;
        if (next_mtu < ICMPV4_MIN_MTU)
            next_mtu = ICMPV4_MIN_MTU;
        if (next_mtu > 0xffff)
            next_mtu = 0xffff;

        rel_type = ICMP_DEST_UNREACH;
        rel_code = ICMP_FRAG_NEEDED;
        rel_extra = next_mtu; /* low 16 bits of the word == next-hop MTU */
        relay = true;
        break;
    }
    case ICMPV6_TIME_EXCEED:
        rel_type = ICMP_TIME_EXCEEDED;
        rel_code = icmp6->code == 1 ? ICMP_EXC_FRAGTIME : ICMP_EXC_TTL;
        relay = true;
        break;
    case ICMPV6_DEST_UNREACH:
        switch (icmp6->code) {
        case ICMPV6_NOROUTE:
        case ICMPV6_ADDR_UNREACH:
            rel_type = ICMP_DEST_UNREACH;
            rel_code = ICMP_HOST_UNREACH;
            relay = true;
            break;
        case ICMPV6_ADM_PROHIBITED:
        case ICMPV6_POLICY_FAIL:
            rel_type = ICMP_DEST_UNREACH;
            rel_code = ICMP_HOST_ANO;
            relay = true;
            break;
        }
        break;
    }

    if (!relay) {
        increase_stats_count(STAT_TUNNEL_ICMP_PASS);
        return XDP_PASS;
    }

    /*
     * RFC 1812 §4.3.2.7, exactly as on the paths that originate these errors.
     * Dropped rather than XDP_PASSed: the rule forbids the error being
     * originated at all, and passing it up would just have the kernel's ip6tnl
     * originate the one this datapath is refusing to.
     */
    if (!icmp_error_eligible(&quote)) {
        increase_stats_count(STAT_TUNNEL_ICMP_DROP);
        return XDP_DROP;
    }

    struct b4_config *g = get_b4_config();
    if (!g) {
        increase_stats_count(STAT_NO_CONFIG);
        return XDP_PASS;
    }

    /*
     * Resolve the LAN client the relayed error is addressed to. Requiring it to
     * resolve to a managed LAN interface is also the spoof check: an ICMPv6
     * error quoting a fabricated inner source can't reach a LAN egress, and one
     * quoting a real LAN client's address is exactly what a genuine error does.
     */
    struct bpf_fib_lookup fib = {};
    fib.family = AF_INET;
    fib.l4_protocol = IPPROTO_ICMP;
    fib.tot_len = (__u16)ICMPV4_ERROR_L3_LEN;
    fib.ipv4_dst = quote.iph.saddr;
    fib.ifindex = ctx->ingress_ifindex;

    if (bpf_fib_lookup(ctx, &fib, sizeof(fib), 0) != BPF_FIB_LKUP_RET_SUCCESS ||
        fib.ifindex == g->wan_ifindex || !get_lan_config(fib.ifindex)) {
        increase_stats_count(STAT_TUNNEL_ICMP_PASS);
        return XDP_PASS;
    }

    __u8 *data = (__u8 *)(long)ctx->data;
    __u32 old_len = (__u32)(data_end - data);
    if (l2_len != OUTER_ETH_LEN || old_len < ICMPV4_ERROR_FRAME_LEN) {
        increase_stats_count(STAT_TUNNEL_ICMP_PASS);
        return XDP_PASS;
    }

    /*
     * Last, so the token is spent only on an error that is actually about to be
     * written: every check above can still bail out to the kernel, and this
     * bucket is shared with the datapath's own originated errors
     * (send_dslite_icmp_frag_needed, send_icmpv6_pkt_too_big) -- a stream of
     * matching-but-unrelayable ICMPv6 would otherwise starve those of tokens.
     */
    if (!icmp_error_allowed()) {
        increase_stats_count(STAT_ICMP_RATE_LIMITED);
        return XDP_DROP;
    }

    if (old_len > ICMPV4_ERROR_FRAME_LEN &&
        bpf_xdp_adjust_tail(ctx, (int)ICMPV4_ERROR_FRAME_LEN - (int)old_len) < 0) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }

    data = (__u8 *)(long)ctx->data;
    data_end = (__u8 *)(long)ctx->data_end;

    struct ethhdr *eth = (struct ethhdr *)data;
    struct iphdr *out_iph = (struct iphdr *)(data + OUTER_ETH_LEN);
    struct icmpv4_error *out_icmp =
        (struct icmpv4_error *)(data + OUTER_ETH_LEN + sizeof(struct iphdr));

    if ((void *)(eth + 1) > (void *)data_end ||
        (void *)(out_iph + 1) > (void *)data_end ||
        (void *)(out_icmp + 1) > (void *)data_end) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }

    write_lan_icmpv4_error(eth, out_iph, out_icmp, &quote, &fib, rel_type, rel_code,
                           rel_extra);

    increase_stats_count(STAT_TUNNEL_ICMP_RELAY);
    return redirect_to_ifindex(fib.ifindex, STAT_REDIRECT_LAN);
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

    if (outer_iph->nexthdr != IPPROTO_IPIP) {
        increase_stats_count(STAT_DECAP_NOT_DSLITE);
        return XDP_PASS;
    }

    struct next_hop *nh = find_dslite_peer_nh(outer_iph);
    if (!nh) {
        increase_stats_count(STAT_DECAP_PASS);
        return XDP_PASS;
    }

    /* Loaded once for this packet (see get_migration_ctrl). */
    __u32 ctrl_decap = get_migration_ctrl();

    /* Resolve against the matched slot so a return-path ICMP re-encapsulates
     * back through the AFTR this packet actually came from, not just the
     * active one (they differ briefly during a live AFTR switch). */
    struct b4_config cfg_storage;
    if (!resolve_softwire(&cfg_storage, nh)) {
        increase_stats_count(STAT_NO_CONFIG);
        return XDP_PASS;
    }
    struct b4_config *cfg = &cfg_storage;

    struct iphdr *inner_iph_pre = 0;
    __u16 inner_len = 0;
    int ret = validate_dslite_ipv6(data_end, outer_iph, &inner_iph_pre, &inner_len);
    if (ret != -1)
        return ret;

    /*
     * Feed the migration's flow table from the downlink too (reversed key ==
     * the forward key encap recorded). Decap makes no routing choice here --
     * the packet has already arrived, and find_dslite_peer_nh above accepts
     * either AFTR -- but without this a download-heavy flow (few uplink
     * packets, many downlink) would look idle to the drain GC and have its
     * pin expired out from under it mid-stream. In STEADY this is a single
     * predictable branch and no map access at all.
     */
    if (mig_state(ctrl_decap) != MIG_STEADY)
        touch_flow_affinity(ctrl_decap, inner_iph_pre, data_end, true);

    struct ethhdr old_eth = *(struct ethhdr *)data;

    struct bpf_fib_lookup fib = {};
    __u16 fib_mtu = 0;
    int lan_lookup =
        lookup_lan_nexthop(ctx, cfg, inner_iph_pre, inner_len, &fib, &fib_mtu);
    bool fast = lan_lookup == LAN_LOOKUP_OK;

    /* Off-LAN martian (would bounce back into the softwire) -- drop before
     * decap rather than XDP_PASS it into the kernel's default route. */
    if (lan_lookup == LAN_LOOKUP_DROP)
        return XDP_DROP;

    /*
     * TTL expiry (RFC 1812 §5.3.1) applies only to a packet this B4 is
     * actually *forwarding*, which is why it is decided after the FIB lookup
     * and not on arrival: LAN_LOOKUP_FAIL covers BPF_FIB_LKUP_RET_NOT_FWDED,
     * i.e. a packet addressed to one of the CPE's own IPv4 addresses, which is
     * perfectly legal at TTL 1 and must be delivered locally (the slow path
     * below XDP_PASSes it) rather than answered with Time Exceeded. It also
     * covers NO_NEIGH, where the kernel is the one that finishes the job.
     */
    if ((fast || lan_lookup == LAN_LOOKUP_FRAG_NEEDED) && inner_iph_pre->ttl <= 1)
        return send_dslite_icmp_time_exceeded(ctx, cfg, inner_iph_pre);

    if (lan_lookup == LAN_LOOKUP_FRAG_NEEDED) {
        __u32 next_mtu = fib_mtu;
        if (next_mtu < ICMPV4_MIN_MTU)
            next_mtu = ICMPV4_MIN_MTU;
        if (next_mtu > 0xffff)
            next_mtu = 0xffff;

        if (ipv4_has_df(inner_iph_pre))
            return send_dslite_icmp_frag_needed(ctx, cfg, inner_iph_pre, (__u16)next_mtu);

        /*
         * Fragmentable (non-DF) but too big for the LAN egress: hand the still-
         * encapsulated packet to the kernel (adjust_head hasn't run yet), where
         * the companion ip6tnl decaps it and the IPv4 layer fragments toward the
         * LAN rather than dropping (RFC 6333 §5.3).
         */
        increase_stats_count(STAT_DECAP_FRAG_SLOW);
        return XDP_PASS;
    }

    if (fast) {
        __u32 lan_mtu = 0;
        ret = check_dev_mtu(ctx, fib.ifindex, inner_len, &lan_mtu);
        if (ret == BPF_MTU_CHK_RET_FRAG_NEEDED) {
            __u32 next_mtu = lan_mtu;
            if (next_mtu < ICMPV4_MIN_MTU)
                next_mtu = ICMPV4_MIN_MTU;
            if (next_mtu > 0xffff)
                next_mtu = 0xffff;

            if (ipv4_has_df(inner_iph_pre))
                return send_dslite_icmp_frag_needed(ctx, cfg, inner_iph_pre,
                                                    (__u16)next_mtu);

            /* Non-DF and too big for the LAN egress: same slow path as above --
             * the kernel ip6tnl decaps and IPv4-fragments toward the LAN. */
            increase_stats_count(STAT_DECAP_FRAG_SLOW);
            return XDP_PASS;
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

    /*
     * A fragmented softwire packet (IPv6 fragment header) addressed to us:
     * XDP can't reassemble, so hand it to the kernel, where the companion
     * ip6tnl reassembles and decapsulates it (RFC 6333 §5.3). Checked before
     * the native-IPv6 branch so it's an explicit, countable slow path rather
     * than an incidental XDP_PASS out of handle_ipv6_forward's FIB lookup.
     */
    if (outer_iph->nexthdr == IPPROTO_FRAGMENT && find_dslite_peer_nh(outer_iph)) {
        increase_stats_count(STAT_DECAP_REASM_PASS);
        return XDP_PASS;
    }

    /*
     * An ICMPv6 error about a softwire packet we sent (RFC 2473 §8): relayed to
     * the LAN client as an ICMPv4 error, and mined for the path MTU. Checked
     * before the native-IPv6 branch below, which would otherwise XDP_PASS it as
     * ordinary traffic addressed to the CPE -- anything this doesn't claim
     * still takes exactly that path.
     */
    if (outer_iph->nexthdr == IPPROTO_ICMPV6) {
        int relayed = handle_tunnel_icmpv6(ctx, l2_len, outer_iph, data_end);
        if (relayed != TUNNEL_ICMP_NOT_MINE)
            return relayed;
        /*
         * Nothing was touched on the path that returns NOT_MINE, but one of the
         * other paths through that function calls bpf_xdp_adjust_tail, and the
         * verifier merges them: every packet pointer derived before the call is
         * a scalar to it from here on. Re-derive them.
         */
        data = (__u8 *)(long)ctx->data;
        data_end = (__u8 *)(long)ctx->data_end;
        if (parse_l2_ipv6(data, data_end, &l2_len, &outer_iph) != 1) {
            increase_stats_count(STAT_DECAP_PASS);
            return XDP_PASS;
        }
    }

    if (outer_iph->nexthdr != IPPROTO_IPIP) {
        /*
         * Native (non-softwire) IPv6 arriving on the WAN gets the forwarding
         * fastpath (WAN -> LAN) instead of being passed to the kernel.
         */
        struct b4_config cfg6;
        if (!resolve_active_softwire(&cfg6))
            return XDP_PASS;
        int v6action = maybe_redirect_ipv6_to_cpu(ctx, outer_iph, data_end);
        if (v6action)
            return v6action;
        return handle_ipv6_forward(ctx, l2_len, outer_iph, &cfg6);
    }

    if (!find_dslite_peer_nh(outer_iph))
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

/*
 * Software-RSS second stage for native IPv6: runs on the CPU maybe_redirect_
 * ipv6_to_cpu fanned the packet out to (via cpu_map_v6), re-parses the frame,
 * and performs the same handle_ipv6_forward step there. Ingress ifindex is
 * preserved across the cpumap redirect, so the FIB lookup and egress/ingress
 * checks behave exactly as they would on the inline path.
 */
SEC("xdp/cpumap")
int
xdp_ipv6_fwd_cpu(struct xdp_md *ctx)
{
    __u8 *data = (__u8 *)(long)ctx->data;
    __u8 *data_end = (__u8 *)(long)ctx->data_end;

    __u64 l2_len = 0;
    struct ipv6hdr *ip6h = 0;
    if (parse_l2_ipv6(data, data_end, &l2_len, &ip6h) != 1) {
        increase_stats_count(STAT_IPV6_PASS);
        return XDP_PASS;
    }

    struct b4_config cfg;
    if (!resolve_active_softwire(&cfg)) {
        increase_stats_count(STAT_NO_CONFIG);
        return XDP_PASS;
    }

    return handle_ipv6_forward(ctx, l2_len, ip6h, &cfg);
}

/*
 * The rx XDP programs of the softwire-fragmentation companion veth pairs'
 * B ends: pair i's program turns the broadcast clone arriving there into
 * outer-IPv6 fragment i and sends it out the WAN (see encap_fragment_outer /
 * emit_softwire_fragment). One program per possible fragment, its index a
 * compile-time constant: nothing about the clones themselves differs, so
 * which fragment a clone becomes is decided entirely by which pair it was
 * cloned into (see frag_ports for why that must be one *device* per
 * fragment, not one devmap egress program per entry).
 */
#define SOFTWIRE_FRAG_PROG(i)                                                            \
    SEC("xdp")                                                                           \
    int xdp_softwire_frag##i(struct xdp_md *ctx)                                         \
    {                                                                                    \
        return emit_softwire_fragment(ctx, i);                                           \
    }

SOFTWIRE_FRAG_PROG(0)
SOFTWIRE_FRAG_PROG(1)
SOFTWIRE_FRAG_PROG(2)
SOFTWIRE_FRAG_PROG(3)

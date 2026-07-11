#!/bin/bash
# Builds the DS-Lite (RFC 6333) netns test rig described in common.sh.
# Requires root (network namespaces, veth, iptables) and dnsmasq.
#
# Usage: sudo ./test/netns/setup.sh
#        sudo MM_AFTR_DISCOVERY=hb46pp ./test/netns/setup.sh
#
# MM_AFTR_DISCOVERY selects how mm-isp publishes the AFTR's address:
#   dhcpv6 (default) -- Kea serves RFC 6334 OPTION_AFTR_NAME over stateless
#                       DHCPv6, exercising minuteman's pkg/aftrdiscovery path.
#   hb46pp           -- Kea withholds option 64; dnsmasq instead serves the
#                       4over6.info discovery TXT record and a provisioning
#                       HTTP server (python3 http.server) answers with the
#                       DS-Lite JSON, exercising minuteman's pkg/hb46pp
#                       fallback path (DHCPv6 Reply without AFTR-Name ->
#                       HB46PP).
#
# After this completes, run minuteman as the B4 with test/netns/run-cpe.sh,
# then test end-to-end connectivity with test/netns/smoketest.sh (it reads
# the mode this script recorded and asserts the matching discovery checks).

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./common.sh

if [[ $EUID -ne 0 ]]; then
    echo "must run as root" >&2
    exit 1
fi

AFTR_DISCOVERY="${MM_AFTR_DISCOVERY:-dhcpv6}"
case "$AFTR_DISCOVERY" in
dhcpv6 | hb46pp) ;;
*)
    echo "error: MM_AFTR_DISCOVERY must be 'dhcpv6' or 'hb46pp' (got '$AFTR_DISCOVERY')" >&2
    exit 1
    ;;
esac

# veth TX checksum/GSO/TSO/SG offloads leave TCP segments with an unfinalized
# (CHECKSUM_PARTIAL) checksum, on the assumption that a real NIC (or the
# kernel stack at final delivery) will fill it in later. minuteman's XDP
# programs run in native/driver mode directly on the raw frame *before* an skb
# exists, so they read whatever bytes are actually in the buffer -- if the
# checksum hasn't been finalized yet, the datapath's incremental
# checksum-update helpers (TTL decrement, etc.) corrupt it instead of fixing
# it, and the corrupted segment is silently dropped at the real destination.
# ICMP is unaffected (ping computes its checksum in userspace before the
# packet ever reaches the kernel), which is why only TCP broke. Same fix gregw
# (the sister GRE-tunnel project this datapath was modeled on) applies in its
# own netns rig: https://github.com/shun159/gregw/blob/master/scripts/create-netns.sh
disable_veth_offloads() {
    local ns=$1 dev=$2
    ip netns exec "$ns" ethtool -K "$dev" tx off gso off tso off sg off >/dev/null
}

# The AFTR's decap step needs the ip6_tunnel kernel module (mode ipip6, i.e.
# IPv4-in-IPv6). Check it up front with a clear message: on Arch this module
# commonly goes missing right after a kernel package upgrade, since the old
# kernel's /lib/modules/<old-version>/ gets replaced by the new package's
# before the machine has rebooted into that new kernel -- `uname -r` and the
# on-disk module directory then disagree, and modprobe fails with nothing
# useful to go on.
if ! lsmod | grep -q '^ip6_tunnel' && ! modprobe -n ip6_tunnel >/dev/null 2>&1; then
    running="$(uname -r)"
    echo "error: ip6_tunnel kernel module unavailable for the running kernel ($running)." >&2
    if [[ ! -d "/lib/modules/$running" ]]; then
        echo "  /lib/modules/$running does not exist on disk -- the running kernel and the" >&2
        echo "  installed kernel package have diverged (common right after a kernel upgrade" >&2
        echo "  on Arch, before rebooting). Reboot into the currently installed kernel and" >&2
        echo "  re-run this script." >&2
    else
        echo "  Try: sudo modprobe ip6_tunnel" >&2
    fi
    exit 1
fi

if ! command -v kea-dhcp6 >/dev/null 2>&1; then
    echo "error: kea-dhcp6 not found in PATH (needed for the DHCPv6-PD server in mm-isp)." >&2
    echo "  Try: sudo pacman -S kea" >&2
    exit 1
fi

if [[ "$AFTR_DISCOVERY" == hb46pp ]] && ! command -v python3 >/dev/null 2>&1; then
    echo "error: python3 not found in PATH (needed for the HB46PP provisioning HTTP server in mm-isp)." >&2
    exit 1
fi

if ip netns list | grep -qE "^($NETNS_HOST|$NETNS_CPE|$NETNS_ISP|$NETNS_AFTR|$NETNS_INET)( |$)"; then
    echo "one or more mm-* namespaces already exist; run teardown.sh first" >&2
    exit 1
fi

mkdir -p "$RUNDIR"

echo "== creating namespaces =="
for ns in "${ALL_NETNS[@]}"; do
    ip netns add "$ns"
    ip netns exec "$ns" ip link set lo up
done

echo "== creating veth links =="
ip link add "$VETH_HOST_CPE" netns "$NETNS_HOST" type veth peer name "$VETH_CPE_HOST" netns "$NETNS_CPE"
ip link add "$VETH_CPE_ISP" netns "$NETNS_CPE" type veth peer name "$VETH_ISP_CPE" netns "$NETNS_ISP"
ip link add "$VETH_ISP_AFTR" netns "$NETNS_ISP" type veth peer name "$VETH_AFTR_ISP" netns "$NETNS_AFTR"
ip link add "$VETH_AFTR_INET" netns "$NETNS_AFTR" type veth peer name "$VETH_INET_AFTR" netns "$NETNS_INET"

echo "== mm-host: LAN client =="
netns_exec "$NETNS_HOST" ip addr add "$LAN_HOST_ADDR" dev "$VETH_HOST_CPE"
netns_exec "$NETNS_HOST" ip link set "$VETH_HOST_CPE" up
netns_exec "$NETNS_HOST" ip route add default via "${LAN_CPE_ADDR%/*}"
disable_veth_offloads "$NETNS_HOST" "$VETH_HOST_CPE"
# v-host-cpe (this end) has no XDP program of its own; it's the *peer* of
# mm-cpe's LAN-side XDP redirect target (v-cpe-host). The kernel only sets up
# the NAPI/ptr_ring a redirected frame needs on a veth end that either runs
# its own XDP program or has GRO enabled -- without one of those, every
# xdp_dslite_encap redirect into v-cpe-host silently drops on the source
# side's rx_queue_drops counter and never reaches the wire.
netns_exec "$NETNS_HOST" ethtool -K "$VETH_HOST_CPE" gro on

# mm-isp's RA/dnsmasq must be up and answering *before* mm-cpe's WAN link
# comes up below: Linux only retries Router Solicitation a few times right
# after an interface goes up, so starting the RA server afterwards means the
# CPE gives up before ever seeing an answer.
echo "== mm-isp: ISP IPv6 access network (RA + stateless DHCPv6 + AFTR-Name) =="
netns_exec "$NETNS_ISP" sysctl -qw net.ipv6.conf.all.forwarding=1
netns_exec "$NETNS_ISP" ip addr add "$WAN_ISP_ADDR" dev "$VETH_ISP_CPE"
netns_exec "$NETNS_ISP" ip addr add "$CORE_ISP_ADDR" dev "$VETH_ISP_AFTR"
netns_exec "$NETNS_ISP" ip link set "$VETH_ISP_CPE" up
netns_exec "$NETNS_ISP" ip link set "$VETH_ISP_AFTR" up
disable_veth_offloads "$NETNS_ISP" "$VETH_ISP_CPE"
disable_veth_offloads "$NETNS_ISP" "$VETH_ISP_AFTR"
# v-isp-cpe is the peer of mm-cpe's WAN-side XDP redirect target
# (v-cpe-isp) -- same GRO requirement as v-host-cpe above, this time for the
# encap path's redirect out to the WAN.
netns_exec "$NETNS_ISP" ethtool -K "$VETH_ISP_CPE" gro on

# dnsmasq on the CPE-facing link serves Router Advertisements (SLAAC) and DNS
# (resolving the AFTR-Name to the AFTR's tunnel address). DHCPv6 itself
# (both stateless Information-Request and DHCPv6-PD) is Kea's job below --
# only one process can bind port 547 on this link, and dnsmasq has no
# DHCPv6-PD support at all -- so dnsmasq's dhcp-range is "ra-only" (RA, no
# DHCP) rather than the stateless-DHCPv6-serving "ra-stateless" it used to
# be; the two dhcp-option lines that used to answer Information-Request
# (dns-server, RFC 6334 AFTR-Name) move to Kea's option-data instead.
cat >"$DNSMASQ_CONF" <<EOF
interface=$VETH_ISP_CPE
bind-interfaces
except-interface=lo
no-resolv
no-hosts
leasefile-ro
dhcp-leasefile=$DNSMASQ_LEASEFILE
enable-ra
dhcp-range=::,constructor:$VETH_ISP_CPE,ra-only
address=/$AFTR_FQDN/${CORE_AFTR_ADDR%/*}
EOF
# In HB46PP mode dnsmasq additionally answers the discovery TXT lookup on
# 4over6.info -- in a real deployment that answer comes from the VNE's own
# full-service resolvers, which is exactly what mm-isp's dnsmasq plays here.
if [[ "$AFTR_DISCOVERY" == hb46pp ]]; then
    echo "txt-record=4over6.info,v=v6mig-1 url=$HB46PP_URL t=a" >>"$DNSMASQ_CONF"
fi
netns_exec "$NETNS_ISP" dnsmasq --conf-file="$DNSMASQ_CONF" --pid-file="$DNSMASQ_PIDFILE"

# Only now -- with mm-isp's RA server already up and answering, per the
# ordering note above -- bring up mm-cpe's end of this same link. A veth end
# only reports RUNNING/carrier-up once its peer is also admin-up, and Kea's
# socket-opening check (unlike dnsmasq's) requires RUNNING, so this also
# needs to happen before Kea starts below.
netns_exec "$NETNS_CPE" ip link set "$VETH_CPE_ISP" up
# v-isp-cpe's link-local address is tentative (DAD-pending) for a moment
# right after an interface comes up; Kea's socket-opening code (unlike
# dnsmasq's) doesn't retry the bind if it's still tentative, and it fails
# hard (DHCP6_OPEN_SOCKETS_FAILED) rather than recovering later. Wait for
# DAD to actually finish rather than sleeping a fixed amount -- a fixed
# "sleep 2" here turned out to lose the race often enough to matter.
for _ in $(seq 1 50); do
    if ! netns_exec "$NETNS_ISP" ip -6 addr show dev "$VETH_ISP_CPE" | grep -q tentative; then
        break
    fi
    sleep 0.2
done
if netns_exec "$NETNS_ISP" ip -6 addr show dev "$VETH_ISP_CPE" | grep -q tentative; then
    echo "error: $VETH_ISP_CPE addresses still tentative (DAD stuck?) after 10s" >&2
    exit 1
fi

# Kea DHCPv6 server: answers both Information-Request (RFC 3736 -- DNS
# servers + RFC 6334 OPTION_AFTR_NAME, dnsmasq's old job, requested via
# pkg/aftrdiscovery's own OPTION_ORO so no "always-send" config is needed)
# and DHCPv6-PD (RFC 3633, via pd-pools) on the same link. The pd-pools
# entry has prefix-len == delegated-len (PD_DELEGATED_BITS): the pool *is*
# the one delegation this single-CPE rig ever hands out (see common.sh), so
# with Kea's in-memory/non-persistent lease-database, mm-cpe deterministically
# gets $PD_POOL_PREFIX every fresh run.
aftr_name_hex_nocolons="$(encode_dns_name "$AFTR_FQDN" | tr -d ':')"
pd_pool_addr="${PD_POOL_PREFIX%/*}"
# In HB46PP mode Kea withholds OPTION_AFTR_NAME (that's the whole point of
# the mode: a DHCPv6 Reply without option 64 is what makes minuteman fall
# back to HB46PP), while still serving dns-servers -- HB46PP's TXT lookup
# needs a resolver, and minuteman feeds it the one from this same Reply.
kea_option_data="{ \"name\": \"dns-servers\", \"data\": \"${WAN_ISP_ADDR%/*}\" }"
if [[ "$AFTR_DISCOVERY" == dhcpv6 ]]; then
    kea_option_data+=",
      { \"code\": 64, \"space\": \"dhcp6\", \"csv-format\": false, \"data\": \"$aftr_name_hex_nocolons\" }"
fi
cat >"$KEA_CONF" <<EOF
{
  "Dhcp6": {
    "interfaces-config": {
      "interfaces": ["$VETH_ISP_CPE"]
    },
    "lease-database": {
      "type": "memfile",
      "persist": false
    },
    "renew-timer": 1800,
    "rebind-timer": 2880,
    "preferred-lifetime": 3600,
    "valid-lifetime": 7200,
    "option-data": [
      $kea_option_data
    ],
    "subnet6": [
      {
        "id": 1,
        "subnet": "$WAN_PREFIX",
        "interface": "$VETH_ISP_CPE",
        "pd-pools": [
          { "prefix": "$pd_pool_addr", "prefix-len": $PD_DELEGATED_BITS, "delegated-len": $PD_DELEGATED_BITS }
        ]
      }
    ],
    "loggers": [
      {
        "name": "kea-dhcp6",
        "output-options": [ { "output": "$KEA_LOG" } ],
        "severity": "INFO"
      }
    ]
  }
}
EOF
ip netns exec "$NETNS_ISP" kea-dhcp6 -c "$KEA_CONF" &
echo $! >"$KEA_PIDFILE"
sleep 1
if ! kill -0 "$(cat "$KEA_PIDFILE")" 2>/dev/null; then
    echo "error: kea-dhcp6 exited immediately; see $KEA_LOG" >&2
    cat "$KEA_LOG" >&2 2>/dev/null || true
    exit 1
fi

if [[ "$AFTR_DISCOVERY" == hb46pp ]]; then
    echo "== mm-isp: HB46PP provisioning server =="
    # The provisioning response, served as a static file: python3's
    # http.server drops the query string when mapping a request to a file,
    # so "GET /rule.cgi?vendorid=...&capability=dslite" serves this file
    # as-is -- good enough for a rig whose client always asks for dslite.
    # The aftr value is the FQDN (not the address) so the HB46PP path also
    # exercises the same DNS resolution step the DHCPv6 path does.
    mkdir -p "$HB46PP_WWWDIR"
    cat >"$HB46PP_WWWDIR/rule.cgi" <<EOF
{
  "enabler_name": "Minuteman Test VNE",
  "service_name": "netns rig DS-Lite",
  "ttl": 86400,
  "order": [ "dslite" ],
  "dslite": {
    "aftr": "$AFTR_FQDN"
  }
}
EOF
    # Binding to the WAN-side address works here (unlike Kea, which needed
    # the DAD wait above) only because that same wait has already passed.
    ip netns exec "$NETNS_ISP" python3 -m http.server "$HB46PP_PORT" \
        --bind "${WAN_ISP_ADDR%/*}" --directory "$HB46PP_WWWDIR" \
        >"$HB46PP_HTTP_LOG" 2>&1 &
    echo $! >"$HB46PP_HTTP_PIDFILE"
    sleep 1
    if ! kill -0 "$(cat "$HB46PP_HTTP_PIDFILE")" 2>/dev/null; then
        echo "error: HB46PP http.server exited immediately; see $HB46PP_HTTP_LOG" >&2
        cat "$HB46PP_HTTP_LOG" >&2 2>/dev/null || true
        exit 1
    fi
fi
echo "$AFTR_DISCOVERY" >"$AFTR_DISCOVERY_MODE_FILE"

echo "== mm-cpe: B4 element (minuteman runs here) =="
# ip_forward/net.ipv6.conf.all.forwarding=1 (required for bpf_fib_lookup() in
# the datapath to succeed) and accept_ra=2 on the WAN link (needed to keep
# accepting Router Advertisements once forwarding is on) are no longer set
# here: minuteman's pkg/datapath.Loader.AttachWAN configures both itself.
netns_exec "$NETNS_CPE" ip addr add "$LAN_CPE_ADDR" dev "$VETH_CPE_HOST"
netns_exec "$NETNS_CPE" ip link set "$VETH_CPE_HOST" up
# $VETH_CPE_ISP is already up (see mm-isp block above, brought up early for
# Kea's benefit).
disable_veth_offloads "$NETNS_CPE" "$VETH_CPE_HOST"
disable_veth_offloads "$NETNS_CPE" "$VETH_CPE_ISP"
# Statically pinned WAN/B4 address, used both as minuteman's -b4 value and
# as the AFTR's fixed tunnel peer below. RA/stateless DHCPv6 from mm-isp
# (started just above) additionally reaches this link for
# forward-compatibility with a future DHCPv6 B4/AFTR-discovery client;
# minuteman doesn't consume it yet.
netns_exec "$NETNS_CPE" ip addr add "$WAN_CPE_ADDR" dev "$VETH_CPE_ISP"

echo "== mm-aftr: AFTR (DS-Lite decap + NAPT44) =="
netns_exec "$NETNS_AFTR" sysctl -qw net.ipv4.ip_forward=1
netns_exec "$NETNS_AFTR" sysctl -qw net.ipv4.conf.all.rp_filter=0
netns_exec "$NETNS_AFTR" sysctl -qw net.ipv4.conf.default.rp_filter=0
netns_exec "$NETNS_AFTR" ip addr add "$CORE_AFTR_ADDR" dev "$VETH_AFTR_ISP"
netns_exec "$NETNS_AFTR" ip addr add "$PUBLIC_AFTR_ADDR" dev "$VETH_AFTR_INET"
netns_exec "$NETNS_AFTR" ip link set "$VETH_AFTR_ISP" up
netns_exec "$NETNS_AFTR" ip link set "$VETH_AFTR_INET" up
disable_veth_offloads "$NETNS_AFTR" "$VETH_AFTR_ISP"
disable_veth_offloads "$NETNS_AFTR" "$VETH_AFTR_INET"
netns_exec "$NETNS_AFTR" ip -6 route add default via "${CORE_ISP_ADDR%/*}"
# Kernel ip6tnl in ipip6 mode = IPv4-in-IPv6, i.e. RFC 6333's softwire
# encapsulation (next header IPPROTO_IPIP), fixed to this rig's single B4.
# encaplimit none: without it, ip6_tunnel inserts an RFC 2473 Tunnel
# Encapsulation Limit destination options header before the inner IPv4
# packet on every frame it encapsulates (the default limit is 4, not
# disabled). minuteman's xdp_dslite_decap expects nexthdr == IPPROTO_IPIP
# immediately after the outer IPv6 header, per how its own encap side writes
# it, and doesn't parse a destination options header -- with the limit
# enabled, decap silently misses every AFTR->B4 return packet (returns
# XDP_PASS to the kernel, which then replies with an ICMPv6 "unreachable"),
# so nothing ever gets back to the LAN client.
netns_exec "$NETNS_AFTR" ip -6 tunnel add "$AFTR_TUN" mode ipip6 \
    local "${CORE_AFTR_ADDR%/*}" remote "${WAN_CPE_ADDR%/*}" encaplimit none
netns_exec "$NETNS_AFTR" ip link set "$AFTR_TUN" up
netns_exec "$NETNS_AFTR" ip route add "$LAN_PREFIX" dev "$AFTR_TUN"
netns_exec "$NETNS_AFTR" iptables -t nat -A POSTROUTING -s "$LAN_PREFIX" -o "$VETH_AFTR_INET" -j MASQUERADE

echo "== mm-inet: simulated public IPv4 internet =="
netns_exec "$NETNS_INET" ip addr add "$PUBLIC_INET_ADDR" dev "$VETH_INET_AFTR"
netns_exec "$NETNS_INET" ip link set "$VETH_INET_AFTR" up
disable_veth_offloads "$NETNS_INET" "$VETH_INET_AFTR"

echo "== done =="
echo "Next: sudo ./test/netns/run-cpe.sh   (starts minuteman as the B4 in mm-cpe)"
echo "Then: sudo ./test/netns/smoketest.sh (LAN client -> AFTR -> simulated internet)"

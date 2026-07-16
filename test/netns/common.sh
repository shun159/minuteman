#!/bin/bash
# Shared topology definition for the DS-Lite (RFC 6333) netns test rig.
# Sourced by setup.sh, teardown.sh, run-cpe.sh and smoketest.sh so the
# topology is defined in exactly one place.
#
# Topology (RFC 6333 Figure 1: Host -- B4 -- AFTR -- Internet):
#
#   mm-host --192.168.1.0/24--> mm-cpe --fd00:1::/64--> mm-isp --fd00:2::/64--> mm-aftr --203.0.113.0/30--> mm-inet
#   (LAN client)      (B4, runs minuteman)   (ISP IPv6 access net,   (AFTR: DS-Lite decap    (simulated
#                                              RA + stateless          + NAPT44 via iptables    public IPv4
#                                              DHCPv6 + AFTR-Name       MASQUERADE)              internet)
#                                              per RFC 6334)
#
# mm-isp serves the AFTR's address in one of two selectable ways (see
# MM_AFTR_DISCOVERY in setup.sh): as RFC 6334 OPTION_AFTR_NAME over stateless
# DHCPv6 (the default), or -- with the DHCPv6 option withheld -- via HB46PP
# (JAIPA's v6mig-1 HTTP provisioning protocol: a 4over6.info TXT record
# pointing at a provisioning HTTP server), exercising minuteman's fallback
# discovery path. Either way minuteman discovers the AFTR itself; only -b4 is
# statically configured (see run-cpe.sh).

set -euo pipefail

NETNS_HOST=mm-host
NETNS_CPE=mm-cpe
NETNS_ISP=mm-isp
NETNS_AFTR=mm-aftr
NETNS_INET=mm-inet
ALL_NETNS=("$NETNS_HOST" "$NETNS_CPE" "$NETNS_ISP" "$NETNS_AFTR" "$NETNS_INET")

# LAN (host <-> cpe), IPv4, private
VETH_HOST_CPE=v-host-cpe   # in mm-host
VETH_CPE_HOST=v-cpe-host   # in mm-cpe
LAN_HOST_ADDR=192.168.1.2/24
LAN_CPE_ADDR=192.168.1.1/24   # minuteman -lan gatewayIP
LAN_PREFIX=192.168.1.0/24
# In MM_DHCPV4=1 mode the host's static 192.168.1.2 above is not assigned;
# it instead receives the DHCPv4 pool's first free address, which -- with
# the server (.1) excluded -- is .2, i.e. the same address, so the AFTR's
# NAT and the smoketest assertions line up either way. DHCPV4_LAN_MTU is the
# interface MTU minuteman advertises via option 26: the WAN veth MTU (1500)
# minus the 40-byte DS-Lite tunnel overhead.
DHCPV4_HOST_ADDR=192.168.1.2
DHCPV4_LAN_MTU=1460

# WAN (cpe <-> isp), IPv6-only softwire access link
VETH_CPE_ISP=v-cpe-isp     # in mm-cpe
VETH_ISP_CPE=v-isp-cpe     # in mm-isp
WAN_CPE_ADDR=fd00:1::2/64     # minuteman -b4 (statically pinned; see setup.sh comments)
WAN_ISP_ADDR=fd00:1::1/64
WAN_PREFIX=fd00:1::/64
# A second WAN global on the same /64, added by smoketest.sh's MM_DYNAMIC_B4
# renumbering scenario as a clean candidate source: it then deprecates
# WAN_CPE_ADDR (preferred_lft 0) so the kernel's RFC 6724 source selection -- and
# thus minuteman's dynamic B4 -- must move off it (to this address or the WAN's
# own SLAAC one), re-points the AFTR's ip6tnl remote at whatever minuteman picked,
# and re-tests the softwire. Same prefix, so it needs no new routing. Unused
# unless MM_DYNAMIC_B4=1.
WAN_CPE_ADDR2=fd00:1::9/64

# ISP core (isp <-> aftr), IPv6
VETH_ISP_AFTR=v-isp-aftr   # in mm-isp
VETH_AFTR_ISP=v-aftr-isp   # in mm-aftr
CORE_ISP_ADDR=fd00:2::1/64
CORE_AFTR_ADDR=fd00:2::2/64   # minuteman -aftr, and the AFTR's DS-Lite tunnel endpoint
CORE_PREFIX=fd00:2::/64

# Public side (aftr <-> inet), IPv4 (RFC 5737 TEST-NET-3)
VETH_AFTR_INET=v-aftr-inet # in mm-aftr
VETH_INET_AFTR=v-inet-aftr # in mm-inet
PUBLIC_AFTR_ADDR=203.0.113.1/30
PUBLIC_INET_ADDR=203.0.113.2/30

# MM_DUALSTACK=1 (see setup.sh): mm-inet doubles as a dual-stack "public
# server". Alongside its IPv4 (PUBLIC_INET_ADDR, reached through the DS-Lite
# softwire + AFTR NAPT44), it gets a *native* IPv6 address on a second subnet
# on the same aftr<->inet link. That native IPv6 is reached WITHOUT the
# softwire -- host -> cpe -> isp -> aftr(acting as a plain IPv6 router, NOT
# decapsulating) -> inet -- which is exactly RFC 6333's dual-stack premise:
# a DS-Lite B4 tunnels only IPv4; IPv6 is forwarded natively (minuteman's
# xdp_dslite_encap only ever matches ETH_P_IP and XDP_PASSes everything else,
# so this is structurally guaranteed, not just configured). dnsmasq serves
# DUALSTACK_FQDN with both an A and an AAAA record so smoketest.sh can steer
# the LAN client down either path purely by DNS record type and confirm (via
# tcpdump on the AFTR's dslite0) that only the IPv4/A path crosses the tunnel.
# 2001:db8:beef::/64 is another slice of IANA's IPv6 documentation range
# (RFC 3849), like PD_POOL_PREFIX.
DUALSTACK_FQDN=dualstack.example.com
PUBLIC6_PREFIX=2001:db8:beef::/64
PUBLIC6_AFTR_ADDR=2001:db8:beef::1/64   # mm-aftr's end of the inet link (plain IPv6 router hop)
PUBLIC6_INET_ADDR=2001:db8:beef::2/64   # mm-inet's native IPv6 == DUALSTACK_FQDN's AAAA

# DS-Lite tunnel device inside mm-aftr (kernel ip6tnl, mode ipip6 = IPv4-in-IPv6,
# i.e. RFC 6333's softwire encapsulation with next header IPPROTO_IPIP).
AFTR_TUN=dslite0

# RFC 6334 AFTR-Name served over stateless DHCPv6 by dnsmasq in mm-isp, and
# resolved (also by that dnsmasq) to CORE_AFTR_ADDR.
AFTR_FQDN=aftr.dslite.example.com

# DHCPv6-PD (RFC 3633) pool served by Kea in mm-isp, on the same WAN link --
# used when MM_WAN_MODEL=dhcpv6-pd (the default; see setup.sh). Kea's
# pd-pools is set to prefix-len == delegated-len (56 == 56): the whole
# pool *is* the one delegation this single-CPE rig ever hands out, so which
# /56 mm-cpe receives is fully deterministic across runs (Kea's lease db is
# in-memory/non-persistent, so a fresh setup.sh always starts from the same
# empty state) -- smoketest.sh can assert the exact resulting addresses
# instead of a loose prefix match. 2001:db8::/32 is IANA's IPv6 documentation
# range (RFC 3849), matching this rig's existing use of RFC 5737 TEST-NETs
# for the IPv4 side.
PD_POOL_PREFIX=2001:db8:f00d::/56
PD_DELEGATED_BITS=56

RUNDIR=/run/minuteman-netns-test
DNSMASQ_PIDFILE="$RUNDIR/dnsmasq.pid"
DNSMASQ_LEASEFILE="$RUNDIR/dnsmasq.leases"
DNSMASQ_CONF="$RUNDIR/dnsmasq-isp.conf"
KEA_PIDFILE="$RUNDIR/kea-dhcp6.pid"
KEA_CONF="$RUNDIR/kea-dhcp6.conf"
# Kea's Arch package hardens its logger to only accept paths under
# /var/log/kea (rejects any other "output" path at config-load time), so
# this can't live under $RUNDIR like the rest of this rig's runtime state;
# teardown.sh removes this one file specifically instead.
KEA_LOG="/var/log/kea/minuteman-netns-test.log"

# HB46PP (MM_AFTR_DISCOVERY=hb46pp) rig pieces: dnsmasq serves a 4over6.info
# TXT record ("v=v6mig-1 url=$HB46PP_URL t=a" -- t=a means plain http, no
# TLS, which spares the rig a certificate authority) pointing at a python3
# http.server in mm-isp that serves the provisioning JSON as a static
# rule.cgi file (python's handler ignores the query string, so minuteman's
# real vendorid/product/version/capability parameters are accepted and
# simply unread). setup.sh records the selected mode in
# $AFTR_DISCOVERY_MODE_FILE so smoketest.sh knows which discovery log lines
# to assert.
HB46PP_PORT=8046
HB46PP_URL="http://[${WAN_ISP_ADDR%/*}]:$HB46PP_PORT/rule.cgi"
HB46PP_WWWDIR="$RUNDIR/hb46pp-www"
HB46PP_HTTP_PIDFILE="$RUNDIR/hb46pp-http.pid"
HB46PP_HTTP_LOG="$RUNDIR/hb46pp-http.log"
AFTR_DISCOVERY_MODE_FILE="$RUNDIR/aftr-discovery-mode"

# WAN IPv6 provisioning model minuteman is started with -- orthogonal to
# AFTR_DISCOVERY_MODE_FILE above (that selects how the *AFTR* is found; this
# selects how the *LAN gets IPv6 reachability*). "dhcpv6-pd" (the default)
# is the PD_POOL_PREFIX scenario above; "ndproxy" instead omits Kea's
# pd-pools entirely and starts minuteman with -ndproxy, which learns
# WAN_PREFIX itself via SLAAC (dnsmasq's RA on $VETH_ISP_CPE already
# provides this regardless of mode) and extends it onto $VETH_CPE_HOST via
# RFC 4389 proxying instead. setup.sh records the mode here so run-cpe.sh
# and smoketest.sh start minuteman with the matching flag.
WAN_MODEL_FILE="$RUNDIR/wan-model"

# Whether minuteman is started with -dns-proxy -- a third, independent
# toggle (orthogonal to both AFTR_DISCOVERY_MODE_FILE and WAN_MODEL_FILE):
# it needs only a DNS server address, which mm-isp's Kea always hands out
# via dns-servers option-data regardless of the other two axes. Off by
# default (MM_DNS_PROXY unset or "0") so the common case stays exactly as
# before; setup.sh records the choice here so run-cpe.sh/smoketest.sh add
# -dns-proxy to the minuteman invocation only when asked.
DNS_PROXY_ENABLED_FILE="$RUNDIR/dns-proxy-enabled"

# Whether minuteman is started with -dhcpv4 -- a fourth independent toggle
# (orthogonal to the three above). When on, setup.sh does NOT statically
# assign mm-host's IPv4 address/default route; smoketest.sh instead has
# mm-host acquire them from minuteman's DHCPv4 server with dhclient, and the
# existing DS-Lite data-path checks then run over that DHCP-assigned config.
# Off by default (MM_DHCPV4 unset or "0").
DHCPV4_ENABLED_FILE="$RUNDIR/dhcpv4-enabled"
DHCLIENT_CONF="$RUNDIR/dhclient.conf"
DHCLIENT_LEASES="$RUNDIR/dhclient.leases"
DHCLIENT_PIDFILE="$RUNDIR/dhclient.pid"

# Whether setup.sh built the MM_DUALSTACK native-IPv6 topology above -- a
# fifth independent toggle (orthogonal to the four above; it changes no
# minuteman flag at all, since IPv6-goes-native is inherent to the datapath,
# not a configurable option). smoketest.sh reads this to decide whether to run
# the A-vs-AAAA record datapath checks. Off by default (MM_DUALSTACK unset or
# "0"). Pairs naturally with MM_DHCPV4=1 to give mm-host both a DHCPv4 address
# and a SLAAC IPv6 one -- the "host has both" case -- but works with mm-host's
# static IPv4 too.
DUALSTACK_ENABLED_FILE="$RUNDIR/dualstack-enabled"
DUALSTACK_PCAP="$RUNDIR/dualstack-dslite.pcap"

# Whether minuteman is started WITHOUT -b4 -- a sixth independent toggle
# (orthogonal to the five above). When on, minuteman selects its B4 softwire
# source dynamically from the WAN's kernel-chosen source toward the AFTR (RFC
# 6724) and re-selects it when the WAN address changes (the DS-Lite B4-address
# change of RFC 7785); when off (the
# default), -b4 pins WAN_CPE_ADDR statically as before. smoketest.sh additionally
# drives a renumbering scenario in this mode (see WAN_CPE_ADDR2 below). Off by
# default (MM_DYNAMIC_B4 unset or "0").
DYNAMIC_B4_FILE="$RUNDIR/dynamic-b4"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MINUTEMAN_BIN="$REPO_ROOT/bin/minuteman"

# encode_dns_name <fqdn> prints the RFC 1035 wire-format encoding of an FQDN
# as colon-separated hex bytes, e.g. "a.bc" -> "01:61:02:62:63:00". Used to
# build the raw OPTION_AFTR_NAME (DHCPv6 option 64) value for dnsmasq, which
# has no built-in encoder for this RFC 6334 option.
encode_dns_name() {
    local fqdn="$1" label hex=""
    local IFS=.
    for label in $fqdn; do
        hex+=$(printf '%02x:' "${#label}")
        hex+=$(printf '%s' "$label" | xxd -p -c256 | sed 's/\(..\)/\1:/g')
    done
    hex+="00"
    echo "$hex"
}

netns_exec() {
    local ns="$1"
    shift
    ip netns exec "$ns" "$@"
}

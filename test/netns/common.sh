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

# WAN (cpe <-> isp), IPv6-only softwire access link
VETH_CPE_ISP=v-cpe-isp     # in mm-cpe
VETH_ISP_CPE=v-isp-cpe     # in mm-isp
WAN_CPE_ADDR=fd00:1::2/64     # minuteman -b4 (statically pinned; see setup.sh comments)
WAN_ISP_ADDR=fd00:1::1/64
WAN_PREFIX=fd00:1::/64

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

# DS-Lite tunnel device inside mm-aftr (kernel ip6tnl, mode ipip6 = IPv4-in-IPv6,
# i.e. RFC 6333's softwire encapsulation with next header IPPROTO_IPIP).
AFTR_TUN=dslite0

# RFC 6334 AFTR-Name served over stateless DHCPv6 by dnsmasq in mm-isp, and
# resolved (also by that dnsmasq) to CORE_AFTR_ADDR.
AFTR_FQDN=aftr.dslite.example.com

# DHCPv6-PD (RFC 3633) pool served by Kea in mm-isp, on the same WAN link.
# Kea's pd-pools is set to prefix-len == delegated-len (56 == 56): the whole
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

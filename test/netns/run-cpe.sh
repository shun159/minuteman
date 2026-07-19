#!/bin/bash
# Runs minuteman as the B4 element inside mm-cpe, wired up for the topology
# built by setup.sh. Requires setup.sh to have been run first, and
# bin/minuteman to have been built (`make` from the repo root).
#
# Usage: sudo ./test/netns/run-cpe.sh [extra minuteman flags...]
#
# -aftr is intentionally omitted below: mm-isp (see setup.sh) serves the
# AFTR's address for whichever discovery mode the rig was built in -- RFC
# 6334 OPTION_AFTR_NAME over stateless DHCPv6 by default, or the HB46PP
# TXT-record/provisioning-server chain under MM_AFTR_DISCOVERY=hb46pp -- so
# minuteman discovers it exactly as it would against a real ISP/VNE. Pass
# -aftr <addr> as an extra argument to override with a static address
# instead (it's appended after the defaults below, and the later occurrence
# of a flag wins).
#
# -dhcpv6-pd or -ndproxy is passed depending on which MM_WAN_MODEL setup.sh
# was run with (read from WAN_MODEL_FILE, defaulting to dhcpv6-pd if that
# file is missing -- e.g. an old rig from before this flag existed):
# dhcpv6-pd acquires a real delegated prefix from mm-isp's Kea server and
# assigns the carved /64 to -lan; ndproxy instead learns the WAN's own SLAAC
# /64 and extends it onto -lan via RFC 4389 proxying. Either way Router
# Advertisements go out -lan exactly as they would against a real ISP.
#
# -dns-proxy is additionally passed if setup.sh was run with MM_DNS_PROXY=1
# (read from DNS_PROXY_ENABLED_FILE), and -dhcpv4 if it was run with
# MM_DHCPV4=1 (DHCPV4_ENABLED_FILE).
#
# MM_DUALSTACK deliberately has no effect here: IPv6-goes-native is inherent
# to the XDP datapath (xdp_dslite_encap only ever tunnels IPv4), not a
# configurable minuteman option, so that mode adds only topology in setup.sh
# and assertions in smoketest.sh -- nothing to the minuteman invocation.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./common.sh

if [[ $EUID -ne 0 ]]; then
    echo "must run as root" >&2
    exit 1
fi

if [[ ! -x "$MINUTEMAN_BIN" ]]; then
    echo "$MINUTEMAN_BIN not found; run 'make' from the repo root first" >&2
    exit 1
fi

if ! ip netns list | grep -q "^$NETNS_CPE"; then
    echo "$NETNS_CPE netns not found; run setup.sh first" >&2
    exit 1
fi

wan_model=dhcpv6-pd
if [[ -f "$WAN_MODEL_FILE" ]]; then
    wan_model="$(cat "$WAN_MODEL_FILE")"
fi
wan_model_flag="-dhcpv6-pd"
if [[ "$wan_model" == ndproxy ]]; then
    wan_model_flag="-ndproxy"
fi

dns_proxy_flags=()
if [[ -f "$DNS_PROXY_ENABLED_FILE" && "$(cat "$DNS_PROXY_ENABLED_FILE")" == 1 ]]; then
    dns_proxy_flags=(-dns-proxy)
fi

dhcpv4_flags=()
if [[ -f "$DHCPV4_ENABLED_FILE" && "$(cat "$DHCPV4_ENABLED_FILE")" == 1 ]]; then
    dhcpv4_flags=(-dhcpv4)
fi

# -b4 is omitted under MM_DYNAMIC_B4=1 so minuteman selects it dynamically from
# the WAN's kernel-chosen source toward the AFTR (RFC 6724); otherwise it's
# pinned to WAN_CPE_ADDR as before.
b4_flags=(-b4 "${WAN_CPE_ADDR%/*}")
if [[ -f "$DYNAMIC_B4_FILE" && "$(cat "$DYNAMIC_B4_FILE")" == 1 ]]; then
    b4_flags=()
fi

# nsenter --net rather than `ip netns exec`: the latter also creates a new
# mount namespace and remounts /sys, so the stats map minuteman pins at
# /sys/fs/bpf/minuteman would land on a private bpffs no later process can
# see. nsenter switches only the network namespace, keeping the host's
# /sys/fs/bpf, so `minuteman stats` (and bpftool) can read the pin from the
# host while this runs.
exec nsenter --net="/var/run/netns/$NETNS_CPE" "$MINUTEMAN_BIN" \
    -wan "$VETH_CPE_ISP" \
    "${b4_flags[@]}" \
    -lan "$VETH_CPE_HOST=${LAN_CPE_ADDR%/*}" \
    "$wan_model_flag" \
    -stats-interval 0 \
    "${dns_proxy_flags[@]}" \
    "${dhcpv4_flags[@]}" \
    "$@"

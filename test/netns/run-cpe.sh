#!/bin/bash
# Runs minuteman as the B4 element inside mm-cpe, wired up for the topology
# built by setup.sh. Requires setup.sh to have been run first, and
# bin/minuteman to have been built (`make` from the repo root).
#
# Usage: sudo ./test/netns/run-cpe.sh [extra minuteman flags...]
#
# -aftr is intentionally omitted below: mm-isp's dnsmasq (see setup.sh)
# serves a real RFC 6334 OPTION_AFTR_NAME + DNS record for it, so minuteman
# discovers the AFTR itself via DHCPv6 exactly as it would against a real
# ISP. Pass -aftr <addr> as an extra argument to override with a static
# address instead (it's appended after the defaults below, and the later
# occurrence of a flag wins).
#
# -dhcpv6-pd is on by default too: mm-isp's Kea server (see setup.sh) delegates
# a real DHCPv6-PD prefix, so minuteman acquires it, assigns the carved /64 to
# -lan, and starts advertising it via Router Advertisements exactly as it
# would against a real ISP.

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

exec ip netns exec "$NETNS_CPE" "$MINUTEMAN_BIN" \
    -wan "$VETH_CPE_ISP" \
    -b4 "${WAN_CPE_ADDR%/*}" \
    -lan "$VETH_CPE_HOST=${LAN_CPE_ADDR%/*}" \
    -dhcpv6-pd \
    "$@"

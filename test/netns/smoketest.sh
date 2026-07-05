#!/bin/bash
# End-to-end smoke test for the DS-Lite netns rig: pings and curls from the
# simulated LAN client, through minuteman's B4 encap, the AFTR's decap+NAPT44,
# to the simulated public internet host, and back. Also spot-checks that
# mm-isp's stateless DHCPv6 + DNS correctly serve the RFC 6334 AFTR-Name.
#
# Starts minuteman itself (if not already running) and stops it again on
# exit, unless it detects an existing instance to leave alone.
#
# Usage: sudo ./test/netns/smoketest.sh

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./common.sh

if [[ $EUID -ne 0 ]]; then
    echo "must run as root" >&2
    exit 1
fi

for ns in "$NETNS_HOST" "$NETNS_CPE" "$NETNS_ISP" "$NETNS_AFTR" "$NETNS_INET"; do
    if ! ip netns list | grep -q "^$ns"; then
        echo "$ns netns not found; run setup.sh first" >&2
        exit 1
    fi
done

fail=0
started_minuteman=0
minuteman_pid=""

cleanup() {
    if [[ $started_minuteman -eq 1 && -n "$minuteman_pid" ]]; then
        kill "$minuteman_pid" 2>/dev/null
        wait "$minuteman_pid" 2>/dev/null
    fi
}
trap cleanup EXIT

check() {
    local desc="$1"
    shift
    if "$@"; then
        echo "PASS: $desc"
    else
        echo "FAIL: $desc"
        fail=1
    fi
}

# retry runs "$@" up to 10 times (1s apart), succeeding as soon as one
# attempt does -- for conditions with real, variable-latency dependencies
# (e.g. mm-host processing an RA and completing SLAAC) where a single fixed
# sleep before checking would either be flaky (too short) or slow down every
# run for a rare slow case (too long).
retry() {
    for _ in $(seq 1 10); do
        if "$@"; then
            return 0
        fi
        sleep 1
    done
    return 1
}

if ip netns pids "$NETNS_CPE" 2>/dev/null | xargs -r -I{} readlink -f /proc/{}/exe 2>/dev/null | grep -qx "$MINUTEMAN_BIN"; then
    echo "== minuteman already running in $NETNS_CPE, reusing it =="
else
    echo "== starting minuteman in $NETNS_CPE (no -aftr: discovers it live via DHCPv6; -dhcpv6-pd: acquires a delegated prefix live too) =="
    ip netns exec "$NETNS_CPE" "$MINUTEMAN_BIN" \
        -wan "$VETH_CPE_ISP" \
        -b4 "${WAN_CPE_ADDR%/*}" \
        -lan "$VETH_CPE_HOST=${LAN_CPE_ADDR%/*}" \
        -dhcpv6-pd \
        -stats-interval 0 >"$RUNDIR/minuteman.log" 2>&1 &
    minuteman_pid=$!
    started_minuteman=1
    # DHCPv6 discovery includes an RFC 3315 initial random delay (up to 1s)
    # before its first retransmission-timed attempt; DHCPv6-PD's own
    # Solicit/Request exchange runs after that, followed by the LAN /64
    # assignment and the first Router Advertisement -- give it real headroom
    # before the checks below assume all of that has finished.
    sleep 5
fi

echo "== RFC 6334 AFTR-Name / DNS discovery =="
if [[ $started_minuteman -eq 1 ]]; then
    check "minuteman discovered the AFTR via DHCPv6 (see $RUNDIR/minuteman.log)" \
        grep -q "discovered AFTR $AFTR_FQDN -> ${CORE_AFTR_ADDR%/*}" "$RUNDIR/minuteman.log"
fi
# Independent cross-check queried directly against mm-isp, to confirm the
# server itself is serving the record minuteman is expected to have used --
# runs regardless of whether we started minuteman ourselves.
check "mm-isp resolves $AFTR_FQDN to the AFTR's tunnel address" \
    bash -c "[[ \$(ip netns exec $NETNS_CPE dig @${WAN_ISP_ADDR%/*} -6 +short AAAA $AFTR_FQDN) == '${CORE_AFTR_ADDR%/*}' ]]"

echo "== DHCPv6-PD (RFC 3633) + Router Advertisement (RFC 4861) SLAAC =="
pd_lan_addr="${PD_POOL_PREFIX%/*}1" # AssignedAddress's ::1 within the carved /64, e.g. 2001:db8:f00d::1
# A prefix-only substring match (not the full "::"-compressed /64), since
# mm-host's SLAAC'd interface identifier is arbitrary and RFC 5952 forbids
# compressing a lone 16-bit zero field -- e.g. "2001:db8:f00d:0:1:2:3:4" is
# valid canonical text for an address in this /64 and doesn't contain "::".
pd_pool_label="${PD_POOL_PREFIX%%::*}:" # e.g. 2001:db8:f00d: (note trailing colon)
if [[ $started_minuteman -eq 1 ]]; then
    check "minuteman acquired the delegated prefix and assigned it to $VETH_CPE_HOST (see $RUNDIR/minuteman.log)" \
        grep -q "assigned $pd_lan_addr to $VETH_CPE_HOST (from delegated prefix $PD_POOL_PREFIX)" "$RUNDIR/minuteman.log"
fi
check "$VETH_CPE_HOST carries the delegated-prefix address" \
    bash -c "ip netns exec $NETNS_CPE ip -6 addr show dev $VETH_CPE_HOST | grep -q '$pd_lan_addr/64'"
# A retry, not just a longer fixed sleep: this is the tail of a strictly
# longer dependent chain (PD acquire -> LAN /64 assignment -> first RA sent
# -> mm-host receives it -> SLAAC -> DAD) than the other checks above, whose
# own dependencies are already satisfied well within the initial sleep. How
# long the RA/SLAAC/DAD tail specifically takes varies run to run.
check "$NETNS_HOST (LAN client) SLAAC'd a global address from the delegated /64 via minuteman's Router Advertisements" \
    retry bash -c "ip netns exec $NETNS_HOST ip -6 addr show dev $VETH_HOST_CPE scope global | grep -q '$pd_pool_label'"

echo "== DS-Lite data path (RFC 6333): $NETNS_HOST -> B4 -> AFTR -> $NETNS_INET =="
check "LAN client can ping the simulated internet host through the softwire" \
    ip netns exec "$NETNS_HOST" ping -c 2 -W 2 -I "$VETH_HOST_CPE" "${PUBLIC_INET_ADDR%/*}"

ip netns exec "$NETNS_INET" bash -c \
    "printf 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok' | timeout 5 nc -l -p 8080 -q1" &
nc_pid=$!
sleep 0.3
check "LAN client can reach a TCP service on the simulated internet host" \
    ip netns exec "$NETNS_HOST" curl -sf --max-time 3 "http://${PUBLIC_INET_ADDR%/*}:8080/"
wait "$nc_pid" 2>/dev/null

if [[ $fail -eq 0 ]]; then
    echo "== all checks passed =="
else
    echo "== one or more checks FAILED (see minuteman log: $RUNDIR/minuteman.log) =="
fi
exit $fail

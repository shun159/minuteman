#!/bin/bash
# End-to-end smoke test for the DS-Lite netns rig: pings and curls from the
# simulated LAN client, through minuteman's B4 encap, the AFTR's decap+NAPT44,
# to the simulated public internet host, and back. Also spot-checks AFTR
# discovery in whichever mode setup.sh built the rig for (see its
# MM_AFTR_DISCOVERY notes): the RFC 6334 AFTR-Name over stateless DHCPv6, or
# the HB46PP TXT-record + provisioning-server fallback. And spot-checks LAN
# IPv6 reachability in whichever WAN model setup.sh built the rig for (see
# its MM_WAN_MODEL notes): DHCPv6-PD SLAAC from a delegated prefix, or
# RFC 4389 NDProxy extending the WAN's own SLAAC prefix onto the LAN. If
# setup.sh was run with MM_DNS_PROXY=1, also spot-checks minuteman's DNS
# proxy (RFC 6333's B4 SHOULD); if with MM_DHCPV4=1, has mm-host acquire its
# IPv4 lease from minuteman's DHCPv4 server (RFC 2131) and checks it.
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

wan_model=dhcpv6-pd
if [[ -f "$WAN_MODEL_FILE" ]]; then
    wan_model="$(cat "$WAN_MODEL_FILE")"
fi
wan_model_flag="-dhcpv6-pd"
if [[ "$wan_model" == ndproxy ]]; then
    wan_model_flag="-ndproxy"
fi

dns_proxy_enabled=0
if [[ -f "$DNS_PROXY_ENABLED_FILE" && "$(cat "$DNS_PROXY_ENABLED_FILE")" == 1 ]]; then
    dns_proxy_enabled=1
fi
dns_proxy_flags=()
if [[ $dns_proxy_enabled -eq 1 ]]; then
    dns_proxy_flags=(-dns-proxy)
fi

dhcpv4_enabled=0
if [[ -f "$DHCPV4_ENABLED_FILE" && "$(cat "$DHCPV4_ENABLED_FILE")" == 1 ]]; then
    dhcpv4_enabled=1
fi
dhcpv4_flags=()
if [[ $dhcpv4_enabled -eq 1 ]]; then
    dhcpv4_flags=(-dhcpv4)
fi

if ip netns pids "$NETNS_CPE" 2>/dev/null | xargs -r -I{} readlink -f /proc/{}/exe 2>/dev/null | grep -qx "$MINUTEMAN_BIN"; then
    echo "== minuteman already running in $NETNS_CPE, reusing it =="
else
    echo "== starting minuteman in $NETNS_CPE (no -aftr: discovers it live via DHCPv6; $wan_model_flag: acquires/learns IPv6 for the LAN live too) =="
    ip netns exec "$NETNS_CPE" "$MINUTEMAN_BIN" \
        -wan "$VETH_CPE_ISP" \
        -b4 "${WAN_CPE_ADDR%/*}" \
        -lan "$VETH_CPE_HOST=${LAN_CPE_ADDR%/*}" \
        "$wan_model_flag" \
        "${dns_proxy_flags[@]}" \
        "${dhcpv4_flags[@]}" \
        -stats-interval 0 >"$RUNDIR/minuteman.log" 2>&1 &
    minuteman_pid=$!
    started_minuteman=1
    # DHCPv6 discovery includes an RFC 3315 initial random delay (up to 1s)
    # before its first retransmission-timed attempt; DHCPv6-PD's own
    # Solicit/Request exchange (or, in ndproxy mode, the WAN prefix
    # discovery poll) runs after that, followed by the LAN /64 assignment
    # and the first Router Advertisement -- give it real headroom before the
    # checks below assume all of that has finished.
    sleep 5
fi

# In DHCPv4 mode mm-host has no IPv4 yet (setup.sh left it unconfigured):
# acquire its address/route/MTU from minuteman's DHCPv4 server now, before
# any later check assumes the host has IPv4 (the DNS-proxy and DS-Lite
# data-path checks both do).
if [[ $dhcpv4_enabled -eq 1 ]]; then
    echo "== DHCPv4 (RFC 2131): $NETNS_HOST acquires its IPv4 lease from minuteman =="
    # Request interface-mtu (option 26) so dhclient applies the DS-Lite
    # softwire MTU minuteman advertises, not just the address.
    cat >"$DHCLIENT_CONF" <<EOF
timeout 20;
request subnet-mask, broadcast-address, routers, domain-name-servers, interface-mtu;
EOF
    if [[ $started_minuteman -eq 1 ]]; then
        check "minuteman is serving DHCPv4 on $VETH_CPE_HOST (see $RUNDIR/minuteman.log)" \
            grep -q "DHCPv4: serving $LAN_PREFIX on $VETH_CPE_HOST" "$RUNDIR/minuteman.log"
    fi
    check "$NETNS_HOST acquired an IPv4 lease via dhclient (DORA against minuteman)" \
        ip netns exec "$NETNS_HOST" dhclient -4 -1 \
            -cf "$DHCLIENT_CONF" -lf "$DHCLIENT_LEASES" -pf "$DHCLIENT_PIDFILE" "$VETH_HOST_CPE"
    check "$NETNS_HOST got the pool's first address ($DHCPV4_HOST_ADDR/24)" \
        bash -c "ip netns exec $NETNS_HOST ip -4 addr show dev $VETH_HOST_CPE | grep -q 'inet $DHCPV4_HOST_ADDR/24'"
    check "$NETNS_HOST installed a default route via the DHCP-supplied router ${LAN_CPE_ADDR%/*}" \
        bash -c "ip netns exec $NETNS_HOST ip -4 route show default | grep -q 'via ${LAN_CPE_ADDR%/*}'"
    check "$NETNS_HOST applied the DS-Lite-adjusted interface MTU ($DHCPV4_LAN_MTU, WAN 1500 - 40 tunnel overhead)" \
        bash -c "ip netns exec $NETNS_HOST ip link show $VETH_HOST_CPE | grep -q 'mtu $DHCPV4_LAN_MTU'"
fi

aftr_mode=dhcpv6
if [[ -f "$AFTR_DISCOVERY_MODE_FILE" ]]; then
    aftr_mode="$(cat "$AFTR_DISCOVERY_MODE_FILE")"
fi

if [[ "$aftr_mode" == hb46pp ]]; then
    echo "== HB46PP (v6mig-1) provisioning discovery =="
    if [[ $started_minuteman -eq 1 ]]; then
        check "minuteman fell back to HB46PP when the DHCPv6 Reply had no AFTR-Name (see $RUNDIR/minuteman.log)" \
            grep -q "DHCPv6 Reply carried no AFTR-Name, trying HB46PP" "$RUNDIR/minuteman.log"
        check "minuteman provisioned the AFTR via HB46PP" \
            grep -q "HB46PP: provisioned by .*AFTR $AFTR_FQDN -> ${CORE_AFTR_ADDR%/*}" "$RUNDIR/minuteman.log"
    fi
    # Independent cross-checks against mm-isp's own servers, confirming the
    # discovery chain minuteman is expected to have walked -- run regardless
    # of whether we started minuteman ourselves.
    check "mm-isp serves the 4over6.info discovery TXT record" \
        bash -c "ip netns exec $NETNS_CPE dig @${WAN_ISP_ADDR%/*} -6 +short TXT 4over6.info | grep -q 'v=v6mig-1'"
    check "the provisioning server answers with DS-Lite parameters" \
        bash -c "ip netns exec $NETNS_CPE curl -sf -g '$HB46PP_URL?vendorid=acde48&product=smoketest&version=0&capability=dslite' | grep -q '\"aftr\"'"
else
    echo "== RFC 6334 AFTR-Name / DNS discovery =="
    if [[ $started_minuteman -eq 1 ]]; then
        check "minuteman discovered the AFTR via DHCPv6 (see $RUNDIR/minuteman.log)" \
            grep -q "discovered AFTR $AFTR_FQDN -> ${CORE_AFTR_ADDR%/*}" "$RUNDIR/minuteman.log"
    fi
fi
# Independent cross-check queried directly against mm-isp, to confirm the
# server itself is serving the record minuteman is expected to have used
# (both discovery modes resolve $AFTR_FQDN through this same dnsmasq) --
# runs regardless of whether we started minuteman ourselves.
check "mm-isp resolves $AFTR_FQDN to the AFTR's tunnel address" \
    bash -c "[[ \$(ip netns exec $NETNS_CPE dig @${WAN_ISP_ADDR%/*} -6 +short AAAA $AFTR_FQDN) == '${CORE_AFTR_ADDR%/*}' ]]"

if [[ "$wan_model" == ndproxy ]]; then
    echo "== NDProxy (RFC 4389): WAN prefix extended onto $VETH_CPE_HOST =="
    if [[ $started_minuteman -eq 1 ]]; then
        check "minuteman learned the WAN's own SLAAC prefix and extended it onto $VETH_CPE_HOST (see $RUNDIR/minuteman.log)" \
            grep -q "NDProxy: extending WAN prefix $WAN_PREFIX onto 1 LAN interface(s)" "$RUNDIR/minuteman.log"
    fi
    # Same prefix-only substring rationale as pd_pool_label below: mm-host's
    # SLAAC'd interface identifier is arbitrary, so match on the label only.
    wan_pool_label="${WAN_PREFIX%%::*}:" # e.g. fd00:1: (note trailing colon)
    # A retry, not just a longer fixed sleep, for the same reason as the PD
    # branch's own SLAAC/DAD check below: it's the tail of a dependent chain
    # (WAN prefix discovery -> first RA sent -> mm-host receives it -> SLAAC
    # -> DAD) whose length varies run to run.
    check "$NETNS_HOST (LAN client) SLAAC'd a global address from the WAN's own /64 via minuteman's Router Advertisements" \
        retry bash -c "ip netns exec $NETNS_HOST ip -6 addr show dev $VETH_HOST_CPE scope global | grep -q '$wan_pool_label'"

    # The exact address, not just the prefix label, so the checks below can
    # target it precisely -- deterministic because setup.sh disabled RFC 4941
    # privacy addresses on mm-host, so there's exactly one to find.
    host_wan_addr="$(ip netns exec "$NETNS_HOST" ip -6 addr show dev "$VETH_HOST_CPE" scope global |
        awk '/inet6/ {print $2}' | cut -d/ -f1 | grep "^${WAN_PREFIX%%::*}:" | head -n1)"
    if [[ -z "$host_wan_addr" ]]; then
        echo "FAIL: could not determine $NETNS_HOST's WAN-prefix SLAAC address"
        fail=1
    else
        # Outbound direction first: On-Link is cleared in NDProxy's RA (see
        # routeradvert.Config.OnLink), so mm-host must be routing this
        # through mm-cpe (its RA-announced default router) as a plain
        # forwarded packet -- exercises the RA/default-route side without
        # touching NDProxy's WAN-side answering at all.
        check "$NETNS_HOST (LAN client) can reach mm-isp through mm-cpe's plain IPv6 forwarding" \
            ip netns exec "$NETNS_HOST" ping -c 2 -W 2 -I "$VETH_HOST_CPE" "${WAN_ISP_ADDR%/*}"

        # Inbound direction: mm-isp is directly L2-adjacent to mm-cpe's WAN
        # link and itself advertised $WAN_PREFIX as on-link there, so pinging
        # $host_wan_addr makes mm-isp's kernel send a Neighbor Solicitation
        # directly onto that link -- which mm-cpe's ndproxy (listening on
        # $VETH_CPE_ISP) must intercept, verify via an LAN-side probe to
        # mm-host, and answer for, exactly RFC 4389's proxying behavior. A
        # retry: this is the tail of a WAN-NS -> LAN-probe -> NA -> host-route
        # chain with real latency.
        check "mm-isp (acting as the rest of the WAN) can reach $NETNS_HOST's address $host_wan_addr through minuteman's ND proxying" \
            retry ip netns exec "$NETNS_ISP" ping -c 2 -W 2 "$host_wan_addr"
        if [[ $started_minuteman -eq 1 ]]; then
            check "minuteman actively confirmed $host_wan_addr before proxying for it (see $RUNDIR/minuteman.log)" \
                grep -q "NDProxy: $host_wan_addr confirmed active behind $VETH_CPE_HOST" "$RUNDIR/minuteman.log"
        fi
        check "minuteman installed a host route for $host_wan_addr via $VETH_CPE_HOST" \
            bash -c "ip netns exec $NETNS_CPE ip -6 route show dev $VETH_CPE_HOST | grep -q '$host_wan_addr'"
    fi
else
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
fi

if [[ $dns_proxy_enabled -eq 1 ]]; then
    echo "== DNS proxy (RFC 6333): $NETNS_HOST -> $VETH_CPE_HOST -> mm-isp, not through the softwire =="
    if [[ $started_minuteman -eq 1 ]]; then
        check "minuteman started the DNS proxy listening on ${LAN_CPE_ADDR%/*} (see $RUNDIR/minuteman.log)" \
            grep -q "DNS proxy: listening on \[${LAN_CPE_ADDR%/*}\]" "$RUNDIR/minuteman.log"
    fi
    # $NETNS_HOST queries minuteman's LAN gateway IP directly (not mm-isp) --
    # a correct answer proves the proxy actually forwarded the query to
    # mm-isp's DNS server over the CPE's own native IPv6 and relayed the
    # answer back, both over UDP and over TCP (dnsproxy.Serve runs both).
    check "$NETNS_HOST (LAN client) resolves $AFTR_FQDN via minuteman's DNS proxy (UDP)" \
        bash -c "[[ \$(ip netns exec $NETNS_HOST dig @${LAN_CPE_ADDR%/*} +short AAAA $AFTR_FQDN) == '${CORE_AFTR_ADDR%/*}' ]]"
    check "$NETNS_HOST (LAN client) resolves $AFTR_FQDN via minuteman's DNS proxy (TCP)" \
        bash -c "[[ \$(ip netns exec $NETNS_HOST dig +tcp @${LAN_CPE_ADDR%/*} +short AAAA $AFTR_FQDN) == '${CORE_AFTR_ADDR%/*}' ]]"
fi

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

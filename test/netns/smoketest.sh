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
# common.sh turns on errexit (set -e) for the setup/teardown scripts that
# source it, but this script collects failures via check() and must keep
# going past a failing probe -- the first unguarded non-zero command (e.g.
# wait on a `timeout`-expired tcpdump returning 124) would otherwise abort
# the whole run mid-way. Undo it; our own set -uo pipefail above stands.
set +e

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

# retry_slow is retry with a longer horizon (25 * 2s = 50s), for the one
# condition that genuinely takes tens of seconds: minuteman's dynamic-B4 watcher
# polls the WAN source every b4WatchInterval (30s), so a renumbering it must
# notice can take a full interval plus DAD on the new address.
retry_slow() {
    for _ in $(seq 1 25); do
        if "$@"; then
            return 0
        fi
        sleep 2
    done
    return 1
}

# dslite_capture runs "$@" while sniffing the AFTR's dslite0 softwire endpoint,
# so a caller can tell whether the traffic it generated actually crossed the
# DS-Lite tunnel. dslite0 only ever carries softwire-decapsulated (or about-to-
# be-encapsulated) inner IPv4, so any packet seen there means the tunnel was
# used and zero means it wasn't. Sets two globals: DSLITE_CONN (the command's
# exit status) and DSLITE_PKTS (packets captured on dslite0 during the run).
dslite_capture() {
    rm -f "$DUALSTACK_PCAP"
    ip netns exec "$NETNS_AFTR" tcpdump -i "$AFTR_TUN" -n -w "$DUALSTACK_PCAP" \
        >/dev/null 2>&1 &
    local td=$!
    # Give tcpdump a moment to actually open the capture before generating
    # traffic, or the first packets race the sniffer and go uncounted.
    sleep 0.7
    "$@"
    DSLITE_CONN=$?
    sleep 0.5
    kill "$td" 2>/dev/null
    wait "$td" 2>/dev/null
    DSLITE_PKTS=$(tcpdump -r "$DUALSTACK_PCAP" 2>/dev/null | wc -l)
}

# read_stat prints one datapath counter by name (e.g. read_stat EncapFragSlow),
# read out-of-band from the stats map minuteman pins to bpffs
# (/sys/fs/bpf/minuteman/stats) via the `minuteman stats` subcommand -- no
# -stats-interval logging or log ownership needed, and it works against a
# reused instance too. Runs from the host: bpffs pins are mount-namespace
# state, not netns state (and minuteman is started via nsenter --net below
# precisely so its pin lands on the host's bpffs). Prints 0 if the counter
# (or the pin) is missing so callers can do arithmetic unconditionally.
read_stat() {
    local v
    v="$("$MINUTEMAN_BIN" stats 2>/dev/null | awk -v k="$1:" '$1 == k {print $2}')"
    echo "${v:-0}"
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

dualstack_enabled=0
if [[ -f "$DUALSTACK_ENABLED_FILE" && "$(cat "$DUALSTACK_ENABLED_FILE")" == 1 ]]; then
    dualstack_enabled=1
fi

dynamic_b4_enabled=0
if [[ -f "$DYNAMIC_B4_FILE" && "$(cat "$DYNAMIC_B4_FILE")" == 1 ]]; then
    dynamic_b4_enabled=1
fi

softwire_frag_enabled=0
if [[ -f "$SOFTWIRE_FRAG_ENABLED_FILE" && "$(cat "$SOFTWIRE_FRAG_ENABLED_FILE")" == 1 ]]; then
    softwire_frag_enabled=1
fi
# -b4 is omitted under MM_DYNAMIC_B4=1 (minuteman selects it dynamically); pinned
# to WAN_CPE_ADDR otherwise.
b4_flags=(-b4 "${WAN_CPE_ADDR%/*}")
if [[ $dynamic_b4_enabled -eq 1 ]]; then
    b4_flags=()
fi

if ip netns pids "$NETNS_CPE" 2>/dev/null | xargs -r -I{} readlink -f /proc/{}/exe 2>/dev/null | grep -qx "$MINUTEMAN_BIN"; then
    echo "== minuteman already running in $NETNS_CPE, reusing it =="
else
    echo "== starting minuteman in $NETNS_CPE (no -aftr: discovers it live via DHCPv6; $wan_model_flag: acquires/learns IPv6 for the LAN live too) =="
    # Counter assertions below read the bpffs-pinned stats map out-of-band via
    # `minuteman stats` (see read_stat), so -stats-interval logging stays off.
    # MM_IPV6_SW_RSS=1 enables the native-IPv6 software-RSS cpumap stage (and
    # its counter assertion).
    ipv6_rss_flags=()
    if [[ "${MM_IPV6_SW_RSS:-0}" == 1 ]]; then
        ipv6_rss_flags=(-ipv6-sw-rss)
    fi
    # nsenter --net rather than `ip netns exec`: the latter also creates a new
    # mount namespace and remounts /sys, so the stats map minuteman pins at
    # /sys/fs/bpf/minuteman would land on a private bpffs no later process can
    # see. nsenter switches only the network namespace, keeping the host's
    # /sys/fs/bpf, so read_stat (and bpftool) can open the pin from the host.
    nsenter --net="/var/run/netns/$NETNS_CPE" "$MINUTEMAN_BIN" \
        -wan "$VETH_CPE_ISP" \
        "${b4_flags[@]}" \
        -lan "$VETH_CPE_HOST=${LAN_CPE_ADDR%/*}" \
        "$wan_model_flag" \
        "${dns_proxy_flags[@]}" \
        "${dhcpv4_flags[@]}" \
        "${ipv6_rss_flags[@]}" \
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
        # The listen list is now "[<gateway-IPv4> <link-local-IPv6>%<iface>]"
        # (RFC 8106 RDNSS points LAN clients at that link-local, so the proxy
        # must actually bind it), so the IPv4 is followed by a space, not the
        # closing bracket -- match either.
        check "minuteman started the DNS proxy listening on ${LAN_CPE_ADDR%/*} (see $RUNDIR/minuteman.log)" \
            grep -qE "DNS proxy: listening on \[${LAN_CPE_ADDR%/*}[] ]" "$RUNDIR/minuteman.log"
        check "minuteman's DNS proxy also listens on the LAN link-local address (the RDNSS target it advertises)" \
            grep -qE "DNS proxy: listening on \[.*fe80:" "$RUNDIR/minuteman.log"
    fi
    # $NETNS_HOST queries minuteman's LAN gateway IP directly (not mm-isp) --
    # a correct answer proves the proxy actually forwarded the query to
    # mm-isp's DNS server over the CPE's own native IPv6 and relayed the
    # answer back, both over UDP and over TCP (dnsproxy's Server.Serve runs both).
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

if [[ $softwire_frag_enabled -eq 1 && $started_minuteman -eq 1 ]]; then
    echo "== Softwire fragmentation (RFC 6333 §5.3): the kernel companion ip6tnl fragments/reassembles what XDP can't =="

    # Snapshot the slow-path counters before generating any traffic, so the
    # assertions below are deltas -- immune to whatever an earlier check (or a
    # reused instance) already accumulated.
    encap_frag0="$(read_stat EncapFragSlow)"
    reasm_pass0="$(read_stat DecapReasmPass)"
    martian0="$(read_stat DecapMartian)"

    # The companion device and its IPv4 default route must exist while minuteman
    # runs (both are torn down on shutdown).
    check "minuteman created the companion ip6tnl (mm-dslite0) in $NETNS_CPE" \
        ip netns exec "$NETNS_CPE" ip link show mm-dslite0
    check "minuteman installed the IPv4 default route via mm-dslite0" \
        bash -c "ip netns exec $NETNS_CPE ip route show default | grep -q 'dev mm-dslite0'"

    # Encap direction: an oversized *non-DF* inner IPv4 packet (1500B, -M dont)
    # exceeds the softwire's usable MTU (WAN 1500 - 40), so the encap must
    # XDP_PASS it to the kernel, which fragments the IPv4 to the tunnel MTU and
    # the ip6tnl encapsulates each piece. It must still reach the internet host.
    check "oversized non-DF traffic reaches the internet host via the fragmentation slow path" \
        ip netns exec "$NETNS_HOST" ping -M dont -s 1472 -c 2 -W 2 -I "$VETH_HOST_CPE" "${PUBLIC_INET_ADDR%/*}"

    # A *DF* oversized packet gets an ICMPv4 Fragmentation Needed (PMTUD), so it
    # doesn't get through. NB: this is a deliberate deviation from RFC 6333 §5.3
    # (errata 5847), which would have the B4 tunnel-fragment the outer IPv6 and
    # ignore the inner DF bit -- the kernel ip6tnl can't do that (backlog #4), and
    # minuteman's advertised WAN-40 LAN MTU makes an oversized DF packet a
    # misbehaving-client case anyway, for which PMTUD signalling is reasonable.
    if ip netns exec "$NETNS_HOST" ping -M do -s 1472 -c 1 -W 1 -I "$VETH_HOST_CPE" "${PUBLIC_INET_ADDR%/*}" >/dev/null 2>&1; then
        check "oversized DF traffic is NOT silently fragmented (expected it to fail)" false
    else
        check "oversized DF traffic gets ICMP Frag Needed (PMTUD; not tunnel-fragmented -- backlog #4)" true
    fi

    # Decap direction: hand-craft a fragmented softwire packet (a real Linux AFTR
    # never emits outer-IPv6 fragments) toward the B4. The decap must XDP_PASS
    # both fragments so the kernel reassembles them and the ip6tnl decapsulates
    # the result, delivering the inner ICMP echo to the LAN client (which replies).
    wan_mac="$(ip netns exec "$NETNS_CPE" cat "/sys/class/net/$VETH_CPE_ISP/address")"
    isp_mac="$(ip netns exec "$NETNS_ISP" cat "/sys/class/net/$VETH_ISP_CPE/address")"
    frag_pcap="$RUNDIR/frag-inner.log"
    ip netns exec "$NETNS_HOST" timeout 5 tcpdump -i "$VETH_HOST_CPE" -n -c 1 \
        'icmp and src 203.0.113.2' >"$frag_pcap" 2>/dev/null &
    frag_tcpdump_pid=$!
    sleep 1
    ip netns exec "$NETNS_ISP" python3 "$PWD/send-softwire-fragments.py" \
        "$wan_mac" "$isp_mac" "$VETH_ISP_CPE" "${CORE_AFTR_ADDR%/*}" "${WAN_CPE_ADDR%/*}"
    wait "$frag_tcpdump_pid" 2>/dev/null
    check "a fragmented softwire packet is reassembled and its inner echo reaches the LAN client" \
        grep -q "203.0.113.2 > 192.168.1" "$frag_pcap"

    # The softwire slow path's IPv4 default route (via mm-dslite0) must not make
    # the B4 a reflector: a decapped inner IPv4 whose destination is off-LAN would
    # otherwise be routed straight back into the tunnel. Send one such packet (inner
    # dst 8.8.8.8) and confirm the decap drops it (STAT_DECAP_MARTIAN) rather than
    # bouncing it back toward the AFTR.
    ip netns exec "$NETNS_AFTR" timeout 4 tcpdump -i "$VETH_AFTR_ISP" -n 'ip6 proto 4 and dst host fd00:2::2' \
        >"$RUNDIR/bounce.log" 2>/dev/null &
    bounce_tcpdump_pid=$!
    sleep 1
    ip netns exec "$NETNS_ISP" python3 "$PWD/send-softwire-fragments.py" \
        "$wan_mac" "$isp_mac" "$VETH_ISP_CPE" "${CORE_AFTR_ADDR%/*}" "${WAN_CPE_ADDR%/*}" martian 8.8.8.8
    wait "$bounce_tcpdump_pid" 2>/dev/null
    check "an off-LAN decapped packet is NOT bounced back into the softwire (no reflection to the AFTR)" \
        bash -c "! grep -q '8.8.8.8' '$RUNDIR/bounce.log'"

    encap_frag="$(read_stat EncapFragSlow)"
    reasm_pass="$(read_stat DecapReasmPass)"
    martian="$(read_stat DecapMartian)"
    check "encap fragmentation slow path was exercised (datapath EncapFragSlow +$((encap_frag - encap_frag0)))" \
        test "$encap_frag" -gt "$encap_frag0"
    check "decap reassembly slow path was exercised (datapath DecapReasmPass +$((reasm_pass - reasm_pass0)))" \
        test "$reasm_pass" -gt "$reasm_pass0"
    check "the off-LAN decapped packet was dropped in XDP (datapath DecapMartian +$((martian - martian0)))" \
        test "$martian" -gt "$martian0"
fi

if [[ $dynamic_b4_enabled -eq 1 && $started_minuteman -eq 1 ]]; then
    echo "== Dynamic B4 (RFC 7785 B4-address change): a WAN-address change re-selects the softwire source =="
    # At startup minuteman had no -b4, so it asked the kernel (RFC 6724) which
    # source to use toward the AFTR and got WAN_CPE_ADDR (the only WAN global).
    check "minuteman selected the B4 source dynamically toward the AFTR (see $RUNDIR/minuteman.log)" \
        grep -q "dynamic B4: kernel selected ${WAN_CPE_ADDR%/*} " "$RUNDIR/minuteman.log"

    # Renumber the WAN: add a clean second global (WAN_CPE_ADDR2) as a candidate,
    # then deprecate the address minuteman is currently using so the kernel's
    # RFC 6724 source selection -- and thus minuteman's watchB4/handleWANChange
    # -- must move off it. (Deprecating rather than deleting keeps the old
    # address reachable, so anything still routing via it, e.g. a PD return route
    # on mm-isp, is unaffected; only *source* selection avoids it.)
    echo "-- renumbering mm-cpe WAN: add ${WAN_CPE_ADDR2%/*}, deprecate ${WAN_CPE_ADDR%/*}"
    ip netns exec "$NETNS_CPE" ip addr add "$WAN_CPE_ADDR2" dev "$VETH_CPE_ISP"
    ip netns exec "$NETNS_CPE" ip addr change "$WAN_CPE_ADDR" dev "$VETH_CPE_ISP" preferred_lft 0

    # watchB4 polls every 30s; give it a full interval (plus the new address's
    # DAD) to notice the change and hard-switch. It re-selects whichever source
    # the kernel now prefers among the remaining non-deprecated WAN globals
    # (WAN_CPE_ADDR2, or the WAN's own SLAAC address) -- parse that from the log
    # rather than assuming which, then assert it moved off the deprecated one.
    check "minuteman re-selected the softwire source after the WAN address change" \
        retry_slow grep -q "switched softwire source to " "$RUNDIR/minuteman.log"
    switched_b4="$(sed -n 's/.*switched softwire source to \([^ ]*\) .*/\1/p' "$RUNDIR/minuteman.log" | tail -n1)"
    check "the re-selected B4 ($switched_b4) is no longer the deprecated ${WAN_CPE_ADDR%/*}" \
        test -n "$switched_b4" -a "$switched_b4" != "${WAN_CPE_ADDR%/*}"

    # Follow through on the ISP side: point the AFTR's ip6tnl at whatever B4
    # minuteman picked -- the NAT-state-follows-the-address step a real AFTR does
    # via its own B4 re-learning. Until this lands the AFTR rejects the new outer
    # source, so this is also what makes the re-test below prove the switch took.
    echo "-- pointing the AFTR's softwire tunnel at the re-selected B4 $switched_b4"
    ip netns exec "$NETNS_AFTR" ip -6 tunnel change "$AFTR_TUN" mode ipip6 \
        local "${CORE_AFTR_ADDR%/*}" remote "$switched_b4" encaplimit none

    # The softwire must work end to end again, now sourced from the new B4. This
    # only succeeds if minuteman really moved to $switched_b4 (the AFTR now
    # accepts only that source, and decap now expects return traffic to it).
    check "LAN client reaches the internet through the softwire after renumbering (B4 now $switched_b4)" \
        retry ip netns exec "$NETNS_HOST" ping -c 2 -W 2 -I "$VETH_HOST_CPE" "${PUBLIC_INET_ADDR%/*}"
fi

if [[ $dualstack_enabled -eq 1 ]]; then
    echo "== Dual-stack (RFC 6333): IPv4 via softwire, IPv6 native -- A vs AAAA =="
    # Snapshot the IPv6-fastpath counters up front so the assertions at the end
    # are deltas over just this section's traffic (works against a reused
    # instance too -- read_stat needs no log ownership).
    ipv6_fwd0="$(read_stat IPv6Fwd)"
    ipv6_rss0="$(read_stat IPv6RSSRedirect)"
    # The whole point: a DS-Lite B4 tunnels only IPv4; native IPv6 is forwarded
    # directly. mm-host is dual-stack, mm-inet answers on both families under
    # one name (DUALSTACK_FQDN), and we steer traffic down each path purely by
    # DNS record type, confirming via dslite0 which path the softwire carried.

    # mm-host is genuinely dual-stack: an IPv4 (static, or from -dhcpv4) and a
    # global SLAAC IPv6 both live on its LAN interface right now.
    check "$NETNS_HOST holds both an IPv4 and a global IPv6 address (dual-stack)" \
        bash -c "ip netns exec $NETNS_HOST ip -4 addr show dev $VETH_HOST_CPE | grep -q 'inet ' &&
                 ip netns exec $NETNS_HOST ip -6 addr show dev $VETH_HOST_CPE scope global | grep -q 'inet6 '"

    # Resolve DUALSTACK_FQDN once per family against mm-isp's resolver (over
    # native IPv6, exactly as a real dual-stack CPE client would): A ->
    # mm-inet's public IPv4, AAAA -> mm-inet's native IPv6.
    a_addr="$(ip netns exec "$NETNS_HOST" dig @"${WAN_ISP_ADDR%/*}" +short A "$DUALSTACK_FQDN" | head -n1)"
    aaaa_addr="$(ip netns exec "$NETNS_HOST" dig @"${WAN_ISP_ADDR%/*}" +short AAAA "$DUALSTACK_FQDN" | head -n1)"
    check "DNS returns the A record for $DUALSTACK_FQDN (${PUBLIC_INET_ADDR%/*})" \
        test "$a_addr" = "${PUBLIC_INET_ADDR%/*}"
    check "DNS returns the AAAA record for $DUALSTACK_FQDN (${PUBLIC6_INET_ADDR%/*})" \
        test "$aaaa_addr" = "${PUBLIC6_INET_ADDR%/*}"

    # A record -> IPv4: MUST cross the softwire. Reachability proves the tunnel
    # path works end to end; a non-zero dslite0 count is the positive control
    # for the AAAA check below (proving the sniffer would have caught a leak).
    if [[ -n "$a_addr" ]]; then
        dslite_capture ip netns exec "$NETNS_HOST" \
            ping -c 2 -W 2 -I "$VETH_HOST_CPE" "$a_addr"
        check "IPv4/A path to $a_addr reaches the internet (through the softwire)" \
            test "${DSLITE_CONN:-1}" -eq 0
        check "IPv4/A path DID cross the AFTR's dslite0 tunnel (${DSLITE_PKTS:-0} pkts there, want >0)" \
            test "${DSLITE_PKTS:-0}" -gt 0
    fi

    # AAAA record -> IPv6: MUST NOT touch the softwire (RFC 6333 -- a B4
    # tunnels only IPv4). Reachability proves native IPv6 forwarding works; a
    # ZERO dslite0 count proves it bypassed the tunnel entirely.
    if [[ -n "$aaaa_addr" ]]; then
        dslite_capture ip netns exec "$NETNS_HOST" \
            ping -6 -c 2 -W 2 -I "$VETH_HOST_CPE" "$aaaa_addr"
        check "IPv6/AAAA path to $aaaa_addr reaches mm-inet natively" \
            test "${DSLITE_CONN:-1}" -eq 0
        check "IPv6/AAAA path did NOT cross the AFTR's dslite0 tunnel (${DSLITE_PKTS:-0} pkts there, want 0)" \
            test "${DSLITE_PKTS:-0}" -eq 0
    fi

    # Prove that native IPv6 was carried by minuteman's XDP forwarding fastpath
    # -- not the kernel slow path. The reachability/dslite0 checks above hold
    # for either, so here we read the datapath's own IPv6-forward counter from
    # the pinned stats map: it advances only when handle_ipv6_forward
    # redirected a packet in XDP.
    ipv6_fwd="$(read_stat IPv6Fwd)"
    check "native IPv6 was forwarded by the XDP fastpath (datapath IPv6Fwd +$((ipv6_fwd - ipv6_fwd0)))" \
        test "$ipv6_fwd" -gt "$ipv6_fwd0"
    if [[ "${MM_IPV6_SW_RSS:-0}" == 1 ]]; then
        ipv6_rss="$(read_stat IPv6RSSRedirect)"
        check "IPv6 software-RSS fanned native-IPv6 packets across CPUs (datapath IPv6RSSRedirect +$((ipv6_rss - ipv6_rss0)))" \
            test "$ipv6_rss" -gt "$ipv6_rss0"
    fi
fi

if [[ $fail -eq 0 ]]; then
    echo "== all checks passed =="
else
    echo "== one or more checks FAILED (see minuteman log: $RUNDIR/minuteman.log) =="
fi
exit $fail

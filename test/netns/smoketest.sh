#!/bin/bash
# End-to-end smoke test for the DS-Lite netns rig: pings and curls from the
# simulated LAN client, through minuteman's B4 encap, the AFTR's decap+NAPT44,
# to the simulated public internet host, and back. Also spot-checks AFTR
# discovery in whichever mode setup.sh built the rig for (see its
# MM_AFTR_DISCOVERY notes): the RFC 6334 AFTR-Name over stateless DHCPv6, or
# the HB46PP TXT-record + provisioning-server fallback. And spot-checks LAN
# IPv6 reachability in whichever WAN model setup.sh built the rig for (see
# its MM_WAN_MODEL notes): DHCPv6-PD SLAAC from a delegated prefix, or
# RFC 4389 NDProxy extending the WAN's own SLAAC prefix onto the LAN. TCP MSS
# clamping is checked unconditionally (it is on by default and needs no rig
# topology of its own): both directions of a SYN exchange are captured and the
# advertised MSS compared against what the rig's WAN MTU implies. If
# setup.sh was run with MM_DNS_PROXY=1, also spot-checks minuteman's DNS
# proxy (RFC 6333's B4 SHOULD); if with MM_DHCPV4=1, has mm-host acquire its
# IPv4 lease from minuteman's DHCPv4 server (RFC 2131) and checks it; if with
# MM_PD_ZERO_TIMERS=1, waits out the renewal timer minuteman derived for
# itself from a T1=T2=0 delegation (RFC 9915 §14.2) and checks it renewed
# once on it rather than storming the server (this mode alone adds ~90s).
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

# iface_stats runs `minuteman stats interfaces` (passing along any extra args,
# e.g. --json), which reports the driver counters -- the `ethtool -S` set -- of
# every interface the datapath has XDP attached to, labelled with its role.
#
# Unlike read_stat this has to run *inside* mm-cpe: the interfaces live there,
# while the bpffs pin the subcommand identifies the instance's programs by lives
# on the host. nsenter --net enters only the network namespace and so satisfies
# both at once -- `ip netns exec` would remount /sys and hide the pin, the same
# reason minuteman itself is started with nsenter below.
iface_stats() {
    nsenter --net="/var/run/netns/$NETNS_CPE" "$MINUTEMAN_BIN" stats interfaces "$@" 2>/dev/null
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

tunnel_icmp_enabled=0
if [[ -f "$TUNNEL_ICMP_ENABLED_FILE" && "$(cat "$TUNNEL_ICMP_ENABLED_FILE")" == 1 ]]; then
    tunnel_icmp_enabled=1
fi

pd_zero_timers=0
if [[ -f "$PD_ZERO_TIMERS_FILE" && "$(cat "$PD_ZERO_TIMERS_FILE")" == 1 ]]; then
    pd_zero_timers=1
fi
# The T1 minuteman derives from Kea's zero timers under MM_PD_ZERO_TIMERS:
# 0.5 x PD_ZERO_PREFERRED_LIFETIME, per RFC 9915 §21.21's recommended ratio
# (see pkg/prefixdelegation's effectiveTimers), formatted as time.Duration
# prints it -- both the value the log line below is matched against and the
# interval the renewal check waits out.
pd_zero_t1=$((PD_ZERO_PREFERRED_LIFETIME / 2))
pd_zero_t2=$((PD_ZERO_PREFERRED_LIFETIME * 4 / 5))
fmt_duration() { printf '%dm%ds' $(($1 / 60)) $(($1 % 60)); }

# kea_renew_count prints how many Renew messages mm-isp's Kea has logged
# receiving so far (0 if it has no log yet) -- the renewal check below
# compares two readings of this rather than an absolute count, since Kea's
# log spans the whole rig lifetime and may already hold a previous
# smoketest run's renewals.
kea_renew_count() {
    local n
    n="$(grep -c "RENEW (type 5) received" "$KEA_LOG" 2>/dev/null || true)"
    echo "${n:-0}"
}
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
    # When the DHCPv6-PD renewal check runs at the end of this script, it
    # has to have waited out a full derived T1 measured from the lease --
    # which is acquired a second or two after this point. Everything the
    # script does in between counts toward that wait, so its baseline for
    # Kea's Renew count has to be taken here, not there: on a slow enough
    # run (or with enough other toggles on) the renewal it looks for can
    # land before the final check even starts.
    minuteman_started_at=$(date +%s)
    kea_renews0="$(kea_renew_count)"
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
    # dhclient runs with a script of its own (-sf), applying the address,
    # the default route and the MTU -- what the checks below look at -- and
    # nothing else. The system dhclient-script would also write the DNS
    # server minuteman hands out (its LAN gateway, with -dns-proxy) to
    # /etc/resolv.conf, and `ip netns exec` gives a namespace its own
    # network, not its own /etc: that is the *host's* resolv.conf, left
    # pointing at an address only mm-host can reach, and the long-lived
    # dhclient would rewrite it again on every renewal.
    cat >"$DHCLIENT_SCRIPT" <<'SCRIPT'
#!/bin/sh
case "$reason" in
BOUND|RENEW|REBIND|REBOOT)
    if [ -n "$new_interface_mtu" ]; then
        ip link set dev "$interface" mtu "$new_interface_mtu"
    fi
    ip addr replace "$new_ip_address/$new_subnet_mask" dev "$interface"
    for router in $new_routers; do
        ip route replace default via "$router" dev "$interface"
        break
    done
    ;;
EXPIRE|FAIL|RELEASE|STOP)
    if [ -n "$old_ip_address" ]; then
        ip addr del "$old_ip_address/$old_subnet_mask" dev "$interface"
    fi
    ;;
esac
exit 0
SCRIPT
    chmod +x "$DHCLIENT_SCRIPT"
    if [[ $started_minuteman -eq 1 ]]; then
        check "minuteman is serving DHCPv4 on $VETH_CPE_HOST (see $RUNDIR/minuteman.log)" \
            grep -q "DHCPv4: serving $LAN_PREFIX on $VETH_CPE_HOST" "$RUNDIR/minuteman.log"
    fi
    check "$NETNS_HOST acquired an IPv4 lease via dhclient (DORA against minuteman)" \
        ip netns exec "$NETNS_HOST" dhclient -4 -1 -sf "$DHCLIENT_SCRIPT" \
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
        if [[ $pd_zero_timers -eq 1 ]]; then
            # Kea delegated with T1 = T2 = 0 (RFC 9915 §21.21: the renewal
            # timing is the requesting router's to choose), so minuteman
            # must have picked §21.21's recommended ratios of the ${PD_ZERO_PREFERRED_LIFETIME}s
            # preferred lifetime for itself rather than taking the 0s
            # literally. The renewal that timer schedules is checked at the
            # end of this script, once it has had time to happen.
            check "minuteman chose its own renewal timers for a T1=T2=0 delegation (RFC 9915 §14.2: renew $(fmt_duration $pd_zero_t1), rebind $(fmt_duration $pd_zero_t2))" \
                grep -q "DHCPv6-PD lease on $VETH_CPE_ISP: prefix $PD_POOL_PREFIX, renew in $(fmt_duration $pd_zero_t1), rebind in $(fmt_duration $pd_zero_t2)" "$RUNDIR/minuteman.log"
        fi
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
    # answer back, both over UDP and over TCP (internal/dnsproxy listens on both).
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

echo "== stats subcommands: datapath counters and every XDP-bound interface's driver counters =="

# The interface list is derived from the kernel (a link dump plus the pinned
# stats map), not from the flags minuteman was started with, so this asserts
# that derivation end-to-end: the WAN and LAN veths must come back with the
# right roles, and so must all four of the softwire fragmenter's companion
# veths -- which no flag names at all.
iface_report="$RUNDIR/stats-interfaces.log"
iface_stats >"$iface_report"
check "\`stats interfaces\` reports the WAN veth $VETH_CPE_ISP with role wan" \
    grep -q "^$VETH_CPE_ISP (ifindex .*role wan" "$iface_report"
check "\`stats interfaces\` reports the LAN veth $VETH_CPE_HOST with role lan" \
    grep -q "^$VETH_CPE_HOST (ifindex .*role lan" "$iface_report"
# 4 = datapath.MaxSoftwireFrags = fragpath.NumPairs, the companion veth pairs
# the in-XDP fragmenter bounces its clones through.
check "\`stats interfaces\` reports all 4 fragmenter companion veths with role frag" \
    test "$(grep -c 'role frag' "$iface_report")" -eq 4

# Both JSON views must stay directly walkable: `stats --json` is the counter
# object itself, `stats interfaces --json` the per-interface array. Checked
# with python3 (already needed by send-softwire-fragments.py) rather than jq,
# which the rig doesn't otherwise depend on.
stats_json_is_counter_object() {
    "$MINUTEMAN_BIN" stats --json | python3 -c '
import json, sys
d = json.load(sys.stdin)
sys.exit(0 if isinstance(d, dict) and "DecapMartian" in d else 1)
'
}
iface_json_is_array() {
    iface_stats --json | python3 -c '
import json, sys
d = json.load(sys.stdin)
sys.exit(0 if isinstance(d, list) and d and all("Role" in i for i in d) else 1)
'
}
check "\`stats --json\` decodes as an object of datapath counters" \
    stats_json_is_counter_object
check "\`stats interfaces --json\` decodes as an array of per-interface entries" \
    iface_json_is_array

if [[ $started_minuteman -eq 1 ]]; then
    echo "== TCP MSS clamping: neither end offers segments the softwire would have to fragment =="

    # Both directions are asserted because the MSS option announces what its
    # *sender* will receive: the LAN client's SYN bounds what arrives through
    # the softwire, the remote's SYN-ACK bounds what the LAN client sends into
    # it, and the two are clamped by different programs (encap and decap).
    #
    # The expected value is derived, not hardcoded, so it stays right if the rig's
    # WAN MTU changes: minuteman's automatic clamp is the softwire MTU less the
    # 40-byte outer IPv6 header and the 40 bytes of option-free IPv4 + TCP header
    # an MSS excludes (see pkg/datapath's autoTCPMSSClamp).
    mss_clamped0="$(read_stat MSSClamped)"
    mss_wan_mtu="$(ip netns exec "$NETNS_CPE" cat "/sys/class/net/$VETH_CPE_ISP/mtu")"
    expected_mss=$((mss_wan_mtu - 80))
    # A clamp is counted only where an MSS is lowered. The remote's SYN-ACK
    # always is; the LAN client's SYN not when the client already sizes it
    # to fit -- as under MM_DHCPV4=1, where it takes the softwire-adjusted
    # MTU minuteman hands out (option 26), so its SYN carries expected_mss
    # to begin with.
    mss_host_mtu="$(ip netns exec "$NETNS_HOST" cat "/sys/class/net/$VETH_HOST_CPE/mtu")"
    expected_clamps=2
    if ((mss_host_mtu - 40 <= expected_mss)); then
        expected_clamps=1
    fi
    mss_syn_pcap="$RUNDIR/mss-clamp-outbound.log"
    mss_synack_pcap="$RUNDIR/mss-clamp-inbound.log"

    # The outbound SYN as the AFTR sees it once decapsulated, and the inbound
    # SYN-ACK as the LAN client sees it. Port 8081 rather than the 8080 used
    # above so neither capture can be consumed by a retransmit of that
    # connection; -c 1 on the AFTR side is safe because the SYN is by definition
    # the first packet of the connection to reach it.
    ip netns exec "$NETNS_AFTR" timeout 8 tcpdump -i "$AFTR_TUN" -n -vv -c 1 \
        "tcp port 8081" >"$mss_syn_pcap" 2>/dev/null &
    mss_syn_td=$!
    ip netns exec "$NETNS_HOST" timeout 8 tcpdump -i "$VETH_HOST_CPE" -n -vv -c 1 \
        "tcp port 8081 and tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)" \
        >"$mss_synack_pcap" 2>/dev/null &
    mss_synack_td=$!
    sleep 1

    ip netns exec "$NETNS_INET" bash -c \
        "printf 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok' | timeout 5 nc -l -p 8081 -q1" &
    nc_pid=$!
    sleep 0.3
    # A completed request is also the checksum assertion: XDP has no
    # bpf_l4_csum_replace, so the rewrite fixes up the TCP checksum by hand
    # (csum_replace16), and getting that wrong drops the SYN at the far end.
    check "a TCP connection still completes end-to-end with the MSS rewritten" \
        ip netns exec "$NETNS_HOST" curl -sf --max-time 4 "http://${PUBLIC_INET_ADDR%/*}:8081/"
    wait "$nc_pid" 2>/dev/null
    wait "$mss_syn_td" 2>/dev/null
    wait "$mss_synack_td" 2>/dev/null

    mss_clamped="$(read_stat MSSClamped)"
    check "the LAN client's SYN reaches the AFTR advertising mss $expected_mss (encap side)" \
        grep -q "mss $expected_mss" "$mss_syn_pcap"
    check "the remote's SYN-ACK reaches the LAN client advertising mss $expected_mss (decap side)" \
        grep -q "mss $expected_mss" "$mss_synack_pcap"
    check "the datapath counted a clamp wherever an MSS was lowered (MSSClamped +$((mss_clamped - mss_clamped0)), want $expected_clamps)" \
        test "$((mss_clamped - mss_clamped0))" -ge "$expected_clamps"
fi

if [[ $started_minuteman -eq 1 ]]; then
    echo "== Tunnel-originated ICMPv4 (RFC 1812 §5.3.1, RFC 6333 §5.7): B4 replies through the softwire =="

    # Runs after the checks above on purpose: the decap only answers Time
    # Exceeded for a packet it would really forward (a resolved LAN next hop),
    # so the LAN client must already be in mm-cpe's neighbour table -- which the
    # ping/curl above guarantee.
    time_exceeded0="$(read_stat ICMPTimeExceeded)"
    wan_mac="$(ip netns exec "$NETNS_CPE" cat "/sys/class/net/$VETH_CPE_ISP/address")"
    isp_mac="$(ip netns exec "$NETNS_ISP" cat "/sys/class/net/$VETH_ISP_CPE/address")"
    time_exceeded_pcap="$RUNDIR/decap-time-exceeded.log"
    # The filter reaches past the outer IPv6 header into the softwire payload
    # (ip6[49] is the inner IPv4 protocol, ip6[60] the inner ICMP type once
    # ihl == 5) so only a Time Exceeded matches: "any softwire packet B4 ->
    # AFTR" would also match a stray retransmit from the checks above and, with
    # -c 1, consume the capture on it.
    ip netns exec "$NETNS_ISP" timeout 5 tcpdump -i "$VETH_ISP_CPE" -n -vv -c 1 \
        "ip6 proto 4 and src host ${WAN_CPE_ADDR%/*} and dst host ${CORE_AFTR_ADDR%/*} \
         and ip6[49] == 1 and ip6[60] == 11" \
        >"$time_exceeded_pcap" 2>/dev/null &
    time_exceeded_tcpdump_pid=$!
    sleep 1
    ip netns exec "$NETNS_ISP" python3 "$PWD/send-softwire-fragments.py" \
        "$wan_mac" "$isp_mac" "$VETH_ISP_CPE" "${CORE_AFTR_ADDR%/*}" "${WAN_CPE_ADDR%/*}" ttl1
    wait "$time_exceeded_tcpdump_pid" 2>/dev/null

    time_exceeded="$(read_stat ICMPTimeExceeded)"
    check "an inbound inner TTL expiry draws ICMPv4 Time Exceeded back through the softwire" \
        bash -c "grep -q 'time exceeded' '$time_exceeded_pcap'"
    check "the B4's tunnel-originated ICMPv4 uses the well-known 192.0.0.2 source" \
        bash -c "grep -q '192.0.0.2 > 203.0.113.2' '$time_exceeded_pcap'"
    check "the datapath counted the decap-side Time Exceeded reply (ICMPTimeExceeded +$((time_exceeded - time_exceeded0)))" \
        test "$time_exceeded" -gt "$time_exceeded0"
fi

if [[ $softwire_frag_enabled -eq 1 && $started_minuteman -eq 1 ]]; then
    echo "== Softwire fragmentation (RFC 6333 §5.3): XDP fragments the outer IPv6 outbound, the kernel ip6tnl reassembles inbound =="

    # Force the FIB FRAG_NEEDED branch on decap and assert an XDP-originated
    # DF error, then verify oversized off-LAN traffic is still rejected.
    wan_mac="$(ip netns exec "$NETNS_CPE" cat "/sys/class/net/$VETH_CPE_ISP/address")"
    isp_mac="$(ip netns exec "$NETNS_ISP" cat "/sys/class/net/$VETH_ISP_CPE/address")"
    lan_mtu_orig="$(ip netns exec "$NETNS_CPE" cat "/sys/class/net/$VETH_CPE_HOST/mtu")"
    ip netns exec "$NETNS_CPE" ip link set "$VETH_CPE_HOST" mtu 1280
    frag_needed0="$(read_stat ICMPFragNeeded)"
    ip netns exec "$NETNS_ISP" python3 "$PWD/send-softwire-fragments.py" \
        "$wan_mac" "$isp_mac" "$VETH_ISP_CPE" "${CORE_AFTR_ADDR%/*}" "${WAN_CPE_ADDR%/*}" oversized 192.168.1.2
    sleep 1
    check "decap FIB MTU overflow originates an XDP ICMPv4 DF error" \
        test "$(read_stat ICMPFragNeeded)" -gt "$frag_needed0"
    ip netns exec "$NETNS_CPE" ip link set "$VETH_CPE_HOST" mtu "$lan_mtu_orig"
    tunnel_mtu_orig="$(ip netns exec "$NETNS_CPE" cat /sys/class/net/mm-dslite0/mtu)"
    ip netns exec "$NETNS_CPE" ip link set mm-dslite0 mtu 1280
    oversized_martian0="$(read_stat DecapMartian)"
    ip netns exec "$NETNS_ISP" python3 "$PWD/send-softwire-fragments.py" \
        "$wan_mac" "$isp_mac" "$VETH_ISP_CPE" "${CORE_AFTR_ADDR%/*}" "${WAN_CPE_ADDR%/*}" oversized 8.8.8.8
    sleep 1
    check "oversized off-LAN decap is classified as martian" \
        test "$(read_stat DecapMartian)" -gt "$oversized_martian0"
    ip netns exec "$NETNS_CPE" ip link set mm-dslite0 mtu "$tunnel_mtu_orig"

    # Snapshot the fragmentation counters before generating any traffic, so the
    # assertions below are deltas -- immune to whatever an earlier check (or a
    # reused instance) already accumulated.
    frag_xdp0="$(read_stat EncapFragXDP)"
    frag_seg0="$(read_stat EncapFragSeg)"
    encap_frag0="$(read_stat EncapFragSlow)"
    reasm_pass0="$(read_stat DecapReasmPass)"
    martian0="$(read_stat DecapMartian)"

    # The companion device and its IPv4 default route must exist while minuteman
    # runs (both are torn down on shutdown): they carry the inbound reassembly
    # half and the encap fragmenter's fallback cases.
    check "minuteman created the companion ip6tnl (mm-dslite0) in $NETNS_CPE" \
        ip netns exec "$NETNS_CPE" ip link show mm-dslite0
    check "minuteman installed the IPv4 default route via mm-dslite0" \
        bash -c "ip netns exec $NETNS_CPE ip route show default | grep -q 'dev mm-dslite0'"

    # Encap direction: an oversized inner IPv4 packet (1500B) exceeds the
    # softwire's usable MTU (WAN 1500 - 40), so the encap must encapsulate it
    # whole and fragment the *outer IPv6* in XDP (RFC 6333 §5.3, errata 5847 ->
    # RFC 2473 §7.2(b)) -- never the inner IPv4, and ignoring the DF bit, so
    # both a non-DF and a DF oversized packet must reach the internet host
    # transparently (each as two outer fragments the AFTR reassembles).
    check "oversized non-DF traffic reaches the internet host via XDP outer-IPv6 fragmentation" \
        ip netns exec "$NETNS_HOST" ping -M dont -s 1472 -c 2 -W 2 -I "$VETH_HOST_CPE" "${PUBLIC_INET_ADDR%/*}"
    check "oversized DF traffic also reaches the internet host (DF ignored per errata 5847)" \
        ip netns exec "$NETNS_HOST" ping -M do -s 1472 -c 2 -W 2 -I "$VETH_HOST_CPE" "${PUBLIC_INET_ADDR%/*}"

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

    frag_xdp="$(read_stat EncapFragXDP)"
    frag_seg="$(read_stat EncapFragSeg)"
    encap_frag="$(read_stat EncapFragSlow)"
    reasm_pass="$(read_stat DecapReasmPass)"
    martian="$(read_stat DecapMartian)"
    check "oversized packets were outer-fragmented in XDP (datapath EncapFragXDP +$((frag_xdp - frag_xdp0)))" \
        test "$frag_xdp" -gt "$frag_xdp0"
    # Every oversized packet in this rig (1500B inner, 1448B fragment payload)
    # yields exactly two outer fragments.
    check "each fragmented packet produced 2 outer-IPv6 fragments (datapath EncapFragSeg +$((frag_seg - frag_seg0)))" \
        test "$((frag_seg - frag_seg0))" -eq "$((2 * (frag_xdp - frag_xdp0)))"
    check "the kernel ip6tnl encap fallback was NOT needed (datapath EncapFragSlow +$((encap_frag - encap_frag0)))" \
        test "$encap_frag" -eq "$encap_frag0"
    check "decap reassembly slow path was exercised (datapath DecapReasmPass +$((reasm_pass - reasm_pass0)))" \
        test "$reasm_pass" -gt "$reasm_pass0"
    check "the off-LAN decapped packet was dropped in XDP (datapath DecapMartian +$((martian - martian0)))" \
        test "$martian" -gt "$martian0"

    # The same fragmentation seen from underneath the XDP programs: the counters
    # above say the fragmenter ran, `stats interfaces` says the clones really
    # left through the companion veths. Summed by substring match over every
    # frag-role interface, because a veth reports these per rx queue
    # (rx_queue_0_xdp_redirect) and the queue count is not ours to assume.
    frag_redirects="$(iface_stats --json | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(sum(v for i in d if i.get("Role") == "frag"
          for k, v in (i.get("Stats") or {}).items() if "xdp_redirect" in k))
')"
    check "the companion veths redirected the fragment clones (xdp_redirect ${frag_redirects:-0} across the frag-role interfaces)" \
        test "${frag_redirects:-0}" -gt 0

    # --- Encap fallback (backlog §1 residual): a packet the in-XDP fragmenter
    # can't take must fall to the kernel ip6tnl (EncapFragSlow) -- and crucially
    # a *DF* one must still draw an ICMPv4 Fragmentation-Needed (PMTUD) rather
    # than silently blackhole. That's the specific regression risk this PR
    # introduces: DF oversized packets now route to the fallback instead of the
    # old in-XDP plain ICMPv4 reply, so the DF-on-the-fallback behavior is worth
    # asserting directly.
    #
    # The over-MaxInnerLen *inner-size* trigger isn't reachable from the LAN in
    # this rig -- the CPE's XDP-attached LAN veth caps the pair's MTU, so the
    # client can never emit a >1500 inner packet (it IP-fragments first, and each
    # fragment takes the fast path). The reachable trigger is a runtime WAN-MTU
    # shrink below the fragment size frag_unit was computed from at startup
    # (1448 at WAN 1500): every oversized packet then exceeds frag_unit and takes
    # the fallback. ---
    echo "-- encap fallback: a runtime WAN-MTU shrink forces the kernel ip6tnl path (DF -> PMTUD) --"
    wan_mtu_orig="$(ip netns exec "$NETNS_CPE" cat "/sys/class/net/$VETH_CPE_ISP/mtu")"
    ip netns exec "$NETNS_CPE" ip link set "$VETH_CPE_ISP" mtu 1400

    fb_encap0="$(read_stat EncapFragSlow)"
    fb_xdp0="$(read_stat EncapFragXDP)"

    # A DF packet too big for the shrunk WAN once encapsulated: the encap can no
    # longer outer-fragment within frag_unit, so it XDP_PASSes to the kernel
    # ip6tnl, which -- unable to fragment a DF inner packet -- answers ICMPv4
    # Fragmentation-Needed back to the client (PMTUD). Capture that signal on the
    # LAN; the ping itself is expected to fail (that IS the PMTUD drop), and the
    # client caches the lower PMTU, so only the first packet reaches the encap.
    pmtud_pcap="$RUNDIR/pmtud-df.log"
    ip netns exec "$NETNS_HOST" timeout 5 tcpdump -i "$VETH_HOST_CPE" -n -c 1 \
        'icmp[0] == 3 and icmp[1] == 4' >"$pmtud_pcap" 2>/dev/null &
    pmtud_tcpdump_pid=$!
    sleep 1
    ip netns exec "$NETNS_HOST" ping -M do -s 1400 -c 2 -W 2 -I "$VETH_HOST_CPE" "${PUBLIC_INET_ADDR%/*}" >/dev/null 2>&1 || true
    wait "$pmtud_tcpdump_pid" 2>/dev/null

    fb_encap="$(read_stat EncapFragSlow)"
    fb_xdp="$(read_stat EncapFragXDP)"
    check "the kernel ip6tnl encap fallback was exercised (datapath EncapFragSlow +$((fb_encap - fb_encap0)))" \
        test "$fb_encap" -gt "$fb_encap0"
    check "a DF packet on the fallback draws ICMPv4 Fragmentation-Needed (PMTUD), not a blackhole" \
        bash -c "grep -q 'need to frag' '$pmtud_pcap'"
    check "the fallback did NOT engage the in-XDP fragmenter (datapath EncapFragXDP +$((fb_xdp - fb_xdp0)))" \
        test "$fb_xdp" -eq "$fb_xdp0"

    # Restore the WAN MTU and flush the client's PMTU cache so later checks (and
    # reruns) see the rig's 1500 baseline.
    ip netns exec "$NETNS_CPE" ip link set "$VETH_CPE_ISP" mtu "$wan_mtu_orig"
    ip netns exec "$NETNS_HOST" ip route flush cache 2>/dev/null || true
fi

if [[ $dynamic_b4_enabled -eq 1 && $started_minuteman -eq 1 ]]; then
    echo "== Dynamic B4 (RFC 7785 B4-address change): a WAN-address change re-selects the softwire source =="
    # At startup minuteman had no -b4, so it asked the kernel (RFC 6724) which
    # source to use toward the AFTR and got WAN_CPE_ADDR (the only WAN global).
    check "minuteman selected the B4 source dynamically toward the AFTR (see $RUNDIR/minuteman.log)" \
        grep -q "dynamic B4: kernel selected ${WAN_CPE_ADDR%/*} " "$RUNDIR/minuteman.log"

    # Renumber the WAN: add a clean second global (WAN_CPE_ADDR2) as a candidate,
    # then deprecate the address minuteman is currently using so the kernel's
    # RFC 6724 source selection -- and thus minuteman's softwirectl B4 poll
    # -- must move off it. (Deprecating rather than deleting keeps the old
    # address reachable, so anything still routing via it, e.g. a PD return route
    # on mm-isp, is unaffected; only *source* selection avoids it.)
    echo "-- renumbering mm-cpe WAN: add ${WAN_CPE_ADDR2%/*}, deprecate ${WAN_CPE_ADDR%/*}"
    ip netns exec "$NETNS_CPE" ip addr add "$WAN_CPE_ADDR2" dev "$VETH_CPE_ISP"
    ip netns exec "$NETNS_CPE" ip addr change "$WAN_CPE_ADDR" dev "$VETH_CPE_ISP" preferred_lft 0

    # The B4 poll runs every 30s; give it a full interval (plus the new address's
    # DAD) to notice the change and hard-switch. It re-selects whichever source
    # the kernel now prefers among the remaining non-deprecated WAN globals
    # (WAN_CPE_ADDR2: setup.sh turns SLAAC off on this link in this mode) --
    # parse that from the log rather than assuming which, then assert it moved
    # off the deprecated one.
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

    # The reply must work from the CPUMAP stage too (XDP_TX is unsupported).
    wan_mtu_orig="$(ip netns exec "$NETNS_CPE" cat "/sys/class/net/$VETH_CPE_ISP/mtu")"
    ip netns exec "$NETNS_CPE" ip link set "$VETH_CPE_ISP" mtu 1280
    ip netns exec "$NETNS_HOST" timeout 5 tcpdump -i "$VETH_HOST_CPE" -n -c 1 \
        'icmp6 and ip6[40] == 2' >"$RUNDIR/native-ptb.log" 2>/dev/null &
    native_ptb_pid=$!
    sleep 1
    ip netns exec "$NETNS_HOST" ping -6 -M do -s 1352 -c 1 -W 2 "${PUBLIC6_INET_ADDR%/*}" >/dev/null 2>&1 || true
    wait "$native_ptb_pid" 2>/dev/null
    check "native IPv6 MTU overflow returns Packet Too Big, including software RSS" \
        grep -q 'packet too big' "$RUNDIR/native-ptb.log"
    ip netns exec "$NETNS_CPE" ip link set "$VETH_CPE_ISP" mtu "$wan_mtu_orig"

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

if [[ $tunnel_icmp_enabled -eq 1 && $started_minuteman -eq 1 ]]; then
    echo "== Tunnel ICMPv6 relay (RFC 2473 §8): an ICMPv6 error about a softwire packet becomes an ICMPv4 error to the LAN client =="

    # Runs after every other datapath section on purpose: the second half below
    # leaves a learned softwire path MTU in force for 10 minutes
    # (datapath.TunnelPMTUExpiry), which re-sizes the fragments the
    # MM_SOFTWIRE_FRAG checks assert on.

    wan_mac="$(ip netns exec "$NETNS_CPE" cat "/sys/class/net/$VETH_CPE_ISP/address")"
    isp_mac="$(ip netns exec "$NETNS_ISP" cat "/sys/class/net/$VETH_ISP_CPE/address")"

    # inject_tunnel_icmp <tag> <mode...> captures whatever ICMPv4 reaches the LAN
    # client while one hand-crafted ICMPv6 error is sent to the B4 from the ISP
    # side (as an intermediate router on the B4<->AFTR path would), leaving the
    # capture in $tunnel_icmp_pcap for the caller to assert against.
    inject_tunnel_icmp() {
        local tag="$1"
        shift
        tunnel_icmp_pcap="$RUNDIR/tunnel-icmp-$tag.log"
        ip netns exec "$NETNS_HOST" timeout 5 tcpdump -i "$VETH_HOST_CPE" -n icmp \
            >"$tunnel_icmp_pcap" 2>/dev/null &
        local td=$!
        sleep 1
        ip netns exec "$NETNS_ISP" env MM_QUOTED_SRC="${MM_QUOTED_SRC:-192.168.1.2}" python3 "$PWD/send-softwire-fragments.py" \
            "$wan_mac" "$isp_mac" "$VETH_ISP_CPE" "${CORE_AFTR_ADDR%/*}" "${WAN_CPE_ADDR%/*}" "$@"
        wait "$td" 2>/dev/null
    }

    # Correct softwire endpoints do not authorize a non-LAN quoted source.
    # Neither DF nor non-DF may poison the PMTU map.
    untrusted_pmtu0="$(read_stat TunnelPMTU)"
    for quote_df in df nodf; do
        MM_QUOTED_SRC=198.51.100.123 inject_tunnel_icmp "nonlan-$quote_df" icmp6ptb 1280 "$quote_df"
    done
    check "non-LAN quoted sources cannot update softwire PMTU" \
        test "$(read_stat TunnelPMTU)" -eq "$untrusted_pmtu0"

    relay0="$(read_stat TunnelICMPRelay)"
    pmtu0="$(read_stat TunnelPMTU)"

    # Packet Too Big about a DF packet: relayed as ICMPv4 Fragmentation Needed
    # with the tunnel overhead taken off the reported MTU, sourced from the
    # well-known B4 address rather than a LAN gateway address (RFC 6333 §5.7) --
    # which is also what distinguishes minuteman's own relay from the kernel
    # ip6tnl's, the only thing that answered these before.
    #
    # The MTU injected here is deliberately NOT CORE_NARROW_MTU: it is learned
    # as a real path MTU too, so reusing that value would satisfy the second
    # half's assertions below before the core link is even narrowed.
    inject_tunnel_icmp ptb icmp6ptb "$INJECTED_PTB_MTU" df
    check "an ICMPv6 Packet Too Big about a softwire packet is relayed as ICMPv4 Fragmentation Needed" \
        bash -c "grep -q 'need to frag (mtu $((INJECTED_PTB_MTU - 40)))' '$RUNDIR/tunnel-icmp-ptb.log'"
    check "the relayed ICMPv4 error uses the well-known 192.0.0.2 source (RFC 6333 §5.7)" \
        bash -c "grep -q '192.0.0.2 > ${LAN_HOST_ADDR%/*}' '$RUNDIR/tunnel-icmp-ptb.log'"

    # Hop limit expiring inside the tunnel: RFC 7915 §5.3 maps this to ICMPv4
    # Time Exceeded. Asserted negatively too, since the kernel ip6tnl relays
    # this one as Host Unreachable -- the wrong error entirely, and the reason
    # this type is worth handling in the datapath at all.
    inject_tunnel_icmp texc icmp6texc df
    check "an ICMPv6 Time Exceeded about a softwire packet is relayed as ICMPv4 Time Exceeded" \
        bash -c "grep -q 'time exceeded' '$RUNDIR/tunnel-icmp-texc.log'"
    check "it is NOT relayed as Host Unreachable (what the kernel ip6tnl would have produced)" \
        bash -c "! grep -q 'host .* unreachable' '$RUNDIR/tunnel-icmp-texc.log'"

    inject_tunnel_icmp unreach icmp6unreach 1 df
    check "an ICMPv6 Destination Unreachable (admin prohibited) is relayed as its ICMPv4 equivalent" \
        bash -c "grep -q 'admin prohibited' '$RUNDIR/tunnel-icmp-unreach.log'"

    relay="$(read_stat TunnelICMPRelay)"
    check "the datapath counted the relays (TunnelICMPRelay +$((relay - relay0)))" \
        test "$((relay - relay0))" -ge 3

    # An ICMPv6 error quoting a softwire that is not this B4's must be ignored
    # outright: believing one would let anyone on the IPv6 internet inject
    # ICMPv4 errors into the LAN, or talk the B4 into a smaller path MTU.
    relay0="$(read_stat TunnelICMPRelay)"
    inject_tunnel_icmp bogus icmp6bogus "$INJECTED_PTB_MTU"
    relay="$(read_stat TunnelICMPRelay)"
    check "an ICMPv6 error quoting someone else's softwire is not relayed" \
        bash -c "! grep -q 'unreachable' '$RUNDIR/tunnel-icmp-bogus.log'"
    check "and is not counted as a relay (TunnelICMPRelay +$((relay - relay0)))" \
        test "$relay" -eq "$relay0"

    pmtu="$(read_stat TunnelPMTU)"
    check "the softwire path MTU was learned from the Packet Too Big (TunnelPMTU +$((pmtu - pmtu0)))" \
        test "$pmtu" -gt "$pmtu0"

    # --- The same thing without hand-crafted packets: narrow the core link so a
    # real router sends a real Packet Too Big about real traffic. The CPE's own
    # WAN stays at 1500, so nothing local can see this -- learning it from the
    # ICMPv6 error is the only way the fragmenter stops emitting fragments the
    # path can only drop. ---
    echo "-- a narrowed core link: real Packet Too Big, learned path MTU, re-sized fragments --"
    ip netns exec "$NETNS_ISP" ip link set "$VETH_ISP_AFTR" mtu "$CORE_NARROW_MTU"
    ip netns exec "$NETNS_AFTR" ip link set "$VETH_AFTR_ISP" mtu "$CORE_NARROW_MTU"
    # Both caches would otherwise hide the narrowing: the client's from an
    # earlier PMTUD signal, the CPE's from the kernel's own PMTU exception.
    ip netns exec "$NETNS_HOST" ip route flush cache 2>/dev/null || true
    ip netns exec "$NETNS_CPE" ip -6 route flush cache 2>/dev/null || true

    frag_xdp0="$(read_stat EncapFragXDP)"
    # The first oversized packet is still fragmented to the WAN's MTU and lost
    # -- that loss is what produces the Packet Too Big -- so this is about what
    # happens afterwards, not about this ping's own success.
    ip netns exec "$NETNS_HOST" ping -M dont -s 1472 -c 2 -i 0.5 -W 2 \
        -I "$VETH_HOST_CPE" "${PUBLIC_INET_ADDR%/*}" >/dev/null 2>&1 || true
    # Give the userspace applier (cmd/minuteman's watchTunnelPMTU, a 2s tick)
    # time to re-derive the fragment size and the companion device's MTU.
    sleep 5

    # Both of these can only be satisfied by the *real* Packet Too Big: the
    # injected one above reported INJECTED_PTB_MTU, a different value, so
    # neither the log line nor the device MTU below can already be there.
    check "minuteman learned the narrowed softwire path MTU ($CORE_NARROW_MTU)" \
        grep -q "softwire path MTU: $CORE_NARROW_MTU " "$RUNDIR/minuteman.log"
    # WAN 1500 - 40 = 1460 before, CORE_NARROW_MTU - 40 after: the companion
    # ip6tnl fragments the inner IPv4 on every fallback path, so it has to
    # follow the same reading the fast path did.
    check "the companion ip6tnl's MTU followed it ($((CORE_NARROW_MTU - 40)))" \
        bash -c "ip netns exec $NETNS_CPE ip link show mm-dslite0 | grep -q 'mtu $((CORE_NARROW_MTU - 40))'"

    # With the fragmenter re-sized, oversized traffic -- DF included, since this
    # B4 fragments the outer IPv6 rather than signalling PMTUD (RFC 6333 §5.3 /
    # errata 5847) -- crosses the narrowed path with no loss at all.
    check "oversized non-DF traffic crosses the narrowed path once the MTU is learned" \
        ip netns exec "$NETNS_HOST" ping -M dont -s 1472 -c 3 -W 2 -I "$VETH_HOST_CPE" "${PUBLIC_INET_ADDR%/*}"
    check "oversized DF traffic does too (no PMTUD signal needed, DF ignored)" \
        ip netns exec "$NETNS_HOST" ping -M do -s 1472 -c 3 -W 2 -I "$VETH_HOST_CPE" "${PUBLIC_INET_ADDR%/*}"

    frag_xdp="$(read_stat EncapFragXDP)"
    check "those packets were outer-fragmented in XDP, not handed to the kernel (EncapFragXDP +$((frag_xdp - frag_xdp0)))" \
        test "$frag_xdp" -gt "$frag_xdp0"

    # The third consumer of a learned path MTU, alongside the fragmenter and the
    # ip6tnl above: the automatic TCP MSS clamp tracks it too, so connections
    # opened after the narrowing offer segments the narrowed path can carry.
    # Only new connections, by nature -- an MSS is negotiated once, in the SYN.
    narrow_mss=$((CORE_NARROW_MTU - 80))
    narrow_mss_pcap="$RUNDIR/mss-clamp-narrowed.log"
    ip netns exec "$NETNS_AFTR" timeout 8 tcpdump -i "$AFTR_TUN" -n -vv -c 1 \
        "tcp port 8082" >"$narrow_mss_pcap" 2>/dev/null &
    narrow_mss_td=$!
    sleep 1
    ip netns exec "$NETNS_INET" bash -c \
        "printf 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok' | timeout 5 nc -l -p 8082 -q1" &
    narrow_mss_nc=$!
    sleep 0.3
    ip netns exec "$NETNS_HOST" curl -sf --max-time 4 \
        "http://${PUBLIC_INET_ADDR%/*}:8082/" >/dev/null
    wait "$narrow_mss_nc" 2>/dev/null
    wait "$narrow_mss_td" 2>/dev/null
    check "the TCP MSS clamp followed the learned path MTU too (mss $narrow_mss)" \
        grep -q "mss $narrow_mss" "$narrow_mss_pcap"

    # Restore the core link. The learned MTU stays in force for its own expiry
    # (10 minutes), which only means smaller fragments than necessary until then.
    ip netns exec "$NETNS_ISP" ip link set "$VETH_ISP_AFTR" mtu 1500
    ip netns exec "$NETNS_AFTR" ip link set "$VETH_AFTR_ISP" mtu 1500
    ip netns exec "$NETNS_HOST" ip route flush cache 2>/dev/null || true
fi

# Deliberately last: this is the one check that has to wait out a real timer
# (the T1 minuteman derived for itself, PD_ZERO_PREFERRED_LIFETIME / 2), so
# every check above overlaps with the waiting.
if [[ $pd_zero_timers -eq 1 ]]; then
    echo "== DHCPv6-PD renewal on client-chosen timers (RFC 9915 §14.2) =="
    if [[ $started_minuteman -ne 1 ]]; then
        echo "SKIP: reusing an already-running minuteman, whose lease age is unknown"
    else
        # Wait until a derived T1 has fully elapsed since the lease was
        # acquired (a second or two after minuteman started), plus slack for
        # the exchange itself.
        renew_deadline=$((minuteman_started_at + pd_zero_t1 + 20))
        now="$(date +%s)"
        if ((now < renew_deadline)); then
            echo "   waiting $((renew_deadline - now))s for the derived T1 ($(fmt_duration $pd_zero_t1)) to elapse"
            sleep $((renew_deadline - now))
        fi
        elapsed=$(($(date +%s) - minuteman_started_at))

        # Every successful Renew re-applies the lease and logs a line, so
        # these lines are "1 acquire + one per renewal". The upper bound is
        # what makes this a regression test for the storm: taking a T1 of 0
        # literally renewed on every exchange RTT (hundreds of lines here),
        # whereas the client's own choice can never be more often than
        # pkg/prefixdelegation's minDerivedT1 floor.
        pd_zero_min_interval=60 # pkg/prefixdelegation's minDerivedT1
        leases="$(grep -c "DHCPv6-PD lease on $VETH_CPE_ISP:" "$RUNDIR/minuteman.log")"
        max_leases=$((2 + elapsed / pd_zero_min_interval))
        check "minuteman renewed the delegation at its derived T1 ($((leases - 1)) renewal(s) in ${elapsed}s)" \
            test "$leases" -ge 2
        check "minuteman did not storm the server with Renews ($leases lease application(s) in ${elapsed}s, at most $max_leases possible)" \
            test "$leases" -le "$max_leases"

        # Server-side confirmation that the renewal was a real exchange, not
        # just minuteman re-applying a lease it already had. Counted from
        # the baseline taken when minuteman started, so a renewal that
        # happened while the checks above ran still counts.
        kea_renews="$(kea_renew_count)"
        check "mm-isp's Kea received the Renew(s) ($((kea_renews - kea_renews0)) in ${elapsed}s)" \
            test "$((kea_renews - kea_renews0))" -ge 1

        # A renewal must not disturb what the lease already produced: same
        # delegated prefix, same LAN address carved from it.
        check "the delegated prefix survived the renewal unchanged ($pd_lan_addr still on $VETH_CPE_HOST)" \
            bash -c "ip netns exec $NETNS_CPE ip -6 addr show dev $VETH_CPE_HOST | grep -q '$pd_lan_addr/64'"
    fi
fi

if [[ $fail -eq 0 ]]; then
    echo "== all checks passed =="
else
    echo "== one or more checks FAILED (see minuteman log: $RUNDIR/minuteman.log) =="
fi
exit $fail

#!/bin/bash
# Tears down the DS-Lite netns test rig created by setup.sh. Safe to run
# even if setup.sh only partially completed.
#
# Usage: sudo ./test/netns/teardown.sh

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./common.sh

if [[ $EUID -ne 0 ]]; then
    echo "must run as root" >&2
    exit 1
fi

echo "== stopping minuteman (if running in mm-cpe) =="
pkill -f "$MINUTEMAN_BIN" 2>/dev/null || true

echo "== stopping dnsmasq =="
if [[ -f "$DNSMASQ_PIDFILE" ]]; then
    kill "$(cat "$DNSMASQ_PIDFILE")" 2>/dev/null || true
    rm -f "$DNSMASQ_PIDFILE"
fi
# Namespaces don't kill processes running inside them; catch anything the
# pidfile missed by name as well.
pkill -f "dnsmasq --conf-file=$DNSMASQ_CONF" 2>/dev/null || true

echo "== stopping kea-dhcp6 =="
if [[ -f "$KEA_PIDFILE" ]]; then
    kill "$(cat "$KEA_PIDFILE")" 2>/dev/null || true
    rm -f "$KEA_PIDFILE"
fi
pkill -f "kea-dhcp6 -c $KEA_CONF" 2>/dev/null || true
rm -f "$KEA_LOG"

echo "== stopping HB46PP provisioning server (if any) =="
if [[ -f "$HB46PP_HTTP_PIDFILE" ]]; then
    kill "$(cat "$HB46PP_HTTP_PIDFILE")" 2>/dev/null || true
    rm -f "$HB46PP_HTTP_PIDFILE"
fi
pkill -f "http.server $HB46PP_PORT" 2>/dev/null || true

echo "== deleting namespaces (also removes veths/tunnels inside them) =="
for ns in "${ALL_NETNS[@]}"; do
    ip netns del "$ns" 2>/dev/null || true
done

rm -rf "$RUNDIR"

echo "== done =="

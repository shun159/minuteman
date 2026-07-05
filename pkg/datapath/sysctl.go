package datapath

import (
	"fmt"
	"os"
	"path/filepath"
)

func writeSysctl(path, value string) error {
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
		return fmt.Errorf("writing %s=%s: %w", path, value, err)
	}
	return nil
}

// configureWANSysctls enables the IPv4/IPv6 forwarding bpf_fib_lookup()
// needs to succeed in the datapath -- both the encap and decap programs
// perform FIB lookups in both address families regardless of which
// interface they're attached to (encap checks LAN-local routes in AF_INET
// and resolves the AFTR next hop in AF_INET6; decap resolves the LAN
// egress next hop in AF_INET), so without these the kernel returns
// BPF_FIB_LKUP_RET_FWD_DISABLED for every lookup and nothing gets
// encapsulated. It also re-enables Router Advertisement acceptance on
// ifaceName specifically, which enabling net.ipv6.conf.all.forwarding
// otherwise suppresses by default -- needed so SLAAC-assigned addresses
// and RA-installed default routes keep being refreshed on the WAN link.
//
// net.ipv4.ip_forward and net.ipv6.conf.all.forwarding are process-wide
// (there is no meaningful "only this interface" scope for them), so
// calling this repeatedly (e.g. once per AttachWAN/AttachLAN call) is
// harmless.
func configureWANSysctls(wanIfaceName string) error {
	if err := writeSysctl("/proc/sys/net/ipv4/ip_forward", "1"); err != nil {
		return err
	}
	if err := writeSysctl("/proc/sys/net/ipv6/conf/all/forwarding", "1"); err != nil {
		return err
	}
	if err := writeSysctl(filepath.Join("/proc/sys/net/ipv6/conf", wanIfaceName, "accept_ra"), "2"); err != nil {
		return err
	}
	return nil
}

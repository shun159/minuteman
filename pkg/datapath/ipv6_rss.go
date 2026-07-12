package datapath

import "fmt"

// ipv6RSSQueueSize is the per-CPU backlog queue depth used for the native-IPv6
// software-RSS cpumap. It matches the value the kernel's own xdp_redirect_cpu
// sample defaults to; large enough to absorb bursts without wasting memory.
const ipv6RSSQueueSize = 2048

// maxRSSCPUs bounds the CPU ids/slots accepted by EnableIPv6SoftwareRSS; it
// mirrors MAX_CPUS in bpf/datapath.bpf.c (the cpu_map_v6 / ipv6_rss_cpus
// max_entries).
const maxRSSCPUs = 256

// EnableIPv6SoftwareRSS turns on cpumap-based CPU fanout for the native-IPv6
// forwarding fastpath, spreading forwarding work across the given CPU ids
// (typically every online CPU). It is off by default: a NIC with capable
// hardware RSS (e.g. mlx4) already distributes flows across CPUs, making this
// software stage redundant overhead. Passing an empty cpus slice is an error;
// to leave software RSS disabled, simply don't call this.
//
// This is independent of the (currently dormant) DS-Lite CPU fanout: it uses
// its own cpu_map_v6 / ipv6_rss_cpus / ipv6_rss_config_map maps, so enabling it
// never activates that path.
func (l *Loader) EnableIPv6SoftwareRSS(cpus []uint32) error {
	if len(cpus) == 0 {
		return fmt.Errorf("EnableIPv6SoftwareRSS: no CPUs given")
	}
	if len(cpus) > maxRSSCPUs {
		return fmt.Errorf("EnableIPv6SoftwareRSS: %d CPUs exceeds max %d", len(cpus), maxRSSCPUs)
	}

	progFD := l.objs.XdpIpv6FwdCpu.FD()

	for slot, cpu := range cpus {
		if cpu >= maxRSSCPUs {
			return fmt.Errorf("EnableIPv6SoftwareRSS: CPU id %d exceeds max %d", cpu, maxRSSCPUs-1)
		}

		val := bpfBpfCpumapVal{Qsize: ipv6RSSQueueSize}
		val.BpfProg.Fd = int32(progFD)
		if err := l.objs.CpuMapV6.Put(&cpu, &val); err != nil {
			return fmt.Errorf("populating cpu_map_v6 for CPU %d: %w", cpu, err)
		}

		slotKey := uint32(slot)
		cpuVal := cpu
		if err := l.objs.Ipv6RssCpus.Put(&slotKey, &cpuVal); err != nil {
			return fmt.Errorf("populating ipv6_rss_cpus slot %d: %w", slot, err)
		}
	}

	key := uint32(0)
	cfg := bpfIpv6RssConfig{Enabled: 1, CpuCount: uint32(len(cpus))}
	if err := l.objs.Ipv6RssConfigMap.Put(&key, &cfg); err != nil {
		return fmt.Errorf("enabling ipv6_rss_config: %w", err)
	}

	return nil
}

package datapath

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/cilium/ebpf"
)

// Maps pinned to bpffs so out-of-band tools can reach them while minuteman
// runs: the stats map for reading counters (the `minuteman stats`
// subcommand, `bpftool map dump pinned ...`), and the two xdpcap capture
// hooks for installing a capture into the running datapath (see the
// xdpcap_hook comment in bpf/datapath.bpf.c). Other maps stay unpinned until
// something needs them.
const (
	bpffsDir     = "/sys/fs/bpf/minuteman"
	statsPinPath = bpffsDir + "/stats"

	// XDPCapHookPinPath is the capture hook of the rx-XDP programs -- the
	// encap, decap and fragment-emitting paths, i.e. everything except the
	// optional cpumap stages.
	XDPCapHookPinPath = bpffsDir + "/xdpcap_hook"
	// XDPCapHookCPUPinPath is the capture hook of the cpumap-attached
	// second-stage programs (DS-Lite decap fanout, native-IPv6 software
	// RSS). Separate from XDPCapHookPinPath because a prog array binds to
	// the flavor of program that claims it: filter programs installed here
	// must carry the BPF_XDP_CPUMAP expected attach type, which an
	// off-the-shelf xdpcap does not set (see bpf/datapath.bpf.c).
	XDPCapHookCPUPinPath = bpffsDir + "/xdpcap_hook_cpu"
)

// pinMaps pins the maps observers reach minuteman through, replacing any
// stale pin a previous crashed run left behind (same stance as
// internal/slowpath's stale-device cleanup: the old pin references a dead
// program's map, so a fresh one is what an observer wants).
//
// All-or-nothing: a failure part-way through unpins what it already pinned,
// because Load's caller gets an error and never starts a datapath, and a
// surviving pin would advertise a running minuteman that isn't there -- an
// observer would read zeroed counters from it forever (`minuteman stats`),
// and XDPRoles would resolve interface membership against a map no attached
// program references.
func (l *Loader) pinMaps() error {
	if err := os.MkdirAll(bpffsDir, 0o755); err != nil {
		return fmt.Errorf("creating %s (is /sys/fs/bpf a mounted bpffs? under `ip netns exec` /sys is remounted without it -- use `nsenter --net=...` instead): %w", bpffsDir, err)
	}
	var pinned []pinnedMap
	for _, p := range l.pinnedMaps() {
		if err := os.Remove(p.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			unpinAll(pinned)
			return fmt.Errorf("removing stale pin %s: %w", p.path, err)
		}
		if err := p.m.Pin(p.path); err != nil {
			unpinAll(pinned)
			return fmt.Errorf("pinning %s map to %s: %w", p.name, p.path, err)
		}
		pinned = append(pinned, p)
	}
	return nil
}

// unpinMaps removes every pin pinMaps made, best-effort: a leftover pin is
// only stale state for the next run's pinMaps to sweep, not worth failing
// shutdown over.
func (l *Loader) unpinMaps() {
	unpinAll(l.pinnedMaps())
}

func unpinAll(maps []pinnedMap) {
	for _, p := range maps {
		p.m.Unpin()
	}
}

type pinnedMap struct {
	name string
	path string
	m    *ebpf.Map
}

func (l *Loader) pinnedMaps() []pinnedMap {
	return []pinnedMap{
		{"stats", statsPinPath, l.objs.Stats},
		{"xdpcap_hook", XDPCapHookPinPath, l.objs.XdpcapHook},
		{"xdpcap_hook_cpu", XDPCapHookCPUPinPath, l.objs.XdpcapHookCpu},
	}
}

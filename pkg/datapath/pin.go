package datapath

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// The stats map is pinned to bpffs so it can be read out-of-band while
// minuteman runs (the `minuteman stats` subcommand, `bpftool map dump
// pinned ...`). Other maps stay unpinned until something needs them.
const (
	bpffsDir     = "/sys/fs/bpf/minuteman"
	statsPinPath = bpffsDir + "/stats"
)

// pinStats pins the stats map to statsPinPath, replacing any stale pin a
// previous crashed run left behind (same stance as internal/slowpath's
// stale-device cleanup: the old pin references a dead program's map, so a
// fresh, zeroed one is what an observer wants).
func (l *Loader) pinStats() error {
	if err := os.MkdirAll(bpffsDir, 0o755); err != nil {
		return fmt.Errorf("creating %s (is /sys/fs/bpf a mounted bpffs? under `ip netns exec` /sys is remounted without it -- use `nsenter --net=...` instead): %w", bpffsDir, err)
	}
	if err := os.Remove(statsPinPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("removing stale pin %s: %w", statsPinPath, err)
	}
	if err := l.objs.Stats.Pin(statsPinPath); err != nil {
		return fmt.Errorf("pinning stats map to %s: %w", statsPinPath, err)
	}
	return nil
}

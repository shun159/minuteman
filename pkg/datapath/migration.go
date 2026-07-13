package datapath

import (
	"fmt"
	"net/netip"
	"time"

	"golang.org/x/sys/unix"
)

// Migration states, mirroring MIG_* in bpf/datapath.bpf.c.
const (
	migSteady   uint32 = 0
	migPriming  uint32 = 1
	migDraining uint32 = 2
)

// migrationCtrl is the unpacked form of the datapath's single-__u32 migration
// control word (see the bit layout on migration_ctrl in bpf/datapath.bpf.c).
// Keeping it one word is what makes every state transition a single atomic
// store, so the datapath can never observe a half-applied transition.
type migrationCtrl struct {
	activeSlot uint32 // the slot encap uses by default
	oldSlot    uint32 // during DRAINING, where pre-cutover flows stay pinned
	state      uint32 // migSteady / migPriming / migDraining
	epoch      uint32 // this migration's generation (0..255)
}

func (c migrationCtrl) pack() uint32 {
	return (c.activeSlot & 0xff) |
		((c.oldSlot & 0xff) << 8) |
		((c.state & 0xff) << 16) |
		((c.epoch & 0xff) << 24)
}

func unpackMigrationCtrl(v uint32) migrationCtrl {
	return migrationCtrl{
		activeSlot: v & 0xff,
		oldSlot:    (v >> 8) & 0xff,
		state:      (v >> 16) & 0xff,
		epoch:      (v >> 24) & 0xff,
	}
}

func (l *Loader) readCtrl() (migrationCtrl, error) {
	key := uint32(0)
	var v uint32
	if err := l.objs.MigrationCtrl.Lookup(&key, &v); err != nil {
		return migrationCtrl{}, fmt.Errorf("reading migration control: %w", err)
	}
	return unpackMigrationCtrl(v), nil
}

func (l *Loader) writeCtrl(c migrationCtrl) error {
	key := uint32(0)
	v := c.pack()
	if err := l.objs.MigrationCtrl.Put(&key, &v); err != nil {
		return fmt.Errorf("writing migration control: %w", err)
	}
	return nil
}

// BeginMigration starts a graceful AFTR migration to (b4, aftr): it writes the
// endpoint into the currently-inactive next-hop slot and moves the datapath to
// PRIMING under a fresh epoch. Traffic keeps using the *old* AFTR; what changes
// is that encap and decap now record every softwire flow they see into the
// affinity table.
//
// That recording is the whole point of PRIMING. Once the switch happens, a
// flow-table miss cannot distinguish a brand-new flow from a pre-existing
// flow's next packet -- UDP/QUIC/ICMP have no start marker -- so which flows
// predate the switch has to be learned *before* switching. A flow that stays
// completely idle through PRIMING is the accepted, bounded cost: it will be
// treated as new at cutover.
//
// Follow with Cutover once PRIMING has run long enough (and the datapath's
// affinity-insert-failure counter is still zero), or AbortMigration.
func (l *Loader) BeginMigration(b4, aftr netip.Addr) error {
	if err := validateSoftwireAddrs(b4, aftr); err != nil {
		return err
	}

	c, err := l.readCtrl()
	if err != nil {
		return err
	}
	if c.state != migSteady {
		return fmt.Errorf("migration already in progress (state %d)", c.state)
	}

	newSlot := (c.activeSlot + 1) % numNextHops
	if err := l.writeNextHop(newSlot, b4, aftr); err != nil {
		return err
	}

	// active stays on the old AFTR; only the state and epoch move.
	return l.writeCtrl(migrationCtrl{
		activeSlot: c.activeSlot,
		oldSlot:    c.activeSlot,
		state:      migPriming,
		epoch:      (c.epoch + 1) & 0xff,
	})
}

// Cutover flips traffic to the new AFTR while keeping every flow recorded
// during PRIMING pinned to the old one: after this, an affinity hit carrying
// the current epoch routes to the old slot, and a miss (a flow that started
// after the cutover) routes to the new one. Both slots stay valid, so decap
// accepts return traffic from either AFTR for the whole drain.
//
// The caller must check that the datapath recorded every flow it saw --
// Stats().AffinityInsertFail must still be zero -- before calling this. A flow
// that PRIMING failed to record may be pre-existing, and would be silently
// moved to the new AFTR (which has no NAT state for it) at cutover; abandoning
// the migration and staying on a working AFTR is the safe response.
func (l *Loader) Cutover() error {
	c, err := l.readCtrl()
	if err != nil {
		return err
	}
	if c.state != migPriming {
		return fmt.Errorf("cutover requires PRIMING, datapath is in state %d", c.state)
	}

	oldSlot := c.activeSlot
	newSlot := (oldSlot + 1) % numNextHops
	return l.writeCtrl(migrationCtrl{
		activeSlot: newSlot,
		oldSlot:    oldSlot,
		state:      migDraining,
		epoch:      c.epoch,
	})
}

// CompleteMigration ends the drain: it returns the datapath to STEADY on the
// new AFTR and then retires the old slot, so decap stops accepting the old
// AFTR's traffic. Control first, slot second -- never the other way round, or
// a packet in flight could resolve a slot that has just been invalidated.
//
// Leftover affinity entries from this migration are *not* deleted here; they
// carry a now-past epoch, which the datapath ignores on lookup, so a later
// GCFlowAffinity can reclaim them lazily and the next migration need not wait
// for the table to be empty.
func (l *Loader) CompleteMigration() error {
	c, err := l.readCtrl()
	if err != nil {
		return err
	}
	if c.state != migDraining {
		return fmt.Errorf("completing requires DRAINING, datapath is in state %d", c.state)
	}

	newSlot := c.activeSlot
	if err := l.writeCtrl(migrationCtrl{
		activeSlot: newSlot,
		oldSlot:    newSlot,
		state:      migSteady,
		epoch:      c.epoch,
	}); err != nil {
		return err
	}
	return l.clearNextHop(c.oldSlot)
}

// AbortMigration gives up on an in-progress migration and leaves the datapath
// on the AFTR it is already using, discarding the slot prepared for the new
// one. Valid from PRIMING (e.g. the affinity table filled up, so some
// pre-existing flow may have gone unrecorded and cutting over would break it)
// and from DRAINING is *not* supported -- once traffic has moved, going back
// would strand the flows that already migrated.
func (l *Loader) AbortMigration() error {
	c, err := l.readCtrl()
	if err != nil {
		return err
	}
	if c.state != migPriming {
		return fmt.Errorf("abort requires PRIMING, datapath is in state %d", c.state)
	}

	if err := l.writeCtrl(migrationCtrl{
		activeSlot: c.activeSlot,
		oldSlot:    c.activeSlot,
		state:      migSteady,
		epoch:      c.epoch,
	}); err != nil {
		return err
	}
	return l.clearNextHop((c.activeSlot + 1) % numNextHops)
}

// FlowIdleTimeouts bound how long a recorded flow may go without a packet (in
// either direction) before the drain stops holding it on the old AFTR.
type FlowIdleTimeouts struct {
	TCP   time.Duration
	Other time.Duration // UDP/QUIC/ICMP/everything else
}

// GCFlowAffinity reclaims flow-affinity entries and reports how many
// current-epoch (still-pinned) flows remain, which is the drain's completion
// signal: when it reaches zero, nothing is left on the old AFTR and
// CompleteMigration can retire it.
//
// It always deletes entries stamped with a past epoch (leftovers from an
// earlier migration; the datapath already ignores them). Whether it may also
// expire a *current-epoch* entry depends on the state:
//
//   - PRIMING: never. The current-epoch entries are the record being built, and
//     an entry is only there because a flow was seen. Expiring one on idleness
//     here would silently reclassify that flow as new at cutover and move it to
//     the new AFTR -- the exact failure PRIMING exists to prevent. A flow's
//     idleness only matters once it's being drained.
//   - DRAINING: yes, on the protocol's idle timeout. Idleness is what bounds
//     the drain, not a fixed window: an active stream keeps refreshing the old
//     AFTR's NAT state indefinitely, so a fixed deadline would cut a long
//     download or video call mid-flight. Both directions refresh last_seen
//     (encap by the forward key, decap by the reversed one), so a
//     download-heavy flow doesn't look idle.
//   - STEADY: yes. Nothing consults the table, so leftovers are inert and just
//     take up room.
func (l *Loader) GCFlowAffinity(timeouts FlowIdleTimeouts) (remaining int, err error) {
	c, err := l.readCtrl()
	if err != nil {
		return 0, err
	}
	expireCurrentEpoch := c.state != migPriming

	now, err := monotonicNanos()
	if err != nil {
		return 0, err
	}

	var (
		key   bpfFlowKey
		val   bpfFlowAffinity
		stale []bpfFlowKey
	)
	iter := l.objs.FlowAffinityMap.Iterate()
	for iter.Next(&key, &val) {
		if val.Epoch != c.epoch {
			stale = append(stale, key)
			continue
		}
		if !expireCurrentEpoch {
			remaining++
			continue
		}
		idle := timeouts.Other
		if key.Proto == unix.IPPROTO_TCP {
			idle = timeouts.TCP
		}
		if int64(now)-int64(val.LastSeenNs) > idle.Nanoseconds() {
			stale = append(stale, key)
			continue
		}
		remaining++
	}
	if err := iter.Err(); err != nil {
		return 0, fmt.Errorf("iterating flow affinity: %w", err)
	}

	// Deleted after iterating, not during: removing entries mid-iteration can
	// make a HASH walk skip others.
	for i := range stale {
		if err := l.objs.FlowAffinityMap.Delete(&stale[i]); err != nil {
			// A concurrent datapath delete is impossible (only userspace
			// deletes), but tolerate a vanished key rather than aborting GC.
			continue
		}
	}
	return remaining, nil
}

// monotonicNanos reads the same clock bpf_ktime_get_ns() stamps flows with
// (CLOCK_MONOTONIC), so last_seen_ns comparisons are meaningful.
func monotonicNanos() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, fmt.Errorf("reading CLOCK_MONOTONIC: %w", err)
	}
	return uint64(ts.Nano()), nil
}

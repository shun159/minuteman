package datapath

import (
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

var (
	testB4    = netip.MustParseAddr("fd00:1::2")
	testAFTRA = netip.MustParseAddr("fd00:2::2")
	testAFTRB = netip.MustParseAddr("fd00:2::3")
	testAFTRC = netip.MustParseAddr("fd00:2::4")
)

// loadForMigrationTest loads the datapath (which creates the maps) without
// attaching it to any interface, and seeds STEADY on slot 0 with testAFTRA --
// the state SetB4Config would leave behind, minus its tx_ports registration,
// which needs a real ifindex.
func loadForMigrationTest(t *testing.T) *Loader {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root: loads BPF maps into the kernel")
	}

	l, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	t.Cleanup(func() { l.Close() })

	if err := l.writeNextHop(0, testB4, testAFTRA); err != nil {
		t.Fatalf("seeding slot 0: %v", err)
	}
	if err := l.writeCtrl(migrationCtrl{activeSlot: 0, oldSlot: 0, state: migSteady}); err != nil {
		t.Fatalf("seeding control word: %v", err)
	}
	return l
}

func readSlot(t *testing.T, l *Loader, slot uint32) bpfNextHop {
	t.Helper()
	var nh bpfNextHop
	if err := l.objs.NextHops.Lookup(&slot, &nh); err != nil {
		t.Fatalf("reading slot %d: %v", slot, err)
	}
	return nh
}

func aftrOf(nh bpfNextHop) netip.Addr {
	return netip.AddrFrom16(nh.AftrAddr.In6U.U6Addr8)
}

// TestMigrationLifecycle walks STEADY -> PRIMING -> DRAINING -> STEADY and
// checks the control word and slots at each step.
func TestMigrationLifecycle(t *testing.T) {
	l := loadForMigrationTest(t)

	// PRIMING: the new AFTR is staged in the free slot, but traffic must stay
	// on the old one -- only the state and epoch move.
	if err := l.BeginMigration(testB4, testAFTRB); err != nil {
		t.Fatalf("BeginMigration: %v", err)
	}
	c, err := l.readCtrl()
	if err != nil {
		t.Fatal(err)
	}
	if c.state != migPriming || c.activeSlot != 0 || c.epoch != 1 {
		t.Fatalf("after BeginMigration: %+v, want PRIMING active=0 epoch=1", c)
	}
	if got := aftrOf(readSlot(t, l, 1)); got != testAFTRB {
		t.Fatalf("slot 1 = %s, want the staged new AFTR %s", got, testAFTRB)
	}
	if got := aftrOf(readSlot(t, l, 0)); got != testAFTRA {
		t.Fatalf("slot 0 (still serving traffic) = %s, want %s untouched", got, testAFTRA)
	}

	// Cutover: traffic moves to the new slot; the old one stays live for the
	// flows PRIMING pinned to it.
	if err := l.Cutover(); err != nil {
		t.Fatalf("Cutover: %v", err)
	}
	if c, err = l.readCtrl(); err != nil {
		t.Fatal(err)
	}
	if c.state != migDraining || c.activeSlot != 1 || c.oldSlot != 0 || c.epoch != 1 {
		t.Fatalf("after Cutover: %+v, want DRAINING active=1 old=0 epoch=1", c)
	}
	if readSlot(t, l, 0).Valid != 1 {
		t.Fatal("old slot was invalidated at cutover; pinned flows would break")
	}

	// Complete: back to STEADY on the new AFTR, old slot retired.
	if err := l.CompleteMigration(); err != nil {
		t.Fatalf("CompleteMigration: %v", err)
	}
	if c, err = l.readCtrl(); err != nil {
		t.Fatal(err)
	}
	if c.state != migSteady || c.activeSlot != 1 {
		t.Fatalf("after CompleteMigration: %+v, want STEADY active=1", c)
	}
	if readSlot(t, l, 0).Valid != 0 {
		t.Fatal("old slot still valid after completing; decap would keep accepting the retired AFTR")
	}
}

// TestWriteNextHopRefusesLiveSlot is the real regression test for the hazard
// the slot indirection exists to prevent, and it is enforced rather than merely
// asserted on end state: a naive "write (active+1), then flip" during DRAINING
// produces exactly the same *final* slots and control word as the correct
// sequence, so only the write itself can be caught. During DRAINING both slots
// are live -- encap resolves the active one for new flows and the old one for
// flows PRIMING pinned -- so neither may be overwritten while it lasts.
func TestWriteNextHopRefusesLiveSlot(t *testing.T) {
	l := loadForMigrationTest(t)

	// STEADY: the active slot is live and must not be rewritten in place.
	if err := l.writeNextHop(0, testB4, testAFTRC); err == nil {
		t.Fatal("writeNextHop overwrote the active slot in STEADY")
	}
	// ...but the free slot is fair game (this is what BeginMigration does).
	if err := l.writeNextHop(1, testB4, testAFTRB); err != nil {
		t.Fatalf("writeNextHop refused the free slot in STEADY: %v", err)
	}

	if err := l.BeginMigration(testB4, testAFTRB); err != nil {
		t.Fatalf("BeginMigration: %v", err)
	}
	if err := l.Cutover(); err != nil {
		t.Fatalf("Cutover: %v", err)
	}
	// DRAINING: active=1 (AFTR B, new flows), old=0 (AFTR A, pinned flows).
	// With two slots there is now no free slot at all.
	if err := l.writeNextHop(0, testB4, testAFTRC); err == nil {
		t.Fatal("writeNextHop overwrote the old slot while pinned flows were still resolving it")
	}
	if err := l.writeNextHop(1, testB4, testAFTRC); err == nil {
		t.Fatal("writeNextHop overwrote the active slot during DRAINING")
	}
}

// TestSwitchAFTRDuringDrainingEndsMigrationFirst: because no slot is free
// during DRAINING (see TestWriteNextHopRefusesLiveSlot), a hard switch has to
// end the migration before it can write one. If it didn't, the guarded
// writeNextHop would reject the write and this would fail.
func TestSwitchAFTRDuringDrainingEndsMigrationFirst(t *testing.T) {
	l := loadForMigrationTest(t)

	if err := l.BeginMigration(testB4, testAFTRB); err != nil {
		t.Fatalf("BeginMigration: %v", err)
	}
	if err := l.Cutover(); err != nil {
		t.Fatalf("Cutover: %v", err)
	}

	if err := l.SwitchAFTR(testB4, testAFTRC); err != nil {
		t.Fatalf("SwitchAFTR during DRAINING: %v", err)
	}

	c, err := l.readCtrl()
	if err != nil {
		t.Fatal(err)
	}
	if c.state != migSteady {
		t.Fatalf("after SwitchAFTR: state %d, want STEADY (the migration must be ended)", c.state)
	}
	if got := aftrOf(readSlot(t, l, c.activeSlot)); got != testAFTRC {
		t.Fatalf("active slot %d holds %s, want the switched-to AFTR %s", c.activeSlot, got, testAFTRC)
	}
}

// TestSwitchAFTRDuringPrimingDiscardsStagedSlot: a hard switch from PRIMING
// must drop the staged (not yet live) endpoint rather than leave a half-set-up
// migration behind.
func TestSwitchAFTRDuringPrimingDiscardsStagedSlot(t *testing.T) {
	l := loadForMigrationTest(t)

	if err := l.BeginMigration(testB4, testAFTRB); err != nil {
		t.Fatalf("BeginMigration: %v", err)
	}
	if err := l.SwitchAFTR(testB4, testAFTRC); err != nil {
		t.Fatalf("SwitchAFTR during PRIMING: %v", err)
	}

	c, err := l.readCtrl()
	if err != nil {
		t.Fatal(err)
	}
	if c.state != migSteady {
		t.Fatalf("after SwitchAFTR: state %d, want STEADY", c.state)
	}
	if got := aftrOf(readSlot(t, l, c.activeSlot)); got != testAFTRC {
		t.Fatalf("active slot holds %s, want %s", got, testAFTRC)
	}
}

// TestBeginMigrationRejectsConcurrentMigration guards the one-migration-at-a-
// time invariant the two-slot design rests on.
func TestBeginMigrationRejectsConcurrentMigration(t *testing.T) {
	l := loadForMigrationTest(t)

	if err := l.BeginMigration(testB4, testAFTRB); err != nil {
		t.Fatalf("BeginMigration: %v", err)
	}
	if err := l.BeginMigration(testB4, testAFTRC); err == nil {
		t.Fatal("a second BeginMigration was accepted while one was in progress")
	}
}

// TestAbortMigrationRestoresSteady checks the escape hatch used when PRIMING
// couldn't record every flow (a full affinity table): stay on the AFTR that
// still works, and discard the staged one.
func TestAbortMigrationRestoresSteady(t *testing.T) {
	l := loadForMigrationTest(t)

	if err := l.BeginMigration(testB4, testAFTRB); err != nil {
		t.Fatalf("BeginMigration: %v", err)
	}
	if err := l.AbortMigration(); err != nil {
		t.Fatalf("AbortMigration: %v", err)
	}

	c, err := l.readCtrl()
	if err != nil {
		t.Fatal(err)
	}
	if c.state != migSteady || c.activeSlot != 0 {
		t.Fatalf("after abort: %+v, want STEADY on the original slot 0", c)
	}
	if got := aftrOf(readSlot(t, l, 0)); got != testAFTRA {
		t.Fatalf("slot 0 = %s, want the original AFTR %s", got, testAFTRA)
	}
	if readSlot(t, l, 1).Valid != 0 {
		t.Fatal("staged slot still valid after abort")
	}

	// A migration can start again afterwards.
	if err := l.BeginMigration(testB4, testAFTRC); err != nil {
		t.Fatalf("BeginMigration after abort: %v", err)
	}
}

// TestGCFlowAffinityNeverExpiresDuringPriming: during PRIMING the table *is*
// the record being built, so an entry must survive to the cutover however idle
// it looks. Expiring one here would silently reclassify a flow we did observe
// as new, and move it to the new AFTR at cutover -- the exact failure PRIMING
// exists to prevent. Once DRAINING, the same idle entry is fair game: idleness
// is what bounds the drain.
func TestGCFlowAffinityNeverExpiresDuringPriming(t *testing.T) {
	l := loadForMigrationTest(t)

	if err := l.BeginMigration(testB4, testAFTRB); err != nil {
		t.Fatalf("BeginMigration: %v", err)
	}

	// A flow recorded by this migration (epoch 1) that looks ancient.
	key := bpfFlowKey{Src: 0x0201a8c0, Dst: 0x027100cb, Proto: unix.IPPROTO_UDP}
	if err := l.objs.FlowAffinityMap.Put(&key, &bpfFlowAffinity{LastSeenNs: 0, Epoch: 1}); err != nil {
		t.Fatalf("seeding flow: %v", err)
	}

	// An aggressive GC must still leave it alone while PRIMING.
	aggressive := FlowIdleTimeouts{TCP: time.Nanosecond, Other: time.Nanosecond}
	remaining, err := l.GCFlowAffinity(aggressive)
	if err != nil {
		t.Fatalf("GCFlowAffinity during PRIMING: %v", err)
	}
	if remaining != 1 {
		t.Fatalf("remaining = %d, want 1 (the recorded flow must be kept)", remaining)
	}
	var got bpfFlowAffinity
	if err := l.objs.FlowAffinityMap.Lookup(&key, &got); err != nil {
		t.Fatal("PRIMING GC expired a recorded flow: it would be misclassified as new at cutover")
	}

	// After the cutover, the same idle entry is drained away.
	if err := l.Cutover(); err != nil {
		t.Fatalf("Cutover: %v", err)
	}
	remaining, err = l.GCFlowAffinity(aggressive)
	if err != nil {
		t.Fatalf("GCFlowAffinity during DRAINING: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("remaining = %d, want 0 (an idle flow should drain)", remaining)
	}
	if err := l.objs.FlowAffinityMap.Lookup(&key, &got); err == nil {
		t.Fatal("DRAINING GC kept an idle flow; the drain would never finish")
	}
}

// TestGCFlowAffinityReapsStaleEpochs: leftovers from an earlier migration are
// reclaimable in any state -- the datapath already ignores them, which is what
// lets a new migration start without first draining the table to empty.
func TestGCFlowAffinityReapsStaleEpochs(t *testing.T) {
	l := loadForMigrationTest(t)

	if err := l.BeginMigration(testB4, testAFTRB); err != nil {
		t.Fatalf("BeginMigration: %v", err)
	}

	// epoch 0 is a leftover; the current migration is epoch 1.
	stale := bpfFlowKey{Src: 0x0201a8c0, Dst: 0x027100cb, Proto: unix.IPPROTO_TCP}
	if err := l.objs.FlowAffinityMap.Put(&stale, &bpfFlowAffinity{LastSeenNs: 0, Epoch: 0}); err != nil {
		t.Fatalf("seeding stale flow: %v", err)
	}

	// Even a GC with timeouts long enough to keep everything must drop it,
	// and it must not be counted as a flow still pinned to the old AFTR.
	remaining, err := l.GCFlowAffinity(FlowIdleTimeouts{TCP: time.Hour, Other: time.Hour})
	if err != nil {
		t.Fatalf("GCFlowAffinity: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("remaining = %d, want 0 (a stale-epoch entry is not a pinned flow)", remaining)
	}
	var got bpfFlowAffinity
	if err := l.objs.FlowAffinityMap.Lookup(&stale, &got); err == nil {
		t.Fatal("stale-epoch entry survived GC")
	}
}

// TestCutoverRequiresPriming / TestCompleteRequiresDraining: the state machine
// must reject out-of-order transitions rather than corrupt the slots.
func TestTransitionsRejectWrongState(t *testing.T) {
	l := loadForMigrationTest(t)

	if err := l.Cutover(); err == nil {
		t.Fatal("Cutover accepted from STEADY")
	}
	if err := l.CompleteMigration(); err == nil {
		t.Fatal("CompleteMigration accepted from STEADY")
	}
	if err := l.AbortMigration(); err == nil {
		t.Fatal("AbortMigration accepted from STEADY")
	}

	if err := l.BeginMigration(testB4, testAFTRB); err != nil {
		t.Fatalf("BeginMigration: %v", err)
	}
	if err := l.CompleteMigration(); err == nil {
		t.Fatal("CompleteMigration accepted from PRIMING (skipping the cutover)")
	}
}

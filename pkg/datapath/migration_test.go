package datapath

import "testing"

// TestMigrationCtrlRoundTrip pins the bit layout the BPF side reads (see the
// MIG_* accessors in bpf/datapath.bpf.c): a mismatch here would silently route
// packets to the wrong AFTR slot, so the packing is worth asserting explicitly.
func TestMigrationCtrlRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		ctrl migrationCtrl
		want uint32
	}{
		{
			name: "steady on slot 0",
			ctrl: migrationCtrl{activeSlot: 0, oldSlot: 0, state: migSteady, epoch: 0},
			want: 0x00000000,
		},
		{
			name: "priming: traffic still on slot 0, epoch 1",
			ctrl: migrationCtrl{activeSlot: 0, oldSlot: 0, state: migPriming, epoch: 1},
			want: 0x01010000,
		},
		{
			name: "draining: active slot 1, pre-existing flows pinned to slot 0",
			ctrl: migrationCtrl{activeSlot: 1, oldSlot: 0, state: migDraining, epoch: 1},
			want: 0x01020001,
		},
		{
			name: "steady on slot 1 after completing",
			ctrl: migrationCtrl{activeSlot: 1, oldSlot: 1, state: migSteady, epoch: 1},
			want: 0x01000101,
		},
		{
			name: "all fields at their byte maximum",
			ctrl: migrationCtrl{activeSlot: 0xff, oldSlot: 0xff, state: 0xff, epoch: 0xff},
			want: 0xffffffff,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.ctrl.pack(); got != c.want {
				t.Fatalf("pack() = %#08x, want %#08x", got, c.want)
			}
			if got := unpackMigrationCtrl(c.want); got != c.ctrl {
				t.Fatalf("unpackMigrationCtrl(%#08x) = %+v, want %+v", c.want, got, c.ctrl)
			}
		})
	}
}

// TestMigrationCtrlEpochWraps documents that the epoch is a byte and wraps.
// That's harmless: migrations are day-scale and stale entries are GC'd between
// them, so a wrapped epoch colliding with a leftover entry can at worst pin one
// flow to a slot that is still valid.
func TestMigrationCtrlEpochWraps(t *testing.T) {
	c := migrationCtrl{epoch: (255 + 1) & 0xff}
	if got := unpackMigrationCtrl(c.pack()).epoch; got != 0 {
		t.Fatalf("epoch after wrap = %d, want 0", got)
	}
}

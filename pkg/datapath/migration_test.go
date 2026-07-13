package datapath

import "testing"

// TestMigrationCtrlRoundTrip pins the bit layout the BPF side reads (see the
// MIG_* accessors in bpf/datapath.bpf.c). A mismatch would silently route
// packets to the wrong next-hop slot, so the packing is worth asserting
// explicitly -- including the fields no state uses yet, since the datapath
// already unpacks them.
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
			name: "steady on slot 1",
			ctrl: migrationCtrl{activeSlot: 1, oldSlot: 1, state: migSteady, epoch: 0},
			want: 0x00000101,
		},
		{
			name: "reserved fields survive the round trip",
			ctrl: migrationCtrl{activeSlot: 1, oldSlot: 0, state: 2, epoch: 1},
			want: 0x01020001,
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

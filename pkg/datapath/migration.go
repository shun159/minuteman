package datapath

import "fmt"

// Migration states, mirroring MIG_* in bpf/datapath.bpf.c. Only STEADY exists
// today; PRIMING/DRAINING arrive with graceful AFTR migration, which is what
// the state/old_slot/epoch fields of the control word are reserved for.
const migSteady uint32 = 0

// migrationCtrl is the unpacked form of the datapath's single-__u32 control
// word (see the bit layout on migration_ctrl in bpf/datapath.bpf.c). Keeping it
// one word is what makes every transition a single atomic store, so the
// datapath can never observe a half-applied one.
type migrationCtrl struct {
	activeSlot uint32 // the slot encap uses
	oldSlot    uint32 // (migration) where pre-cutover flows stay pinned
	state      uint32 // migSteady today
	epoch      uint32 // (migration) generation stamp, 0..255
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

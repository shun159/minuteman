package datapath

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// Run with MM_BPF_TEST=1 as root. Exercise the actual fragment programs,
// changing the live config between clones of one datagram.
func TestFragmentUnitSnapshot(t *testing.T) {
	if os.Getenv("MM_BPF_TEST") != "1" {
		t.Skip("requires MM_BPF_TEST=1 and CAP_BPF")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}
	for name := range spec.Programs {
		if name != "xdp_softwire_frag0" && name != "xdp_softwire_frag1" && name != "xdp_softwire_frag2" {
			delete(spec.Programs, name)
		}
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer coll.Close()
	const total, unit = 3000, 1448
	clone := make([]byte, 14+40+8+total)
	binary.BigEndian.PutUint16(clone[12:14], 0x86dd)
	clone[14] = 0x60
	binary.BigEndian.PutUint16(clone[16:18], unit) // private flow-label snapshot
	binary.BigEndian.PutUint16(clone[18:20], total+8)
	clone[20] = 44
	clone[54] = 4
	for i := 0; i < total; i++ {
		clone[62+i] = byte(i)
	}
	var rebuilt []byte
	for i, name := range []string{"xdp_softwire_frag0", "xdp_softwire_frag1", "xdp_softwire_frag2"} {
		cfg := bpfB4Config{WanIfindex: 1, FragUnit: uint32(1232 + i*8)}
		if err := coll.Maps["b4_config_map"].Put(uint32(0), cfg); err != nil {
			t.Fatal(err)
		}
		_, out, err := coll.Programs[name].Test(clone)
		if err != nil {
			t.Fatal(err)
		}
		n := total - i*unit
		if n > unit {
			n = unit
		}
		if len(out) != 62+n {
			t.Fatalf("fragment %d length %d, want %d", i, len(out), 62+n)
		}
		off := binary.BigEndian.Uint16(out[56:58])
		want := uint16(i * unit)
		if i < 2 {
			want |= 1
		}
		if off != want {
			t.Fatalf("fragment %d offset/M %d, want %d", i, off, want)
		}
		if !bytes.Equal(out[15:18], []byte{0, 0, 0}) {
			t.Fatal("private flow label leaked")
		}
		rebuilt = append(rebuilt, out[62:]...)
	}
	if !bytes.Equal(rebuilt, clone[62:]) {
		t.Fatal("fragments do not reconstruct original payload")
	}
}

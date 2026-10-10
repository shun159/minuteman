package tunnelpmtu

import (
	"errors"
	"slices"
	"testing"

	"github.com/shun159/molecule/behaviours/supervisor"
	"github.com/shun159/molecule/gensim"
	"github.com/shun159/molecule/proc"
)

type fakeDatapath struct {
	learned uint32
	ok      bool
	fail    bool
	frag    []int
}

func (d *fakeDatapath) TunnelPMTU() (uint32, bool) { return d.learned, d.ok }
func (d *fakeDatapath) SetSoftwireMTU(mtu int) error {
	if d.fail {
		return errors.New("map update failed")
	}
	d.frag = append(d.frag, mtu)
	return nil
}

type fakeTunnel struct {
	fail bool
	mtu  []int
}

func (t *fakeTunnel) SetSoftwireMTU(mtu int) error {
	if t.fail {
		return errors.New("netlink failed")
	}
	t.mtu = append(t.mtu, mtu)
	return nil
}

type rig struct {
	w    watcher
	dp   *fakeDatapath
	tun  *fakeTunnel
	logs int
	st   state
}

func newRig(t *testing.T) *rig {
	r := &rig{dp: &fakeDatapath{}, tun: &fakeTunnel{}}
	r.w = watcher{
		cfg:  Config{Datapath: r.dp, Tunnel: r.tun, WANMTU: 1500},
		logf: func(f string, a ...any) { r.logs++; t.Logf(f, a...) },
	}
	r.st, _, _ = r.w.Init(proc.PID{})
	return r
}

func (r *rig) tick() { r.st, _ = r.w.HandleInfo(r.st, tick{}) }

// The first tick applies the WAN MTU, quietly: what the process last
// applied is not known. Then nothing happens until the path MTU changes.
func TestFirstTick(t *testing.T) {
	r := newRig(t)
	r.tick()
	r.tick()
	if len(r.dp.frag) != 1 || r.dp.frag[0] != 1500 || len(r.tun.mtu) != 1 || r.tun.mtu[0] != 1500 {
		t.Errorf("applied %v and %v, want 1500 once each", r.dp.frag, r.tun.mtu)
	}
	if r.logs != 0 {
		t.Errorf("%d lines logged, want none", r.logs)
	}
}

// A learned path MTU narrower than the WAN's is applied to both, and
// logged once; its ageing out widens both back.
func TestNarrowAndWiden(t *testing.T) {
	r := newRig(t)
	r.tick()
	r.dp.learned, r.dp.ok = 1400, true
	r.tick()
	r.tick()
	r.dp.ok = false
	r.tick()
	if want := []int{1500, 1400, 1500}; !slices.Equal(r.dp.frag, want) || !slices.Equal(r.tun.mtu, want) {
		t.Errorf("applied %v and %v, want %v", r.dp.frag, r.tun.mtu, want)
	}
	if r.logs != 2 {
		t.Errorf("%d lines logged, want one per change", r.logs)
	}
}

// A learned path MTU wider than the WAN's is not applied.
func TestWiderIgnored(t *testing.T) {
	r := newRig(t)
	r.tick()
	r.dp.learned, r.dp.ok = 9000, true
	r.tick()
	if len(r.dp.frag) != 1 {
		t.Errorf("applied %v", r.dp.frag)
	}
}

// One failing doesn't hold the other back, and is retried next tick.
func TestRetry(t *testing.T) {
	r := newRig(t)
	r.tick()
	r.dp.learned, r.dp.ok = 1400, true
	r.tun.fail = true
	r.tick()
	if !slices.Equal(r.dp.frag, []int{1500, 1400}) || !slices.Equal(r.tun.mtu, []int{1500}) {
		t.Fatalf("applied %v and %v", r.dp.frag, r.tun.mtu)
	}
	r.tun.fail = false
	r.tick()
	if !slices.Equal(r.dp.frag, []int{1500, 1400}) || !slices.Equal(r.tun.mtu, []int{1500, 1400}) {
		t.Errorf("applied %v and %v, want the tunnel retried alone", r.dp.frag, r.tun.mtu)
	}
}

// The tree starts, its process ticking.
func TestSpecStarts(t *testing.T) {
	s := gensim.New(1)
	dp := &fakeDatapath{}
	if _, err := gensim.Start(s, supervisor.Child(Spec(Config{Datapath: dp, Tunnel: &fakeTunnel{}, WANMTU: 1500}))); err != nil {
		t.Fatal(err)
	}
	s.Advance(PollInterval)
	if len(dp.frag) != 1 {
		t.Errorf("applied %v, want the first tick's", dp.frag)
	}
}

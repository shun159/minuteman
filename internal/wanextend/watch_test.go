package wanextend

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/shun159/miniteman/pkg/routeradvert"
	"github.com/shun159/molecule"
	"github.com/shun159/molecule/behaviours/supervisor"
	"github.com/shun159/molecule/gensim"
	"github.com/shun159/molecule/proc"
)

type advertised struct {
	iface  string
	prefix netip.Prefix
}

type fakeAdv struct{ got []advertised }

func (a *fakeAdv) Advertise(iface string, cfg routeradvert.Config) {
	a.got = append(a.got, advertised{iface, cfg.Prefix})
}

var (
	oldPrefix = netip.MustParsePrefix("2001:db8:1::/64")
	newPrefix = netip.MustParsePrefix("2001:db8:2::/64")
)

// The watch reads the WAN at once, then every watchPollInterval, extending
// a changed prefix onto every LAN -- and nothing else: the same prefix, a
// failed read, no address.
func TestWatch(t *testing.T) {
	adv := &fakeAdv{}
	reading, readErr := oldPrefix, error(nil)
	w := watcher{
		cfg:     Config{LANs: []string{"lan0", "lan1"}, Adv: adv},
		initial: oldPrefix,
		read:    func() (netip.Prefix, error) { return reading, readErr },
		logf:    t.Logf,
	}
	st, effs, _ := w.Init(proc.PID{})
	if timer, ok := effs[0].(molecule.StartTimer); !ok || timer.After != 0 {
		t.Errorf("Init: %v, want a read at once", effs)
	}

	st, effs = w.HandleInfo(st, tick{})
	if timer := effs[0].(molecule.StartTimer); timer.After != watchPollInterval {
		t.Errorf("next read after %v", timer.After)
	}
	readErr = errors.New("netlink")
	st, _ = w.HandleInfo(st, tick{})
	reading, readErr = netip.Prefix{}, nil
	st, _ = w.HandleInfo(st, tick{})
	if len(adv.got) != 0 || st != oldPrefix {
		t.Fatalf("no change, yet %v advertised, %v kept", adv.got, st)
	}

	reading = newPrefix
	st, _ = w.HandleInfo(st, tick{})
	want := []advertised{{"lan0", newPrefix}, {"lan1", newPrefix}}
	if st != newPrefix || len(adv.got) != 2 || adv.got[0] != want[0] || adv.got[1] != want[1] {
		t.Errorf("renumbered: %v advertised, %v kept; want %v", adv.got, st, want)
	}
}

// The tree starts.
func TestSpecStarts(t *testing.T) {
	s := gensim.New(1)
	spec := Spec(Config{LANs: []string{"lan0"}, Adv: &fakeAdv{}}, oldPrefix)
	if _, err := gensim.Start(s, supervisor.Child(spec)); err != nil {
		t.Fatal(err)
	}
}

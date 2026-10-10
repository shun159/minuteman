package ndppd

import (
	"net/netip"

	"github.com/shun159/molecule"
	"github.com/shun159/molecule/behaviours/genserver"
	"github.com/shun159/molecule/proc"
)

// Casts to the routes process.
type (
	install struct {
		Target netip.Addr
		Iface  string
	}
	remove struct {
		Target netip.Addr
		Iface  string
	}
)

// routes owns the host routes: it installs the route of a host the proxy
// has confirmed, and removes it once the host has gone quiet. It is where
// the proxy's decisions meet the routing table, and so not pure: each cast
// is a netlink round trip, done as it is handled. A failure is logged, not
// fatal -- without its route, a host's traffic keeps arriving proxied and
// unrouted, no worse than before it was confirmed.
type routes struct {
	genserver.Default[Routes]
	open func() (Routes, error)
	logf func(format string, args ...any)
}

func (r routes) Init(proc.PID) (Routes, []molecule.Effect, error) {
	rs, err := r.open()
	if err != nil {
		return nil, nil, err
	}
	// Trapping exits, so that Terminate closes the routes on shutdown.
	return rs, molecule.Do(molecule.TrapExit{On: true}), nil
}

func (r routes) HandleCast(rs Routes, msg any) (Routes, []molecule.Effect) {
	switch m := msg.(type) {
	case install:
		r.logf("NDProxy: %s confirmed active behind %s", m.Target, m.Iface)
		if err := rs.Install(m.Target, m.Iface); err != nil {
			r.logf("NDProxy: installing the route to %s via %s: %v", m.Target, m.Iface, err)
		}
	case remove:
		r.logf("NDProxy: %s behind %s expired", m.Target, m.Iface)
		rs.Remove(m.Target, m.Iface)
	}
	return rs, nil
}

func (r routes) Terminate(rs Routes, _ error) []molecule.Effect {
	rs.Close()
	return nil
}

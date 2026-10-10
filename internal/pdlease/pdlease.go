// Package pdlease keeps minuteman's DHCPv6-PD lease, as a molecule
// supervision tree: a process running pkg/prefixdelegation's renewal ladder
// -- Renew at T1, Rebind at T2, Solicit afresh once the lease expires --
// and one making each new lease the LAN's. The exchanges go through the
// WAN's DHCPv6 client (internal/dhcpv6client); what a lease means for the
// LAN is internal/lanprefix's, which the caller's Apply runs.
package pdlease

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/shun159/miniteman/pkg/dhcpv6"
	"github.com/shun159/miniteman/pkg/prefixdelegation"
	"github.com/shun159/molecule"
	"github.com/shun159/molecule/behaviours/genserver"
	"github.com/shun159/molecule/behaviours/genstatem"
	"github.com/shun159/molecule/behaviours/supervisor"
)

// Names of the processes.
const (
	LeaseName molecule.Local = "dhcpv6-pd lease"
	ApplyName molecule.Local = "dhcpv6-pd apply"
)

// releaseTimeout bounds the Release on shutdown: a client stops using the
// binding whether or not the server answers, so a shutdown doesn't wait
// out the whole exchange.
const releaseTimeout = 5 * time.Second

// Config configures the tree.
type Config struct {
	// Exchanger runs the DHCPv6 exchanges: the WAN's DHCPv6 client.
	Exchanger dhcpv6.Exchanger
	// Lease is the lease the caller acquired, and has already applied.
	Lease *prefixdelegation.Lease
	// Apply makes a lease the LAN's. It is called for every lease after
	// Lease, one at a time.
	Apply func(*prefixdelegation.Lease)
}

// Spec is the supervision tree keeping cfg.Lease:
//
//	dhcpv6-pd (one_for_one)
//	├── dhcpv6-pd apply   genserver: applies each new lease, by casts
//	└── dhcpv6-pd lease   genstatem: the renewal ladder
//
// A restarted lease process starts again from cfg.Lease: before its T1, it
// still is the lease; past it, it is renewed at once -- or rebound, or
// solicited afresh, as far down the ladder as its age takes it -- and the
// server's answer, the binding as it stands, applied.
func Spec(cfg Config) supervisor.Spec {
	ex := cfg.Exchanger
	l := leaser{
		initial: cfg.Lease,
		renew: func(ctx context.Context, l *prefixdelegation.Lease) (*prefixdelegation.Lease, error) {
			return prefixdelegation.Renew(ctx, ex, l)
		},
		rebind: func(ctx context.Context, l *prefixdelegation.Lease) (*prefixdelegation.Lease, error) {
			return prefixdelegation.Rebind(ctx, ex, l)
		},
		acquire: func(ctx context.Context) (*prefixdelegation.Lease, error) {
			return prefixdelegation.Acquire(ctx, ex)
		},
		release: func(l *prefixdelegation.Lease) {
			ctx, cancel := context.WithTimeout(context.Background(), releaseTimeout)
			defer cancel()
			if err := prefixdelegation.Release(ctx, ex, l); err != nil && !errors.Is(err, context.DeadlineExceeded) {
				log.Printf("DHCPv6-PD: releasing the lease: %v", err)
			}
		},
		logf: log.Printf,
	}
	return supervisor.Spec{
		Name:     molecule.Local("dhcpv6-pd"),
		Strategy: supervisor.OneForOne,
		Children: []supervisor.ChildSpec{
			{ID: "dhcpv6-pd apply", Start: genserver.Child(applier{apply: cfg.Apply}, molecule.WithName(ApplyName))},
			{ID: "dhcpv6-pd lease", Start: genstatem.Child(l, molecule.WithName(LeaseName))},
		},
	}
}

// applied is the cast to the apply process: lease is the new lease.
type applied struct{ Lease *prefixdelegation.Lease }

// applier makes each new lease the LAN's: addresses, routes, RAs. It is
// where the lease meets the system, and so not pure: each cast is applied
// as it is handled. Apart from the lease process, so that the latter is
// pure, and its timers not held up by netlink.
type applier struct {
	genserver.Default[struct{}]
	apply func(*prefixdelegation.Lease)
}

func (a applier) HandleCast(st struct{}, msg any) (struct{}, []molecule.Effect) {
	if m, ok := msg.(applied); ok {
		a.apply(m.Lease)
	}
	return st, nil
}

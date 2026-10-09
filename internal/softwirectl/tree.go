package softwirectl

import (
	"context"
	"time"

	"github.com/shun159/molecule"
	"github.com/shun159/molecule/behaviours/genserver"
	"github.com/shun159/molecule/behaviours/genstatem"
	"github.com/shun159/molecule/behaviours/supervisor"
	"github.com/shun159/molecule/proc"
)

// Names of the processes of the tree.
const (
	SoftwireName   molecule.Local = "softwire"
	DiscoveryName  molecule.Local = "aftr-discovery"
	ControllerName molecule.Local = "softwirectl"
	SupervisorName molecule.Local = "softwirectl-sup"
)

// Config configures the tree.
type Config struct {
	Softwire   *Softwire
	Controller Controller
	// Discover and RetryDelay run re-discovery, with a dynamic AFTR.
	Discover   DiscoverFunc
	RetryDelay func(error) time.Duration
}

// Spec is the supervision tree of the softwire endpoints:
//
//	softwirectl-sup (rest_for_one)
//	├── softwire        serves the datapath, tunnel and netlink to the controller
//	├── aftr-discovery  runs discovery attempts (with a dynamic AFTR)
//	└── softwirectl     the controller
//
// rest_for_one because each depends on those before it: a restarted softwire
// server or discovery process takes the controller with it, which then
// recovers from the softwire, whose state outlives them all.
func Spec(cfg Config) supervisor.Spec {
	d := discoverer{discover: cfg.Discover, retryDelay: cfg.RetryDelay}
	return spec(cfg, supervisor.StartFunc(func(ctx context.Context, parent *proc.Self) (proc.PID, error) {
		return parent.StartLink(ctx, d.run)
	}))
}

// spec is Spec with the discovery process started by discovery, which tests
// replace: gensim simulates behaviours, not processes written against proc.
func spec(cfg Config, discovery supervisor.Starter) supervisor.Spec {
	children := []supervisor.ChildSpec{{
		ID:    "softwire",
		Start: genserver.Child(server{sw: cfg.Softwire}, molecule.WithName(SoftwireName)),
	}}
	if cfg.Controller.DynamicAFTR {
		children = append(children, supervisor.ChildSpec{ID: "aftr-discovery", Start: discovery})
	}
	children = append(children, supervisor.ChildSpec{
		ID:    "softwirectl",
		Start: genstatem.Child(cfg.Controller, molecule.WithName(ControllerName)),
	})
	return supervisor.Spec{
		Name:     SupervisorName,
		Strategy: supervisor.RestForOne,
		Children: children,
	}
}

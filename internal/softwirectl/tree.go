package softwirectl

import (
	"github.com/shun159/molecule"
	"github.com/shun159/molecule/behaviours/genserver"
	"github.com/shun159/molecule/behaviours/genstatem"
	"github.com/shun159/molecule/behaviours/supervisor"
)

// Names of the processes of the tree.
const (
	SoftwireName   molecule.Local = "softwire"
	ControllerName molecule.Local = "softwirectl"
	SupervisorName molecule.Local = "softwirectl-sup"
)

// Config configures the tree.
type Config struct {
	Softwire   *Softwire
	Controller Controller
}

// Spec is the supervision tree of the softwire endpoints:
//
//	softwirectl-sup (rest_for_one)
//	├── softwire        serves the datapath, tunnel and netlink to the controller
//	└── softwirectl     the controller; discovery runs in an Async of its own
//
// rest_for_one because the controller depends on the softwire server: a
// restarted server takes the controller with it, which then recovers from the
// softwire, whose state outlives them both.
func Spec(cfg Config) supervisor.Spec {
	return supervisor.Spec{
		Name:     SupervisorName,
		Strategy: supervisor.RestForOne,
		Children: []supervisor.ChildSpec{
			{
				ID:    "softwire",
				Start: genserver.Child(server{sw: cfg.Softwire}, molecule.WithName(SoftwireName)),
			},
			{
				ID:    "softwirectl",
				Start: genstatem.Child(cfg.Controller, molecule.WithName(ControllerName)),
			},
		},
	}
}

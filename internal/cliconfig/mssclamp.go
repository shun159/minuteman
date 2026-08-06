package cliconfig

import (
	"fmt"
	"strconv"

	"github.com/shun159/miniteman/pkg/datapath"
)

// minExplicitMSSClamp is the smallest MSS an operator may pin by hand: 536 is
// what every IPv4 endpoint must accept without path MTU discovery (RFC 1122
// §4.2.2.6), so anything below it is far more likely to be a typo (a value
// meant as an MTU, say) than an intent.
const minExplicitMSSClamp = 536

// maxExplicitMSSClamp is a sanity ceiling: the MSS field is 16 bits, but a
// value that couldn't fit any Ethernet-derived MTU never clamps anything and is
// almost certainly a mistake.
const maxExplicitMSSClamp = 65495

// ParseMSSClamp parses the -tcp-mss-clamp flag value into the policy
// datapath.B4Config.TCPMSSClamp takes: "auto" (derive from the softwire MTU and
// track a learned path MTU), "off" (no clamping), or an explicit MSS in bytes.
func ParseMSSClamp(s string) (int, error) {
	switch s {
	case "auto", "":
		return datapath.TCPMSSClampAuto, nil
	case "off", "none", "0":
		return 0, nil
	}

	mss, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("must be \"auto\", \"off\", or an MSS in bytes, got %q", s)
	}
	if mss < minExplicitMSSClamp || mss > maxExplicitMSSClamp {
		return 0, fmt.Errorf("MSS %d is out of range (%d..%d); use \"off\" to disable clamping", mss, minExplicitMSSClamp, maxExplicitMSSClamp)
	}
	return mss, nil
}

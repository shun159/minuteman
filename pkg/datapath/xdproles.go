package datapath

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// XDPRole names what one of minuteman's XDP programs does on the interface
// it's attached to, so an out-of-band observer (the `minuteman stats`
// subcommand) can label an interface without being told which is which.
type XDPRole string

const (
	XDPRoleWAN     XDPRole = "wan"  // xdp_dslite_decap: the WAN/softwire side
	XDPRoleLAN     XDPRole = "lan"  // xdp_dslite_encap: a LAN side
	XDPRoleFrag    XDPRole = "frag" // xdp_softwire_frag<i>: a fragmenter companion veth
	XDPRoleUnknown XDPRole = "minuteman"
)

// XDPRoles classifies XDP program ids -- as reported by a link dump's
// IFLA_XDP_PROG_ID (pkg/netlink's Link) -- returning an entry only for those
// belonging to the *running* minuteman instance.
//
// Membership is decided by the program referencing the same stats map this
// instance pinned to bpffs, not by its name: a name can be shared by an
// unrelated XDP program (or by a second, stale minuteman whose pin has already
// been replaced), whereas a map id is unique per loaded map, so anything
// reaching the pinned map's id really is part of the datapath being observed.
// Every interface-attached program bumps a stats counter, so none is missed.
// The name is then used only to label the role.
//
// A program id that can't be opened or inspected is treated as not ours rather
// than as an error: the dump is a snapshot, and a device can lose its program
// (or the whole instance can exit) between the dump and this call.
func XDPRoles(progIDs []uint32) (map[uint32]XDPRole, error) {
	statsID, err := pinnedStatsMapID()
	if err != nil {
		return nil, err
	}

	roles := make(map[uint32]XDPRole, len(progIDs))
	for _, id := range progIDs {
		if role, ok := programRole(ebpf.ProgramID(id), statsID); ok {
			roles[id] = role
		}
	}
	return roles, nil
}

// pinnedStatsMapID returns the kernel id of the stats map the running
// minuteman pinned (see pinStats), the identity XDPRoles matches programs
// against.
func pinnedStatsMapID() (ebpf.MapID, error) {
	m, err := ebpf.LoadPinnedMap(statsPinPath, nil)
	if err != nil {
		return 0, fmt.Errorf("opening pinned stats map %s (is minuteman running?): %w", statsPinPath, err)
	}
	defer m.Close()

	info, err := m.Info()
	if err != nil {
		return 0, fmt.Errorf("reading pinned stats map info: %w", err)
	}
	id, ok := info.ID()
	if !ok {
		return 0, fmt.Errorf("kernel reports no id for the pinned stats map")
	}
	return id, nil
}

// programRole reports whether the program with the given id belongs to the
// minuteman instance owning statsID, and if so which role its name identifies.
func programRole(id ebpf.ProgramID, statsID ebpf.MapID) (XDPRole, bool) {
	prog, err := ebpf.NewProgramFromID(id)
	if err != nil {
		return "", false
	}
	defer prog.Close()

	info, err := prog.Info()
	if err != nil {
		return "", false
	}
	mapIDs, ok := info.MapIDs()
	if !ok {
		return "", false
	}
	for _, m := range mapIDs {
		if m == statsID {
			return roleForProgramName(info.Name), true
		}
	}
	return "", false
}

// bpfObjNameLen is BPF_OBJ_NAME_LEN from <linux/bpf.h>: the kernel stores a
// program's name in a NUL-terminated field this wide, i.e. 15 usable
// characters, and silently truncates anything longer -- which several of the
// datapath's program names are.
const bpfObjNameLen = 16

// roleForProgramName maps a program's reported name to its role.
//
// Both sides of the comparison are truncated to what the kernel's name field
// can hold, because the reported name may or may not have survived it:
// cilium/ebpf recovers the full name from the program's BTF func info when the
// raw name looks truncated, so "xdp_dslite_encap" comes back whole on a
// BTF-carrying build and as "xdp_dslite_enca" without one. Truncating both
// sides classifies either the same way.
//
// Two consequences of that truncation, both harmless here:
// "xdp_dslite_decap" and "xdp_dslite_decap_cpu" collapse together, but the
// cpumap variant is never attached to an interface and so never reaches this
// function; and all four "xdp_softwire_frag<i>" collapse together, but the
// fragment index is carried by the companion device's own name
// (internal/fragpath's mm-frag<i>p), not by the role.
func roleForProgramName(name string) XDPRole {
	switch truncateProgramName(name) {
	case truncateProgramName("xdp_dslite_decap"):
		return XDPRoleWAN
	case truncateProgramName("xdp_dslite_encap"):
		return XDPRoleLAN
	case truncateProgramName("xdp_softwire_frag0"):
		return XDPRoleFrag
	default:
		// Ours by the map-id check above, but a program this build doesn't
		// know a name for -- report it rather than hiding the interface.
		return XDPRoleUnknown
	}
}

func truncateProgramName(name string) string {
	if len(name) > bpfObjNameLen-1 {
		return name[:bpfObjNameLen-1]
	}
	return name
}

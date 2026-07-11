package lanprefix

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/shun159/miniteman/pkg/netlink"
)

// Assignment records which /64 subnet and address this project has assigned
// to a LAN interface, so a later Reconcile call can detect when a renewed
// delegation changed the subnet and clean up the stale address.
// ValidLifetime/PreferredLifetime are carried through from the delegated
// prefix (not derived here) so a caller advertising this subnet via Router
// Advertisements (see RAManager) can keep them in sync with the actual
// upstream delegation.
type Assignment struct {
	Iface                            string
	Subnet                           netip.Prefix
	Address                          netip.Addr
	ValidLifetime, PreferredLifetime time.Duration
}

// Reconcile carves a /64 per entry in lanIfaces out of delegated (via
// SubnetFor, indexed by each interface's position in the slice) and
// assigns AssignedAddress(subnet) to it. validLifetime/preferredLifetime
// are the delegated prefix's own lifetimes (RFC 3633's IA_PD Prefix option
// carries these; see pkg/prefixdelegation's IAPrefix), stored on the
// returned Assignment for callers that don't otherwise track them. prev, if
// non-nil, is the result of the previous call: for any interface whose
// subnet has changed since then, the old address is removed first
// (RTM_DELADDR) before the new one is added (RTM_NEWADDR); if the subnet is
// unchanged, both netlink calls are skipped.
//
// One netlink socket is used for the whole call. Per-interface failures
// (e.g. a LAN interface that doesn't exist) are collected with errors.Join
// so one bad interface doesn't block the others; the returned []Assignment
// always has one entry per lanIfaces (even ones that errored, so the next
// Reconcile call can retry them) unless opening the netlink socket itself
// fails.
func Reconcile(delegated netip.Prefix, validLifetime, preferredLifetime time.Duration, lanIfaces []string, prev []Assignment) ([]Assignment, error) {
	sock, err := netlink.Open()
	if err != nil {
		return nil, err
	}
	defer sock.Close()

	result := make([]Assignment, len(lanIfaces))
	var errs []error

	for i, ifaceName := range lanIfaces {
		a, err := reconcileOne(sock, delegated, validLifetime, preferredLifetime, i, ifaceName, prev)
		result[i] = a
		if err != nil {
			errs = append(errs, fmt.Errorf("lanprefix: %s: %w", ifaceName, err))
		}
	}

	return result, errors.Join(errs...)
}

func reconcileOne(sock *netlink.Socket, delegated netip.Prefix, validLifetime, preferredLifetime time.Duration, index int, ifaceName string, prev []Assignment) (Assignment, error) {
	subnet, err := SubnetFor(delegated, index)
	if err != nil {
		return Assignment{Iface: ifaceName}, err
	}
	addr, err := AssignedAddress(subnet)
	if err != nil {
		return Assignment{Iface: ifaceName, Subnet: subnet}, err
	}
	a := Assignment{
		Iface:             ifaceName,
		Subnet:            subnet,
		Address:           addr,
		ValidLifetime:     validLifetime,
		PreferredLifetime: preferredLifetime,
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return a, fmt.Errorf("looking up interface: %w", err)
	}

	if index < len(prev) && prev[index].Subnet == subnet {
		return a, nil // unchanged since the last Reconcile: nothing to do
	}

	if index < len(prev) && prev[index].Subnet.IsValid() {
		old := prev[index]
		if err := sock.DelAddr(iface.Index, old.Address, old.Subnet.Bits()); err != nil {
			return a, fmt.Errorf("removing stale address %s: %w", old.Address, err)
		}
	}

	if err := sock.AddAddr(iface.Index, addr, subnet.Bits()); err != nil {
		return a, fmt.Errorf("assigning address %s: %w", addr, err)
	}
	return a, nil
}

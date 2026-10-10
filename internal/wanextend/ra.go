package wanextend

import (
	"net/netip"
	"time"

	"github.com/shun159/miniteman/pkg/routeradvert"
)

// validLifetime/preferredLifetime are the Valid/Preferred lifetimes this
// package advertises for the WAN's own SLAAC prefix when re-advertising it
// to LAN clients: RFC 4861 §6.2.1's recommended AdvValidLifetime/
// AdvPreferredLifetime defaults. The WAN-side RA that actually assigned
// this prefix carries its own (possibly different) lifetimes, but
// DiscoverPrefix/WatchChanges read the prefix back from the kernel's
// address list (pkg/netlink.Socket.Addrs), which doesn't expose
// IFA_CACHEINFO's remaining lifetimes -- a known simplification, not a
// protocol requirement.
const (
	validLifetime     = 2592000 * time.Second // 30 days
	preferredLifetime = 604800 * time.Second  // 7 days
)

// Advertiser makes a configuration what an interface advertises in its
// Router Advertisements, in place: internal/radvd's.
type Advertiser interface {
	Advertise(iface string, cfg routeradvert.Config)
}

// raManager decides what each LAN interface advertises -- the shared WAN
// prefix -- and hands that to an Advertiser, mirroring
// internal/lanprefix.RAManager.
type raManager struct {
	adv          Advertiser
	rdnssByIface map[string]netip.Addr
}

// newRAManager mirrors internal/lanprefix.NewRAManager's rdnssByIface
// parameter -- see routeradvert.Config.RDNSSAddr's own doc.
func newRAManager(adv Advertiser, rdnssByIface map[string]netip.Addr) *raManager {
	return &raManager{adv: adv, rdnssByIface: rdnssByIface}
}

// sync makes prefix the one every lanIfaces interface advertises, the
// advertiser updating in place -- the same reasoning as
// internal/lanprefix.RAManager.Sync: an advertiser's shutdown announces
// RouterLifetime=0 (RFC 4861 §6.2.5), so restarting on a WAN prefix change
// would withdraw the default route and the RDNSS server from every LAN
// client for as long as the replacement takes to announce itself.
//
// That final RA never deprecated the *old* prefix anyway -- it carries a
// Prefix Information Option for the outgoing prefix with its lifetimes
// intact -- so nothing about renumbering is lost by not restarting. LAN
// clients keep their old SLAAC address until its own advertised valid
// lifetime runs out either way; advertising the superseded prefix with
// PreferredLifetime=0 to deprecate it promptly is RFC 9096 territory, an
// open item in docs/rfc-compliance-backlog.md.
func (m *raManager) sync(prefix netip.Prefix, lanIfaces []string) {
	for _, iface := range lanIfaces {
		m.adv.Advertise(iface, m.config(iface, prefix))
	}
}

// config builds the Router Advertisement configuration for one LAN
// interface: the shared WAN prefix with On-Link cleared (see the package
// doc) and this interface's RDNSS address, if any.
func (m *raManager) config(iface string, prefix netip.Prefix) routeradvert.Config {
	return routeradvert.Config{
		Prefix:            prefix,
		OnLink:            false,
		ValidLifetime:     validLifetime,
		PreferredLifetime: preferredLifetime,
		RDNSSAddr:         m.rdnssByIface[iface],
	}
}

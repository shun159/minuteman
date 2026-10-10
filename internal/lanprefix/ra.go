package lanprefix

import (
	"net/netip"

	"github.com/shun159/miniteman/pkg/routeradvert"
)

// Advertiser makes a configuration what an interface advertises in its
// Router Advertisements, in place: internal/radvd's.
type Advertiser interface {
	Advertise(iface string, cfg routeradvert.Config)
}

// RAManager decides what each LAN interface advertises to LAN clients via
// Router Advertisements -- its currently-assigned /64 (see Assignment) --
// and hands that to an Advertiser. Not safe for concurrent use.
type RAManager struct {
	adv          Advertiser
	rdnssByIface map[string]netip.Addr
}

// NewRAManager returns an RAManager advertising through adv. rdnssByIface
// maps a LAN interface name to the DNS-server address to advertise in its
// RAs' RDNSS option (RFC 8106) -- it must be an address a DNS proxy actually
// bound (see routeradvert.Config.RDNSSAddr's own doc), so the caller passes
// exactly the link-local addresses internal/dnsproxy reported binding. An
// interface absent from the map (or a nil map) gets no RDNSS.
func NewRAManager(adv Advertiser, rdnssByIface map[string]netip.Addr) *RAManager {
	return &RAManager{adv: adv, rdnssByIface: rdnssByIface}
}

// Sync makes every assigned entry with a valid Subnet the configuration
// advertised on its interface.
//
// The advertiser updates what it advertises in place, which matters because
// a DHCPv6-PD Renew resets ValidLifetime/PreferredLifetime on every lease
// change, so Sync is reached on every T1 interval even when nothing about
// the subnet changed. Restarting the advertiser would deliver those
// refreshed lifetimes too, but its shutdown sends RFC 4861 §6.2.5's
// RouterLifetime=0 (plus RDNSS Lifetime=0) advertisement, so every LAN
// client would see its default route and DNS server withdrawn once per
// renewal and reinstated a moment later.
//
// Entries whose Subnet is invalid (Reconcile failed for that interface) are
// left alone -- the interface keeps advertising what it did rather than
// being torn down over a transient error.
func (m *RAManager) Sync(assigned []Assignment) {
	for _, a := range assigned {
		if !a.Subnet.IsValid() {
			continue
		}
		m.adv.Advertise(a.Iface, m.config(a))
	}
}

// config builds the Router Advertisement configuration for one assigned
// interface.
func (m *RAManager) config(a Assignment) routeradvert.Config {
	return routeradvert.Config{
		Prefix: a.Subnet,
		// DHCPv6-PD delegates this /64 distinctly to this LAN
		// interface, so it really is on-link for it -- unlike
		// internal/wanextend's NDProxy model, which shares one
		// prefix across WAN and LAN and must clear this.
		OnLink:            true,
		ValidLifetime:     a.ValidLifetime,
		PreferredLifetime: a.PreferredLifetime,
		RDNSSAddr:         m.rdnssByIface[a.Iface],
	}
}

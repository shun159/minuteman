package netlink

import (
	"net"
	"net/netip"
	"os"
	"testing"
)

// TestSourceForDestRig runs inside the netns rig's mm-cpe namespace: toward the
// AFTR (fd00:2::2) out the WAN, the kernel's chosen source must be a global
// address the interface actually has. Set MM_RIG_WAN to the WAN ifname to
// enable; skipped otherwise.
func TestSourceForDestRig(t *testing.T) {
	wan := os.Getenv("MM_RIG_WAN")
	if wan == "" || os.Geteuid() != 0 {
		t.Skip("set MM_RIG_WAN (and run as root inside the netns) to enable")
	}
	ifi, err := net.InterfaceByName(wan)
	if err != nil {
		t.Fatalf("interface %s: %v", wan, err)
	}
	own := map[string]bool{}
	addrs, _ := ifi.Addrs()
	for _, a := range addrs {
		ipn := a.(*net.IPNet)
		if ipn.IP.To4() == nil && ipn.IP.IsGlobalUnicast() {
			na, _ := netip.AddrFromSlice(ipn.IP)
			own[na.String()] = true
		}
	}

	s, err := Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	dst := netip.MustParseAddr(os.Getenv("MM_RIG_AFTR"))
	src, ok, err := s.SourceForDest(ifi.Index, dst)
	if err != nil {
		t.Fatalf("SourceForDest: %v", err)
	}
	if !ok {
		t.Fatal("no source returned toward the AFTR (WAN route missing?)")
	}
	if !own[src.String()] {
		t.Fatalf("picked %s, not one of the WAN's global addresses %v", src, own)
	}
	t.Logf("kernel picked B4 source %s toward AFTR %s", src, dst)
}

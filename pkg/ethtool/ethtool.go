// Package ethtool is a minimal, hand-rolled SIOCETHTOOL client covering
// exactly one thing: reading a network device's driver-specific statistics --
// the counters `ethtool -S <iface>` prints. minuteman uses it to report, from
// its own `stats interfaces` subcommand, what the drivers underneath the XDP
// datapath see (a veth's xdp_packets/xdp_drops, a real NIC's per-queue and
// per-XDP counters), so an operator needn't correlate two tools' output by hand.
//
// No ethtool library dependency and no `ethtool` exec, matching this project's
// no-sidecar, no-external-process ethos (pkg/netlink hand-rolls rtnetlink the
// same way, pkg/datapath/sysctl.go writes /proc/sys directly instead of
// exec'ing sysctl).
//
// Only the ETH_SS_STATS string set is implemented -- the driver-defined
// counters, which is what `-S` means. The standardised groups the newer
// ethtool *netlink* interface exposes (ETHTOOL_MSG_STATS_GET) are deliberately
// not covered: they'd be a second, differently-shaped transport for a strictly
// smaller set of counters.
package ethtool

import (
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Constants from <linux/ethtool.h> that golang.org/x/sys/unix doesn't export
// (it has the ETHTOOL_G* command numbers but not the string-set ids or the
// name length), vendored here the same way pkg/netlink vendors IFLA_IPTUN_*
// and pkg/routeradvert vendors ICMP6_FILTER.
const (
	ethSSStats    = 1  // ETH_SS_STATS: the driver-defined statistics string set
	ethGstringLen = 32 // ETH_GSTRING_LEN: fixed width of each name, NUL-padded
)

// ErrNotSupported reports that the device's driver exposes no ETH_SS_STATS
// counters at all -- either it implements none (loopback, most virtual devices
// other than veth) or it predates the ioctls used here. Distinguished from a
// real failure so callers can report "nothing to show" rather than an error.
var ErrNotSupported = errors.New("ethtool: driver exposes no statistics")

// Stat is one driver counter: the name the driver reports in ETH_SS_STATS and
// its current value. Order is preserved as the driver returns it, which is the
// order `ethtool -S` prints (drivers group related counters, e.g. per queue).
type Stat struct {
	Name  string
	Value uint64
}

// Stats reads ifname's driver statistics, the equivalent of `ethtool -S
// <ifname>`. Returns ErrNotSupported when the driver exposes none.
//
// The read is three ioctls, as ethtool(8) itself does it: ETHTOOL_GSSET_INFO
// for how many counters there are, ETHTOOL_GSTRINGS for their names, and
// ETHTOOL_GSTATS for the values. They are not atomic with respect to each
// other, but the name list only changes when the driver is reconfigured (queue
// count), so a torn read is a vanishing case and would at worst mislabel.
func Stats(ifname string) ([]Stat, error) {
	if ifname == "" || len(ifname) >= unix.IFNAMSIZ {
		return nil, fmt.Errorf("ethtool: interface name %q must be 1..%d characters", ifname, unix.IFNAMSIZ-1)
	}

	// Any socket will do: SIOCETHTOOL is dispatched on the ifreq's interface
	// name, not on anything about the socket itself.
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("ethtool: opening ioctl socket: %w", err)
	}
	defer unix.Close(fd)

	count, err := statCount(fd, ifname)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, ErrNotSupported
	}

	names, err := statNames(fd, ifname, count)
	if err != nil {
		return nil, err
	}
	values, err := statValues(fd, ifname, count)
	if err != nil {
		return nil, err
	}

	stats := make([]Stat, count)
	for i := range stats {
		stats[i] = Stat{Name: names[i], Value: values[i]}
	}
	return stats, nil
}

// statCount issues ETHTOOL_GSSET_INFO for ETH_SS_STATS.
//
// struct ethtool_sset_info { __u32 cmd; __u32 reserved; __u64 sset_mask;
// __u32 data[]; } -- the kernel clears sset_mask's bit for a string set the
// driver doesn't implement, in which case data[] comes back empty and the
// count is 0 rather than an error.
func statCount(fd int, ifname string) (int, error) {
	const (
		maskOff = 8
		dataOff = 16
	)
	buf := alignedBuf(dataOff + 4)
	nativePutUint32(buf[0:4], unix.ETHTOOL_GSSET_INFO)
	nativePutUint64(buf[maskOff:maskOff+8], 1<<ethSSStats)

	if err := ioctlEthtool(fd, ifname, buf); err != nil {
		// EOPNOTSUPP means the driver has no get_sset_count at all;
		// EINVAL is what a few older drivers return for the same thing.
		if errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EINVAL) {
			return 0, ErrNotSupported
		}
		return 0, fmt.Errorf("ethtool: ETHTOOL_GSSET_INFO on %s: %w", ifname, err)
	}

	if nativeUint64(buf[maskOff:maskOff+8]) == 0 {
		return 0, nil
	}
	count := nativeUint32(buf[dataOff : dataOff+4])
	if count > maxStats {
		return 0, fmt.Errorf("ethtool: %s reports %d statistics, refusing above %d", ifname, count, maxStats)
	}
	return int(count), nil
}

// maxStats bounds what a driver can make this package allocate. Real drivers
// top out in the low thousands (a many-queue NIC with per-queue counters); the
// cap only exists so a nonsense count can't turn into a huge allocation.
const maxStats = 1 << 16

// statNames issues ETHTOOL_GSTRINGS for ETH_SS_STATS.
//
// struct ethtool_gstrings { __u32 cmd; __u32 string_set; __u32 len;
// __u8 data[]; } -- data is count fixed-width ETH_GSTRING_LEN entries, each
// NUL-padded (and not necessarily NUL-terminated, when a name uses all 32).
func statNames(fd int, ifname string, count int) ([]string, error) {
	const dataOff = 12
	buf := alignedBuf(dataOff + count*ethGstringLen)
	nativePutUint32(buf[0:4], unix.ETHTOOL_GSTRINGS)
	nativePutUint32(buf[4:8], ethSSStats)
	nativePutUint32(buf[8:12], uint32(count))

	if err := ioctlEthtool(fd, ifname, buf); err != nil {
		return nil, fmt.Errorf("ethtool: ETHTOOL_GSTRINGS on %s: %w", ifname, err)
	}

	names := make([]string, count)
	for i := range names {
		off := dataOff + i*ethGstringLen
		names[i] = cstring(buf[off : off+ethGstringLen])
	}
	return names, nil
}

// statValues issues ETHTOOL_GSTATS for ETH_SS_STATS.
//
// struct ethtool_stats { __u32 cmd; __u32 n_stats; __u64 data[]; } -- the
// __u64 array is why the request buffer has to be 8-byte aligned (alignedBuf).
func statValues(fd int, ifname string, count int) ([]uint64, error) {
	const dataOff = 8
	buf := alignedBuf(dataOff + count*8)
	nativePutUint32(buf[0:4], unix.ETHTOOL_GSTATS)
	nativePutUint32(buf[4:8], uint32(count))

	if err := ioctlEthtool(fd, ifname, buf); err != nil {
		return nil, fmt.Errorf("ethtool: ETHTOOL_GSTATS on %s: %w", ifname, err)
	}

	values := make([]uint64, count)
	for i := range values {
		off := dataOff + i*8
		values[i] = nativeUint64(buf[off : off+8])
	}
	return values, nil
}

// ifreqData is struct ifreq as SIOCETHTOOL uses it: an interface name and
// ifr_data pointing at the ethtool command block. x/sys/unix models this
// internally (its ifreqData) but doesn't export it or an ioctl taking it, so
// it's rebuilt here -- the memory layout is the interesting part and it is
// fixed by the kernel ABI.
//
// It must be the *whole* struct ifreq wide, not just the bytes SIOCETHTOOL
// itself looks at: the kernel's socket-ioctl path copies a full struct ifreq in
// from user space before dispatching on the command, so a short object can be
// read past -- an EFAULT when it happens to sit at the end of a mapping, and
// otherwise a silent read of whatever Go put next to it.
type ifreqData struct {
	name [unix.IFNAMSIZ]byte
	// A distinct pointer-typed field rather than bytes of the union, so the
	// GC still sees the reference (the same reason x/sys/unix keeps its own
	// ifreqData separate from its raw ifreq).
	data unsafe.Pointer
	_    [ifreqUnionPad]byte
}

// ifreqUnionPad is the rest of struct ifreq's union after ifr_data: 16 bytes on
// 64-bit (a 24-byte union, of which the pointer is 8), 12 on 32-bit. Derived
// from x/sys/unix's own per-architecture generated layout -- unsafe.Sizeof is a
// compile-time constant, and unix.Ifreq wraps exactly the raw struct -- rather
// than hard-coded, since the union's width is set by struct ifmap, whose
// unsigned longs make it arch-dependent.
const ifreqUnionPad = unsafe.Sizeof(unix.Ifreq{}) - unix.IFNAMSIZ - unsafe.Sizeof(unsafe.Pointer(nil))

// Compile-time assertion that the padding above really does make ifreqData as
// wide as the kernel's struct ifreq: too narrow and this array length goes
// negative, which does not compile.
var _ [unsafe.Sizeof(ifreqData{}) - unsafe.Sizeof(unix.Ifreq{})]byte

// ioctlEthtool issues SIOCETHTOOL against ifname with cmd as the in/out
// ethtool command block. cmd is written back in place by the kernel.
func ioctlEthtool(fd int, ifname string, cmd []byte) error {
	var ifr ifreqData
	copy(ifr.name[:], ifname)
	ifr.data = unsafe.Pointer(&cmd[0])

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.SIOCETHTOOL), uintptr(unsafe.Pointer(&ifr)))
	// cmd is reachable only through an unsafe.Pointer for the duration of the
	// call, so pin it across the syscall.
	runtime.KeepAlive(cmd)
	if errno != 0 {
		return errno
	}
	return nil
}

// alignedBuf allocates an n-byte buffer guaranteed to be 8-byte aligned, which
// struct ethtool_stats' trailing __u64 array requires and a plain make([]byte)
// does not promise. Allocating []uint64 and viewing it as bytes gets the
// alignment from the element type; the byte slice keeps the allocation alive.
func alignedBuf(n int) []byte {
	words := make([]uint64, (n+7)/8)
	return unsafe.Slice((*byte)(unsafe.Pointer(&words[0])), len(words)*8)[:n]
}

// cstring decodes a fixed-width NUL-padded field (an ETH_GSTRING_LEN name),
// tolerating one that fills the field with no terminator.
func cstring(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// The ethtool ioctl structs are plain host-endian kernel structs, so every
// field is read and written in native byte order (unlike pkg/dhcpv6 and
// friends, whose codecs are on the wire and big-endian). pkg/netlink reaches
// for binary.NativeEndian for the same reason.
func nativeUint32(b []byte) uint32 { return binary.NativeEndian.Uint32(b) }
func nativeUint64(b []byte) uint64 { return binary.NativeEndian.Uint64(b) }

func nativePutUint32(b []byte, v uint32) { binary.NativeEndian.PutUint32(b, v) }
func nativePutUint64(b []byte, v uint64) { binary.NativeEndian.PutUint64(b, v) }

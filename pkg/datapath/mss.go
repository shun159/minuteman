package datapath

// TCPMSSClampAuto asks SetB4Config to derive the clamp from the softwire MTU
// (see autoTCPMSSClamp) and to keep re-deriving it whenever SetSoftwireMTU
// reports a new one. A B4Config.TCPMSSClamp of 0 disables clamping instead,
// and any positive value pins it, immune to a learned path MTU.
const TCPMSSClampAuto = -1

// softwireEncapOverhead is what DS-Lite encapsulation costs a packet: the outer
// IPv6 header (RFC 6333 §5.3's 40 bytes, no extension headers on the unfragmented
// path). It mirrors TUNNEL_L3_OVERHEAD in bpf/datapath.bpf.c.
const softwireEncapOverhead = 40

// tcpMSSOverhead is what the MSS excludes: a 20-byte IPv4 header plus a 20-byte
// TCP header, both option-free. RFC 6691 is explicit that options are *not*
// deducted here -- an endpoint using them shrinks its own segments accordingly --
// so the fixed 40 is right even for a peer that sends timestamps.
const tcpMSSOverhead = 40

// minTCPMSSClamp is the floor below which clamping stops being worth doing:
// 536 is the MSS every IPv4 endpoint must accept without path MTU discovery
// (RFC 1122 §4.2.2.6), and pushing peers below it would cost far more in
// per-segment overhead than the occasional fragmented packet it saves. A
// softwire that narrow leaves the work to the fragmenter instead.
const minTCPMSSClamp = 536

// autoTCPMSSClamp derives the largest MSS that fits the softwire from the MTU
// available to it -- the WAN device's own, or the smaller path MTU learned from
// an ICMPv6 Packet Too Big (see TunnelPMTU). Returns 0 (clamping disabled) for
// an MTU too small to leave a usable MSS.
func autoTCPMSSClamp(softwireMTU int) uint32 {
	mss := softwireMTU - softwireEncapOverhead - tcpMSSOverhead
	if mss < minTCPMSSClamp {
		return 0
	}
	return uint32(mss)
}

// resolveMSSClamp turns the configured policy into the value the datapath
// stores, recording the policy on the Loader so SetSoftwireMTU can re-derive an
// automatic clamp later without the caller restating it.
func (l *Loader) resolveMSSClamp(policy int, softwireMTU int) uint32 {
	l.mssClampAuto = policy == TCPMSSClampAuto
	if l.mssClampAuto {
		return autoTCPMSSClamp(softwireMTU)
	}
	if policy <= 0 {
		return 0
	}
	return uint32(policy)
}

// Package aftrdiscovery implements RFC 6334 AFTR discovery: it uses
// pkg/dhcpv6's stateless DHCPv6 client to fetch OPTION_AFTR_NAME and
// OPTION_DNS_SERVERS, then resolves the AFTR-Name to an IPv6 address via
// DNS, entirely in-process (no external DHCP/DNS client processes).
package aftrdiscovery

import "fmt"

// maxDomainNameLength is RFC 1035 §3.1's domain name size limit, used as a
// defensive bound against a malformed or hostile server.
const maxDomainNameLength = 255

// decodeDNSName decodes data as a single RFC 1035 §3.1 wire-format domain
// name: a sequence of length-prefixed labels terminated by a zero-length
// label. RFC 3315 §8 explicitly disallows DNS name compression (RFC 1035
// §4.1.4) for domain names embedded in DHCPv6 options -- there's no
// enclosing DNS message for a compression pointer to resolve against
// anyway -- so any length byte with its top two bits set (0x40 or above,
// which covers the compression-pointer prefix 11 and the two prefixes 01/10
// that RFC 1035 leaves reserved/undefined) is rejected outright, not
// interpreted.
//
// data must contain exactly one name: the terminating zero-length label
// must consume the buffer exactly, with nothing left over.
func decodeDNSName(data []byte) (string, error) {
	var labels []string
	nameLen := 0
	i := 0
	for {
		if i >= len(data) {
			return "", fmt.Errorf("aftrdiscovery: truncated name, missing terminating zero-length label")
		}
		n := int(data[i])
		if n&0xC0 != 0 {
			return "", fmt.Errorf("aftrdiscovery: invalid label length byte 0x%02x (compression/reserved prefix not allowed)", data[i])
		}
		i++
		if n == 0 {
			break
		}
		if i+n > len(data) {
			return "", fmt.Errorf("aftrdiscovery: label of length %d runs past end of option data", n)
		}
		labels = append(labels, string(data[i:i+n]))
		nameLen += n + 1
		i += n
	}
	if i != len(data) {
		return "", fmt.Errorf("aftrdiscovery: %d trailing byte(s) after terminating label", len(data)-i)
	}
	if nameLen > maxDomainNameLength {
		return "", fmt.Errorf("aftrdiscovery: decoded name exceeds %d octets", maxDomainNameLength)
	}

	name := ""
	for i, l := range labels {
		if i > 0 {
			name += "."
		}
		name += l
	}
	return name, nil
}

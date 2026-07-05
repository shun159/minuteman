package cliconfig

import "net"

// ParseMAC parses a MAC address flag value, treating an empty string as
// "not set" rather than an error.
func ParseMAC(s string) (net.HardwareAddr, error) {
	if s == "" {
		return nil, nil
	}
	return net.ParseMAC(s)
}

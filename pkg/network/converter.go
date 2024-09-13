package network

import "net"

func IntToIP(ip uint32) net.IP {
	return net.IPv4(
		byte(ip>>24), // nolint:mnd
		byte(ip>>16), // nolint:mnd
		byte(ip>>8),  // nolint:mnd
		byte(ip),
	)
}

func Ntohs(val uint16) uint16 {
	return (val<<8)&0xff00 | val>>8 // nolint:mnd
}

func Ntohl(val uint32) uint32 {
	return (val<<24)&0xff000000 | // nolint:mnd
		(val<<8)&0x00ff0000 | // nolint:mnd
		(val>>8)&0x0000ff00 | // nolint:mnd
		(val>>24)&0x000000ff // nolint:mnd
}

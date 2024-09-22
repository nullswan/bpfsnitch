package network

import "net"

const SubnetMask24 = 0xFFFFFF00 // nolint:mnd

func IntToIP(ip uint32) net.IP {
	return net.IPv4(
		byte(ip>>24), // nolint:mnd
		byte(ip>>16), // nolint:mnd
		byte(ip>>8),  // nolint:mnd
		byte(ip),
	)
}

func IntToSubnet(ip uint32, mask uint32) *net.IPNet {
	ipMask := net.IPv4Mask(
		byte(mask>>24),
		byte(mask>>16),
		byte(mask>>8),
		byte(mask),
	)
	maskLength, _ := ipMask.Size() // Get the mask length in bits

	networkPart := ip & (0xFFFFFFFF << (32 - maskLength)) // Keep only the network part
	ipAddr := net.IPv4(
		byte(networkPart>>24),
		byte(networkPart>>16),
		byte(networkPart>>8),
		byte(networkPart),
	)
	return &net.IPNet{
		IP:   ipAddr,
		Mask: ipMask,
	}
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

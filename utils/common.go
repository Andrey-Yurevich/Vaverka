package utils

import (
	"bytes"
	"net"
)

// ResolveHost returns first element of resolved domain. Could be any: v4 or v6
func ResolveHost(s string) (net.IP, error) {
	var ipList []net.IP
	var err error
	ipList, err = net.LookupIP(s)
	if err != nil {
		return nil, err
	}

	// forcibly return first element if no v4 in slice
	return ipList[0], nil
}

func IsIPInRange(startIP, endIP, ipToCheck []byte) bool {

	if endIP == nil && startIP != nil {
		return bytes.Equal(startIP, ipToCheck)
	}

	if startIP == nil && endIP != nil {
		return bytes.Equal(endIP, ipToCheck)
	}

	return bytes.Compare(ipToCheck, startIP) >= 0 && bytes.Compare(ipToCheck, endIP) <= 0
}

func IPtoIPNet(address net.IP) net.IPNet {
	if address.To4() != nil {
		return net.IPNet{IP: address, Mask: net.IPMask{255, 255, 255, 255}}
	}

	return net.IPNet{IP: address, Mask: net.IPMask{
		255, 255, 255, 255,
		255, 255, 255, 255,
		255, 255, 255, 255,
		255, 255, 255, 255}}
}

func Htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

// MaxIP returns the "greater" of two IP addresses in byte-order comparison.
func MaxIP(a, b net.IP) net.IP {

	if a == nil && b != nil {
		return b
	}

	if b == nil && a != nil {
		return a
	}

	if bytes.Compare(a, b) > 0 {
		return a
	}
	return b
}

// MinIP returns the "smaller" of two IP addresses in byte-order comparison.
func MinIP(a, b net.IP) net.IP {

	if a == nil && b != nil {
		return b
	}

	if b == nil && a != nil {
		return a
	}

	if bytes.Compare(a, b) < 0 {
		return a
	}
	return b
}

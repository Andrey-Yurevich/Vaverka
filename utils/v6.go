package utils

import (
	"bytes"
	"net"
	"syscall"

	"github.com/vishvananda/netlink"
)

func LastIPv6(network *net.IPNet) net.IP {
	ip := network.IP.To16()
	if ip == nil {
		return nil
	}

	last := make(net.IP, len(ip))
	copy(last, ip)

	for i := range ip {
		last[i] |= ^network.Mask[i]
	}
	return last
}

func GetSocketV6() (uintptr, error) {
	var sock int
	var err error
	sock, err = syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(Htons(syscall.ETH_P_IPV6)))
	return uintptr(sock), err
}

// GetDefaultV6Gateway retrieves the default gateway for IPv6.
// It lists all routes and returns the gateway from the route with a nil destination (default route).
func GetDefaultV6Gateway() (net.IP, error) {
	var ones, bits int

	// List all IPv6 routes.
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V6)
	if err != nil {
		return nil, err
	}

	// Iterate over the routes to find the default route.
	for _, route := range routes {
		// A nil destination indicates a default route.
		if route.Dst == nil {
			// If a gateway is set, return it.
			if route.Gw != nil {
				return route.Gw, nil
			}
		}

		if bytes.Equal(route.Dst.IP.To16(), net.IP{0, 0, 0, 0,
			0, 0, 0, 0,
			0, 0, 0, 0,
			0, 0, 0, 0}) {

			ones, bits = route.Dst.Mask.Size()

			if ones == 0 && bits == 128 && route.Gw != nil {
				return route.Gw, nil
			}
		}
	}

	return nil, nil
}

func PreviousIPv6(ip net.IP) net.IP {
	ip = ip.To16()
	prev := make(net.IP, len(ip))
	copy(prev, ip)
	for i := len(prev) - 1; i >= 0; i-- {
		if prev[i] == 0 {
			prev[i] = 255
		} else {
			prev[i]--
			break
		}
	}
	return prev
}

func NextIPv6(ip net.IP) net.IP {
	ip = ip.To16()
	next := make(net.IP, len(ip))

	copy(next, ip)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
	}
	return next
}

func ContainsSubnetV6(super, sub *net.IPNet) bool {
	return super.Contains(sub.IP) && super.Contains(LastIPv4(sub))
}

func GetHardwareAddrFromNeighborCache(ip net.IP) (net.HardwareAddr, error) {
	// TODO: netlink NEIGH lookup.
	return nil, nil
}

func IPv6RangeBytesChunks(startIP, endIP net.IP, shuffle bool) <-chan [][]byte {
	// TODO: real iterator.
	ch := make(chan [][]byte)
	close(ch)
	return ch
}

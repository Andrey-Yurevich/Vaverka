package utils

import (
	"bytes"
	"fmt"
	"math/rand"
	"net"
	"syscall"
	"time"

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

func IPv6RangeBytesChunks(startIP, endIP net.IP, shuffle bool) <-chan [][]byte {
	// TODO: real iterator.
	ch := make(chan [][]byte)
	close(ch)
	return ch
}

func GetHardwareAddrFromNeighborCache(ifIndex int, ip net.IP) (net.HardwareAddr, error) {

	const validStates = netlink.NUD_REACHABLE | // 0x02
		netlink.NUD_STALE | // 0x04
		netlink.NUD_PERMANENT // 0x80

	if ip.To4() != nil {
		return nil, fmt.Errorf("IPv4 not supported")
	}

	if ip.To16() == nil {
		return nil, fmt.Errorf("invalid IPv6 format")
	}

	list, err := netlink.NeighList(ifIndex, netlink.FAMILY_V6)
	if err != nil {
		return nil, err
	}

	for i := 0; i < len(list); i++ {
		if list[i].IP.Equal(ip) && list[i].State&validStates != 0 && len(list[i].HardwareAddr) > 0 {
			return list[i].HardwareAddr, nil
		}
	}
	return nil, nil
}

// GetRemoteMacAddrSingleV6HostWithWarmUp This function is used when there’s no MAC address entry for the host in the kernel cache.
// In such cases, an empty UDP packet is sent to “warm up” the system so that it performs neighbor discovery and stores the MAC in the kernel cache.
// This approach saves a lot of time and lines of code.
func GetRemoteMacAddrSingleV6HostWithWarmUp(sourceInterface int, sourceIP, remoteIP net.IP) (net.HardwareAddr, error) {
	sourcePort := 49152 + rand.Intn(65535-49152+1)
	conn, err := net.DialUDP("udp6", &net.UDPAddr{IP: sourceIP, Port: sourcePort}, &net.UDPAddr{IP: remoteIP, Port: 0})
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write([]byte{0}); err != nil {
		return nil, fmt.Errorf("failed to send dummy udp packet: %w", err)
	}
	time.Sleep(50 * time.Millisecond)
	MacAddress, err := GetHardwareAddrFromNeighborCache(sourceInterface, remoteIP)

	return MacAddress, err
}

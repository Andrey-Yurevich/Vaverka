package utils

import (
	"Vaverka/constants"
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
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

// IPv6RangeBytesChunks returns a channel that yields chunks of IPv6 addresses in [16]uint8 form.
func IPv6RangeBytesChunks(startIP, endIP net.IP, shuffle bool) <-chan [][16]uint8 {
	const maxChunks = 16

	// Special case: if endIP is nil, return a chunk containing only startIP.
	if endIP == nil && startIP != nil {
		ch := make(chan [][16]uint8, 1)
		ip16 := startIP.To16()
		if ip16 != nil {
			var single [16]uint8
			copy(single[:], ip16)
			ch <- [][16]uint8{single}
		}
		close(ch)
		return ch
	}

	// Normalize start and end IPs to 16-byte form.
	start := MinIP(startIP, endIP).To16()
	end := MaxIP(startIP, endIP).To16()

	// If either IP is invalid, return an empty channel.
	if start == nil || end == nil {
		ch := make(chan [][16]uint8)
		close(ch)
		return ch
	}

	// Split the 128-bit addresses into two uint64 words (big-endian).
	startHi := binary.BigEndian.Uint64(start[0:8])
	startLo := binary.BigEndian.Uint64(start[8:16])
	endHi := binary.BigEndian.Uint64(end[0:8])
	endLo := binary.BigEndian.Uint64(end[8:16])

	// Create a buffered channel to limit memory usage.
	ch := make(chan [][16]uint8, maxChunks)

	go func() {
		defer close(ch)

		// Initialize 128-bit cursor hi:lo.
		hi, lo := startHi, startLo

		// Preallocate a staging buffer to the maximum chunk size.
		var buf [constants.IOVecPacketsChunkSize][16]uint8

	Outer:
		// Continue until cursor exceeds the end address.
		for hi < endHi || (hi == endHi && lo <= endLo) {
			n := 0
			done := false

			// Fill the staging buffer up to the chunk size.
			for ; n < constants.IOVecPacketsChunkSize; n++ {
				// Write the high and low words in big-endian order.
				binary.BigEndian.PutUint64(buf[n][0:8], hi)
				binary.BigEndian.PutUint64(buf[n][8:16], lo)

				// Check if this was the last address in the range.
				if hi == endHi && lo == endLo {
					done = true
					n++   // include this address in the chunk
					break // exit inner loop
				}

				// Increment the 128-bit counter (lo++; carry to hi on overflow).
				lo++
				if lo == 0 {
					hi++
				}
			}

			// Slice out exactly n entries and send the chunk.
			chunk := make([][16]uint8, n)
			copy(chunk, buf[:n])

			if shuffle {
				rand.Shuffle(len(chunk), func(i, j int) {
					chunk[i], chunk[j] = chunk[j], chunk[i]
				})
			}

			ch <- chunk

			// If we have sent the last address, break out of both loops.
			if done {
				break Outer
			}
		}
	}()

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

func isSolicitedNodeMulticast(ip net.IP) bool {
	ip = ip.To16()
	if ip == nil || !ip.IsMulticast() {
		return false
	}
	// префикс ff02::1:ff/104
	prefix := net.ParseIP("ff02::1:ff00:0").To16()
	mask := net.CIDRMask(104, 128)
	return ip.Mask(mask).Equal(prefix)
}

func Ipv6MulticastAddresses(iface *net.Interface) ([]net.IP, error) {
	var v6McastAddrs []net.IP
	var ipAddr net.IP
	v6McastAddrs = make([]net.IP, 0)
	allMcastAddrs, err := iface.MulticastAddrs()

	if err != nil {
		return nil, err
	}

	for _, addr := range allMcastAddrs {
		ipAddr = net.ParseIP(addr.String())
		if ipAddr.To16() != nil && ipAddr.To4() == nil {

			if isSolicitedNodeMulticast(ipAddr) {
				continue
			}

			v6McastAddrs = append(v6McastAddrs, ipAddr)
		}
	}
	return v6McastAddrs, nil
}

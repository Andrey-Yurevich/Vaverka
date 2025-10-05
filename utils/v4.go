package utils

import (
	"Vaverka/constants"
	"bufio"
	"bytes"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink"
)

func GetSocketV4() (uintptr, error) {
	var sock int
	var err error
	sock, err = syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(Htons(syscall.ETH_P_IP)))
	return uintptr(sock), err
}

func PreviousIPv4(ip net.IP) net.IP {
	ip = ip.To4()
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

func NextIPv4(ip net.IP) net.IP {
	ip = ip.To4()
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

func LastIPv4(network *net.IPNet) net.IP {
	ip := network.IP.To4()
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

func ContainsSubnetV4(super, sub *net.IPNet) bool {
	return super.Contains(sub.IP) && super.Contains(LastIPv4(sub))
}

// GetHardwareAddrFromARPTable searches the ARP table for a record matching the given IP
// and returns the corresponding HardwareAddr.
func GetHardwareAddrFromARPTable(ip net.IP) (net.HardwareAddr, error) {
	// Convert IP to string for comparison with entries in the file.
	var hwAddr net.HardwareAddr
	var targetIpString string
	var scanner *bufio.Scanner
	var file *os.File
	var err error
	var arpTablePath string
	arpTablePath = "/proc/net/arp"
	targetIpString = ip.String()

	file, err = os.Open(arpTablePath)
	if err != nil {
		return nil, err
	}

	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	scanner = bufio.NewScanner(file)

	// Skip the header line.
	if !scanner.Scan() {
		return nil, fmt.Errorf("failed to read %s", arpTablePath)
	}

	// Read the file line by line and look for a record with the target IP.
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue // skip malformed lines
		}

		// fields[0] is the IP address, fields[3] is the MAC address.
		if fields[0] == targetIpString {
			hwAddr, err = net.ParseMAC(fields[3])
			if err != nil {
				return nil, err
			}
			return hwAddr, nil
		}
	}

	if err = scanner.Err(); err != nil {
		return nil, err
	}

	// If no record is found for the IP, return nil, nil.
	return nil, nil
}

func ipv4ToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	return (uint32(ip4[0]) << 24) | (uint32(ip4[1]) << 16) |
		(uint32(ip4[2]) << 8) | uint32(ip4[3])
}

// IPv4RangeBytesChunks returns a channel that yields chunks of IPv4 addresses in [4]uint8 form.
func IPv4RangeBytesChunks(startIP, endIP net.IP, shuffle bool) <-chan [][4]uint8 {
	const maxChunks int = 16

	// Special case: if endIP is nil, return a chunk containing only startIP.
	if endIP == nil && startIP != nil {
		ch := make(chan [][4]uint8, 1)
		// Create a chunk with a single IP address.
		chunk := [][4]uint8{{startIP.To4()[0], startIP.To4()[1], startIP.To4()[2], startIP.To4()[3]}}
		ch <- chunk
		close(ch)
		return ch
	}

	start := MinIP(startIP, endIP).To4()
	end := MaxIP(startIP, endIP).To4()

	// If not valid IPv4 addresses, return an empty channel.
	if start == nil || end == nil {
		ch := make(chan [][4]uint8)
		close(ch)
		return ch
	}

	// Use uint64 to avoid overflow when calculating the full range.
	startNum := uint64(ipv4ToUint32(start))
	endNum := uint64(ipv4ToUint32(end))

	// Channel capacity is limited to avoid high memory usage with large ranges.
	ch := make(chan [][4]uint8, maxChunks)

	go func() {
		defer close(ch)

		// Declare all loop variables once.
		var (
			current   = startNum
			remain    uint64
			chunkSize int
		)
		// Preallocate a buffer for the maximum possible chunk size.
		var buf [constants.IOVecPacketsChunkSize][4]uint8

		for current <= endNum {
			remain = endNum - current + 1
			if remain > uint64(constants.IOVecPacketsChunkSize) {
				chunkSize = constants.IOVecPacketsChunkSize
			} else {
				chunkSize = int(remain)
			}

			// Fill the preallocated buffer with IP addresses.
			for i := 0; i < chunkSize; i++ {
				buf[i][0] = byte(current >> 24)
				buf[i][1] = byte(current >> 16)
				buf[i][2] = byte(current >> 8)
				buf[i][3] = byte(current)
				current++
			}

			// Создаем новый срез нужного размера и копируем в него данные из buf.
			chunk := make([][4]uint8, chunkSize)
			copy(chunk, buf[:chunkSize])

			if shuffle {
				rand.Shuffle(len(chunk), func(i, j int) {
					chunk[i], chunk[j] = chunk[j], chunk[i]
				})
			}
			ch <- chunk
		}
	}()

	return ch
}

// GetDefaultV4Gateway retrieves the default gateway for IPv4.
// It lists all routes and returns the gateway from the route with a nil destination (default route).
func GetDefaultV4Gateway() (net.IP, error) {
	var ones, bits int

	// List all IPv4 routes.
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
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

		if bytes.Equal(route.Dst.IP.To4(), net.IP{0, 0, 0, 0}) {

			ones, bits = route.Dst.Mask.Size()

			if ones == 0 && bits == 32 && route.Gw != nil {
				return route.Gw, nil
			}
		}
	}

	return nil, nil
}

func IsV4NetworkAddress(ip net.IP, routes []netlink.Route) bool {
	for _, route := range routes {
		switch {
		case route.Dst != nil && route.Dst.IP.Equal(ip):
			return true
		case ip[3] == 0:
			return true
		}
	}
	return false
}

func IsSingleV4HostMask(mask net.IPMask) bool {
	if mask[0] == 255 && mask[1] == 255 && mask[2] == 255 && mask[3] == 255 {
		return true
	}
	return false
}

func IsV4BroadcastAddress(ip net.IP, routes []netlink.Route) bool {
	for _, route := range routes {
		if route.Dst != nil {
			ones, bits := route.Dst.Mask.Size()
			if ones < bits-1 {
				lastIP := LastIPv4(route.Dst)
				if lastIP.Equal(ip) {
					return true
				}
			}
		}
	}
	return false
}

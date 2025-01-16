package utils

import (
	"Vaverka/constants"
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
)

//func IsValidFQDN(s string) bool {
//	// Regular expression to validate domain name
//	regex := `^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`
//	match, _ := regexp.MatchString(regex, s)
//	return match
//}

func ResolveHost(s string) (net.IP, error) {
	var ipList []net.IP
	var err error
	ipList, err = net.LookupIP(s)
	if err != nil {
		return net.IP{}, err
	} else {
		return ipList[0], nil
	}

}

func IPtoIPNet(address net.IP) net.IPNet {
	if address.To4() != nil {
		return net.IPNet{IP: address, Mask: net.IPMask{255, 255, 255, 255}}
	} else {
		return net.IPNet{IP: address, Mask: net.IPMask{
			255, 255, 255, 255,
			255, 255, 255, 255,
			255, 255, 255, 255,
			255, 255, 255, 255}}
	}
}

func Htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func GetSocket() (int, error) {
	return syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(Htons(syscall.ETH_P_IP)))
}

func IncIPv4Bytes(ip [4]uint8, n uint) [4]uint8 {
	var ipBytes [4]uint8
	var v uint
	v = uint(ip[0])<<24 + uint(ip[1])<<16 + uint(ip[2])<<8 + uint(ip[3])
	v += n

	ipBytes[3] = byte(v & 0xFF)
	ipBytes[2] = byte((v >> 8) & 0xFF)
	ipBytes[1] = byte((v >> 16) & 0xFF)
	ipBytes[0] = byte((v >> 24) & 0xFF)

	return ipBytes
}

func PreviousIP(ip net.IP) net.IP {
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

// NextIPv4Bytes increments an IPv4 address by 1
func NextIPv4Bytes(ip [4]uint8) [4]uint8 {
	var ipBytes [4]uint8
	var v uint
	v = uint(ip[0])<<24 + uint(ip[1])<<16 + uint(ip[2])<<8 + uint(ip[3])
	v += 1

	ipBytes[3] = byte(v & 0xFF)
	ipBytes[2] = byte((v >> 8) & 0xFF)
	ipBytes[1] = byte((v >> 16) & 0xFF)
	ipBytes[0] = byte((v >> 24) & 0xFF)
	return ipBytes
}

func LastIP(network *net.IPNet) net.IP {
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

func ContainsSubnet(super, sub *net.IPNet) bool {
	return super.Contains(sub.IP) && super.Contains(LastIP(sub))
}

func IterateIpRangeChunksBytes(startIP, endIP net.IP) [][constants.IOVecPacketsChunkSize][4]uint8 {
	// Convert starting and ending IPs to byte arrays
	startBytes := [4]uint8(startIP.To4())
	endBytes := [4]uint8(endIP.To4())

	// Convert startBytes and endBytes to their integer representation for easier comparison
	startInt := uint32(startBytes[0])<<24 | uint32(startBytes[1])<<16 | uint32(startBytes[2])<<8 | uint32(startBytes[3])
	endInt := uint32(endBytes[0])<<24 | uint32(endBytes[1])<<16 | uint32(endBytes[2])<<8 | uint32(endBytes[3])

	// Calculate the total number of IP addresses and estimate the number of chunks needed
	totalAddresses := endInt - startInt + 1
	chunkSize := constants.IOVecPacketsChunkSize
	numChunks := (totalAddresses + uint32(chunkSize) - 1) / uint32(chunkSize)

	// Initialize a slice to hold all chunks
	chunks := make([][constants.IOVecPacketsChunkSize][4]uint8, 0, numChunks)

	chunkStartIPBytes := startBytes

	for {
		// Convert the current start IP to an integer
		chunkStartInt := uint32(chunkStartIPBytes[0])<<24 | uint32(chunkStartIPBytes[1])<<16 |
			uint32(chunkStartIPBytes[2])<<8 | uint32(chunkStartIPBytes[3])
		if chunkStartInt > endInt {
			break
		}

		// Determine the tentative end of the block containing chunkSize addresses
		chunkEndIPBytes := IncIPv4Bytes(chunkStartIPBytes, uint(chunkSize-1))
		chunkEndInt := uint32(chunkEndIPBytes[0])<<24 | uint32(chunkEndIPBytes[1])<<16 |
			uint32(chunkEndIPBytes[2])<<8 | uint32(chunkEndIPBytes[3])
		// Adjust the tentative end if it exceeds the actual end IP
		if chunkEndInt > endInt {
			chunkEndIPBytes = endBytes
		}

		var addrRange [constants.IOVecPacketsChunkSize][4]uint8
		var currentIPIndex uint
		tempAddr := chunkStartIPBytes

		// Fill the current chunk with IP addresses from chunkStartIPBytes to chunkEndIPBytes
		for {
			addrRange[currentIPIndex] = tempAddr
			currentIPIndex++
			if tempAddr == chunkEndIPBytes {
				break
			}
			if currentIPIndex == constants.IOVecPacketsChunkSize {
				break
			}
			tempAddr = NextIPv4Bytes(tempAddr)
		}

		// Append the filled chunk to the slice
		chunks = append(chunks, addrRange)

		// If we've reached the end of the range, exit the loop
		if chunkEndIPBytes == endBytes {
			break
		}

		// Prepare for the next block: increment the starting IP
		chunkStartIPBytes = IncIPv4Bytes(chunkEndIPBytes, 1)
	}

	return chunks
}

// GetHardwareAddrFromARP searches the ARP table for a record matching the given IP
// and returns the corresponding HardwareAddr.
func GetHardwareAddrFromARP(ip net.IP) (net.HardwareAddr, error) {
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

// MaxIP returns the "greater" of two IP addresses in byte-order comparison.
func MaxIP(a, b net.IP) net.IP {
	if bytes.Compare(a, b) > 0 {
		return a
	}
	return b
}

// MinIP returns the "smaller" of two IP addresses in byte-order comparison.
func MinIP(a, b net.IP) net.IP {
	if bytes.Compare(a, b) < 0 {
		return a
	}
	return b
}

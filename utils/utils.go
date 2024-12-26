package utils

import (
	"Vaverka/constants"
	"fmt"
	"net"
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

func NextIPv4(ip net.IP) net.IP {
	i := ip.To4()
	v := uint(i[0])<<24 + uint(i[1])<<16 + uint(i[2])<<8 + uint(i[3])
	v += 1
	v3 := byte(v & 0xFF)
	v2 := byte((v >> 8) & 0xFF)
	v1 := byte((v >> 16) & 0xFF)
	v0 := byte((v >> 24) & 0xFF)
	return net.IPv4(v0, v1, v2, v3)
}

func IncIPv4(ip net.IP, n uint) net.IP {
	i := ip.To4()
	v := uint(i[0])<<24 + uint(i[1])<<16 + uint(i[2])<<8 + uint(i[3])
	v += n
	v3 := byte(v & 0xFF)
	v2 := byte((v >> 8) & 0xFF)
	v1 := byte((v >> 16) & 0xFF)
	v0 := byte((v >> 24) & 0xFF)
	return net.IPv4(v0, v1, v2, v3)
}

func Htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func GetSocketParameters(sourceInterface *net.Interface) syscall.RawSockaddrLinklayer {
	return syscall.RawSockaddrLinklayer{
		Family:   syscall.AF_PACKET,
		Protocol: Htons(syscall.ETH_P_IP),
		Ifindex:  int32(sourceInterface.Index),
	}
}

func GetSocket() (int, error) {
	return syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(Htons(syscall.ETH_P_IP)))

}

func GetNetAddrBySrcIP(srcIp net.IP) (*net.IPNet, error) {
	var interfacesAddresses []net.Addr
	var network *net.IPNet
	var err error

	interfacesAddresses, err = net.InterfaceAddrs()

	if err != nil {
		panic(err)
	}

	for _, address := range interfacesAddresses {
		_, network, err = net.ParseCIDR(address.String())
		if err != nil {
			return nil, err
		}
		if network.Contains(srcIp) {
			return network, nil
		}
	}
	return nil, nil
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

// ContainsBytes checks if 'ip' is inside the network defined by 'network' and 'mask'
func ContainsBytes(network, mask, ip [4]uint8) bool {
	for i := 0; i < 4; i++ {
		if (ip[i] & mask[i]) != (network[i] & mask[i]) {
			return false
		}
	}
	return true
}

// maskTo4Bytes converts a net.IPMask to [4]uint8 (assuming IPv4)
func maskTo4Bytes(netmask net.IPMask) ([4]uint8, error) {
	ip4 := net.IP(netmask).To4()
	if ip4 == nil {
		return [4]uint8{}, fmt.Errorf("not an IPv4 mask")
	}
	var arr [4]uint8
	copy(arr[:], ip4)
	return arr, nil
}

// IterateSubnetBlocksBytes generates chunks of IPv4 addresses (size = constants.IOvecPacketsChunkSize) within the given net.IPNet.
// It returns a channel of arrays [constants.IOvecPacketsChunkSize][4]uint8, each representing a block of IPs.
func IterateSubnetBlocksBytes(networkAddress net.IPNet) <-chan [constants.IOvecPacketsChunkSize][4]uint8 {
	var (
		chunkStartIPBytes [4]uint8
		chunkEndIPBytes   [4]uint8
		networkIPBytes    [4]uint8
		networkMask       [4]uint8
		err               error
	)

	// Create a channel to emit blocks
	ch := make(chan [constants.IOvecPacketsChunkSize][4]uint8)

	// Convert net.IP to [4]uint8
	networkIPBytes = [4]uint8(networkAddress.IP.To4())

	// Convert net.IPMask to [4]uint8
	networkMask, err = maskTo4Bytes(networkAddress.Mask)
	if err != nil {
		panic(err)
	}

	go func() {
		defer close(ch)

		// Start iterating blocks from the network base address
		for chunkStartIPBytes = networkIPBytes; ContainsBytes(networkIPBytes, networkMask, chunkStartIPBytes); chunkStartIPBytes = IncIPv4Bytes(chunkStartIPBytes, constants.IOvecPacketsChunkSize) {
			// We consider chunkEndIP to be inclusive: chunkStartIP + (chunkSize - 1)
			chunkEndIPBytes = IncIPv4Bytes(chunkStartIPBytes, constants.IOvecPacketsChunkSize-1)

			// If chunkEndIP is out of the subnet, we "trim" it to the last valid IP in this subnet
			if !ContainsBytes(networkIPBytes, networkMask, chunkEndIPBytes) {
				var temp = chunkStartIPBytes
				// Move forward until the next address is not in the subnet
				for ContainsBytes(networkIPBytes, networkMask, IncIPv4Bytes(temp, 1)) {
					temp = IncIPv4Bytes(temp, 1)
				}
				chunkEndIPBytes = temp
			}

			// Create an array to hold the block of addresses
			var addrRange [constants.IOvecPacketsChunkSize][4]uint8
			var currentIPIndex uint

			// Iterate from chunkStartIP up to and including chunkEndIP
			for addr := chunkStartIPBytes; ; addr = NextIPv4Bytes(addr) {
				addrRange[currentIPIndex] = addr
				currentIPIndex++
				if addr == chunkEndIPBytes {
					break
				}
				// Safety check: if we somehow exceed the array bounds, break
				if currentIPIndex == constants.IOvecPacketsChunkSize {
					break
				}
			}

			ch <- addrRange

			// If we ended up trimming the block to the last valid IP in the subnet, no more blocks are possible
			// so we break out of the loop
			if !ContainsBytes(networkIPBytes, networkMask, IncIPv4Bytes(chunkEndIPBytes, 1)) {
				break
			}
		}
	}()

	return ch
}

package utils

import (
	"Vaverka/constants"
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

func Htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func GetSocket() (int, error) {
	return syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(Htons(syscall.ETH_P_IP)))
}

// Will be used later
//func GetNetAddrBySrcIP(srcIp net.IP) (*net.IPNet, error) {
//	var interfacesAddresses []net.Addr
//	var network *net.IPNet
//	var err error
//
//	interfacesAddresses, err = net.InterfaceAddrs()
//
//	if err != nil {
//		panic(err)
//	}
//
//	for _, address := range interfacesAddresses {
//		_, network, err = net.ParseCIDR(address.String())
//		if err != nil {
//			return nil, err
//		}
//		if network.Contains(srcIp) {
//			return network, nil
//		}
//	}
//	return nil, nil
//}

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

func СontainsSubnet(super, sub *net.IPNet) bool {
	return super.Contains(sub.IP) && super.Contains(LastIP(sub))
}

func IterateIpRangeChunksBytes(startIP, endIP net.IP) <-chan [constants.IOVecPacketsChunkSize][4]uint8 {
	ch := make(chan [constants.IOVecPacketsChunkSize][4]uint8)
	startBytes := [4]uint8(startIP.To4())
	endBytes := [4]uint8(endIP.To4())

	go func() {
		defer close(ch)

		chunkStartIPBytes := startBytes

		for {
			// Compare current start IP with the end IP of the range.
			chunkStartInt := uint32(chunkStartIPBytes[0])<<24 | uint32(chunkStartIPBytes[1])<<16 |
				uint32(chunkStartIPBytes[2])<<8 | uint32(chunkStartIPBytes[3])
			endInt := uint32(endBytes[0])<<24 | uint32(endBytes[1])<<16 |
				uint32(endBytes[2])<<8 | uint32(endBytes[3])
			if chunkStartInt > endInt {
				break
			}

			// Determine the tentative end of the block of 64 addresses.
			chunkEndIPBytes := IncIPv4Bytes(chunkStartIPBytes, constants.IOVecPacketsChunkSize-1)
			chunkEndInt := uint32(chunkEndIPBytes[0])<<24 | uint32(chunkEndIPBytes[1])<<16 |
				uint32(chunkEndIPBytes[2])<<8 | uint32(chunkEndIPBytes[3])
			// If the tentative end exceeds the range, adjust it.
			if chunkEndInt > endInt {
				chunkEndIPBytes = endBytes
			}

			var addrRange [constants.IOVecPacketsChunkSize][4]uint8
			var currentIPIndex uint
			tempAddr := chunkStartIPBytes

			// Fill the block with addresses from the current start-up to the calculated end.
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

			// Send the filled block to the channel.
			ch <- addrRange

			// If the end of the range has been reached, exit the loop.
			if chunkEndIPBytes == endBytes {
				break
			}

			// Prepare the start for the next block.
			chunkStartIPBytes = IncIPv4Bytes(chunkEndIPBytes, 1)
		}
	}()

	return ch
}

package scanner

import (
	"Vaverka/constants"
	"Vaverka/router"
	"Vaverka/rule"
	"Vaverka/utils"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// arpScan sends ARP requests for each IP address in the subnet and waits for replies.
func arpScan(c *scannerContext, r *router.IpRangeRouteContext, arpWg *sync.WaitGroup) {

	defer close(r.ReadyToInterceptChan)
	defer arpWg.Done()

	var messageHeaders [constants.IOVecPacketsChunkSize]Mmsghdr
	var ethernetAndArpHeadersTemplate [constants.ArpAndEthernetHeadersSize]byte
	var arpPacketBodyTemplate [constants.ArpPacketPayloadBodySize]byte
	var rawArpPacketBodies [constants.IOVecPacketsChunkSize][20]byte
	var ioVectors [constants.IOVecPacketsChunkSize][3]syscall.Iovec

	arpWg.Add(1)
	go interceptArpPackets(c, r, arpWg)

	<-r.ReadyToInterceptChan

	ethernetAndArpHeadersTemplate = prepareArpAndEthernetHeadersTemplate(r.SocketParameters.SourceInterface.HardwareAddr)
	arpPacketBodyTemplate = prepareArpPacketBodyTemplate(r.SocketParameters.SourceInterface.HardwareAddr, r.Route.Src)

	for _, ipChunk := range utils.IterateIpRangeChunksBytes(r.Start, r.End) {
		for i := range ipChunk {

			rawArpPacketBodies[i] = arpPacketBodyTemplate
			copy(rawArpPacketBodies[i][16:], ipChunk[i][:])

			ioVectors[i][0] = syscall.Iovec{
				Base: &ethernetAndArpHeadersTemplate[0],
				Len:  22,
			}

			ioVectors[i][1] = syscall.Iovec{
				Base: &rawArpPacketBodies[i][0],
				Len:  20,
			}

			ioVectors[i][2] = syscall.Iovec{
				Base: &constants.ArpPacketPaddingPart[0],
				Len:  18,
			}

			messageHeaders[i].Msg = syscall.Msghdr{
				Name:    r.SocketParameters.SocketAddressName,
				Namelen: r.SocketParameters.SocketAddressNameLen,
				Iov:     &ioVectors[i][0],
				Iovlen:  3,
			}
		}
		if err := Limiter.Wait(context.Background()); err != nil {
			c.errorChan <- err
			return
		}
		_, _, errno := syscall.RawSyscall(
			constants.SendMmsgSyscallIndex, // Syscall number for sendmmsg on some architectures
			uintptr(c.socketFD),
			uintptr(unsafe.Pointer(&messageHeaders[0])),
			uintptr(len(messageHeaders)),
		)

		if errno != 0 {
			c.errorChan <- errno
		}
	}
	// Pause to give hosts time to respond to ARP requests
	time.Sleep(constants.DefaultTimeout)
	r.DoneChan <- true
}

func pingScan(c *scannerContext, r *router.IpRangeRouteContext, gatewayMac net.HardwareAddr, pingWg *sync.WaitGroup) {
	//defer fmt.Println("DEBUG: pingScan is done")
	defer close(r.ReadyToInterceptChan)
	defer pingWg.Done()

	// Prepare slices of structures for the sendmmsg syscall
	var messageHeaders [constants.IOVecPacketsChunkSize]Mmsghdr
	var rawICMPPacketsIpPart [constants.IOVecPacketsChunkSize][constants.ICMPPacketIPPartSize]byte
	var ioVectors [constants.IOVecPacketsChunkSize][3]syscall.Iovec
	var IcmpPacketEthernetPart [constants.ICMPPacketEthernetPartSize]byte
	var IcmpPacketIpPart [constants.ICMPPacketIPPartSize]byte

	pingWg.Add(1)
	go interceptPingPackets(c, r, pingWg)

	<-r.ReadyToInterceptChan

	IcmpPacketEthernetPart = prepareIcmpPacketEthernetPart(r.SocketParameters.SourceInterface.HardwareAddr, gatewayMac)
	IcmpPacketIpPart = prepareIcmpPacketIpPartTemplate(r.Route.Src)

	for _, ipChunk := range utils.IterateIpRangeChunksBytes(r.Start, r.End) {
		for i := range ipChunk {
			rawICMPPacketsIpPart[i] = IcmpPacketIpPart
			copy(rawICMPPacketsIpPart[i][16:], ipChunk[i][:])

			var sum uint32
			// Calculate sum over IP header from byte 14 to 33 (inclusive)
			for j := 0; j < constants.ICMPPacketIPPartSize; j += 2 {
				// Sum 16-bit words formed by adjacent bytes
				sum += uint32(rawICMPPacketsIpPart[i][j])<<8 | uint32(rawICMPPacketsIpPart[i][j+1])
			}

			// Add carries from top 16 bits into lower 16 bits
			sum = (sum & 0xFFFF) + (sum >> 16)
			sum = (sum & 0xFFFF) + (sum >> 16)

			// Write one's complement of sum into IP checksum field at bytes 24 and 25 in big-endian format
			binary.BigEndian.PutUint16(rawICMPPacketsIpPart[i][10:12], ^uint16(sum))

			// Proceed with setting up iovec and message headers
			ioVectors[i][0] = syscall.Iovec{
				Base: &IcmpPacketEthernetPart[0],
				Len:  constants.ICMPPacketEthernetPartSize,
			}

			ioVectors[i][1] = syscall.Iovec{
				Base: &rawICMPPacketsIpPart[i][0],
				Len:  constants.ICMPPacketIPPartSize,
			}

			ioVectors[i][2] = syscall.Iovec{
				Base: &constants.ICMPPacketICMPPartAndPadding[0],
				Len:  constants.ICMPPacketICMPPartAndPaddingSize,
			}

			messageHeaders[i].Msg = syscall.Msghdr{
				Name:    r.SocketParameters.SocketAddressName,
				Namelen: r.SocketParameters.SocketAddressNameLen,
				Iov:     &ioVectors[i][0],
				Iovlen:  3,
			}

		}
		if err := Limiter.Wait(context.Background()); err != nil {
			c.errorChan <- err
			return
		}
		_, _, errno := syscall.RawSyscall(
			constants.SendMmsgSyscallIndex, // Syscall number for sendmmsg on some architectures
			uintptr(c.socketFD),
			uintptr(unsafe.Pointer(&messageHeaders[0])),
			uintptr(len(messageHeaders)),
		)
		
		if errno != 0 {
			c.errorChan <- errno
		}
	}
	// Pause to give hosts time to respond to Ping requests
	time.Sleep(constants.DefaultTimeout)
	r.DoneChan <- true
}

// scanOverGateway is a placeholder for scanning through a gateway.
func scanOverGateway(c *scannerContext, r *router.IpRangeRouteContext, IpRangeScannerWg *sync.WaitGroup) {

	defer IpRangeScannerWg.Done()
	var pingWg sync.WaitGroup
	var gatewayMacAddress net.HardwareAddr
	var err error
	// Trying to get Mac address from arp table
	gatewayMacAddress, err = utils.GetHardwareAddrFromARP(r.Route.Gw)

	if err != nil {
		c.errorChan <- err
		return
	}

	if gatewayMacAddress == nil {
		// Getting from remote
		gatewayMacAddress, err = GetRemoteMacAddrSingleHost(r.Route.Src, r.Route.Gw, r.SocketParameters.SourceInterface)

		if err != nil {
			c.errorChan <- err
			return
		}

		if gatewayMacAddress == nil {
			c.errorChan <- fmt.Errorf("cannot find gateway mac for %s", r.Route.Gw)
			return
		}

	}

	pingWg.Add(1)
	go pingScan(c, r, gatewayMacAddress, &pingWg)
	pingWg.Wait()
}

// scanPointToPoint performs point-to-point scanning within a single subnet.
func scanPointToPoint(c *scannerContext, r *router.IpRangeRouteContext, IpRangeScannerWg *sync.WaitGroup) {
	defer IpRangeScannerWg.Done()
	//defer fmt.Println("DEBUG: scanPointToPoint is done")

	var arpWg sync.WaitGroup

	arpWg.Add(1)
	go arpScan(c, r, &arpWg)

	arpWg.Wait()
}

// VerticalPortScanner is the main function for port scanning using the provided rule.
func VerticalPortScanner(scanRule rule.Rule, errorChan chan error) {

	var IpRangeScannerWg sync.WaitGroup
	//defer fmt.Println("DEBUG: VerticalPortScanner is done")

	// If dealing with a loopback interface, handle separately
	if scanRule.Network.IP.IsLoopback() {
		if err := getLocalhostPorts(); err != nil {
			errorChan <- err
			return
		}
	}

	ScanContext, err := createScannerContext(scanRule)

	if err != nil {
		errorChan <- err
		return
	}
	for _, networkRange := range ScanContext.ipRanges {
		switch networkRange.Route.Gw {
		case nil:
			IpRangeScannerWg.Add(1)
			go scanPointToPoint(ScanContext, networkRange, &IpRangeScannerWg)
		default:
			IpRangeScannerWg.Add(1)
			go scanOverGateway(ScanContext, networkRange, &IpRangeScannerWg)
		}
	}

	done := make(chan struct{})
	go func() {
		IpRangeScannerWg.Wait()
		close(done)
	}()

	select {
	case err = <-ScanContext.errorChan:
		errorChan <- err
		return
	case <-done:
	}

	IpRangeScannerWg.Wait()
}

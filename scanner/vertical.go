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
	//defer fmt.Println("DEBUG: scanOverGateway is done")
	defer close(r.ReadyToInterceptChan)
	defer arpWg.Done()

	// Prepare slices of structures for the sendmmsg syscall
	var messageHeaders [constants.IOVecPacketsChunkSize]Mmsghdr
	var rawArpPackets [constants.IOVecPacketsChunkSize][constants.MinFrameSize]byte
	var ioVectors [constants.IOVecPacketsChunkSize]syscall.Iovec

	arpWg.Add(1)
	go interceptArpPackets(c, r, arpWg)

	<-r.ReadyToInterceptChan

	arpPacketTemplate := prepareArpPacketTemplate(r.SocketParameters.SourceInterface.HardwareAddr, r.Route.Src)
	packetLength := uint64(constants.MinFrameSize)

	// Generate ARP packets for each IP chunk in the subnet
	// TODO
	for _, ipChunk := range utils.IterateIpRangeChunksBytes(r.Start, r.End) {
		for i := range ipChunk {
			rawArpPackets[i] = arpPacketTemplate
			copy(rawArpPackets[i][38:], ipChunk[i][:])

			ioVectors[i] = syscall.Iovec{
				Base: &rawArpPackets[i][0],
				Len:  packetLength,
			}
			messageHeaders[i].Msg = syscall.Msghdr{
				Name:    r.SocketParameters.SocketAddressName,
				Namelen: r.SocketParameters.SocketAddressNameLen,
				Iov:     &ioVectors[i],
				Iovlen:  1,
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
	var rawICMPPackets [constants.IOVecPacketsChunkSize][constants.MinFrameSize]byte
	var ioVectors [constants.IOVecPacketsChunkSize]syscall.Iovec

	pingWg.Add(1)
	go interceptPingPackets(c, r, pingWg)

	<-r.ReadyToInterceptChan

	pingPacketTemplate := prepareIcmpEchoPacketTemplate(r.SocketParameters.SourceInterface.HardwareAddr,
		gatewayMac,
		r.Route.Src)

	packetLength := uint64(constants.MinFrameSize)

	for _, ipChunk := range utils.IterateIpRangeChunksBytes(r.Start, r.End) {
		for i := range ipChunk {
			rawICMPPackets[i] = pingPacketTemplate
			copy(rawICMPPackets[i][30:], ipChunk[i][:])

			var sum uint32
			// Calculate sum over IP header from byte 14 to 33 (inclusive)
			for j := constants.IpV4HeaderStart; j < constants.IpHeaderLength+constants.IpV4HeaderStart; j += 2 {
				// Sum 16-bit words formed by adjacent bytes
				sum += uint32(rawICMPPackets[i][j])<<8 | uint32(rawICMPPackets[i][j+1])
			}

			// Add carries from top 16 bits into lower 16 bits
			sum = (sum & 0xFFFF) + (sum >> 16)
			sum = (sum & 0xFFFF) + (sum >> 16)

			// Write one's complement of sum into IP checksum field at bytes 24 and 25 in big-endian format
			binary.BigEndian.PutUint16(rawICMPPackets[i][24:26], ^uint16(sum))

			// Proceed with setting up iovec and message headers
			ioVectors[i] = syscall.Iovec{
				Base: &rawICMPPackets[i][0],
				Len:  packetLength,
			}
			messageHeaders[i].Msg = syscall.Msghdr{
				Name:    r.SocketParameters.SocketAddressName,
				Namelen: r.SocketParameters.SocketAddressNameLen,
				Iov:     &ioVectors[i],
				Iovlen:  1,
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

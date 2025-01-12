package scanner

import (
	"Vaverka/constants"
	"Vaverka/router"
	"Vaverka/rule"
	"Vaverka/utils"
	"context"
	"fmt"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// interceptArpPackets listens for ARP packets on the given interface within the specified subnet.
func interceptArpPackets(c *scannerContext, r *router.IpRangeRouteContext, arpWg *sync.WaitGroup) {

	var err error
	defer arpWg.Done()
	//defer fmt.Println("DEBUG: interceptArpPackets is done")

	handle, err := pcap.OpenLive(
		r.SocketParameters.SourceInterface.Name,
		constants.ArpPacketPayloadSize,
		true,
		constants.PcapCaptureTimeout,
	)
	if err != nil {
		c.errorChan <- err
		return
	}
	defer handle.Close()

	err = handle.SetBPFFilter(fmt.Sprintf("net %s and arp", r.Route.Dst.String()))
	if err != nil {
		c.errorChan <- err
		return
	}

	err = handle.SetDirection(pcap.DirectionIn)
	if err != nil {
		c.errorChan <- err
		return
	}

	err = handle.SetLinkType(layers.LinkTypeEthernet)
	if err != nil {
		c.errorChan <- err
		return
	}

	packetSource := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	incomingPacketsChan := packetSource.Packets()

	// Notify that we are ready to capture ARP packets
	r.ReadyToInterceptChan <- true

	for {
		select {
		case packet, isOpen := <-incomingPacketsChan:
			if !isOpen {
				return
			}
			if packet.Layer(layers.LayerTypeARP) == nil {
				continue
			}
			arpData := packet.Layer(layers.LayerTypeARP).(*layers.ARP)
			fmt.Printf(
				"{\"host\": \"%s\", \"state\": \"up\", \"technique\": \"arp\", \"network\": \"%s\", \"hardwareAddress\": \"%s\"}\n",
				net.IP(arpData.SourceProtAddress),
				(*r.Route.Dst).String(),
				net.HardwareAddr(arpData.SourceHwAddress),
			)
		case <-r.DoneChan:
			return
		}
	}
}

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

// scanOverGateway is a placeholder for scanning through a gateway.
func scanOverGateway(c *scannerContext, r *router.IpRangeRouteContext, scannerWg *sync.WaitGroup) {
	// TODO: implement scanning through a gateway
	defer scannerWg.Done()
	//defer fmt.Println("DEBUG: scanOverGateway is done")
	fmt.Println("scanOverGateway is not implemented yet", c, r)
}

// scanPointToPoint performs point-to-point scanning within a single subnet.
func scanPointToPoint(c *scannerContext, r *router.IpRangeRouteContext, scannerWg *sync.WaitGroup) {
	defer scannerWg.Done()
	//defer fmt.Println("DEBUG: scanPointToPoint is done")

	var arpWg sync.WaitGroup

	arpWg.Add(1)
	go arpScan(c, r, &arpWg)

	arpWg.Wait()
}

// VerticalPortScanner is the main function for port scanning using the provided rule.
func VerticalPortScanner(scanRule rule.Rule) error {

	var scannerWg sync.WaitGroup
	//defer fmt.Println("DEBUG: VerticalPortScanner is done")

	// If dealing with a loopback interface, handle separately
	if scanRule.Network.IP.IsLoopback() {
		if err := getLocalhostPorts(); err != nil {
			return err
		}
		return nil
	}

	ScanContext, err := createScannerContext(scanRule)

	if err != nil {
		return err
	}
	for _, networkRange := range ScanContext.ipRanges {
		switch networkRange.Route.Gw {
		case nil:
			scannerWg.Add(1)
			go scanPointToPoint(ScanContext, networkRange, &scannerWg)
		default:
			scannerWg.Add(1)
			go scanOverGateway(ScanContext, networkRange, &scannerWg)
		}
	}

	done := make(chan struct{})
	go func() {
		scannerWg.Wait()
		close(done)
	}()

	select {
	case err = <-ScanContext.errorChan:
		return err
	case <-done:
	}

	scannerWg.Wait()

	return nil
}

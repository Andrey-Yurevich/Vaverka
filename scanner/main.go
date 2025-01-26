package scanner

import (
	"Vaverka/constants"
	"Vaverka/router"
	"Vaverka/rule"
	"Vaverka/utils"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/vishvananda/netlink"
	"golang.org/x/time/rate"
	"net"
	"slices"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var Limiter *rate.Limiter

func getLocalhostPorts() error { return nil }

// HostStateDetection represents whether a host responded to different checks
type HostStateDetection struct {
	Ping bool
	Arp  bool
}

// Mmsghdr is a wrapper for syscall.Mmsghdr
type Mmsghdr struct {
	Msg syscall.Msghdr
	Len uint32
	_   [4]byte
}

type scannerContext struct {
	errorChan   chan error
	ipRanges    []*router.IpRangeRouteContext
	routeTables []netlink.Route
	socketFD    int
	rule        *rule.Rule
	ports       []uint16
}

func createScannerContext(r rule.Rule) (*scannerContext, error) {
	var c scannerContext
	var err error
	var portsList []uint16
	portsList = make([]uint16, 0)
	for _, portRange := range r.PortsRanges {
		if portRange.Validate() {
			portsList = append(portsList, portRange.Expand()...)
		} else {
			return nil, fmt.Errorf("port range %d-%d is not valid", portRange.Start, portRange.End)
		}
	}
	portsList = append(portsList, r.Ports...)
	slices.Sort(portsList)
	portsList = slices.Compact(portsList)
	c.ports = portsList

	c.errorChan = make(chan error, constants.ErrorChanBufferSize)
	c.routeTables, err = netlink.RouteList(nil, netlink.FAMILY_V4)
	c.rule = &r

	c.ipRanges, err = r.Options.Router(c.routeTables, &r.Network)
	if err != nil {
		return nil, fmt.Errorf("error splitting network to subranges: %v", err)
	}

	c.socketFD, err = utils.GetSocket()
	if err != nil {
		return nil, fmt.Errorf("error creating socket: %v", err)
	}
	return &c, nil
}

func preparePacketEthernetPart(sourceMAC, destinationMAC net.HardwareAddr) [constants.PacketEthernetV4PartSize]byte {
	var ICMPPacketEthernetPartTemplate [constants.PacketEthernetV4PartSize]byte
	ICMPPacketEthernetPartTemplate = constants.EthernetV4Part

	copy(ICMPPacketEthernetPartTemplate[0:6], destinationMAC)
	copy(ICMPPacketEthernetPartTemplate[6:12], sourceMAC)

	return ICMPPacketEthernetPartTemplate
}

func prepareIpv4PartTemplate(sourceIP net.IP) [constants.IPv4PartSize]byte {
	var ICMPPacketIPPartTemplate [constants.IPv4PartSize]byte
	ICMPPacketIPPartTemplate = constants.IPv4TCPPart

	copy(ICMPPacketIPPartTemplate[12:], sourceIP.To4())

	return ICMPPacketIPPartTemplate
}

func prepareArpAndEthernetHeadersTemplate(localMAC net.HardwareAddr) [constants.EthernetAndArpHeadersSize]byte {
	var arpPacketEthernetArpHeadersTemplate [constants.EthernetAndArpHeadersSize]byte
	arpPacketEthernetArpHeadersTemplate = constants.EthernetAndArpHeadersPart

	copy(arpPacketEthernetArpHeadersTemplate[6:], localMAC)

	return arpPacketEthernetArpHeadersTemplate
}

func prepareArpPacketBodyTemplate(localMAC net.HardwareAddr, localIP net.IP) [20]byte {
	var ArpPacketPayloadTemplate [20]byte
	ArpPacketPayloadTemplate = constants.ArpPacketPayloadPart

	copy(ArpPacketPayloadTemplate[0:], localMAC)
	copy(ArpPacketPayloadTemplate[6:], localIP)

	return ArpPacketPayloadTemplate
}

// interceptArpPackets listens for ARP packets on the given interface within the specified subnet.
func interceptArpPackets(c *scannerContext, r *router.IpRangeRouteContext, arpWg *sync.WaitGroup) {

	var err error
	var networkString string
	networkString = c.rule.Network.String()

	defer arpWg.Done()
	//defer fmt.Println("DEBUG: interceptArpPackets is done")

	handle, err := pcap.OpenLive(
		r.SocketParameters.SourceInterface.Name,
		constants.EthIpv4ArpPacketSize,
		true,
		constants.PcapCaptureTimeout,
	)
	if err != nil {
		c.errorChan <- err
		return
	}
	defer handle.Close()

	err = handle.SetBPFFilter(fmt.Sprintf("net %s and arp", networkString))
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
	packetSource.NoCopy = true

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
				"{\"host\": \"%s\", \"state\": \"up\", \"technique\": \"arp\", \"network\": \"%s\"}\n",
				net.IP(arpData.SourceProtAddress),
				networkString,
			)
			r.UpHostsChan <- arpData.SourceProtAddress
		case <-r.DoneChan:
			return
		}
	}
}

func interceptPingPackets(c *scannerContext, r *router.IpRangeRouteContext, pingWg *sync.WaitGroup) {

	var err error
	var networkString string
	defer pingWg.Done()
	networkString = c.rule.Network.String()

	//defer fmt.Println("DEBUG: interceptPingPackets is done")

	handle, err := pcap.OpenLive(
		r.SocketParameters.SourceInterface.Name,
		constants.EthIpv4IcmpV4PacketSize,
		true,
		constants.PcapCaptureTimeout,
	)
	if err != nil {
		c.errorChan <- err
		return
	}
	defer handle.Close()

	err = handle.SetBPFFilter(fmt.Sprintf("net %s and icmp", networkString))
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
	packetSource.NoCopy = true
	incomingPacketsChan := packetSource.Packets()

	// Notify that we are ready to capture ICMP packets
	r.ReadyToInterceptChan <- true

	for {
		select {
		case packet, isOpen := <-incomingPacketsChan:
			if !isOpen {
				return
			}
			if packet.Layer(layers.LayerTypeICMPv4) == nil {
				continue
			}
			ipData := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)

			fmt.Printf(
				"{\"host\": \"%s\", \"state\": \"up\", \"technique\": \"ping4\", \"network\": \"%s\"}\n",
				ipData.SrcIP,
				networkString,
			)

		case <-r.DoneChan:
			return
		}
	}
}

// Will be used later
// This function compiles a BPF expression that should intercept responses from ports
//func compileTransportStateDetectionBPF(r rule.Rule) (*pcap.BPF, error) {
//	var bpfStr string
//	var captureLength = 0
//
//	bpfStr += " net " + r.Network.String() + " and "
//
//	switch {
//	case r.PortScanTechniques.Syn || r.PortScanTechniques.Fin && r.PortScanTechniques.Udp:
//		bpfStr += " (tcp or udp) and "
//		captureLength = constants.ArpPacketPayloadSize
//	case r.PortScanTechniques.Syn || r.PortScanTechniques.Fin && !r.PortScanTechniques.Udp:
//		bpfStr += " tcp and "
//		captureLength = constants.TcpV4PacketPayloadSize
//	case r.PortScanTechniques.Udp && !(r.PortScanTechniques.Fin || r.PortScanTechniques.Syn):
//		bpfStr += "  udp and "
//		captureLength = constants.UdpV4PacketPayloadSize
//	}
//
//	for _, port := range r.Ports {
//		bpfStr += strconv.Itoa(int(port)) + " or "
//	}
//
//	bpfStr = strings.TrimSuffix(bpfStr, " or ")
//
//	return pcap.NewBPF(layers.LinkTypeIPv4, captureLength, bpfStr)
//}

// This legacy function sends an ARP request to the broadcast address to obtain the gateway address.
// It does not fit well with the iovec approach but works reasonably.
func sendRemoteMacAddrRequest(srcIP []byte, dstIP []byte, srcMac net.HardwareAddr, handle *pcap.Handle) error {
	var err error

	eth := layers.Ethernet{
		SrcMAC:       srcMac,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   srcMac,
		SourceProtAddress: srcIP,
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    dstIP,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err = gopacket.SerializeLayers(buf, opts, &eth, &arp)
	if err != nil {
		return err
	}
	err = handle.WritePacketData(buf.Bytes())
	if err != nil {
		return err
	}
	return nil
}

// This function reads ARP packets to obtain the gateway address
func readRemoteMacAddr(handle *pcap.Handle, sourceInterface *net.Interface, stop chan bool, addrChan chan net.HardwareAddr) {
	var packet gopacket.Packet

	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()

	for {
		select {
		case <-stop:
			return
		case packet = <-in:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arpData := arpLayer.(*layers.ARP)
			if arpData.Operation != layers.ARPReply || bytes.Equal(sourceInterface.HardwareAddr, arpData.SourceHwAddress) {
				// This is a packet I sent.
				continue
			}
			addrChan <- arpData.SourceHwAddress
		}
	}
}

// GetRemoteMacAddrSingleHost obtains the MAC address of a single remote host
func GetRemoteMacAddrSingleHost(sourceIP net.IP, remoteIP net.IP, sourceInterface *net.Interface) (net.HardwareAddr, error) {
	var handle *pcap.Handle
	var stop chan bool
	var err error
	var addr net.HardwareAddr
	var timeout <-chan time.Time

	stop = make(chan bool)
	defer close(stop)

	handle, err = pcap.OpenLive(sourceInterface.Name, 65536, false, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	var addrChan = make(chan net.HardwareAddr)
	go readRemoteMacAddr(handle, sourceInterface, stop, addrChan)

	err = sendRemoteMacAddrRequest(sourceIP, remoteIP, sourceInterface.HardwareAddr, handle)
	if err != nil {
		return nil, err
	}

	timeout = time.After(constants.GatewayMacRequestTimeout)

	select {
	case addr = <-addrChan:
		return addr, nil
	case <-timeout:
		return addr, nil
	}
}

//func portsScan(c *scannerContext, r *router.IpRangeRouteContext, portsScanWg *sync.WaitGroup) {
//	var scanTypesCount int
//	var currentIndex int
//	defer portsScanWg.Done()
//	var EthernetV4Part [constants.PacketEthernetV4PartSize]byte
//	var IpTcpPartTemplate [constants.IPv4TCPPartSize]byte
//	var IpUdpPartTemplate [constants.IPv4UDPPartSize]byte
//
//	var messageHeaders [constants.IOVecPacketsChunkSize]Mmsghdr
//	var rawIPPacketBodies [constants.IOVecPacketsChunkSize][20]byte
//	var ioVectors [constants.IOVecPacketsChunkSize][3]syscall.Iovec
//
//	EthernetV4Part = preparePacketEthernetPart(r.SocketParameters.SourceInterface.HardwareAddr, gatewayMac)
//	IpTcpPartTemplate = preparePacketIpPartTemplate(r.Route.Src)
//
//	if c.rule.PortScanTechniques.Syn {
//		scanTypesCount++
//	}
//
//	if c.rule.PortScanTechniques.Fin {
//		scanTypesCount++
//	}
//
//	if c.rule.PortScanTechniques.Udp {
//		scanTypesCount++
//	}
//
//	switch {
//	case len(c.ports)*scanTypesCount < constants.IOVecPacketsChunkSize:
//		for host := range r.UpHostsChan {
//			currentIndex = 0
//
//			if c.rule.PortScanTechniques.Syn {
//				for _, port := range c.ports {
//
//					currentIndex++
//				}
//			}
//
//			if c.rule.PortScanTechniques.Udp {
//				for _, port := range c.ports {
//
//					currentIndex++
//				}
//			}
//
//			if c.rule.PortScanTechniques.Fin {
//				for _, port := range c.ports {
//
//					currentIndex++
//				}
//			}
//
//		}
//	}
//
//}

// arpScan sends ARP requests for each IP address in the subnet and waits for replies.
func arpScan(c *scannerContext, r *router.IpRangeRouteContext, arpWg *sync.WaitGroup) {

	defer close(r.ReadyToInterceptChan)
	defer arpWg.Done()

	var messageHeaders [constants.IOVecPacketsChunkSize]Mmsghdr
	var ethernetAndArpHeadersTemplate [constants.EthernetAndArpHeadersSize]byte
	var arpPacketBodyTemplate [constants.ArpPacketPayloadSize]byte
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
				Len:  constants.EthernetAndArpHeadersSize,
			}

			ioVectors[i][1] = syscall.Iovec{
				Base: &rawArpPacketBodies[i][0],
				Len:  constants.ArpPacketPayloadSize,
			}

			ioVectors[i][2] = syscall.Iovec{
				Base: &constants.EighteenBytesPaddingPart[0],
				Len:  constants.EighteenBytesPaddingPartSize,
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
	var rawICMPPacketsIpPart [constants.IOVecPacketsChunkSize][constants.IPv4PartSize]byte
	var ioVectors [constants.IOVecPacketsChunkSize][3]syscall.Iovec
	var EthernetPart [constants.PacketEthernetV4PartSize]byte
	var Ipv4Part [constants.IPv4PartSize]byte

	pingWg.Add(1)
	go interceptPingPackets(c, r, pingWg)

	<-r.ReadyToInterceptChan

	EthernetPart = preparePacketEthernetPart(r.SocketParameters.SourceInterface.HardwareAddr, gatewayMac)
	Ipv4Part = prepareIpv4PartTemplate(r.Route.Src)

	for _, ipChunk := range utils.IterateIpRangeChunksBytes(r.Start, r.End) {
		for i := range ipChunk {
			rawICMPPacketsIpPart[i] = Ipv4Part
			copy(rawICMPPacketsIpPart[i][16:], ipChunk[i][:])

			var sum uint32
			// Calculate sum over IP header from byte 14 to 33 (inclusive)
			for j := 0; j < constants.IPv4PartSize; j += 2 {
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
				Base: &EthernetPart[0],
				Len:  constants.PacketEthernetV4PartSize,
			}

			ioVectors[i][1] = syscall.Iovec{
				Base: &rawICMPPacketsIpPart[i][0],
				Len:  constants.IPv4PartSize,
			}

			ioVectors[i][2] = syscall.Iovec{
				Base: &constants.IcmpV4Part[0],
				Len:  constants.IcmpV4PartSize,
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

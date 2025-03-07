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
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Limiter is a global rate limiter used to control packet sending rate.
var Limiter *rate.Limiter

// getLocalhostPorts is a stub for handling local ports on a loopback interface.
func getLocalhostPorts() error {
	return nil
}

// HostStateDetection represents whether a host responded to different checks.
type HostStateDetection struct {
	Ping bool
	Arp  bool
}

// Mmsghdr is a wrapper for syscall.Mmsghdr used with sendmmsg.
type Mmsghdr struct {
	Msg syscall.Msghdr
	Len uint32
	_   [4]byte
}

// EthIPPair is used for linking MAC and IP addresses together.
type EthIPPair struct {
	eth *net.HardwareAddr
	ip  *net.IP
}

// scannerContext holds overall state for scanning, including error channels,
// routes, and a raw socket descriptor.
type scannerContext struct {
	errorChan      chan error
	IpRanges       []*router.IpRangeRouteContext
	routeTables    []netlink.Route
	socketFD       uintptr
	rule           *rule.Rule
	ports          []uint16
	defaultGateway net.IP
}

// createScannerContext initializes scannerContext from the provided rule.
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
	// Add explicitly listed ports
	portsList = append(portsList, r.Ports...)
	// Sort and deduplicate
	slices.Sort(portsList)
	portsList = slices.Compact(portsList)

	c.ports = portsList
	c.errorChan = make(chan error, constants.ErrorChanBufferSize)

	c.routeTables, err = netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("cannot get route list: %v", err)
	}

	c.rule = &r

	c.IpRanges, err = r.Options.Router(c.routeTables, &r.Network)
	if err != nil {
		return nil, fmt.Errorf("error splitting network to subranges: %v", err)
	}

	c.socketFD, err = utils.GetSocket()
	if err != nil {
		return nil, fmt.Errorf("error creating socket: %v", err)
	}

	c.defaultGateway, err = utils.GetDefaultGateway()
	if err != nil {
		return nil, fmt.Errorf("error getting default gateway: %v", err)
	}

	return &c, nil
}

// prepareEthernetPart sets up an Ethernet header for raw packet injection.
func prepareEthernetPart(sourceMAC, destinationMAC net.HardwareAddr, networkLayer uint16) []byte {
	ethernetPartTemplate := make([]byte, constants.EthernetHeaderSize)
	copy(ethernetPartTemplate, constants.EthernetHeader[:])

	copy(ethernetPartTemplate[0:6], destinationMAC)
	copy(ethernetPartTemplate[6:12], sourceMAC)

	binary.BigEndian.PutUint16(ethernetPartTemplate[12:14], networkLayer)
	return ethernetPartTemplate
}

// prepareIpv4PartTemplate creates an IPv4 header template with the given source,
// total length, and transport layer protocol (e.g., TCP/ICMP).
func prepareIpv4PartTemplate(sourceIP net.IP, length uint16, transportLayer byte) []byte {
	IPPartTemplate := make([]byte, constants.IPv4HeaderSize)

	copy(IPPartTemplate, constants.IPv4Header[:])

	copy(IPPartTemplate[12:], sourceIP.To4())
	IPPartTemplate[9] = transportLayer

	binary.BigEndian.PutUint16(IPPartTemplate[2:], length)
	return IPPartTemplate
}

// preparePseudoHeader builds a TCP pseudo-header required for correct checksum calculation.
func preparePseudoHeader(SourceIP, DestinationIP []byte, protocol uint8, Length uint16) []byte {
	var PseudoHeader []byte
	PseudoHeader = make([]byte, constants.TCPPseudoHeaderSize)

	copy(PseudoHeader[:4], SourceIP)
	copy(PseudoHeader[4:8], DestinationIP)
	// Reserved byte is always 0
	PseudoHeader[8] = 0x00
	PseudoHeader[9] = protocol
	binary.BigEndian.PutUint16(PseudoHeader[10:], Length)

	return PseudoHeader
}

// prepareArpPacketBodyTemplate creates a template for the ARP body with local MAC and IP.
func prepareArpPacketBodyTemplate(localMAC net.HardwareAddr, localIP net.IP) [constants.ArpBodySize]byte {
	var arpBodyTemplate [constants.ArpBodySize]byte

	arpBodyTemplate = constants.ArpBody

	copy(arpBodyTemplate[0:], localMAC)
	copy(arpBodyTemplate[6:], localIP)

	return arpBodyTemplate
}

// interceptArpPackets listens for ARP packets for the subnet on the specified interface.
func interceptArpPackets(c *scannerContext, r *router.IpRangeRouteContext, arpWg *sync.WaitGroup) {
	defer arpWg.Done()
	//defer fmt.Println("DEBUG: interceptArpPackets is done")

	handle, err := pcap.OpenLive(
		r.SocketParameters.SourceInterface.Name,
		constants.MinFrameSize,
		true,
		constants.PcapCaptureTimeout,
	)
	if err != nil {
		c.errorChan <- err
		return
	}
	defer handle.Close()

	networkString := c.rule.Network.String()
	if err = handle.SetBPFFilter(fmt.Sprintf("net %s and arp", networkString)); err != nil {
		c.errorChan <- err
		return
	}
	if err = handle.SetDirection(pcap.DirectionIn); err != nil {
		c.errorChan <- err
		return
	}
	if err = handle.SetLinkType(layers.LinkTypeEthernet); err != nil {
		c.errorChan <- err
		return
	}

	packetSource := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	packetSource.NoCopy = true
	incomingPacketsChan := packetSource.Packets()

	// Signal that we're ready to capture ARP packets
	r.ReadyToInterceptHostsStateChan <- true

	for {
		select {
		case packet, isOpen := <-incomingPacketsChan:
			if !isOpen {
				return
			}
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arpData, _ := arpLayer.(*layers.ARP)
			if utils.IsIPInRange(r.Start, r.End, arpData.SourceProtAddress) {
				// Print host discovery info (ARP)
				printARPDiscovery(arpData.SourceProtAddress, c.rule.Network)
				// Send discovered host to UpHostsChan
				r.UpHostsChan <- router.UpHostsEthIPChan{
					Ip:  arpData.SourceProtAddress,
					Eth: arpData.SourceHwAddress,
				}
			}

		case <-r.HostDiscoveryDoneChan:
			// Stop interception when signaled
			return
		}
	}
}

// interceptTransportResponses captures packets for TCP/UDP discovery.
// For TCP, it listens for SYN+ACK; for UDP, it captures all packets.
func interceptTransportResponses(c *scannerContext, r *router.IpRangeRouteContext, bpf *pcap.BPF, wg *sync.WaitGroup) {
	defer wg.Done()

	pcapHandle, err := pcap.OpenLive(
		r.SocketParameters.SourceInterface.Name,
		constants.MinFrameSize, // minimal snapshot length
		true,                   // promiscuous mode
		constants.PcapCaptureTimeout,
	)
	if err != nil {
		c.errorChan <- err
		return
	}
	defer pcapHandle.Close()

	filterStr := bpf.String()
	if err = pcapHandle.SetBPFFilter(filterStr); err != nil {
		c.errorChan <- err
		return
	}
	if err = pcapHandle.SetDirection(pcap.DirectionIn); err != nil {
		c.errorChan <- err
		return
	}
	if err = pcapHandle.SetLinkType(layers.LinkTypeEthernet); err != nil {
		c.errorChan <- err
		return
	}

	packetSource := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())
	packetSource.NoCopy = true
	packetChan := packetSource.Packets()

	// Signal that we're ready to intercept TCP/UDP packets
	r.ReadyToInterceptPortsStateChan <- true

	for {
		select {
		case packet, open := <-packetChan:
			if !open {
				return
			}
			ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
			if ipv4Layer == nil {
				continue
			}
			ipv4, ok := ipv4Layer.(*layers.IPv4)
			if !ok {
				continue
			}

			// Check for TCP layer
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, ok := tcpLayer.(*layers.TCP)
				if !ok {
					continue
				}
				// Only process SYN+ACK
				if tcp.SYN && tcp.ACK {
					serviceName, identified := layers.TCPPortNames(tcp.SrcPort)
					if !identified {
						serviceName = "unknown"
					}
					printTCPInfo(ipv4.SrcIP, tcp.SrcPort, &serviceName, c.rule.Network)
				}
			} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
				udp, ok := udpLayer.(*layers.UDP)
				if !ok {
					continue
				}
				serviceName, identified := layers.UDPPortNames(udp.SrcPort)
				if !identified {
					serviceName = "unknown"
				}
				printUDPInfo(ipv4.SrcIP, udp.SrcPort, &serviceName, c.rule.Network)
			}

		case <-r.PortsDiscoveryDoneChan:
			// Stop interception when signaled
			return
		}
	}
}

// interceptPingPackets listens for ICMP (ping) packets and identifies responding hosts.
func interceptPingPackets(c *scannerContext, r *router.IpRangeRouteContext, pingWg *sync.WaitGroup) {
	defer pingWg.Done()
	//defer fmt.Println("DEBUG: interceptPingPackets is done")

	handle, err := pcap.OpenLive(
		r.SocketParameters.SourceInterface.Name,
		constants.MinFrameSize,
		true,
		constants.PcapCaptureTimeout,
	)
	if err != nil {
		c.errorChan <- err
		return
	}
	defer handle.Close()

	networkString := c.rule.Network.String()
	if err = handle.SetBPFFilter(fmt.Sprintf("net %s and icmp", networkString)); err != nil {
		c.errorChan <- err
		return
	}
	if err = handle.SetDirection(pcap.DirectionIn); err != nil {
		c.errorChan <- err
		return
	}
	if err = handle.SetLinkType(layers.LinkTypeEthernet); err != nil {
		c.errorChan <- err
		return
	}

	packetSource := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	packetSource.NoCopy = true
	incomingPacketsChan := packetSource.Packets()

	// Signal that we are ready to capture ICMP packets
	r.ReadyToInterceptHostsStateChan <- true

	for {
		select {
		case packet, isOpen := <-incomingPacketsChan:
			if !isOpen {
				return
			}
			icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
			if icmpLayer == nil || icmpLayer.(*layers.ICMPv4).TypeCode.Type() != layers.ICMPv4TypeEchoReply {
				continue
			}
			ipData := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)

			if utils.IsIPInRange(r.Start, r.End, ipData.SrcIP) {
				// Print host discovery info (ping)
				printPingDiscovery(ipData.SrcIP, c.rule.Network)
				r.UpHostsChan <- router.UpHostsEthIPChan{Ip: ipData.SrcIP, Eth: nil}
			}

		case <-r.HostDiscoveryDoneChan:
			// Stop interception when signaled
			return
		}
	}
}

// compileTransportStateDetectionBPF builds a BPF filter for capturing TCP/UDP
// in the specific scanning techniques.
func compileTransportStateDetectionBPF(c *scannerContext, rc *router.IpRangeRouteContext) (*pcap.BPF, error) {
	var bpfStr string
	captureLength := 0

	bpfStr += " net " + c.rule.Network.String() + " and "

	switch {
	case c.rule.PortScanTechniques.Syn || c.rule.PortScanTechniques.Vav && c.rule.PortScanTechniques.Udp:
		bpfStr += " (tcp or udp) and "
		captureLength = constants.EthernetHeaderSize + constants.IPv4HeaderSize + constants.TCPSynHeaderSize
	case c.rule.PortScanTechniques.Syn || c.rule.PortScanTechniques.Vav && !c.rule.PortScanTechniques.Udp:
		bpfStr += " tcp and "
		captureLength = constants.EthernetHeaderSize + constants.IPv4HeaderSize + constants.TCPSynHeaderSize
	case c.rule.PortScanTechniques.Udp && !(c.rule.PortScanTechniques.Vav || c.rule.PortScanTechniques.Syn):
		bpfStr += " udp and "
		captureLength = constants.EthernetHeaderSize + constants.IPv4HeaderSize + constants.UDPHeaderSize
	}

	// Filter on destination port
	bpfStr += "dst port " + strconv.Itoa(int(rc.SourcePort))

	return pcap.NewBPF(layers.LinkTypeIPv4, captureLength, bpfStr)
}

// sendRemoteMacAddrRequest broadcasts an ARP request for the given IP.
func sendRemoteMacAddrRequest(srcIP []byte, dstIP []byte, srcMac net.HardwareAddr, handle *pcap.Handle) error {
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
	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		return err
	}
	return handle.WritePacketData(buf.Bytes())
}

// readRemoteMacAddr listens for ARP replies to obtain a remote MAC address.
func readRemoteMacAddr(handle *pcap.Handle, sourceInterface *net.Interface, stop chan bool, addrChan chan net.HardwareAddr) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()

	for {
		select {
		case <-stop:
			return
		case packet := <-in:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arpData := arpLayer.(*layers.ARP)
			if arpData.Operation != layers.ARPReply ||
				bytes.Equal(sourceInterface.HardwareAddr, arpData.SourceHwAddress) {
				// Skip if it's not a reply or if it's our own ARP.
				continue
			}
			addrChan <- arpData.SourceHwAddress
		}
	}
}

// GetRemoteMacAddrSingleHost obtains the MAC address of a remote host if not found in the ARP cache.
func GetRemoteMacAddrSingleHost(sourceIP net.IP, remoteIP net.IP, sourceInterface *net.Interface) (net.HardwareAddr, error) {
	stop := make(chan bool)
	defer close(stop)

	handle, err := pcap.OpenLive(sourceInterface.Name, constants.MinFrameSize, false, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	addrChan := make(chan net.HardwareAddr)
	go readRemoteMacAddr(handle, sourceInterface, stop, addrChan)

	if err := sendRemoteMacAddrRequest(sourceIP, remoteIP, sourceInterface.HardwareAddr, handle); err != nil {
		return nil, err
	}

	timeout := time.After(constants.GatewayMacRequestTimeout)

	select {
	case addr := <-addrChan:
		return addr, nil
	case <-timeout:
		return nil, nil
	}
}

// computeChecksum calculates an Internet checksum for the given data.
func computeChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// PointToPointPortsScan sends TCP SYN/VAV packets and UDP packets (if enabled) to discovered hosts.
func PointToPointPortsScan(c *scannerContext, r *router.IpRangeRouteContext, portsScanWg *sync.WaitGroup) {
	// Defer cleanup actions.
	defer portsScanWg.Done()
	defer close(r.ReadyToInterceptPortsStateChan)
	//defer fmt.Println("DEBUG: PointToPointPortsScan is done")

	var (
		// IP header templates for each scan type.
		ipTcpSynTemplate []byte
		ipTcpVavTemplate []byte
		ipUdpTemplate    []byte

		// EthernetTemplate Ethernet header template.
		EthernetTemplate []byte

		// Combined Ethernet+IP buffers for each scan type.
		ethIpBufferSyn []byte
		ethIpBufferVav []byte
		ethIpBufferUdp []byte

		// Source IP in 4-byte format.
		sourceIPBytes = r.Route.Src.To4()

		// Static lengths for iovec segments.
		lenEthernetAndIp uint64 = constants.EthernetHeaderSize + constants.IPv4HeaderSize
		lenTcpVavHeader  uint64 = constants.TCPSynVavHeaderSize
		lenAcorn         uint64 = constants.AcornSize

		// Temporary variable for computing transport-layer checksum.
		pseudoHeader []byte

		// Buffers for concatenating pseudo-header with TCP/UDP headers for checksum calculation.
		pseudoHeaderAndTcpHeaderSyn []byte
		pseudoHeaderAndTcpHeaderVav []byte
		pseudoHeaderAndUdpHeader    []byte

		// Slice of TCP headers for SYN scanning.
		tcpSynHeaders [][constants.TCPSynHeaderSize]byte
		// TCP header template for SYN scan (with predefined source port).
		tcpSynHeaderTemplate [constants.TCPSynHeaderSize]byte

		// Slice of TCP headers for VAV scanning.
		tcpVavHeaders [][constants.TCPSynVavHeaderSize]byte
		// TCP header template for VAV scan (with predefined source port).
		tcpVavHeaderTemplate [constants.TCPSynVavHeaderSize]byte

		// Slice of UDP headers.
		udpHeaders [][constants.UDPHeaderSize]byte
		// UDP header template (with predefined source port).
		udpHeaderTemplate [constants.UDPHeaderSize]byte

		// Message headers and I/O vectors for the sendmmsg syscall.
		messageHeaders [constants.IOVecPacketsChunkSize]Mmsghdr
		ioVectors      [constants.IOVecPacketsChunkSize][3]syscall.Iovec

		// Counter for the number of scan types enabled.
		scanTypesCount int

		// BPF filter for capturing responses.
		bpfExpression *pcap.BPF

		err      error
		checksum uint16
	)

	// Compile the BPF filter for detecting transport-layer responses.
	bpfExpression, err = compileTransportStateDetectionBPF(c, r)
	if err != nil {
		c.errorChan <- err
		return
	}

	// Start a goroutine to intercept TCP/UDP responses.
	portsScanWg.Add(1)
	go interceptTransportResponses(c, r, bpfExpression, portsScanWg)

	// Wait until the interceptor is ready.
	<-r.ReadyToInterceptPortsStateChan

	// Prepare headers and buffers for each enabled scan technique.
	if c.rule.PortScanTechniques.Syn {
		scanTypesCount++
		// Build a base IPv4 header template for SYN scan (IP header + TCP header).
		ipTcpSynTemplate = prepareIpv4PartTemplate(
			r.Route.Src,
			constants.IPv4HeaderSize+constants.TCPSynHeaderSize,
			constants.TrafficTCP,
		)

		// Allocate Ethernet+IP buffer for SYN scan.
		ethIpBufferSyn = make([]byte, constants.EthernetHeaderSize+constants.IPv4HeaderSize)

		// Allocate buffer for concatenating pseudo-header with TCP SYN header.
		pseudoHeaderAndTcpHeaderSyn = make([]byte, constants.TCPPseudoHeaderSize+constants.TCPSynHeaderSize)
		// Allocate slice for TCP headers for all ports.
		tcpSynHeaders = make([][constants.TCPSynHeaderSize]byte, len(c.ports))

		// Initialize the SYN header template and set the source port.
		tcpSynHeaderTemplate = constants.TCPSynHeader
		binary.BigEndian.PutUint16(tcpSynHeaderTemplate[0:2], r.SourcePort)
	}

	if c.rule.PortScanTechniques.Vav {
		// Allocate Ethernet+IP buffer for VAV scan.
		ethIpBufferVav = make([]byte, constants.EthernetHeaderSize+constants.IPv4HeaderSize)

		scanTypesCount++
		// Build a base IPv4 header template for VAV scan (IP header + TCP VAV header + payload length).
		ipTcpVavTemplate = prepareIpv4PartTemplate(
			r.Route.Src,
			constants.IPv4HeaderSize+constants.TCPSynVavHeaderSize+constants.AcornSize,
			constants.TrafficTCP,
		)
		// Allocate buffer for concatenating pseudo-header, TCP VAV header, and payload.
		pseudoHeaderAndTcpHeaderVav = make([]byte, constants.TCPPseudoHeaderSize+constants.TCPSynVavHeaderSize+constants.AcornSize)
		// Allocate slice for TCP VAV headers for all ports.
		tcpVavHeaders = make([][constants.TCPSynVavHeaderSize]byte, len(c.ports))

		// Initialize the VAV header template and set the source port.
		tcpVavHeaderTemplate = constants.TCPSynVavHeader
		binary.BigEndian.PutUint16(tcpVavHeaderTemplate[0:2], r.SourcePort)
	}

	if c.rule.PortScanTechniques.Udp {
		scanTypesCount++

		// Allocate Ethernet+IP buffer for UDP scan.
		ethIpBufferUdp = make([]byte, constants.EthernetHeaderSize+constants.IPv4HeaderSize)

		// Build a base IPv4 header template for UDP scan (IP header + UDP header).
		ipUdpTemplate = prepareIpv4PartTemplate(
			r.Route.Src,
			constants.IPv4HeaderSize+constants.UDPHeaderSize,
			constants.TrafficUDP,
		)
		// Allocate slice for UDP headers for all ports.
		udpHeaders = make([][constants.UDPHeaderSize]byte, len(c.ports))
		// Initialize the UDP header template and set the source port.
		udpHeaderTemplate = constants.UdpHeader
		binary.BigEndian.PutUint16(udpHeaderTemplate[0:2], r.SourcePort)
	}

	// Build a base Ethernet header template with a zeroed destination MAC.
	EthernetTemplate = prepareEthernetPart(
		r.SocketParameters.SourceInterface.HardwareAddr,
		net.HardwareAddr{0, 0, 0, 0, 0, 0},
		constants.EtherTypeIPv4,
	)
	switch {
	// If the total number of packets (ports * scan types) is less than the chunk size,
	// process them as a single batch.
	case len(c.ports)*scanTypesCount < constants.IOVecPacketsChunkSize:
		// Process each discovered host.
		for host := range r.UpHostsChan {
			currentIndex := 0

			// ----- SYN Scan Branch -----
			if c.rule.PortScanTechniques.Syn {
				// Prepare Ethernet+IP buffer for SYN scan.
				copy(ethIpBufferSyn[0:6], host.Eth)                                        // Set destination MAC.
				copy(ethIpBufferSyn[6:constants.EthernetHeaderSize], EthernetTemplate[6:]) // Copy rest of Ethernet header.
				// Copy the SYN IP header template.
				copy(ethIpBufferSyn[constants.EthernetHeaderSize:constants.EthernetHeaderSize+constants.IPv4HeaderSize], ipTcpSynTemplate)
				// Overwrite destination IP.
				copy(ethIpBufferSyn[constants.EthernetHeaderSize+16:constants.EthernetHeaderSize+20], host.Ip)
				// Compute and set IP header checksum.
				checksum = computeChecksum(ethIpBufferSyn[constants.EthernetHeaderSize : constants.EthernetHeaderSize+constants.IPv4HeaderSize])
				binary.BigEndian.PutUint16(ethIpBufferSyn[constants.EthernetHeaderSize+10:constants.EthernetHeaderSize+12], checksum)

				// Prepare the TCP pseudo-header for SYN scan.
				pseudoHeader = preparePseudoHeader(sourceIPBytes, host.Ip, constants.TrafficTCP, constants.TCPSynHeaderSize)

				// Loop through each port for SYN scan.
				for i, port := range c.ports {
					// Initialize TCP header from the SYN template.
					tcpSynHeaders[i] = tcpSynHeaderTemplate
					// Set destination port.
					binary.BigEndian.PutUint16(tcpSynHeaders[i][2:4], port)
					// Build buffer for checksum calculation: pseudo-header + TCP header.
					copy(pseudoHeaderAndTcpHeaderSyn[0:constants.TCPPseudoHeaderSize], pseudoHeader)
					copy(pseudoHeaderAndTcpHeaderSyn[constants.TCPPseudoHeaderSize:], tcpSynHeaders[i][:])
					// Compute TCP checksum and set it.
					checksum = computeChecksum(pseudoHeaderAndTcpHeaderSyn)
					binary.BigEndian.PutUint16(tcpSynHeaders[i][16:18], checksum)

					// Set up I/O vectors.
					ioVectors[currentIndex][0] = syscall.Iovec{
						Base: &ethIpBufferSyn[0],
						Len:  uint64(constants.EthernetHeaderSize + constants.IPv4HeaderSize),
					}
					ioVectors[currentIndex][1] = syscall.Iovec{
						Base: &tcpSynHeaders[i][0],
						Len:  uint64(constants.TCPSynHeaderSize),
					}
					// Create message header with 2 segments.
					messageHeaders[currentIndex].Msg = syscall.Msghdr{
						Name:    r.SocketParameters.SocketAddressName,
						Namelen: r.SocketParameters.SocketAddressNameLen,
						Iov:     &ioVectors[currentIndex][0],
						Iovlen:  2,
					}
					currentIndex++
				}
			}

			// ----- VAV Scan Branch -----
			if c.rule.PortScanTechniques.Vav {
				// Prepare Ethernet+IP buffer for VAV scan.
				copy(ethIpBufferVav[0:6], host.Eth)                                        // Set destination MAC.
				copy(ethIpBufferVav[6:constants.EthernetHeaderSize], EthernetTemplate[6:]) // Copy rest of Ethernet header.
				// Copy the VAV IP header template.
				copy(ethIpBufferVav[constants.EthernetHeaderSize:constants.EthernetHeaderSize+constants.IPv4HeaderSize], ipTcpVavTemplate)
				// Overwrite destination IP.
				copy(ethIpBufferVav[constants.EthernetHeaderSize+16:constants.EthernetHeaderSize+20], host.Ip)
				// Compute and set IP header checksum.
				checksum = computeChecksum(ethIpBufferVav[constants.EthernetHeaderSize : constants.EthernetHeaderSize+constants.IPv4HeaderSize])
				binary.BigEndian.PutUint16(ethIpBufferVav[constants.EthernetHeaderSize+10:constants.EthernetHeaderSize+12], checksum)

				// Prepare the TCP pseudo-header for VAV scan.
				pseudoHeader = preparePseudoHeader(sourceIPBytes, host.Ip, constants.TrafficTCP, constants.TCPSynVavHeaderSize+constants.AcornSize)
				// Loop through each port for VAV scan.
				for i, port := range c.ports {
					// Initialize TCP header from the VAV template.
					tcpVavHeaders[i] = tcpVavHeaderTemplate
					// Set destination port.
					binary.BigEndian.PutUint16(tcpVavHeaders[i][2:4], port)
					// Build buffer for checksum calculation: pseudo-header + TCP VAV header + payload.
					copy(pseudoHeaderAndTcpHeaderVav[0:constants.TCPPseudoHeaderSize], pseudoHeader)
					copy(pseudoHeaderAndTcpHeaderVav[constants.TCPPseudoHeaderSize:constants.TCPPseudoHeaderSize+constants.TCPSynVavHeaderSize], tcpVavHeaders[i][:])
					copy(pseudoHeaderAndTcpHeaderVav[constants.TCPPseudoHeaderSize+constants.TCPSynVavHeaderSize:], constants.Acorn[:])
					// Compute TCP checksum and set it.
					checksum = computeChecksum(pseudoHeaderAndTcpHeaderVav)
					binary.BigEndian.PutUint16(tcpVavHeaders[i][16:18], checksum)

					// Set up I/O vectors.
					ioVectors[currentIndex][0] = syscall.Iovec{
						Base: &ethIpBufferVav[0],
						Len:  lenEthernetAndIp,
					}

					ioVectors[currentIndex][1] = syscall.Iovec{
						Base: &tcpVavHeaders[i][0],
						Len:  lenTcpVavHeader,
					}
					ioVectors[currentIndex][2] = syscall.Iovec{
						Base: &constants.Acorn[0],
						Len:  lenAcorn,
					}
					// Create message header with 3 segments.
					messageHeaders[currentIndex].Msg = syscall.Msghdr{
						Name:    r.SocketParameters.SocketAddressName,
						Namelen: r.SocketParameters.SocketAddressNameLen,
						Iov:     &ioVectors[currentIndex][0],
						Iovlen:  3,
					}
					currentIndex++
				}
			}

			// ----- UDP Scan Branch -----
			if c.rule.PortScanTechniques.Udp {
				// Prepare Ethernet+IP buffer for UDP scan.
				copy(ethIpBufferUdp[0:6], host.Eth)                                        // Set destination MAC.
				copy(ethIpBufferUdp[6:constants.EthernetHeaderSize], EthernetTemplate[6:]) // Copy rest of Ethernet header.
				// Copy the UDP IP header template.
				copy(ethIpBufferUdp[constants.EthernetHeaderSize:constants.EthernetHeaderSize+constants.IPv4HeaderSize], ipUdpTemplate)
				// Overwrite destination IP.
				copy(ethIpBufferUdp[constants.EthernetHeaderSize+16:constants.EthernetHeaderSize+20], host.Ip)
				// Compute and set IP header checksum.
				checksum = computeChecksum(ethIpBufferUdp[constants.EthernetHeaderSize : constants.EthernetHeaderSize+constants.IPv4HeaderSize])
				binary.BigEndian.PutUint16(ethIpBufferUdp[constants.EthernetHeaderSize+10:constants.EthernetHeaderSize+12], checksum)

				// Loop through each port for UDP scan.
				for i, port := range c.ports {
					// Initialize UDP header from the template.
					udpHeaders[i] = udpHeaderTemplate
					// Set destination port.
					binary.BigEndian.PutUint16(udpHeaders[i][2:4], port)
					// Prepare the UDP pseudo-header for checksum calculation.
					pseudoHeader = preparePseudoHeader(sourceIPBytes, host.Ip, constants.TrafficUDP, uint16(constants.UDPHeaderSize))
					pseudoHeaderAndUdpHeader = make([]byte, len(pseudoHeader)+constants.UDPHeaderSize)
					copy(pseudoHeaderAndUdpHeader[0:len(pseudoHeader)], pseudoHeader)
					copy(pseudoHeaderAndUdpHeader[len(pseudoHeader):], udpHeaders[i][:])
					// Compute UDP checksum and set it.
					checksum = computeChecksum(pseudoHeaderAndUdpHeader)
					binary.BigEndian.PutUint16(udpHeaders[i][6:8], checksum)

					// Set up I/O vectors.
					ioVectors[currentIndex][0] = syscall.Iovec{
						Base: &ethIpBufferUdp[0],
						Len:  uint64(constants.EthernetHeaderSize + constants.IPv4HeaderSize),
					}
					ioVectors[currentIndex][1] = syscall.Iovec{
						Base: &udpHeaders[i][0],
						Len:  uint64(constants.UDPHeaderSize),
					}
					// Create message header with 2 segments.
					messageHeaders[currentIndex].Msg = syscall.Msghdr{
						Name:    r.SocketParameters.SocketAddressName,
						Namelen: r.SocketParameters.SocketAddressNameLen,
						Iov:     &ioVectors[currentIndex][0],
						Iovlen:  2,
					}
					currentIndex++
				}
			}

			// Wait for the rate limiter before sending the batch.
			if err = Limiter.Wait(context.Background()); err != nil {
				c.errorChan <- err
				return
			}

			// Send the batch of messages using the sendmmsg syscall.
			_, _, errno := syscall.RawSyscall(
				syscall.SYS_SENDMMSG,
				c.socketFD,
				uintptr(unsafe.Pointer(&messageHeaders[0])),
				uintptr(currentIndex),
			)
			if errno != 0 {
				c.errorChan <- errno
				return
			}
		}

	// Default: total number of packets is greater or equal to constants.IOVecPacketsChunkSize.
	default:
		// Process each discovered host.
		for host := range r.UpHostsChan {
			currentIndex := 0

			// ----- SYN Scan Branch -----
			if c.rule.PortScanTechniques.Syn {
				// Prepare Ethernet+IP buffer for SYN scan.
				copy(ethIpBufferSyn[0:6], host.Eth)                                        // Set destination MAC.
				copy(ethIpBufferSyn[6:constants.EthernetHeaderSize], EthernetTemplate[6:]) // Copy rest of Ethernet header.
				// Copy the SYN IP header template.
				copy(ethIpBufferSyn[constants.EthernetHeaderSize:constants.EthernetHeaderSize+constants.IPv4HeaderSize], ipTcpSynTemplate)
				// Overwrite destination IP.
				copy(ethIpBufferSyn[constants.EthernetHeaderSize+16:constants.EthernetHeaderSize+20], host.Ip)
				// Compute and set IP header checksum.
				checksum = computeChecksum(ethIpBufferSyn[constants.EthernetHeaderSize : constants.EthernetHeaderSize+constants.IPv4HeaderSize])
				binary.BigEndian.PutUint16(ethIpBufferSyn[constants.EthernetHeaderSize+10:constants.EthernetHeaderSize+12], checksum)

				// Prepare the TCP pseudo-header for SYN scan.
				pseudoHeader = preparePseudoHeader(sourceIPBytes, host.Ip, constants.TrafficTCP, constants.TCPSynHeaderSize)

				// Loop through each port for SYN scan.
				for i, port := range c.ports {
					tcpSynHeaders[i] = tcpSynHeaderTemplate
					// Set destination port.
					binary.BigEndian.PutUint16(tcpSynHeaders[i][2:4], port)
					// Build buffer for checksum calculation.
					copy(pseudoHeaderAndTcpHeaderSyn[0:constants.TCPPseudoHeaderSize], pseudoHeader)
					copy(pseudoHeaderAndTcpHeaderSyn[constants.TCPPseudoHeaderSize:], tcpSynHeaders[i][:])
					tcpChecksum := computeChecksum(pseudoHeaderAndTcpHeaderSyn)
					binary.BigEndian.PutUint16(tcpSynHeaders[i][16:18], tcpChecksum)

					// Set up I/O vectors.
					ioVectors[currentIndex][0] = syscall.Iovec{
						Base: &ethIpBufferSyn[0],
						Len:  uint64(constants.EthernetHeaderSize + constants.IPv4HeaderSize),
					}
					ioVectors[currentIndex][1] = syscall.Iovec{
						Base: &tcpSynHeaders[i][0],
						Len:  uint64(constants.TCPSynHeaderSize),
					}
					messageHeaders[currentIndex].Msg = syscall.Msghdr{
						Name:    r.SocketParameters.SocketAddressName,
						Namelen: r.SocketParameters.SocketAddressNameLen,
						Iov:     &ioVectors[currentIndex][0],
						Iovlen:  2,
					}
					currentIndex++

					// If block is full, commit the block.
					if currentIndex == constants.IOVecPacketsChunkSize {
						if err = Limiter.Wait(context.Background()); err != nil {
							c.errorChan <- err
							return
						}
						_, _, errno := syscall.RawSyscall(
							syscall.SYS_SENDMMSG,
							c.socketFD,
							uintptr(unsafe.Pointer(&messageHeaders[0])),
							uintptr(currentIndex),
						)
						if errno != 0 {
							c.errorChan <- errno
							return
						}
						currentIndex = 0
					}
				}
			}

			// ----- VAV Scan Branch -----
			if c.rule.PortScanTechniques.Vav {
				// Prepare Ethernet+IP buffer for VAV scan.
				copy(ethIpBufferVav[0:6], host.Eth)                                        // Set destination MAC.
				copy(ethIpBufferVav[6:constants.EthernetHeaderSize], EthernetTemplate[6:]) // Copy rest of Ethernet header.
				// Copy the VAV IP header template.
				copy(ethIpBufferVav[constants.EthernetHeaderSize:constants.EthernetHeaderSize+constants.IPv4HeaderSize], ipTcpVavTemplate)
				// Overwrite destination IP.
				copy(ethIpBufferVav[constants.EthernetHeaderSize+16:constants.EthernetHeaderSize+20], host.Ip)
				// Compute and set IP header checksum.
				checksum = computeChecksum(ethIpBufferVav[constants.EthernetHeaderSize : constants.EthernetHeaderSize+constants.IPv4HeaderSize])
				binary.BigEndian.PutUint16(ethIpBufferVav[constants.EthernetHeaderSize+10:constants.EthernetHeaderSize+12], checksum)

				// Prepare the TCP pseudo-header for VAV scan.
				pseudoHeader = preparePseudoHeader(sourceIPBytes, host.Ip, constants.TrafficTCP, constants.TCPSynVavHeaderSize+constants.AcornSize)

				// Loop through each port for VAV scan.
				for i, port := range c.ports {
					tcpVavHeaders[i] = tcpVavHeaderTemplate
					// Set destination port.
					binary.BigEndian.PutUint16(tcpVavHeaders[i][2:4], port)
					// Build buffer for checksum calculation.
					copy(pseudoHeaderAndTcpHeaderVav[0:constants.TCPPseudoHeaderSize], pseudoHeader)
					copy(pseudoHeaderAndTcpHeaderVav[constants.TCPPseudoHeaderSize:constants.TCPPseudoHeaderSize+constants.TCPSynVavHeaderSize], tcpVavHeaders[i][:])
					copy(pseudoHeaderAndTcpHeaderVav[constants.TCPPseudoHeaderSize+constants.TCPSynVavHeaderSize:], constants.Acorn[:])
					checksum = computeChecksum(pseudoHeaderAndTcpHeaderVav)
					binary.BigEndian.PutUint16(tcpVavHeaders[i][16:18], checksum)

					// Set up I/O vectors.
					ioVectors[currentIndex][0] = syscall.Iovec{
						Base: &ethIpBufferVav[0],
						Len:  lenEthernetAndIp,
					}
					ioVectors[currentIndex][1] = syscall.Iovec{
						Base: &tcpVavHeaders[i][0],
						Len:  lenTcpVavHeader,
					}
					ioVectors[currentIndex][2] = syscall.Iovec{
						Base: &constants.Acorn[0],
						Len:  lenAcorn,
					}
					messageHeaders[currentIndex].Msg = syscall.Msghdr{
						Name:    r.SocketParameters.SocketAddressName,
						Namelen: r.SocketParameters.SocketAddressNameLen,
						Iov:     &ioVectors[currentIndex][0],
						Iovlen:  3,
					}
					currentIndex++

					// If block is full, commit the block.
					if currentIndex == constants.IOVecPacketsChunkSize {
						if err = Limiter.Wait(context.Background()); err != nil {
							c.errorChan <- err
							return
						}
						_, _, errno := syscall.RawSyscall(
							syscall.SYS_SENDMMSG,
							c.socketFD,
							uintptr(unsafe.Pointer(&messageHeaders[0])),
							uintptr(currentIndex),
						)
						if errno != 0 {
							c.errorChan <- errno
							return
						}
						currentIndex = 0
					}
				}
			}

			// ----- UDP Scan Branch -----
			if c.rule.PortScanTechniques.Udp {
				// Prepare Ethernet+IP buffer for UDP scan.
				copy(ethIpBufferUdp[0:6], host.Eth)                                        // Set destination MAC.
				copy(ethIpBufferUdp[6:constants.EthernetHeaderSize], EthernetTemplate[6:]) // Copy rest of Ethernet header.
				// Copy the UDP IP header template.
				copy(ethIpBufferUdp[constants.EthernetHeaderSize:constants.EthernetHeaderSize+constants.IPv4HeaderSize], ipUdpTemplate)
				// Overwrite destination IP.
				copy(ethIpBufferUdp[constants.EthernetHeaderSize+16:constants.EthernetHeaderSize+20], host.Ip)
				// Compute and set IP header checksum.
				checksum = computeChecksum(ethIpBufferUdp[constants.EthernetHeaderSize : constants.EthernetHeaderSize+constants.IPv4HeaderSize])
				binary.BigEndian.PutUint16(ethIpBufferUdp[constants.EthernetHeaderSize+10:constants.EthernetHeaderSize+12], checksum)

				// Loop through each port for UDP scan.
				for i, port := range c.ports {
					udpHeaders[i] = udpHeaderTemplate
					// Set destination port.
					binary.BigEndian.PutUint16(udpHeaders[i][2:4], port)
					// Prepare the UDP pseudo-header.
					pseudoHeader = preparePseudoHeader(sourceIPBytes, host.Ip, constants.TrafficUDP, constants.UDPHeaderSize)
					pseudoHeaderAndUdpHeader = make([]byte, constants.TCPPseudoHeaderSize+constants.UDPHeaderSize)
					copy(pseudoHeaderAndUdpHeader[0:constants.TCPPseudoHeaderSize], pseudoHeader)
					copy(pseudoHeaderAndUdpHeader[constants.TCPPseudoHeaderSize:], udpHeaders[i][:])
					checksum = computeChecksum(pseudoHeaderAndUdpHeader)
					binary.BigEndian.PutUint16(udpHeaders[i][6:8], checksum)

					// Set up I/O vectors.
					ioVectors[currentIndex][0] = syscall.Iovec{
						Base: &ethIpBufferUdp[0],
						Len:  lenEthernetAndIp,
					}
					ioVectors[currentIndex][1] = syscall.Iovec{
						Base: &udpHeaders[i][0],
						Len:  constants.UDPHeaderSize,
					}
					messageHeaders[currentIndex].Msg = syscall.Msghdr{
						Name:    r.SocketParameters.SocketAddressName,
						Namelen: r.SocketParameters.SocketAddressNameLen,
						Iov:     &ioVectors[currentIndex][0],
						Iovlen:  2,
					}
					currentIndex++

					// If block is full, commit the block.
					if currentIndex == constants.IOVecPacketsChunkSize {
						if err = Limiter.Wait(context.Background()); err != nil {
							c.errorChan <- err
							return
						}
						_, _, errno := syscall.RawSyscall(
							syscall.SYS_SENDMMSG,
							c.socketFD,
							uintptr(unsafe.Pointer(&messageHeaders[0])),
							uintptr(currentIndex),
						)
						if errno != 0 {
							c.errorChan <- errno
							return
						}
						currentIndex = 0
					}
				}
			}

			// Commit any leftover messages for the current host.
			if currentIndex > 0 {
				if err = Limiter.Wait(context.Background()); err != nil {
					c.errorChan <- err
					return
				}
				_, _, errno := syscall.RawSyscall(
					syscall.SYS_SENDMMSG,
					c.socketFD,
					uintptr(unsafe.Pointer(&messageHeaders[0])),
					uintptr(currentIndex),
				)
				if errno != 0 {
					c.errorChan <- errno
					return
				}
			}
		}
	}

	// Allow some time to receive responses before finishing.
	time.Sleep(constants.DefaultTimeout)

	// Signal that port scanning is complete.
	r.PortsDiscoveryDoneChan <- true
}

// ScanPortsOverGateway scans hosts via a gateway.
// The r.UpHostsChan channel carries only target IP addresses.
// The constructed packets include an Ethernet header built from the source interface
// and the provided gatewayMac. Buffers and header templates are reused to minimize allocations.
func ScanPortsOverGateway(c *scannerContext, r *router.IpRangeRouteContext, portsScanWg *sync.WaitGroup, gatewayMac net.HardwareAddr) {
	// Defer cleanup actions.
	defer portsScanWg.Done()
	defer close(r.ReadyToInterceptPortsStateChan)
	//defer fmt.Println("DEBUG: ScanPortsOverGateway is done")

	var (
		// IP header templates for each scan type.
		ipTcpSynTemplate []byte
		ipTcpVavTemplate []byte
		ipUdpTemplate    []byte

		// Ethernet header template.
		ethHeader []byte

		// IP header buffers (reused per host).
		ipBufferSyn []byte
		ipBufferVav []byte
		ipBufferUdp []byte

		// Source IP in 4-byte format.
		sourceIPBytes = r.Route.Src.To4()

		// Temporary variable for computing checksums.
		checksum uint16
		// Buffer for concatenating pseudo-header with transport headers.
		pseudoHeader []byte

		// Buffers for concatenating pseudo-header with TCP/UDP headers for checksum calculation.
		pseudoHeaderAndTcpHeaderSyn []byte
		pseudoHeaderAndTcpHeaderVav []byte
		pseudoHeaderAndUdpHeader    []byte

		// Slices of transport headers for all ports.
		tcpSynHeaders [][constants.TCPSynHeaderSize]byte
		tcpVavHeaders [][constants.TCPSynVavHeaderSize]byte
		udpHeaders    [][constants.UDPHeaderSize]byte

		// Header templates (with predefined source port).
		tcpSynHeaderTemplate [constants.TCPSynHeaderSize]byte
		tcpVavHeaderTemplate [constants.TCPSynVavHeaderSize]byte
		udpHeaderTemplate    [constants.UDPHeaderSize]byte

		// Message headers and I/O vectors for the sendmmsg syscall.
		messageHeaders [constants.IOVecPacketsChunkSize]Mmsghdr
		ioVectors      [constants.IOVecPacketsChunkSize][4]syscall.Iovec

		// Counter for the number of scan types enabled.
		scanTypesCount int

		// Error and other temporary variables.
		err error
	)

	// Compile BPF filter for capturing transport-layer responses.
	var bpfExpression *pcap.BPF
	bpfExpression, err = compileTransportStateDetectionBPF(c, r)
	if err != nil {
		c.errorChan <- err
		return
	}

	// Start a goroutine to intercept TCP/UDP responses.
	portsScanWg.Add(1)
	go interceptTransportResponses(c, r, bpfExpression, portsScanWg)

	// Prepare Ethernet header.
	ethHeader = prepareEthernetPart(r.SocketParameters.SourceInterface.HardwareAddr, gatewayMac, constants.EtherTypeIPv4)

	// Wait until the interceptor is ready.
	<-r.ReadyToInterceptPortsStateChan

	// Prepare headers and buffers for each enabled scan technique.
	if c.rule.PortScanTechniques.Syn {
		scanTypesCount++
		// Build IP header template for SYN scan (IP header + TCP SYN header).
		ipTcpSynTemplate = prepareIpv4PartTemplate(
			r.Route.Src,
			constants.IPv4HeaderSize+constants.TCPSynHeaderSize,
			constants.TrafficTCP,
		)
		// Allocate IP header buffer for SYN scan.
		ipBufferSyn = make([]byte, constants.IPv4HeaderSize)
		// Allocate buffer for pseudo-header + TCP SYN header.
		pseudoHeaderAndTcpHeaderSyn = make([]byte, constants.TCPPseudoHeaderSize+constants.TCPSynHeaderSize)
		// Allocate slice for TCP SYN headers (one per port).
		tcpSynHeaders = make([][constants.TCPSynHeaderSize]byte, len(c.ports))
		// Initialize the SYN header template with the source port.
		tcpSynHeaderTemplate = constants.TCPSynHeader
		binary.BigEndian.PutUint16(tcpSynHeaderTemplate[0:2], r.SourcePort)
	}

	if c.rule.PortScanTechniques.Vav {
		scanTypesCount++
		// Build IP header template for VAV scan (IP header + TCP VAV header + payload).
		ipTcpVavTemplate = prepareIpv4PartTemplate(
			r.Route.Src,
			constants.IPv4HeaderSize+constants.TCPSynVavHeaderSize+constants.AcornSize,
			constants.TrafficTCP,
		)
		// Allocate IP header buffer for VAV scan.
		ipBufferVav = make([]byte, constants.IPv4HeaderSize)
		// Allocate buffer for pseudo-header + TCP VAV header + payload.
		pseudoHeaderAndTcpHeaderVav = make([]byte, constants.TCPPseudoHeaderSize+constants.TCPSynVavHeaderSize+constants.AcornSize)
		// Allocate slice for TCP VAV headers (one per port).
		tcpVavHeaders = make([][constants.TCPSynVavHeaderSize]byte, len(c.ports))
		// Initialize the VAV header template with the source port.
		tcpVavHeaderTemplate = constants.TCPSynVavHeader
		binary.BigEndian.PutUint16(tcpVavHeaderTemplate[0:2], r.SourcePort)
	}

	if c.rule.PortScanTechniques.Udp {
		scanTypesCount++
		// Build IP header template for UDP scan (IP header + UDP header).
		ipUdpTemplate = prepareIpv4PartTemplate(
			r.Route.Src,
			constants.IPv4HeaderSize+constants.UDPHeaderSize,
			constants.TrafficUDP,
		)
		// Allocate IP header buffer for UDP scan.
		ipBufferUdp = make([]byte, constants.IPv4HeaderSize)
		// Allocate slice for UDP headers (one per port).
		udpHeaders = make([][constants.UDPHeaderSize]byte, len(c.ports))
		// Initialize the UDP header template with the source port.
		udpHeaderTemplate = constants.UdpHeader
		binary.BigEndian.PutUint16(udpHeaderTemplate[0:2], r.SourcePort)
	}

	// Determine batching strategy based on total packets.
	totalPackets := len(c.ports) * scanTypesCount

	switch {
	// If total packets is less than the chunk size, process each host as a single batch.
	case totalPackets < constants.IOVecPacketsChunkSize:
		for host := range r.UpHostsChan {
			currentIndex := 0

			// ----- SYN Scan Branch -----
			if c.rule.PortScanTechniques.Syn {
				copy(ipBufferSyn, ipTcpSynTemplate)
				// Overwrite destination IP (offset 16).
				copy(ipBufferSyn[16:20], host.Ip)
				checksum = computeChecksum(ipBufferSyn)
				binary.BigEndian.PutUint16(ipBufferSyn[10:12], checksum)

				pseudoHeader = preparePseudoHeader(sourceIPBytes, host.Ip, constants.TrafficTCP, constants.TCPSynHeaderSize)

				for i, port := range c.ports {
					tcpSynHeaders[i] = tcpSynHeaderTemplate
					binary.BigEndian.PutUint16(tcpSynHeaders[i][2:4], port)

					copy(pseudoHeaderAndTcpHeaderSyn[0:constants.TCPPseudoHeaderSize], pseudoHeader)
					copy(pseudoHeaderAndTcpHeaderSyn[constants.TCPPseudoHeaderSize:], tcpSynHeaders[i][:])
					checksum = computeChecksum(pseudoHeaderAndTcpHeaderSyn)
					binary.BigEndian.PutUint16(tcpSynHeaders[i][16:18], checksum)

					// IOVec: Ethernet, IP, TCP.
					ioVectors[currentIndex][0] = syscall.Iovec{
						Base: &ethHeader[0],
						Len:  constants.EthernetHeaderSize,
					}
					ioVectors[currentIndex][1] = syscall.Iovec{
						Base: &ipBufferSyn[0],
						Len:  uint64(constants.IPv4HeaderSize),
					}
					ioVectors[currentIndex][2] = syscall.Iovec{
						Base: &tcpSynHeaders[i][0],
						Len:  uint64(constants.TCPSynHeaderSize),
					}
					messageHeaders[currentIndex].Msg = syscall.Msghdr{
						Name:    r.SocketParameters.SocketAddressName,
						Namelen: r.SocketParameters.SocketAddressNameLen,
						Iov:     &ioVectors[currentIndex][0],
						Iovlen:  3,
					}
					currentIndex++
				}
			}

			// ----- VAV Scan Branch -----
			if c.rule.PortScanTechniques.Vav {
				copy(ipBufferVav, ipTcpVavTemplate)
				copy(ipBufferVav[16:20], host.Ip)
				checksum = computeChecksum(ipBufferVav)
				binary.BigEndian.PutUint16(ipBufferVav[10:12], checksum)

				pseudoHeader = preparePseudoHeader(sourceIPBytes, host.Ip, constants.TrafficTCP, constants.TCPSynVavHeaderSize+constants.AcornSize)

				for i, port := range c.ports {
					tcpVavHeaders[i] = tcpVavHeaderTemplate
					binary.BigEndian.PutUint16(tcpVavHeaders[i][2:4], port)

					copy(pseudoHeaderAndTcpHeaderVav[0:constants.TCPPseudoHeaderSize], pseudoHeader)
					copy(pseudoHeaderAndTcpHeaderVav[constants.TCPPseudoHeaderSize:constants.TCPPseudoHeaderSize+constants.TCPSynVavHeaderSize], tcpVavHeaders[i][:])
					copy(pseudoHeaderAndTcpHeaderVav[constants.TCPPseudoHeaderSize+constants.TCPSynVavHeaderSize:], constants.Acorn[:])
					checksum = computeChecksum(pseudoHeaderAndTcpHeaderVav)
					binary.BigEndian.PutUint16(tcpVavHeaders[i][16:18], checksum)

					// IOVec: Ethernet, IP, TCP VAV header, payload.
					ioVectors[currentIndex][0] = syscall.Iovec{
						Base: &ethHeader[0],
						Len:  uint64(constants.EthernetHeaderSize),
					}
					ioVectors[currentIndex][1] = syscall.Iovec{
						Base: &ipBufferVav[0],
						Len:  uint64(constants.IPv4HeaderSize),
					}
					ioVectors[currentIndex][2] = syscall.Iovec{
						Base: &tcpVavHeaders[i][0],
						Len:  uint64(constants.TCPSynVavHeaderSize),
					}
					ioVectors[currentIndex][3] = syscall.Iovec{
						Base: &constants.Acorn[0],
						Len:  uint64(constants.AcornSize),
					}
					messageHeaders[currentIndex].Msg = syscall.Msghdr{
						Name:    r.SocketParameters.SocketAddressName,
						Namelen: r.SocketParameters.SocketAddressNameLen,
						Iov:     &ioVectors[currentIndex][0],
						Iovlen:  4,
					}
					currentIndex++
				}
			}

			// ----- UDP Scan Branch -----
			if c.rule.PortScanTechniques.Udp {
				copy(ipBufferUdp, ipUdpTemplate)
				copy(ipBufferUdp[16:20], host.Ip)
				checksum = computeChecksum(ipBufferUdp)
				binary.BigEndian.PutUint16(ipBufferUdp[10:12], checksum)

				for i, port := range c.ports {
					udpHeaders[i] = udpHeaderTemplate
					binary.BigEndian.PutUint16(udpHeaders[i][2:4], port)

					pseudoHeader = preparePseudoHeader(sourceIPBytes, host.Ip, constants.TrafficUDP, constants.UDPHeaderSize)
					pseudoHeaderAndUdpHeader = pseudoHeaderAndUdpHeader[:0]
					pseudoHeaderAndUdpHeader = append(pseudoHeaderAndUdpHeader, pseudoHeader...)
					pseudoHeaderAndUdpHeader = append(pseudoHeaderAndUdpHeader, udpHeaders[i][:]...)
					checksum = computeChecksum(pseudoHeaderAndUdpHeader)
					binary.BigEndian.PutUint16(udpHeaders[i][6:8], checksum)

					// IOVec: Ethernet, IP, UDP.
					ioVectors[currentIndex][0] = syscall.Iovec{
						Base: &ethHeader[0],
						Len:  uint64(constants.EthernetHeaderSize),
					}
					ioVectors[currentIndex][1] = syscall.Iovec{
						Base: &ipBufferUdp[0],
						Len:  uint64(constants.IPv4HeaderSize),
					}
					ioVectors[currentIndex][2] = syscall.Iovec{
						Base: &udpHeaders[i][0],
						Len:  uint64(constants.UDPHeaderSize),
					}
					messageHeaders[currentIndex].Msg = syscall.Msghdr{
						Name:    r.SocketParameters.SocketAddressName,
						Namelen: r.SocketParameters.SocketAddressNameLen,
						Iov:     &ioVectors[currentIndex][0],
						Iovlen:  3,
					}
					currentIndex++
				}
			}

			// Wait for the rate limiter before sending the batch.
			if err = Limiter.Wait(context.Background()); err != nil {
				c.errorChan <- err
				return
			}
			_, _, errno := syscall.RawSyscall(
				syscall.SYS_SENDMMSG,
				c.socketFD,
				uintptr(unsafe.Pointer(&messageHeaders[0])),
				uintptr(currentIndex),
			)
			if errno != 0 {
				c.errorChan <- errno
				return
			}
		}

	// Default: total packets is greater or equal to constants.IOVecPacketsChunkSize.
	default:
		for host := range r.UpHostsChan {
			currentIndex := 0

			// ----- SYN Scan Branch -----
			if c.rule.PortScanTechniques.Syn {
				copy(ipBufferSyn, ipTcpSynTemplate)
				copy(ipBufferSyn[16:20], host.Ip)
				checksum = computeChecksum(ipBufferSyn)
				binary.BigEndian.PutUint16(ipBufferSyn[10:12], checksum)

				pseudoHeader = preparePseudoHeader(sourceIPBytes, host.Ip, constants.TrafficTCP, constants.TCPSynHeaderSize)

				for i, port := range c.ports {
					tcpSynHeaders[i] = tcpSynHeaderTemplate
					binary.BigEndian.PutUint16(tcpSynHeaders[i][2:4], port)

					copy(pseudoHeaderAndTcpHeaderSyn[0:constants.TCPPseudoHeaderSize], pseudoHeader)
					copy(pseudoHeaderAndTcpHeaderSyn[constants.TCPPseudoHeaderSize:], tcpSynHeaders[i][:])
					checksum = computeChecksum(pseudoHeaderAndTcpHeaderSyn)
					binary.BigEndian.PutUint16(tcpSynHeaders[i][16:18], checksum)

					ioVectors[currentIndex][0] = syscall.Iovec{
						Base: &ethHeader[0],
						Len:  constants.EthernetHeaderSize,
					}
					ioVectors[currentIndex][1] = syscall.Iovec{
						Base: &ipBufferSyn[0],
						Len:  uint64(constants.IPv4HeaderSize),
					}
					ioVectors[currentIndex][2] = syscall.Iovec{
						Base: &tcpSynHeaders[i][0],
						Len:  uint64(constants.TCPSynHeaderSize),
					}
					messageHeaders[currentIndex].Msg = syscall.Msghdr{
						Name:    r.SocketParameters.SocketAddressName,
						Namelen: r.SocketParameters.SocketAddressNameLen,
						Iov:     &ioVectors[currentIndex][0],
						Iovlen:  3,
					}
					currentIndex++
					// If block is full, send batch.
					if currentIndex == constants.IOVecPacketsChunkSize {
						if err = Limiter.Wait(context.Background()); err != nil {
							c.errorChan <- err
							return
						}
						_, _, errno := syscall.RawSyscall(
							syscall.SYS_SENDMMSG,
							c.socketFD,
							uintptr(unsafe.Pointer(&messageHeaders[0])),
							uintptr(currentIndex),
						)
						if errno != 0 {
							c.errorChan <- errno
							return
						}
						currentIndex = 0
					}
				}
			}

			// ----- VAV Scan Branch -----
			if c.rule.PortScanTechniques.Vav {
				copy(ipBufferVav, ipTcpVavTemplate)
				copy(ipBufferVav[16:20], host.Ip)
				checksum = computeChecksum(ipBufferVav)
				binary.BigEndian.PutUint16(ipBufferVav[10:12], checksum)

				pseudoHeader = preparePseudoHeader(sourceIPBytes, host.Ip, constants.TrafficTCP,
					constants.TCPSynVavHeaderSize+constants.AcornSize)

				for i, port := range c.ports {
					tcpVavHeaders[i] = tcpVavHeaderTemplate
					binary.BigEndian.PutUint16(tcpVavHeaders[i][2:4], port)

					copy(pseudoHeaderAndTcpHeaderVav[0:constants.TCPPseudoHeaderSize], pseudoHeader)
					copy(pseudoHeaderAndTcpHeaderVav[constants.TCPPseudoHeaderSize:constants.TCPPseudoHeaderSize+constants.TCPSynVavHeaderSize], tcpVavHeaders[i][:])
					copy(pseudoHeaderAndTcpHeaderVav[constants.TCPPseudoHeaderSize+constants.TCPSynVavHeaderSize:], constants.Acorn[:])
					checksum = computeChecksum(pseudoHeaderAndTcpHeaderVav)
					binary.BigEndian.PutUint16(tcpVavHeaders[i][16:18], checksum)

					ioVectors[currentIndex][0] = syscall.Iovec{
						Base: &ethHeader[0],
						Len:  uint64(constants.EthernetHeaderSize),
					}
					ioVectors[currentIndex][1] = syscall.Iovec{
						Base: &ipBufferVav[0],
						Len:  uint64(constants.IPv4HeaderSize),
					}
					ioVectors[currentIndex][2] = syscall.Iovec{
						Base: &tcpVavHeaders[i][0],
						Len:  uint64(constants.TCPSynVavHeaderSize),
					}
					ioVectors[currentIndex][3] = syscall.Iovec{
						Base: &constants.Acorn[0],
						Len:  uint64(constants.AcornSize),
					}
					messageHeaders[currentIndex].Msg = syscall.Msghdr{
						Name:    r.SocketParameters.SocketAddressName,
						Namelen: r.SocketParameters.SocketAddressNameLen,
						Iov:     &ioVectors[currentIndex][0],
						Iovlen:  4,
					}
					currentIndex++
					if currentIndex == constants.IOVecPacketsChunkSize {
						if err = Limiter.Wait(context.Background()); err != nil {
							c.errorChan <- err
							return
						}
						_, _, errno := syscall.RawSyscall(
							syscall.SYS_SENDMMSG,
							c.socketFD,
							uintptr(unsafe.Pointer(&messageHeaders[0])),
							uintptr(currentIndex),
						)
						if errno != 0 {
							c.errorChan <- errno
							return
						}
						currentIndex = 0
					}
				}
			}

			// ----- UDP Scan Branch -----
			if c.rule.PortScanTechniques.Udp {
				copy(ipBufferUdp, ipUdpTemplate)
				copy(ipBufferUdp[16:20], host.Ip)
				checksum = computeChecksum(ipBufferUdp)
				binary.BigEndian.PutUint16(ipBufferUdp[10:12], checksum)

				for i, port := range c.ports {
					udpHeaders[i] = udpHeaderTemplate
					binary.BigEndian.PutUint16(udpHeaders[i][2:4], port)

					pseudoHeader = preparePseudoHeader(sourceIPBytes, host.Ip, constants.TrafficUDP, constants.UDPHeaderSize)
					pseudoHeaderAndUdpHeader = pseudoHeaderAndUdpHeader[:0]
					pseudoHeaderAndUdpHeader = append(pseudoHeaderAndUdpHeader, pseudoHeader...)
					pseudoHeaderAndUdpHeader = append(pseudoHeaderAndUdpHeader, udpHeaders[i][:]...)
					checksum = computeChecksum(pseudoHeaderAndUdpHeader)
					binary.BigEndian.PutUint16(udpHeaders[i][6:8], checksum)

					ioVectors[currentIndex][0] = syscall.Iovec{
						Base: &ethHeader[0],
						Len:  uint64(constants.EthernetHeaderSize),
					}
					ioVectors[currentIndex][1] = syscall.Iovec{
						Base: &ipBufferUdp[0],
						Len:  uint64(constants.IPv4HeaderSize),
					}
					ioVectors[currentIndex][2] = syscall.Iovec{
						Base: &udpHeaders[i][0],
						Len:  uint64(constants.UDPHeaderSize),
					}
					messageHeaders[currentIndex].Msg = syscall.Msghdr{
						Name:    r.SocketParameters.SocketAddressName,
						Namelen: r.SocketParameters.SocketAddressNameLen,
						Iov:     &ioVectors[currentIndex][0],
						Iovlen:  3,
					}
					currentIndex++
					if currentIndex == constants.IOVecPacketsChunkSize {
						if err = Limiter.Wait(context.Background()); err != nil {
							c.errorChan <- err
							return
						}
						_, _, errno := syscall.RawSyscall(
							syscall.SYS_SENDMMSG,
							c.socketFD,
							uintptr(unsafe.Pointer(&messageHeaders[0])),
							uintptr(currentIndex),
						)
						if errno != 0 {
							c.errorChan <- errno
							return
						}
						currentIndex = 0
					}
				}
			}

			// Commit any leftover messages.
			if currentIndex > 0 {
				if err = Limiter.Wait(context.Background()); err != nil {
					c.errorChan <- err
					return
				}
				_, _, errno := syscall.RawSyscall(
					syscall.SYS_SENDMMSG,
					c.socketFD,
					uintptr(unsafe.Pointer(&messageHeaders[0])),
					uintptr(currentIndex),
				)
				if errno != 0 {
					c.errorChan <- errno
					return
				}
			}
		}
	}

	// Allow some time to receive responses before finishing.
	time.Sleep(constants.DefaultTimeout)

	// Signal that port scanning is complete.
	r.PortsDiscoveryDoneChan <- true
}

func scanWithoutHostDiscovery(c *scannerContext, r *router.IpRangeRouteContext, ipRangeScannerWg *sync.WaitGroup) {
	defer ipRangeScannerWg.Done()
	//defer fmt.Println("DEBUG: scanWithoutHostDiscovery is done")

	var (
		gatewayMacAddress net.HardwareAddr
		bpfExpression     *pcap.BPF

		// IP header templates for each scan type.
		ipTcpSynTemplate []byte
		ipTcpVavTemplate []byte
		ipUdpTemplate    []byte

		// Ethernet header template.
		ethHeader []byte

		// Source IP in 4-byte format.
		sourceIPBytes = r.Route.Src.To4()

		// Temporary variable for checksum calculation.
		checksum     uint16
		pseudoHeader []byte

		// Buffers for concatenating pseudo-header with transport headers.
		pseudoHeaderAndTcpHeaderSyn []byte
		pseudoHeaderAndTcpHeaderVav []byte
		pseudoHeaderAndUdpHeader    []byte

		// Transport header templates (with predefined source port).
		tcpSynHeaderTemplate [constants.TCPSynHeaderSize]byte
		tcpVavHeaderTemplate [constants.TCPSynVavHeaderSize]byte
		udpHeaderTemplate    [constants.UDPHeaderSize]byte

		// Message headers and I/O vectors for sendmmsg.
		messageHeaders [constants.IOVecPacketsChunkSize]Mmsghdr
		ioVectors      [constants.IOVecPacketsChunkSize][4]syscall.Iovec

		// currentIndex counts the number of messages in the current block.
		currentIndex int
		err          error
	)

	// Obtain the gateway MAC address.
	gatewayMacAddress, err = utils.GetHardwareAddrFromARP(r.Route.Gw)
	if err != nil {
		c.errorChan <- err
		return
	}
	if gatewayMacAddress == nil {
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

	// Compile BPF filter.
	bpfExpression, err = compileTransportStateDetectionBPF(c, r)
	if err != nil {
		c.errorChan <- err
		return
	}

	// Start intercepting transport responses.
	ipRangeScannerWg.Add(1)
	go interceptTransportResponses(c, r, bpfExpression, ipRangeScannerWg)

	// Prepare the Ethernet header.
	ethHeader = prepareEthernetPart(r.SocketParameters.SourceInterface.HardwareAddr, gatewayMacAddress, constants.EtherTypeIPv4)

	// Allocate fixed buffers for pseudo-header concatenation.
	pseudoHeaderAndTcpHeaderSyn = make([]byte, constants.TCPPseudoHeaderSize+constants.TCPSynHeaderSize)
	pseudoHeaderAndTcpHeaderVav = make([]byte, constants.TCPPseudoHeaderSize+constants.TCPSynVavHeaderSize+constants.AcornSize)

	// Initialize transport header templates with the source port.
	if c.rule.PortScanTechniques.Syn {
		tcpSynHeaderTemplate = constants.TCPSynHeader
		binary.BigEndian.PutUint16(tcpSynHeaderTemplate[0:2], r.SourcePort)
	}
	if c.rule.PortScanTechniques.Vav {
		tcpVavHeaderTemplate = constants.TCPSynVavHeader
		binary.BigEndian.PutUint16(tcpVavHeaderTemplate[0:2], r.SourcePort)
	}
	if c.rule.PortScanTechniques.Udp {
		udpHeaderTemplate = constants.UdpHeader
		binary.BigEndian.PutUint16(udpHeaderTemplate[0:2], r.SourcePort)
	}

	// Prepare IP header templates.
	if c.rule.PortScanTechniques.Syn {
		ipTcpSynTemplate = prepareIpv4PartTemplate(r.Route.Src, constants.IPv4HeaderSize+constants.TCPSynHeaderSize, constants.TrafficTCP)
	}
	if c.rule.PortScanTechniques.Vav {
		ipTcpVavTemplate = prepareIpv4PartTemplate(r.Route.Src, constants.IPv4HeaderSize+constants.TCPSynVavHeaderSize+constants.AcornSize, constants.TrafficTCP)
	}
	if c.rule.PortScanTechniques.Udp {
		ipUdpTemplate = prepareIpv4PartTemplate(r.Route.Src, constants.IPv4HeaderSize+constants.UDPHeaderSize, constants.TrafficUDP)
	}

	// Wait until the interceptor is ready.
	<-r.ReadyToInterceptPortsStateChan

	// Process IP addresses in chunks.
	for ipChunk := range utils.IPRangeBytesChunks(r.Start, r.End) {
		chunkLen := len(ipChunk)
		// Allocate fixed local buffers for IP headers for this chunk.
		var synIPBuffer, vavIPBuffer, udpIPBuffer []byte
		if c.rule.PortScanTechniques.Syn {
			synIPBuffer = make([]byte, constants.IPv4HeaderSize*chunkLen)
		}
		if c.rule.PortScanTechniques.Vav {
			vavIPBuffer = make([]byte, constants.IPv4HeaderSize*chunkLen)
		}
		if c.rule.PortScanTechniques.Udp {
			udpIPBuffer = make([]byte, constants.IPv4HeaderSize*chunkLen)
		}

		// For each IP in the chunk, fill its portion of the fixed IP header buffers.
		for ipIndex, ip := range ipChunk {
			if c.rule.PortScanTechniques.Syn {
				buf := synIPBuffer[ipIndex*constants.IPv4HeaderSize : (ipIndex+1)*constants.IPv4HeaderSize]
				copy(buf, ipTcpSynTemplate)
				// Overwrite destination IP in the IP header.
				copy(buf[16:], ip[:])
				checksum = computeChecksum(buf)
				binary.BigEndian.PutUint16(buf[10:12], checksum)
			}
			if c.rule.PortScanTechniques.Vav {

				buf := vavIPBuffer[ipIndex*constants.IPv4HeaderSize : (ipIndex+1)*constants.IPv4HeaderSize]
				copy(buf, ipTcpVavTemplate)
				// For VAV, destination IP is 4 bytes at offset 16.
				copy(buf[16:20], ip[:])
				checksum = computeChecksum(buf)
				binary.BigEndian.PutUint16(buf[10:12], checksum)
			}
			if c.rule.PortScanTechniques.Udp {
				buf := udpIPBuffer[ipIndex*constants.IPv4HeaderSize : (ipIndex+1)*constants.IPv4HeaderSize]
				copy(buf, ipUdpTemplate)
				copy(buf[16:20], ip[:])
				checksum = computeChecksum(buf)
				binary.BigEndian.PutUint16(buf[10:12], checksum)
			}

			// Process each IP for each scan type.
			// ----- SYN Scan Branch -----
			if c.rule.PortScanTechniques.Syn {
				// Prepare pseudo-header for this IP.
				pseudoHeader = preparePseudoHeader(sourceIPBytes, ip[:], constants.TrafficTCP, constants.TCPSynHeaderSize)
				tcpSynHeaders := make([][constants.TCPSynHeaderSize]byte, len(c.ports))
				for i, port := range c.ports {
					// Update transport header template for current port.
					tcpSynHeaders[i] = tcpSynHeaderTemplate
					binary.BigEndian.PutUint16(tcpSynHeaders[i][2:4], port)
					// Build pseudo-header concatenated with TCP header for checksum.
					copy(pseudoHeaderAndTcpHeaderSyn[0:constants.TCPPseudoHeaderSize], pseudoHeader)
					copy(pseudoHeaderAndTcpHeaderSyn[constants.TCPPseudoHeaderSize:], tcpSynHeaders[i][:])
					checksum = computeChecksum(pseudoHeaderAndTcpHeaderSyn)
					binary.BigEndian.PutUint16(tcpSynHeaders[i][16:18], checksum)

					// Fill iovec with pointers to Ethernet, IP, and TCP header buffers.
					ioVectors[currentIndex][0] = syscall.Iovec{
						Base: &ethHeader[0],
						Len:  constants.EthernetHeaderSize,
					}
					ioVectors[currentIndex][1] = syscall.Iovec{
						Base: &synIPBuffer[ipIndex*constants.IPv4HeaderSize],
						Len:  uint64(constants.IPv4HeaderSize),
					}
					ioVectors[currentIndex][2] = syscall.Iovec{
						Base: &tcpSynHeaders[i][0],
						Len:  uint64(constants.TCPSynHeaderSize),
					}
					messageHeaders[currentIndex].Msg = syscall.Msghdr{
						Name:    r.SocketParameters.SocketAddressName,
						Namelen: r.SocketParameters.SocketAddressNameLen,
						Iov:     &ioVectors[currentIndex][0],
						Iovlen:  3,
					}
					currentIndex++
					// If the iovec block is full, send it immediately.
					if currentIndex == constants.IOVecPacketsChunkSize {
						if err = Limiter.Wait(context.Background()); err != nil {
							c.errorChan <- err
							return
						}
						_, _, errno := syscall.RawSyscall(
							syscall.SYS_SENDMMSG,
							c.socketFD,
							uintptr(unsafe.Pointer(&messageHeaders[0])),
							uintptr(currentIndex),
						)
						if errno != 0 {
							c.errorChan <- errno
							return
						}
						currentIndex = 0
					}
				}
			}

			// ----- VAV Scan Branch -----
			if c.rule.PortScanTechniques.Vav {
				// Prepare pseudo-header for VAV scan.
				tcpVavHeaders := make([][constants.TCPSynVavHeaderSize]byte, len(c.ports))
				pseudoHeader = preparePseudoHeader(sourceIPBytes, ip[:], constants.TrafficTCP, constants.TCPSynVavHeaderSize+constants.AcornSize)
				for i, port := range c.ports {
					tcpVavHeaders[i] = tcpVavHeaderTemplate
					binary.BigEndian.PutUint16(tcpVavHeaders[i][2:4], port)
					copy(pseudoHeaderAndTcpHeaderVav[0:constants.TCPPseudoHeaderSize], pseudoHeader)
					copy(pseudoHeaderAndTcpHeaderVav[constants.TCPPseudoHeaderSize:constants.TCPPseudoHeaderSize+constants.TCPSynVavHeaderSize], tcpVavHeaders[i][:])
					copy(pseudoHeaderAndTcpHeaderVav[constants.TCPPseudoHeaderSize+constants.TCPSynVavHeaderSize:], constants.Acorn[:])
					checksum = computeChecksum(pseudoHeaderAndTcpHeaderVav)
					binary.BigEndian.PutUint16(tcpVavHeaders[i][16:18], checksum)

					ioVectors[currentIndex][0] = syscall.Iovec{
						Base: &ethHeader[0],
						Len:  uint64(constants.EthernetHeaderSize),
					}
					ioVectors[currentIndex][1] = syscall.Iovec{
						Base: &vavIPBuffer[ipIndex*constants.IPv4HeaderSize],
						Len:  uint64(constants.IPv4HeaderSize),
					}
					ioVectors[currentIndex][2] = syscall.Iovec{
						Base: &tcpVavHeaders[i][0],
						Len:  uint64(constants.TCPSynVavHeaderSize),
					}
					ioVectors[currentIndex][3] = syscall.Iovec{
						Base: &constants.Acorn[0],
						Len:  uint64(constants.AcornSize),
					}
					messageHeaders[currentIndex].Msg = syscall.Msghdr{
						Name:    r.SocketParameters.SocketAddressName,
						Namelen: r.SocketParameters.SocketAddressNameLen,
						Iov:     &ioVectors[currentIndex][0],
						Iovlen:  4,
					}
					currentIndex++
					if currentIndex == constants.IOVecPacketsChunkSize {
						if err = Limiter.Wait(context.Background()); err != nil {
							c.errorChan <- err
							return
						}
						_, _, errno := syscall.RawSyscall(
							syscall.SYS_SENDMMSG,
							c.socketFD,
							uintptr(unsafe.Pointer(&messageHeaders[0])),
							uintptr(currentIndex),
						)
						if errno != 0 {
							c.errorChan <- errno
							return
						}
						currentIndex = 0
					}
				}
			}

			// ----- UDP Scan Branch -----
			if c.rule.PortScanTechniques.Udp {
				udpHeaders := make([][constants.UDPHeaderSize]byte, len(c.ports))
				for i, port := range c.ports {
					udpHeaders[i] = udpHeaderTemplate
					binary.BigEndian.PutUint16(udpHeaders[i][2:4], port)
					pseudoHeader = preparePseudoHeader(sourceIPBytes, ip[:], constants.TrafficUDP, constants.UDPHeaderSize)
					// Reuse pseudoHeaderAndUdpHeader slice (with preset capacity)
					pseudoHeaderAndUdpHeader = pseudoHeaderAndUdpHeader[:0]
					pseudoHeaderAndUdpHeader = append(pseudoHeaderAndUdpHeader, pseudoHeader...)
					pseudoHeaderAndUdpHeader = append(pseudoHeaderAndUdpHeader, udpHeaders[i][:]...)
					checksum = computeChecksum(pseudoHeaderAndUdpHeader)
					binary.BigEndian.PutUint16(udpHeaders[i][6:8], checksum)

					ioVectors[currentIndex][0] = syscall.Iovec{
						Base: &ethHeader[0],
						Len:  uint64(constants.EthernetHeaderSize),
					}
					ioVectors[currentIndex][1] = syscall.Iovec{
						Base: &udpIPBuffer[ipIndex*constants.IPv4HeaderSize],
						Len:  uint64(constants.IPv4HeaderSize),
					}
					ioVectors[currentIndex][2] = syscall.Iovec{
						Base: &udpHeaders[i][0],
						Len:  uint64(constants.UDPHeaderSize),
					}
					messageHeaders[currentIndex].Msg = syscall.Msghdr{
						Name:    r.SocketParameters.SocketAddressName,
						Namelen: r.SocketParameters.SocketAddressNameLen,
						Iov:     &ioVectors[currentIndex][0],
						Iovlen:  3,
					}
					currentIndex++
					if currentIndex == constants.IOVecPacketsChunkSize {
						if err = Limiter.Wait(context.Background()); err != nil {
							c.errorChan <- err
							return
						}
						_, _, errno := syscall.RawSyscall(
							syscall.SYS_SENDMMSG,
							c.socketFD,
							uintptr(unsafe.Pointer(&messageHeaders[0])),
							uintptr(currentIndex),
						)
						if errno != 0 {
							c.errorChan <- errno
							return
						}
						currentIndex = 0
					}
				}
			}
		} // End of for each IP in the current chunk.
	} // End of for each IP chunk.
	// If there are any remaining messages, send them.
	if currentIndex > 0 {
		if err = Limiter.Wait(context.Background()); err != nil {
			c.errorChan <- err
			return
		}
		_, _, errno := syscall.RawSyscall(
			syscall.SYS_SENDMMSG,
			c.socketFD,
			uintptr(unsafe.Pointer(&messageHeaders[0])),
			uintptr(currentIndex),
		)
		if errno != 0 {
			c.errorChan <- errno
			return
		}
		currentIndex = 0
	}
}

// arpScan sends ARP requests for each IP in the range and waits for responses.
func arpScan(c *scannerContext, r *router.IpRangeRouteContext, arpWg *sync.WaitGroup) {
	defer close(r.ReadyToInterceptHostsStateChan)
	defer close(r.UpHostsChan)
	defer arpWg.Done()

	var messageHeaders [constants.IOVecPacketsChunkSize]Mmsghdr
	var ethernetPart []byte
	var ethernetAndArpHeadersPartCombined [constants.EthernetHeaderSize + constants.ArpHeaderHeaderSize]byte
	var arpPacketBodyTemplate [constants.ArpBodySize]byte
	var rawArpPacketBodies [constants.IOVecPacketsChunkSize][constants.ArpBodySize]byte
	var ioVectors [constants.IOVecPacketsChunkSize][3]syscall.Iovec

	// Start the goroutine that intercepts ARP responses
	arpWg.Add(1)
	go interceptArpPackets(c, r, arpWg)

	// Wait until interceptArpPackets is ready
	<-r.ReadyToInterceptHostsStateChan

	// Build a base Ethernet part (broadcast as destination)
	ethernetPart = prepareEthernetPart(
		r.SocketParameters.SourceInterface.HardwareAddr,
		constants.EthernetBroadcastAddress,
		constants.EtherTypeARP,
	)

	copy(ethernetAndArpHeadersPartCombined[0:], ethernetPart)
	copy(ethernetAndArpHeadersPartCombined[constants.EthernetHeaderSize:], constants.ArpHeaderPart[:])

	arpPacketBodyTemplate = prepareArpPacketBodyTemplate(
		r.SocketParameters.SourceInterface.HardwareAddr,
		r.Route.Src,
	)

	// Iterate over IP chunks
	for ipChunk := range utils.IPRangeBytesChunks(r.Start, r.End) {
		for i := range ipChunk {
			rawArpPacketBodies[i] = arpPacketBodyTemplate
			copy(rawArpPacketBodies[i][16:], ipChunk[i][:])

			ioVectors[i][0] = syscall.Iovec{
				Base: &ethernetAndArpHeadersPartCombined[0],
				Len:  constants.EthernetHeaderSize + constants.ArpHeaderHeaderSize,
			}
			ioVectors[i][1] = syscall.Iovec{
				Base: &rawArpPacketBodies[i][0],
				Len:  constants.ArpBodySize,
			}
			ioVectors[i][2] = syscall.Iovec{
				Base: &constants.ArpPacketPadding[0],
				Len:  constants.ArpPacketPaddingSize,
			}

			messageHeaders[i].Msg = syscall.Msghdr{
				Name:    r.SocketParameters.SocketAddressName,
				Namelen: r.SocketParameters.SocketAddressNameLen,
				Iov:     &ioVectors[i][0],
				Iovlen:  3,
			}
		}

		// Rate limit
		if err := Limiter.Wait(context.Background()); err != nil {
			c.errorChan <- err
			return
		}

		_, _, errno := syscall.RawSyscall(
			syscall.SYS_SENDMMSG,
			c.socketFD,
			uintptr(unsafe.Pointer(&messageHeaders[0])),
			uintptr(len(messageHeaders)),
		)
		if errno != 0 {
			c.errorChan <- errno
			return
		}
	}

	// Give ARP replies some time
	time.Sleep(constants.DefaultTimeout)

	// Signal that host discovery via ARP is done
	r.HostDiscoveryDoneChan <- true
}

// pingScan sends ICMP echo requests (pings) to each IP in the range.
// pingScan sends ICMP echo requests (pings) to each IP in the range.
// It uses a fixed per-chunk buffer for IP headers to avoid reusing the same
// memory for multiple IPs, which was causing all packets to use the same destination IP.
func pingScan(c *scannerContext, r *router.IpRangeRouteContext, gatewayMac net.HardwareAddr, pingWg *sync.WaitGroup) {
	//defer fmt.Println("DEBUG: pingScan is done")
	defer close(r.ReadyToInterceptHostsStateChan)
	defer close(r.UpHostsChan)
	defer pingWg.Done()

	// Start goroutine to intercept ping replies.
	pingWg.Add(1)
	go interceptPingPackets(c, r, pingWg)

	// Wait until interceptPingPackets is ready.
	<-r.ReadyToInterceptHostsStateChan

	var (
		messageHeaders [constants.IOVecPacketsChunkSize]Mmsghdr
		ioVectors      [constants.IOVecPacketsChunkSize][4]syscall.Iovec
	)

	// Prepare the Ethernet header (constant for all messages).
	EthernetPart := prepareEthernetPart(
		r.SocketParameters.SourceInterface.HardwareAddr,
		gatewayMac,
		constants.EtherTypeIPv4,
	)

	// Prepare the IP header template for ICMP (will be copied per IP).
	Ipv4Part := prepareIpv4PartTemplate(
		r.Route.Src,
		constants.IcmpV4Size+constants.IPv4HeaderSize,
		constants.TrafficICMP,
	)

	// Process IP addresses in chunks.
	for ipChunk := range utils.IPRangeBytesChunks(r.Start, r.End) {
		chunkLen := len(ipChunk)
		// Allocate a fixed buffer for ICMP IP headers for the entire chunk.
		icmpIPBuffer := make([]byte, constants.IPv4HeaderSize*chunkLen)

		// For each IP in the chunk, create its own IP header in the fixed buffer.
		for i, ip := range ipChunk {
			// Create a slice for the i-th IP header.
			buf := icmpIPBuffer[i*constants.IPv4HeaderSize : (i+1)*constants.IPv4HeaderSize]
			// Copy the IP header template.
			copy(buf, Ipv4Part)
			// Overwrite the destination IP (offset 16 in the header).
			copy(buf[16:], ip[:])
			// Compute and set the IP header checksum.
			var sum uint32
			for j := 0; j < constants.IPv4HeaderSize; j += 2 {
				sum += uint32(buf[j])<<8 | uint32(buf[j+1])
			}
			sum = (sum & 0xFFFF) + (sum >> 16)
			sum = (sum & 0xFFFF) + (sum >> 16)
			binary.BigEndian.PutUint16(buf[10:12], ^uint16(sum))

			// Prepare the iovec for this IP.
			ioVectors[i][0] = syscall.Iovec{
				Base: &EthernetPart[0],
				Len:  constants.EthernetHeaderSize,
			}
			ioVectors[i][1] = syscall.Iovec{
				Base: &buf[0],
				Len:  uint64(constants.IPv4HeaderSize),
			}
			ioVectors[i][2] = syscall.Iovec{
				Base: &constants.IcmpV4Header[0],
				Len:  constants.IcmpV4Size,
			}
			ioVectors[i][3] = syscall.Iovec{
				Base: &constants.IcmpPacketPadding[0],
				Len:  constants.IcmpPacketPaddingSize,
			}
			messageHeaders[i].Msg = syscall.Msghdr{
				Name:    r.SocketParameters.SocketAddressName,
				Namelen: r.SocketParameters.SocketAddressNameLen,
				Iov:     &ioVectors[i][0],
				Iovlen:  4,
			}
		}

		// Rate limit before sending the chunk.
		if err := Limiter.Wait(context.Background()); err != nil {
			c.errorChan <- err
			return
		}

		// Send the chunk using sendmmsg with the number of messages equal to chunkLen.
		_, _, errno := syscall.RawSyscall(
			syscall.SYS_SENDMMSG,
			c.socketFD,
			uintptr(unsafe.Pointer(&messageHeaders[0])),
			uintptr(chunkLen),
		)
		if errno != 0 {
			c.errorChan <- errno
			return
		}
	}

	// Allow some time to receive ping responses.
	time.Sleep(constants.DefaultTimeout)

	// Signal that host discovery via ping is done.
	r.HostDiscoveryDoneChan <- true
}

// scanOverGateway scanning through a gateway if network is not local.
func scanOverGateway(c *scannerContext, r *router.IpRangeRouteContext, ipRangeScannerWg *sync.WaitGroup) {
	defer ipRangeScannerWg.Done()
	var pingWg sync.WaitGroup
	var gatewayMacAddress net.HardwareAddr
	var err error

	gatewayMacAddress, err = utils.GetHardwareAddrFromARP(r.Route.Gw)
	if err != nil {
		c.errorChan <- err
		return
	}

	if gatewayMacAddress == nil {
		// Attempt to retrieve gateway MAC by sending an ARP request
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

	// Perform ping-based host discovery behind the gateway
	pingWg.Add(1)
	go pingScan(c, r, gatewayMacAddress, &pingWg)

	pingWg.Add(1)
	go ScanPortsOverGateway(c, r, &pingWg, gatewayMacAddress)

	// Wait for ping scanning to finish
	pingWg.Wait()
}

// scanPointToPoint performs direct scanning in a single subnet without a gateway.
func scanPointToPoint(c *scannerContext, r *router.IpRangeRouteContext, ipRangeScannerWg *sync.WaitGroup) {
	defer ipRangeScannerWg.Done()
	//defer fmt.Println("DEBUG: scanPointToPoint is done")

	var p2pWg sync.WaitGroup

	// Start ARP-based host discovery
	p2pWg.Add(1)
	go arpScan(c, r, &p2pWg)

	// Start port scanning (TCP/UDP)
	p2pWg.Add(1)
	go PointToPointPortsScan(c, r, &p2pWg)

	p2pWg.Wait()
}

// Scan is the main entry point for scanning using the provided rule.
func Scan(scanRule rule.Rule, errorChan chan error) {
	var ipRangeScannerWg sync.WaitGroup
	//defer fmt.Println("DEBUG: Scan is done")

	// If the network is loopback, handle separately
	if scanRule.Network.IP.IsLoopback() {
		if err := getLocalhostPorts(); err != nil {
			errorChan <- err
			return
		}
	}

	scanCtx, err := createScannerContext(scanRule)
	if err != nil {
		errorChan <- err
		return
	}

	if scanRule.Options.NoHostDiscovery {
		for _, networkRange := range scanCtx.IpRanges {
			switch {
			case networkRange.Route.Gw != nil:
				ipRangeScannerWg.Add(1)
				go scanWithoutHostDiscovery(scanCtx, networkRange, &ipRangeScannerWg)
			case scanCtx.defaultGateway != nil:
				networkRange.Route.Gw = scanCtx.defaultGateway
				ipRangeScannerWg.Add(1)
				go scanWithoutHostDiscovery(scanCtx, networkRange, &ipRangeScannerWg)
			default:
				errorChan <- fmt.Errorf("unable to determine a route to network range %s-%s. Gateway required to scan with \"no-host-discovery\" option enabled", networkRange.Start, networkRange.End)
				return
			}
		}
	} else {
		for _, networkRange := range scanCtx.IpRanges {
			if networkRange.Route.Gw == nil {
				ipRangeScannerWg.Add(1)
				go scanPointToPoint(scanCtx, networkRange, &ipRangeScannerWg)
			} else {
				ipRangeScannerWg.Add(1)
				go scanOverGateway(scanCtx, networkRange, &ipRangeScannerWg)
			}
		}
	}

	// Wait in a separate goroutine to signal final completion
	done := make(chan struct{})
	go func() {
		ipRangeScannerWg.Wait()
		close(done)
	}()

	// Either receive an error or see that scanning is complete
	select {
	case err = <-scanCtx.errorChan:
		errorChan <- err
		return
	case <-done:
		// Scanning is finished
	}

	ipRangeScannerWg.Wait()
}

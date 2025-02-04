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
	errorChan   chan error
	ipRanges    []*router.IpRangeRouteContext
	routeTables []netlink.Route
	socketFD    int
	rule        *rule.Rule
	ports       []uint16
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

// prepareEthernetPart sets up an Ethernet header for raw packet injection.
func prepareEthernetPart(sourceMAC, destinationMAC net.HardwareAddr, networkLayer uint16) [constants.EthernetPartSize]byte {
	var ethernetPartTemplate [constants.EthernetPartSize]byte
	ethernetPartTemplate = constants.EthernetPart

	copy(ethernetPartTemplate[0:6], destinationMAC)
	copy(ethernetPartTemplate[6:12], sourceMAC)

	binary.BigEndian.PutUint16(ethernetPartTemplate[12:14], networkLayer)
	return ethernetPartTemplate
}

// prepareIpv4PartTemplate creates an IPv4 header template with the given source,
// total length, and transport layer protocol (e.g., TCP/ICMP).
func prepareIpv4PartTemplate(sourceIP net.IP, length uint16, transportLayer byte) [constants.IPv4HeaderSize]byte {
	var IPPartTemplate [constants.IPv4HeaderSize]byte
	IPPartTemplate = constants.IPv4Part

	copy(IPPartTemplate[12:], sourceIP.To4())
	IPPartTemplate[9] = transportLayer

	binary.BigEndian.PutUint16(IPPartTemplate[2:], length)
	return IPPartTemplate
}

// preparePseudoHeader builds a TCP pseudo-header required for correct checksum calculation.
func preparePseudoHeader(SourceIP, DestinationIP []byte, protocol uint8, Length uint16) [constants.TCPPseudoHeaderSize]byte {
	var PseudoHeader [constants.TCPPseudoHeaderSize]byte

	copy(PseudoHeader[:4], SourceIP)
	copy(PseudoHeader[4:8], DestinationIP)
	// Reserved byte is always 0
	PseudoHeader[8] = 0x00
	PseudoHeader[9] = protocol
	binary.BigEndian.PutUint16(PseudoHeader[10:], Length)

	return PseudoHeader
}

// prepareArpPacketBodyTemplate creates a template for the ARP body with local MAC and IP.
func prepareArpPacketBodyTemplate(localMAC net.HardwareAddr, localIP net.IP) [constants.ArpBodyPartSize]byte {
	var arpBodyTemplate [constants.ArpBodyPartSize]byte
	arpBodyTemplate = constants.ArpBodyPart

	copy(arpBodyTemplate[0:], localMAC)
	copy(arpBodyTemplate[6:], localIP)

	return arpBodyTemplate
}

// interceptArpPackets listens for ARP packets for the subnet on the specified interface.
func interceptArpPackets(c *scannerContext, r *router.IpRangeRouteContext, arpWg *sync.WaitGroup) {
	defer arpWg.Done()
	defer fmt.Println("DEBUG: interceptArpPackets is done")

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

			// Print host discovery info (ARP)
			printARPDiscovery(arpData.SourceProtAddress, c.rule.Network)
			// Send discovered host to UpHostsChan
			r.UpHostsChan <- router.UpHostsEthIPChan{
				Ip:  arpData.SourceProtAddress,
				Eth: arpData.SourceHwAddress,
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
	defer fmt.Println("DEBUG: interceptPingPackets is done")

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
			if icmpLayer == nil {
				continue
			}
			ipData := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)

			// Print host discovery info (ping)
			printPingDiscovery(ipData.SrcIP, c.rule.Network)

			r.UpHostsChan <- router.UpHostsEthIPChan{Ip: ipData.SrcIP, Eth: nil}

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
		captureLength = constants.EthernetPartSize + constants.IPv4HeaderSize + constants.TCPSynHeaderPartSize
	case c.rule.PortScanTechniques.Syn || c.rule.PortScanTechniques.Vav && !c.rule.PortScanTechniques.Udp:
		bpfStr += " tcp and "
		captureLength = constants.EthernetPartSize + constants.IPv4HeaderSize + constants.TCPSynHeaderPartSize
	case c.rule.PortScanTechniques.Udp && !(c.rule.PortScanTechniques.Vav || c.rule.PortScanTechniques.Syn):
		bpfStr += " udp and "
		captureLength = constants.EthernetPartSize + constants.IPv4HeaderSize + constants.UDPHeaderPartSize
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
	defer fmt.Println("DEBUG: PointToPointPortsScan is done")

	var (
		// IP header templates for each scan type.
		ipTcpSynTemplate [constants.IPv4HeaderSize]byte
		ipTcpVavTemplate [constants.IPv4HeaderSize]byte
		ipUdpTemplate    [constants.IPv4HeaderSize]byte

		// Ethernet+IP buffers for each scan type.
		ethIpBufferSyn [constants.EthernetPartSize + constants.IPv4HeaderSize]byte
		ethIpBufferVav [constants.EthernetPartSize + constants.IPv4HeaderSize]byte
		ethIpBufferUdp [constants.EthernetPartSize + constants.IPv4HeaderSize]byte

		// Pseudo-header buffers (concatenated with TCP header and payload) for checksum calculation.
		pseudoHeaderAndTcpHeaderSyn []byte
		pseudoHeaderAndTcpHeaderVav []byte

		// TCP header slice for SYN scanning.
		tcpSynHeaders [][constants.TCPSynHeaderPartSize]byte

		// TCP header slice for Vav scanning.
		tcpVavHeaders [][constants.TCPSynVavHeaderPartSize]byte
		udpHeaders    [][constants.UDPHeaderPartSize]byte

		// Message headers and I/O vectors for sendmmsg.
		messageHeaders [constants.IOVecPacketsChunkSize]Mmsghdr
		ioVectors      [constants.IOVecPacketsChunkSize][3]syscall.Iovec

		// Counter for the number of scan types used.
		scanTypesCount int

		//BPF filter for capturing responses
		bpfExpression *pcap.BPF

		err      error
		checksum uint16
	)

	bpfExpression, err = compileTransportStateDetectionBPF(c, r)
	if err != nil {
		c.errorChan <- err
		return
	}

	// Start a goroutine to intercept TCP/UDP responses.
	portsScanWg.Add(1)
	go interceptTransportResponses(c, r, bpfExpression, portsScanWg)

	// Wait until interceptTransportResponses is ready.
	<-r.ReadyToInterceptPortsStateChan

	// Prepare templates and pseudo-header buffers based on enabled scan techniques.
	if c.rule.PortScanTechniques.Syn {
		scanTypesCount++
		// Build a base IPv4 header for SYN scan (IP header + TCP header).
		ipTcpSynTemplate = prepareIpv4PartTemplate(
			r.Route.Src,
			constants.IPv4HeaderSize+constants.TCPSynHeaderPartSize,
			constants.TrafficTCP,
		)
		// Allocate the SYN pseudo-header buffer.
		pseudoHeaderAndTcpHeaderSyn = make([]byte, constants.TCPPseudoHeaderSize+constants.TCPSynHeaderPartSize)
		// Prepare an array for TCP headers for all ports (for SYN scanning).
		tcpSynHeaders = make([][constants.TCPSynHeaderPartSize]byte, len(c.ports))
	}

	if c.rule.PortScanTechniques.Vav {
		scanTypesCount++
		// Build a base IPv4 header for VAV scan (IP header + TCP headers + payload length).
		ipTcpVavTemplate = prepareIpv4PartTemplate(
			r.Route.Src,
			constants.IPv4HeaderSize+constants.TCPSynVavHeaderPartSize+constants.ArcornSize,
			constants.TrafficTCP,
		)
		// Allocate the VAV(Syn) pseudo-header buffer.
		pseudoHeaderAndTcpHeaderVav = make([]byte, constants.TCPPseudoHeaderSize+constants.TCPSynVavHeaderPartSize+constants.ArcornSize)
		tcpVavHeaders = make([][constants.TCPSynVavHeaderPartSize]byte, len(c.ports))
	}

	if c.rule.PortScanTechniques.Udp {
		scanTypesCount++
		// Build a base IPv4 header for UDP scan (IP header + UDP header).
		ipUdpTemplate = prepareIpv4PartTemplate(
			r.Route.Src,
			constants.IPv4HeaderSize+constants.UDPHeaderPartSize,
			constants.TrafficUDP,
		)
		udpHeaders = make([][constants.UDPHeaderPartSize]byte, len(c.ports))
	}

	// Build an Ethernet template with a zeroed destination MAC.
	EthernetTemplate := prepareEthernetPart(
		r.SocketParameters.SourceInterface.HardwareAddr,
		net.HardwareAddr{0, 0, 0, 0, 0, 0},
		constants.EtherTypeIPv4,
	)

	// Read discovered hosts from UpHostsChan.
	for host := range r.UpHostsChan {
		currentIndex := 0

		// ----- SYN Scan Branch -----
		if c.rule.PortScanTechniques.Syn {
			// Prepare Ethernet + IP buffer for SYN scan.
			copy(ethIpBufferSyn[0:6], host.Eth) // Set destination MAC.
			copy(ethIpBufferSyn[6:constants.EthernetPartSize], EthernetTemplate[6:])

			// Copy the SYN IP header template into the buffer.
			copy(ethIpBufferSyn[constants.EthernetPartSize:constants.EthernetPartSize+constants.IPv4HeaderSize], ipTcpSynTemplate[:])
			// Overwrite the destination IP.
			copy(ethIpBufferSyn[constants.EthernetPartSize+16:constants.EthernetPartSize+20], host.Ip)
			// Compute IP header checksum for SYN scan.
			checksum = computeChecksum(ethIpBufferSyn[constants.EthernetPartSize : constants.EthernetPartSize+constants.IPv4HeaderSize])
			binary.BigEndian.PutUint16(ethIpBufferSyn[constants.EthernetPartSize+10:constants.EthernetPartSize+12], checksum)

			// Prepare the TCP pseudo-header for SYN scan.
			tcpSynPseudoHeader := preparePseudoHeader(r.Route.Src.To4(), host.Ip, constants.TrafficTCP, constants.TCPSynHeaderPartSize)

			// Loop through ports for SYN scan.
			for i, port := range c.ports {
				// Initialize TCP header from a static template.
				tcpSynHeaders[i] = constants.TCPSynHeaderPart

				// Set source and destination ports.
				binary.BigEndian.PutUint16(tcpSynHeaders[i][0:2], r.SourcePort)
				binary.BigEndian.PutUint16(tcpSynHeaders[i][2:4], port)

				// Copy pseudo-header and TCP header into the SYN pseudo-header buffer.
				copy(pseudoHeaderAndTcpHeaderSyn[0:constants.TCPPseudoHeaderSize], tcpSynPseudoHeader[:])
				copy(pseudoHeaderAndTcpHeaderSyn[constants.TCPPseudoHeaderSize:], tcpSynHeaders[i][:])

				// Calculate TCP checksum.
				tcpChecksum := computeChecksum(pseudoHeaderAndTcpHeaderSyn)
				binary.BigEndian.PutUint16(tcpSynHeaders[i][16:18], tcpChecksum)

				// Set up I/O vector segments for SYN scan.
				ioVectors[currentIndex][0] = syscall.Iovec{
					Base: &ethIpBufferSyn[0],
					Len:  uint64(constants.EthernetPartSize + constants.IPv4HeaderSize),
				}
				ioVectors[currentIndex][1] = syscall.Iovec{
					Base: &tcpSynHeaders[i][0],
					Len:  uint64(constants.TCPSynHeaderPartSize),
				}
				// For SYN scan, use 2 segments.
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
			// Prepare Ethernet + IP buffer for VAV scan.
			copy(ethIpBufferVav[0:6], host.Eth) // Set destination MAC.
			copy(ethIpBufferVav[6:constants.EthernetPartSize], EthernetTemplate[6:])

			// Copy the VAV IP header template into the buffer.
			copy(ethIpBufferVav[constants.EthernetPartSize:constants.EthernetPartSize+constants.IPv4HeaderSize], ipTcpVavTemplate[:])
			// Overwrite the destination IP.
			copy(ethIpBufferVav[constants.EthernetPartSize+16:constants.EthernetPartSize+20], host.Ip)
			// Compute IP header checksum for VAV scan.
			checksum = computeChecksum(ethIpBufferVav[constants.EthernetPartSize : constants.EthernetPartSize+constants.IPv4HeaderSize])
			binary.BigEndian.PutUint16(ethIpBufferVav[constants.EthernetPartSize+10:constants.EthernetPartSize+12], checksum)

			// Prepare the TCP pseudo-header for VAV scan.
			tcpVavPseudoHeader := preparePseudoHeader(r.Route.Src.To4(), host.Ip, constants.TrafficTCP, constants.TCPSynVavHeaderPartSize+constants.ArcornSize)

			// Loop through ports for VAV scan.
			for i, port := range c.ports {
				// Initialize a TCP header for VAV scan using a constant template that already contains the hardcoded VAV flags.
				tcpVavHeaders[i] = constants.TCPSynVavHeaderPart

				// Set source and destination ports.
				binary.BigEndian.PutUint16(tcpVavHeaders[i][0:2], r.SourcePort)
				binary.BigEndian.PutUint16(tcpVavHeaders[i][2:4], port)

				// Build a combined buffer for checksum calculation: pseudo-header + TCP VAV header + payload.
				copy(pseudoHeaderAndTcpHeaderVav[0:constants.TCPPseudoHeaderSize], tcpVavPseudoHeader[:])
				copy(pseudoHeaderAndTcpHeaderVav[constants.TCPPseudoHeaderSize:constants.TCPPseudoHeaderSize+constants.TCPSynVavHeaderPartSize], tcpVavHeaders[i][:])
				copy(pseudoHeaderAndTcpHeaderVav[constants.TCPPseudoHeaderSize+constants.TCPSynVavHeaderPartSize:], constants.Arcorn[:])

				tcpChecksum := computeChecksum(pseudoHeaderAndTcpHeaderVav)
				binary.BigEndian.PutUint16(tcpVavHeaders[i][16:18], tcpChecksum)

				// Set up I/O vector segments for VAV scan.
				ioVectors[currentIndex][0] = syscall.Iovec{
					Base: &ethIpBufferVav[0],
					Len:  uint64(constants.EthernetPartSize + constants.IPv4HeaderSize),
				}
				ioVectors[currentIndex][1] = syscall.Iovec{
					Base: &tcpVavHeaders[i][0],
					Len:  uint64(constants.TCPSynVavHeaderPartSize),
				}
				ioVectors[currentIndex][2] = syscall.Iovec{
					Base: &constants.Arcorn[0],
					Len:  uint64(len(constants.Arcorn)),
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

		// ----- UDP Scan Branch -----
		if c.rule.PortScanTechniques.Udp {
			// Prepare Ethernet + IP buffer for UDP scan.
			copy(ethIpBufferUdp[0:6], host.Eth) // Set destination MAC.
			copy(ethIpBufferUdp[6:constants.EthernetPartSize], EthernetTemplate[6:])

			// Copy the UDP IP header template into the buffer.
			copy(ethIpBufferUdp[constants.EthernetPartSize:constants.EthernetPartSize+constants.IPv4HeaderSize], ipUdpTemplate[:])
			// Overwrite the destination IP.
			copy(ethIpBufferUdp[constants.EthernetPartSize+16:constants.EthernetPartSize+20], host.Ip)
			// Compute IP header checksum for UDP scan.
			checksum = computeChecksum(ethIpBufferUdp[constants.EthernetPartSize : constants.EthernetPartSize+constants.IPv4HeaderSize])
			binary.BigEndian.PutUint16(ethIpBufferUdp[constants.EthernetPartSize+10:constants.EthernetPartSize+12], checksum)

			// Loop through ports for UDP scan.
			for i, port := range c.ports {
				udpHeaders[i] = constants.UdpPart
				// Set source and destination ports.
				binary.BigEndian.PutUint16(udpHeaders[i][0:2], r.SourcePort)
				binary.BigEndian.PutUint16(udpHeaders[i][2:4], port)
				// Set UDP length.
				binary.BigEndian.PutUint16(udpHeaders[i][4:6], uint16(constants.UDPHeaderPartSize))

				// Prepare UDP pseudo-header for checksum calculation.
				udpPseudoHeader := preparePseudoHeader(r.Route.Src.To4(), host.Ip, constants.TrafficUDP, uint16(constants.UDPHeaderPartSize))
				pseudoBuffer := make([]byte, len(udpPseudoHeader)+constants.UDPHeaderPartSize)
				copy(pseudoBuffer[0:len(udpPseudoHeader)], udpPseudoHeader[:])
				copy(pseudoBuffer[len(udpPseudoHeader):], udpHeaders[i][:])
				checksum = computeChecksum(pseudoBuffer)
				binary.BigEndian.PutUint16(udpHeaders[i][6:8], checksum)

				// Set up I/O vector segments for UDP scan.
				ioVectors[currentIndex][0] = syscall.Iovec{
					Base: &ethIpBufferUdp[0],
					Len:  uint64(constants.EthernetPartSize + constants.IPv4HeaderSize),
				}
				ioVectors[currentIndex][1] = syscall.Iovec{
					Base: &udpHeaders[i][0],
					Len:  uint64(constants.UDPHeaderPartSize),
				}
				// For UDP, use 2 segments.
				messageHeaders[currentIndex].Msg = syscall.Msghdr{
					Name:    r.SocketParameters.SocketAddressName,
					Namelen: r.SocketParameters.SocketAddressNameLen,
					Iov:     &ioVectors[currentIndex][0],
					Iovlen:  2,
				}
				currentIndex++
			}
		}

		// Rate limit before sending.
		if err = Limiter.Wait(context.Background()); err != nil {
			c.errorChan <- err
			return
		}

		// Send the batch using the sendmmsg syscall.
		_, _, errno := syscall.RawSyscall(
			constants.SendMmsgSyscallIndex,
			uintptr(c.socketFD),
			uintptr(unsafe.Pointer(&messageHeaders[0])),
			uintptr(currentIndex),
		)
		if errno != 0 {
			c.errorChan <- errno
		}
	}

	// Allow some time to receive responses before stopping.
	time.Sleep(constants.DefaultTimeout)

	// Signal that port scanning is complete.
	r.PortsDiscoveryDoneChan <- true
}

// arpScan sends ARP requests for each IP in the range and waits for responses.
func arpScan(c *scannerContext, r *router.IpRangeRouteContext, arpWg *sync.WaitGroup) {
	defer close(r.ReadyToInterceptHostsStateChan)
	defer close(r.UpHostsChan)
	defer arpWg.Done()

	var messageHeaders [constants.IOVecPacketsChunkSize]Mmsghdr
	var ethernetPart [constants.EthernetPartSize]byte
	var ethernetAndArpHeadersPartCombined [constants.EthernetPartSize + constants.ArpHeaderPartSize]byte
	var arpPacketBodyTemplate [constants.ArpBodyPartSize]byte
	var rawArpPacketBodies [constants.IOVecPacketsChunkSize][constants.ArpBodyPartSize]byte
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

	copy(ethernetAndArpHeadersPartCombined[0:], ethernetPart[:])
	copy(ethernetAndArpHeadersPartCombined[constants.EthernetPartSize:], constants.ArpHeaderPart[:])

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
				Len:  constants.EthernetPartSize + constants.ArpHeaderPartSize,
			}
			ioVectors[i][1] = syscall.Iovec{
				Base: &rawArpPacketBodies[i][0],
				Len:  constants.ArpBodyPartSize,
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
			constants.SendMmsgSyscallIndex,
			uintptr(c.socketFD),
			uintptr(unsafe.Pointer(&messageHeaders[0])),
			uintptr(len(messageHeaders)),
		)
		if errno != 0 {
			c.errorChan <- errno
		}
	}

	// Give ARP replies some time
	time.Sleep(constants.DefaultTimeout)

	// Signal that host discovery via ARP is done
	r.HostDiscoveryDoneChan <- true
}

// pingScan sends ICMP echo requests (pings) to each IP in the range.
func pingScan(c *scannerContext, r *router.IpRangeRouteContext, gatewayMac net.HardwareAddr, pingWg *sync.WaitGroup) {
	defer fmt.Println("DEBUG: pingScan is done")
	defer close(r.ReadyToInterceptHostsStateChan)
	defer pingWg.Done()

	// Start goroutine to intercept ping replies
	pingWg.Add(1)
	go interceptPingPackets(c, r, pingWg)

	// Wait until interceptPingPackets is ready
	<-r.ReadyToInterceptHostsStateChan

	var messageHeaders [constants.IOVecPacketsChunkSize]Mmsghdr
	var rawICMPPacketsIpPart [constants.IOVecPacketsChunkSize][constants.IPv4HeaderSize]byte
	var ioVectors [constants.IOVecPacketsChunkSize][4]syscall.Iovec

	var EthernetPart [constants.EthernetPartSize]byte
	var Ipv4Part [constants.IPv4HeaderSize]byte

	EthernetPart = prepareEthernetPart(
		r.SocketParameters.SourceInterface.HardwareAddr,
		gatewayMac,
		constants.EtherTypeIPv4,
	)
	Ipv4Part = prepareIpv4PartTemplate(
		r.Route.Src,
		constants.IcmpV4PartSize+constants.IPv4HeaderSize,
		constants.TrafficICMP,
	)

	for ipChunk := range utils.IPRangeBytesChunks(r.Start, r.End) {
		for i := range ipChunk {
			rawICMPPacketsIpPart[i] = Ipv4Part
			copy(rawICMPPacketsIpPart[i][16:], ipChunk[i][:])

			// Calculate IP checksum
			var sum uint32
			for j := 0; j < constants.IPv4HeaderSize; j += 2 {
				sum += uint32(rawICMPPacketsIpPart[i][j])<<8 | uint32(rawICMPPacketsIpPart[i][j+1])
			}
			sum = (sum & 0xFFFF) + (sum >> 16)
			sum = (sum & 0xFFFF) + (sum >> 16)

			binary.BigEndian.PutUint16(rawICMPPacketsIpPart[i][10:12], ^uint16(sum))

			ioVectors[i][0] = syscall.Iovec{
				Base: &EthernetPart[0],
				Len:  constants.EthernetPartSize,
			}
			ioVectors[i][1] = syscall.Iovec{
				Base: &rawICMPPacketsIpPart[i][0],
				Len:  constants.IPv4HeaderSize,
			}
			ioVectors[i][2] = syscall.Iovec{
				Base: &constants.IcmpV4Part[0],
				Len:  constants.IcmpV4PartSize,
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

		// Rate limit
		if err := Limiter.Wait(context.Background()); err != nil {
			c.errorChan <- err
			return
		}

		_, _, errno := syscall.RawSyscall(
			constants.SendMmsgSyscallIndex,
			uintptr(c.socketFD),
			uintptr(unsafe.Pointer(&messageHeaders[0])),
			uintptr(len(messageHeaders)),
		)
		if errno != 0 {
			c.errorChan <- errno
		}
	}

	// Give ping responses some time
	time.Sleep(constants.DefaultTimeout)

	// Signal that host discovery via ping is done
	r.HostDiscoveryDoneChan <- true
}

// scanOverGateway is a placeholder for scanning through a gateway if needed.
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

	// Wait for ping scanning to finish
	pingWg.Wait()
}

// scanPointToPoint performs direct scanning in a single subnet without a gateway.
func scanPointToPoint(c *scannerContext, r *router.IpRangeRouteContext, ipRangeScannerWg *sync.WaitGroup) {
	defer ipRangeScannerWg.Done()
	defer fmt.Println("DEBUG: scanPointToPoint is done")

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
	defer fmt.Println("DEBUG: Scan is done")

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

	// Launch scanning for each subnet in the context
	for _, networkRange := range scanCtx.ipRanges {
		if networkRange.Route.Gw == nil {
			ipRangeScannerWg.Add(1)
			go scanPointToPoint(scanCtx, networkRange, &ipRangeScannerWg)
		} else {
			ipRangeScannerWg.Add(1)
			go scanOverGateway(scanCtx, networkRange, &ipRangeScannerWg)
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

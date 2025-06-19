package scanner

import (
	"Vaverka/constants"
	"Vaverka/router"
	"Vaverka/rule"
	"Vaverka/utils"
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/vishvananda/netlink"
	"golang.org/x/time/rate"
)

// Limiter is a global rate limiter used to control packet sending rate.
var Limiter *rate.Limiter

// mmsghdr is a wrapper for syscall.mmsghdr used with sendmmsg.
type mmsghdr struct {
	Msg syscall.Msghdr
	Len uint32
	_   [4]byte
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

	if r.Options.Shuffle {
		rand.Shuffle(len(portsList), func(i, j int) {
			portsList[i], portsList[j] = portsList[j], portsList[i]
		})
	}

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

	c.socketFD, err = utils.GetSocketV4()
	if err != nil {
		return nil, fmt.Errorf("error creating socket: %v", err)
	}

	c.defaultGateway, err = utils.GetDefaultV4Gateway()
	if err != nil {
		return nil, fmt.Errorf("error getting default gateway: %v", err)
	}

	return &c, nil
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

				if tcp.RST {
					continue
				}

				// Only process SYN+ACK
				if tcp.SYN && tcp.ACK {
					serviceName, identified := layers.TCPPortNames(tcp.SrcPort)
					if !identified {
						serviceName = "unknown"
					}
					if c.rule.FQDN != "" {
						printPortInfo(c.rule.FQDN, uint16(tcp.SrcPort), &serviceName, c.rule.Network, protoTypeTcp)
					} else {
						printPortInfo(ipv4.SrcIP.String(), uint16(tcp.SrcPort), &serviceName, c.rule.Network, protoTypeTcp)
					}

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
				if c.rule.FQDN != "" {
					printPortInfo(c.rule.FQDN, uint16(udp.SrcPort), &serviceName, c.rule.Network, protoTypeUdp)
				} else {
					printPortInfo(ipv4.SrcIP.String(), uint16(udp.SrcPort), &serviceName, c.rule.Network, protoTypeUdp)
				}

			}

		case <-r.PortsDiscoveryDoneChan:
			// Stop interception when signaled
			return
		}
	}
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

// interceptICMPPackets listens for ICMP (ping) packets and identifies responding hosts.
func interceptICMPPackets(c *scannerContext, r *router.IpRangeRouteContext, pingWg *sync.WaitGroup, proto int8) {
	defer pingWg.Done()
	//defer fmt.Println("DEBUG: interceptPingPackets is done")
	var protoString string
	switch proto {
	case protoTypeICMP4:
		protoString = "icmp"
	case protoTypeICMP6:
		protoString = "icmpv6"
	}

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
	if err = handle.SetBPFFilter(fmt.Sprintf("net %s and %s", networkString, protoString)); err != nil {
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
				if c.rule.FQDN != "" {
					printDiscovery(c.rule.FQDN, c.rule.Network, protoTypeICMP4)
				} else {
					printDiscovery(ipData.SrcIP.String(), c.rule.Network, protoTypeICMP4)
				}
				r.UpHostsChan <- router.EthIPPairBytes{Ip: ipData.SrcIP, Eth: nil}
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

// getRemoteMacAddrSingleHost obtains the MAC address of a remote host if not found in the ARP cache.
func getRemoteMacAddrSingleHost(sourceIP net.IP, remoteIP net.IP, sourceInterface *net.Interface) (net.HardwareAddr, error) {
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

const protoTypeUdp = 1
const protoTypeTcp = 2
const protoTypeICMP4 = 3
const protoTypeArp = 4
const protoTypeICMP6 = 6

func printPortInfo(host string, port uint16, serviceName *string, network net.IPNet, protoType int) {
	var protoStr string
	switch protoType {
	case protoTypeUdp:
		protoStr = "udp"
	case protoTypeTcp:
		protoStr = "tcp"
	}

	fmt.Printf(
		"{%s\"port\"%s: %s%d%s, %s\"host\"%s: %s\"%s\"%s, %s\"state\"%s: %s\"open\"%s, %s\"type\"%s: %s\"%s\"%s, %s\"service\"%s: %s\"%s\"%s, %s\"network\"%s: %s\"%s\"%s}\n",
		// "port" key in blue
		constants.ColorBlue, constants.ColorReset,
		// port value in green
		constants.ColorGreen, port, constants.ColorReset,

		// "host" key in blue
		constants.ColorBlue, constants.ColorReset,
		// host value in green
		constants.ColorGreen, host, constants.ColorReset,

		// "state" key in blue
		constants.ColorBlue, constants.ColorReset,
		// state value in green
		constants.ColorGreen, constants.ColorReset,

		// "type" key in blue
		constants.ColorBlue, constants.ColorReset,
		// type value in green
		constants.ColorGreen, protoStr, constants.ColorReset,

		// "service" key in blue
		constants.ColorBlue, constants.ColorReset,
		// service value in green
		constants.ColorGreen, *serviceName, constants.ColorReset,

		// "network" key in blue
		constants.ColorBlue, constants.ColorReset,
		// network value in green
		constants.ColorGreen, network.String(), constants.ColorReset,
	)
}

func printDiscovery(host string, network net.IPNet, techType int) {
	var techniqueStr string
	if techType == protoTypeArp {
		techniqueStr = "arp"
	} else if techType == protoTypeICMP4 {
		techniqueStr = "ping4"
	}

	fmt.Printf(
		"{%s\"host\"%s: %s\"%s\"%s, %s\"state\"%s: %s\"up\"%s, %s\"technique\"%s: %s\"%s\"%s, %s\"network\"%s: %s\"%s\"%s}\n",
		// "host" key in blue
		constants.ColorBlue, constants.ColorReset,
		// host value in green
		constants.ColorGreen, host, constants.ColorReset,

		// "state" key in blue
		constants.ColorBlue, constants.ColorReset,
		// state value in green
		constants.ColorGreen, constants.ColorReset,

		// "technique" key in blue
		constants.ColorBlue, constants.ColorReset,
		// technique value in green
		constants.ColorGreen, techniqueStr, constants.ColorReset,

		// "network" key in blue
		constants.ColorBlue, constants.ColorReset,
		// network value in green
		constants.ColorGreen, network.String(), constants.ColorReset,
	)
}

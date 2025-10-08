package scanner

import (
	"Vaverka/constants"
	"Vaverka/router"
	"Vaverka/rule"
	"Vaverka/utils"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"slices"
	"strconv"
	"sync"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/vishvananda/netlink"
	"golang.org/x/time/rate"
)

// Limiter is a global rate limiter used to control packet sending rate.
var Limiter *rate.Limiter

// Scan is the main entry point for scanning using the provided rule.
func Scan(scanRule rule.Rule) (<-chan ScanFinding, <-chan error, error) {
	var ipRangeScannerWg sync.WaitGroup

	scanCtx, err := createScannerContext(scanRule)
	if err != nil {
		return nil, nil, err
	}

	// If the network is loopback, handle separately
	if scanRule.Network.IP.IsLoopback() {
		if scanRule.Network.IP.To4() == nil && scanRule.Network.IP.To16() != nil {
			getLocalhostV6Ports(scanCtx)
		} else {
			getLocalhostV4Ports(scanCtx)
		}

		return scanCtx.findingsChan, scanCtx.errorChan, nil
	}

	if scanRule.Network.IP.To4() == nil && scanRule.Network.IP.To16() != nil {
		// start ipv6 scan
		if scanRule.Options.NoHostDiscovery {
			for _, networkRange := range scanCtx.IpRanges {
				switch {
				case networkRange.Route.Gw != nil:
					ipRangeScannerWg.Go(func() {
						scanV6WithoutHostDiscovery(scanCtx, networkRange)
					})
				case scanCtx.defaultGateway != nil:
					networkRange.Route.Gw = scanCtx.defaultGateway

					ipRangeScannerWg.Go(func() {
						scanV6WithoutHostDiscovery(scanCtx, networkRange)
					})
				default:
					return nil, nil, fmt.Errorf("unable to determine a route to network range %s-%s. Gateway required to scan with \"no-host-discovery\" option enabled", networkRange.Start, networkRange.End)
				}
			}
		} else {
			for _, networkRange := range scanCtx.IpRanges {
				switch {
				case networkRange.Route.Gw == nil && scanRule.Options.NoIpV6Multicast && scanCtx.defaultGateway == nil:
					return nil, nil, fmt.Errorf("unable to build a route to the range: the specified IPv6 range %s-%s has no gateway, no default gateway, and multicast is disabled, so the destination MAC address cannot be determined", networkRange.Start, networkRange.End)
				case scanRule.Options.NoIpV6Multicast:
					if networkRange.Route.Gw == nil {
						networkRange.Route.Gw = scanCtx.defaultGateway
					}
					ipRangeScannerWg.Go(func() {
						scanV6OverGateway(scanCtx, networkRange)
					})
				case networkRange.Route.Gw == nil:
					ipRangeScannerWg.Go(func() {
						scanV6PointToPoint(scanCtx, networkRange)
					})
				default:
					ipRangeScannerWg.Go(func() {
						scanV6OverGateway(scanCtx, networkRange)
					})
				}
			}
		}
	} else {
		// start ipv4 scan
		if scanRule.Options.NoHostDiscovery {
			for _, networkRange := range scanCtx.IpRanges {
				switch {
				case networkRange.Route.Gw != nil:
					ipRangeScannerWg.Go(func() {
						scanV4WithoutHostDiscovery(scanCtx, networkRange)
					})
				case scanCtx.defaultGateway != nil:
					networkRange.Route.Gw = scanCtx.defaultGateway
					ipRangeScannerWg.Go(func() {
						scanV4WithoutHostDiscovery(scanCtx, networkRange)
					})
				default:
					return nil, nil, fmt.Errorf("unable to determine a route to network range %s-%s. Gateway required to scan with \"no-host-discovery\" option enabled", networkRange.Start, networkRange.End)
				}
			}
		} else {
			for _, networkRange := range scanCtx.IpRanges {
				if networkRange.Route.Gw == nil {
					ipRangeScannerWg.Go(func() {
						scanV4PointToPoint(scanCtx, networkRange)
					})
				} else {
					ipRangeScannerWg.Go(func() {
						scanV4OverGateway(scanCtx, networkRange)
					})
				}
			}
		}
	}
	return scanCtx.findingsChan, scanCtx.errorChan, nil
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
	c.findingsChan = make(chan ScanFinding, constants.FindingsChanBufferSize)
	if r.Network.IP.To4() == nil && r.Network.IP.To16() != nil {
		c.routeTables, err = netlink.RouteList(nil, netlink.FAMILY_V6)
	} else {
		c.routeTables, err = netlink.RouteList(nil, netlink.FAMILY_V4)
	}

	if err != nil {
		return nil, fmt.Errorf("cannot get route list: %v", err)
	}

	c.rule = &r

	c.IpRanges, err = r.Options.Router(c.routeTables, &r.Network)
	if err != nil {
		return nil, fmt.Errorf("error splitting network to subranges: %v", err)
	}

	if r.Network.IP.To4() == nil && r.Network.IP.To16() != nil {
		c.socketFD, err = utils.GetSocketV6()

	} else {
		c.socketFD, err = utils.GetSocketV4()
	}

	if err != nil {
		return nil, fmt.Errorf("error creating socket: %v", err)
	}

	if r.Network.IP.To4() == nil && r.Network.IP.To16() != nil {
		c.defaultGateway, err = utils.GetDefaultV6Gateway()
	} else {
		c.defaultGateway, err = utils.GetDefaultV4Gateway()
	}

	if err != nil {
		return nil, fmt.Errorf("error getting default gateway: %v", err)
	}

	return &c, nil
}

// prepareIp4TransportPseudoHeader builds a TCP pseudo-header required for correct checksum calculation.
func prepareIp4TransportPseudoHeader(SourceIP, DestinationIP []byte, protocol uint8, Length uint16) []byte {
	var PseudoHeader []byte
	PseudoHeader = make([]byte, constants.IPv4TransportPseudoHeaderSize)

	copy(PseudoHeader[:4], SourceIP)
	copy(PseudoHeader[4:8], DestinationIP)
	// Reserved byte is always 0
	PseudoHeader[8] = 0x00
	PseudoHeader[9] = protocol
	binary.BigEndian.PutUint16(PseudoHeader[10:], Length)

	return PseudoHeader
}

// prepareIp6TransportPseudoHeader builds a TCP pseudo-header required for correct checksum calculation.
func prepareIp6TransportPseudoHeader(SourceIP, DestinationIP []byte, nextHeader uint8, Length uint32) []byte {

	PseudoHeader := make([]byte, 40)

	copy(PseudoHeader[0:16], SourceIP)
	copy(PseudoHeader[16:32], DestinationIP)
	binary.BigEndian.PutUint32(PseudoHeader[32:36], Length)
	PseudoHeader[39] = nextHeader

	return PseudoHeader
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
	var protoString string
	var frameSize int32
	switch proto {
	case protoTypeICMP4:
		protoString = "icmp"
		frameSize = constants.MinFrameSize
	case protoTypeICMP6:
		protoString = "icmp6"
		frameSize = 128
	}

	handle, err := pcap.OpenLive(
		r.SocketParameters.SourceInterface.Name,
		frameSize,
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

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
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
			switch proto {
			case protoTypeICMP4:
				icmp4Layer := packet.Layer(layers.LayerTypeICMPv4)
				if icmp4Layer == nil || icmp4Layer.(*layers.ICMPv4).TypeCode.Type() != layers.ICMPv4TypeEchoReply {
					continue
				}

				ethLayer := packet.Layer(layers.LayerTypeEthernet)

				var srcMAC net.HardwareAddr
				if ethLayer != nil {
					srcMAC = ethLayer.(*layers.Ethernet).SrcMAC
				}

				ip4Data := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)

				if utils.IsIPInRange(r.Start, r.End, ip4Data.SrcIP) {
					// Print host discovery info (ping)
					c.findingsChan <- Host{
						IP:        ip4Data.SrcIP,
						Network:   c.rule.Network,
						Mac:       srcMAC,
						FQDN:      c.rule.FQDN,
						State:     "up",
						Technique: "TMPEMPTY",
					}

					r.UpHostsChan <- router.EthIPPairBytes{Ip: ip4Data.SrcIP, Eth: srcMAC}
				}
			case protoTypeICMP6:
				icmp6Layer := packet.Layer(layers.LayerTypeICMPv6)
				if icmp6Layer == nil || icmp6Layer.(*layers.ICMPv6).TypeCode.Type() != layers.ICMPv6TypeEchoReply {
					continue
				}

				ethLayer := packet.Layer(layers.LayerTypeEthernet)

				var srcMAC net.HardwareAddr
				if ethLayer != nil {
					srcMAC = ethLayer.(*layers.Ethernet).SrcMAC
				}

				ip6Data := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)

				if utils.IsIPInRange(r.Start, r.End, ip6Data.SrcIP) {
					c.findingsChan <- Host{
						IP:        ip6Data.SrcIP,
						Network:   c.rule.Network,
						Mac:       srcMAC,
						FQDN:      c.rule.FQDN,
						State:     "up",
						Technique: "TMPEMPTY",
					}
					r.UpHostsChan <- router.EthIPPairBytes{Ip: ip6Data.SrcIP, Eth: srcMAC}
				}
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

	bpfStr += "net " + c.rule.Network.String() + " and "

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

	if c.rule.Network.IP.To4() == nil && c.rule.Network.IP.To16() != nil {
		return pcap.NewBPF(layers.LinkTypeIPv6, captureLength, bpfStr)
	}

	return pcap.NewBPF(layers.LinkTypeIPv4, captureLength, bpfStr)
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

//func printPortInfo(host string, port uint16, serviceName *string, network net.IPNet, protoType int) {
//	var protoStr string
//	switch protoType {
//	case protoTypeUdp:
//		protoStr = "udp"
//	case protoTypeTcp:
//		protoStr = "tcp"
//	}
//
//	fmt.Printf(
//		"{%s\"port\"%s: %s%d%s, %s\"host\"%s: %s\"%s\"%s, %s\"state\"%s: %s\"open\"%s, %s\"type\"%s: %s\"%s\"%s, %s\"service\"%s: %s\"%s\"%s, %s\"network\"%s: %s\"%s\"%s}\n",
//		// "port" key in blue
//		constants.ColorBlue, constants.ColorReset,
//		// port value in green
//		constants.ColorGreen, port, constants.ColorReset,
//
//		// "host" key in blue
//		constants.ColorBlue, constants.ColorReset,
//		// host value in green
//		constants.ColorGreen, host, constants.ColorReset,
//
//		// "state" key in blue
//		constants.ColorBlue, constants.ColorReset,
//		// state value in green
//		constants.ColorGreen, constants.ColorReset,
//
//		// "type" key in blue
//		constants.ColorBlue, constants.ColorReset,
//		// type value in green
//		constants.ColorGreen, protoStr, constants.ColorReset,
//
//		// "service" key in blue
//		constants.ColorBlue, constants.ColorReset,
//		// service value in green
//		constants.ColorGreen, *serviceName, constants.ColorReset,
//
//		// "network" key in blue
//		constants.ColorBlue, constants.ColorReset,
//		// network value in green
//		constants.ColorGreen, network.String(), constants.ColorReset,
//	)
//}
//
//func printDiscovery(host string, network net.IPNet, techType int) {
//	var techniqueStr string
//
//	switch techType {
//	case protoTypeArp:
//		techniqueStr = "arp"
//	case protoTypeICMP4:
//		techniqueStr = "ping4"
//	case protoTypeICMP6:
//		techniqueStr = "ping6"
//	}
//
//	fmt.Printf(
//		"{%s\"host\"%s: %s\"%s\"%s, %s\"state\"%s: %s\"up\"%s, %s\"technique\"%s: %s\"%s\"%s, %s\"network\"%s: %s\"%s\"%s}\n",
//		// "host" key in blue
//		constants.ColorBlue, constants.ColorReset,
//		// host value in green
//		constants.ColorGreen, host, constants.ColorReset,
//
//		// "state" key in blue
//		constants.ColorBlue, constants.ColorReset,
//		// state value in green
//		constants.ColorGreen, constants.ColorReset,
//
//		// "technique" key in blue
//		constants.ColorBlue, constants.ColorReset,
//		// technique value in green
//		constants.ColorGreen, techniqueStr, constants.ColorReset,
//
//		// "network" key in blue
//		constants.ColorBlue, constants.ColorReset,
//		// network value in green
//		constants.ColorGreen, network.String(), constants.ColorReset,
//	)
//}

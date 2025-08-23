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
	"syscall"

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

// Scan is the main entry point for scanning using the provided rule.
func Scan(scanRule rule.Rule) error {
	var ipRangeScannerWg sync.WaitGroup
	//defer fmt.Println("DEBUG: Scan is done")

	// If the network is loopback, handle separately
	if scanRule.Network.IP.IsLoopback() {
		if scanRule.Network.IP.To4() == nil && scanRule.Network.IP.To16() != nil {
			return getLocalhostV6Ports()
		} else if scanRule.Network.IP.To4() != nil {
			return getLocalhostV4Ports()
		}
	}

	scanCtx, err := createScannerContext(scanRule)
	if err != nil {
		return err
	}

	if scanRule.Network.IP.To4() == nil && scanRule.Network.IP.To16() != nil {
		// start ipv6 scan
		if scanRule.Options.NoHostDiscovery {
			for _, networkRange := range scanCtx.IpRanges {
				switch {
				case networkRange.Route.Gw != nil:
					ipRangeScannerWg.Add(1)
					go scanV6WithoutHostDiscovery(scanCtx, networkRange, &ipRangeScannerWg)
				case scanCtx.defaultGateway != nil:
					networkRange.Route.Gw = scanCtx.defaultGateway
					ipRangeScannerWg.Add(1)
					go scanV6WithoutHostDiscovery(scanCtx, networkRange, &ipRangeScannerWg)
				default:
					return fmt.Errorf("unable to determine a route to network range %s-%s. Gateway required to scan with \"no-host-discovery\" option enabled", networkRange.Start, networkRange.End)
				}
			}
		} else {
			for _, networkRange := range scanCtx.IpRanges {
				if networkRange.Route.Gw == nil {
					ipRangeScannerWg.Add(1)
					// TODO implement
					go scanV6PointToPoint(scanCtx, networkRange, &ipRangeScannerWg)
				} else {
					ipRangeScannerWg.Add(1)
					// TODO implement
					go scanV6OverGateway(scanCtx, networkRange, &ipRangeScannerWg)
				}
			}
		}
	} else {
		// start ipv4 scan
		if scanRule.Options.NoHostDiscovery {
			for _, networkRange := range scanCtx.IpRanges {
				switch {
				case networkRange.Route.Gw != nil:
					ipRangeScannerWg.Add(1)
					go scanV4WithoutHostDiscovery(scanCtx, networkRange, &ipRangeScannerWg)
				case scanCtx.defaultGateway != nil:
					networkRange.Route.Gw = scanCtx.defaultGateway
					ipRangeScannerWg.Add(1)
					go scanV4WithoutHostDiscovery(scanCtx, networkRange, &ipRangeScannerWg)
				default:
					return fmt.Errorf("unable to determine a route to network range %s-%s. Gateway required to scan with \"no-host-discovery\" option enabled", networkRange.Start, networkRange.End)
				}
			}
		} else {
			for _, networkRange := range scanCtx.IpRanges {
				if networkRange.Route.Gw == nil {
					ipRangeScannerWg.Add(1)
					go scanV4PointToPoint(scanCtx, networkRange, &ipRangeScannerWg)
				} else {
					ipRangeScannerWg.Add(1)
					go scanV4OverGateway(scanCtx, networkRange, &ipRangeScannerWg)
				}
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
		return err
	case <-done:
		// Scanning is finished
	}

	ipRangeScannerWg.Wait()
	return nil
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
	PseudoHeader = make([]byte, constants.TCPPseudoHeaderSize)

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
	} else {
		return pcap.NewBPF(layers.LinkTypeIPv4, captureLength, bpfStr)
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

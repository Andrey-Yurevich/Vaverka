package scanner

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"slices"
	"strconv"
	"sync"
	"syscall"

	"github.com/Andrey-Yurevich/Vaverka/constants"
	"github.com/Andrey-Yurevich/Vaverka/router"
	"github.com/Andrey-Yurevich/Vaverka/rule"
	"github.com/Andrey-Yurevich/Vaverka/utils"

	"context"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	psnet "github.com/shirou/gopsutil/v4/net"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
)

// globalLimiter is a global rate globalLimiter used to control packet sending rate.
var globalLimiter *rate.Limiter

// getLocalPorts enumerates local sockets via gopsutil and streams "open" ports.
// - If r.FQDN == "localhost": include both IPv4 and IPv6 listeners.
// - If r.Network.IP is IPv6: include IPv6 (and potential dual-stack) listeners.
// - If r.Network.IP is IPv4: include IPv4 listeners.
// Returns: findings chan, errors chan, and a stub error (real errors go to the error channel).
func getLocalPorts(r rule.Rule) (<-chan ScanFinding, <-chan error, error) {
	c := make(chan ScanFinding, constants.FindingsChanBufferSize)
	e := make(chan error, constants.ErrorChanBufferSize)

	go func() {
		defer close(c)
		defer close(e)

		wantTCP := r.PortScanTechniques.Vav || r.PortScanTechniques.Syn
		wantUDP := r.PortScanTechniques.Udp
		if !wantTCP && !wantUDP {
			return
		}

		// Decide address families of interest.
		wantV4, wantV6 := false, false
		if r.FQDN == "localhost" {
			wantV4, wantV6 = true, true
		} else if r.Network.IP.To16() != nil && r.Network.IP.To4() == nil {
			wantV6 = true
		} else {
			wantV4 = true
		}

		// Single pass over all inet sockets; filter by Family/Type/State ourselves.
		connections, err := psnet.Connections("inet")
		if err != nil {
			e <- err
			return
		}

		for _, cs := range connections {
			// Map protocol by socket type.
			isTCP := cs.Type == syscall.SOCK_STREAM
			isUDP := cs.Type == syscall.SOCK_DGRAM
			if (isTCP && !wantTCP) || (isUDP && !wantUDP) {
				continue
			}

			// Map family and apply desired families.
			isV4 := cs.Family == syscall.AF_INET
			isV6 := cs.Family == syscall.AF_INET6
			if (!wantV4 && isV4) || (!wantV6 && isV6) {
				continue
			}

			// Select listeners/bound only.
			if isTCP {
				if cs.Status != "LISTEN" {
					continue
				}
			} else { // UDP
				// Treat UDP as "listening" when not connected to a remote peer.
				if cs.Raddr.IP != "" || cs.Raddr.Port != 0 {
					continue
				}
			}

			if cs.Laddr.Port == 0 {
				continue
			}
			// Service name (best-effort).
			var serviceName string
			var ok bool
			if isTCP {
				serviceName, ok = layers.TCPPortNames(layers.TCPPort(cs.Laddr.Port))
			} else {
				serviceName, ok = layers.UDPPortNames(layers.UDPPort(cs.Laddr.Port))
			}
			if !ok {
				serviceName = "unknown"
			}

			// Protocol string for the finding.
			proto := "tcp"
			if isUDP {
				proto = "udp"
			}

			c <- Port{
				Host:     net.ParseIP(cs.Laddr.IP),
				Service:  serviceName,
				State:    "open",
				Protocol: proto,
				Port:     uint16(cs.Laddr.Port),
			}
		}
	}()

	return c, e, nil
}

func SetPps(pps uint64) {
	globalLimiter = rate.NewLimiter(rate.Limit(pps), int(pps))
}

// Scan is the main public entry point for scanning using the provided rule.
// Internally, it launches multiple IPv4/IPv6 scanning goroutines, collects
// their results, and merges all findings and errors into a single Stream.
func Scan(scanRule rule.Rule) (*Stream, error) {
	if globalLimiter == nil {
		SetPps(constants.DefaultGlobalPpsLimit)
	}

	scanCtx, err := createScannerContext(scanRule)
	if err != nil {
		return nil, err
	}

	// Loopback networks are handled separately
	if scanRule.Network.IP.IsLoopback() {
		findingsChan, errChan, err := getLocalPorts(scanRule)
		if err != nil {
			return nil, err
		}
		return wrapChannels(findingsChan, errChan), nil
	}

	var ipRangeScannerWg sync.WaitGroup

	// IPv6 scan
	if scanRule.Network.IP.To4() == nil && scanRule.Network.IP.To16() != nil {
		if scanRule.Options.NoHostDiscovery {
			for _, networkRange := range scanCtx.IpRanges {
				switch {
				case networkRange.Route.Gw != nil:
					ipRangeScannerWg.Go(func() { scanV6WithoutHostDiscovery(scanCtx, networkRange) })
				case scanCtx.defaultGateway != nil:
					networkRange.Route.Gw = scanCtx.defaultGateway
					ipRangeScannerWg.Go(func() { scanV6WithoutHostDiscovery(scanCtx, networkRange) })
				default:
					return nil, fmt.Errorf("unable to determine a route to network range %s-%s (gateway required for no-host-discovery)", networkRange.Start, networkRange.End)
				}
			}
		} else {
			for _, networkRange := range scanCtx.IpRanges {
				switch {
				case networkRange.Route.Gw == nil && scanRule.Options.NoIpV6Multicast && scanCtx.defaultGateway == nil:
					return nil, fmt.Errorf("no route to IPv6 range %s-%s (no gateway and multicast disabled)", networkRange.Start, networkRange.End)
				case scanRule.Options.NoIpV6Multicast:
					if networkRange.Route.Gw == nil {
						networkRange.Route.Gw = scanCtx.defaultGateway
					}
					ipRangeScannerWg.Go(func() { scanV6OverGateway(scanCtx, networkRange) })
				case networkRange.Route.Gw == nil:
					ipRangeScannerWg.Go(func() { scanV6PointToPoint(scanCtx, networkRange) })
				default:
					ipRangeScannerWg.Go(func() { scanV6OverGateway(scanCtx, networkRange) })
				}
			}
		}
	} else {
		// IPv4 scan
		if scanRule.Options.NoHostDiscovery {
			for _, networkRange := range scanCtx.IpRanges {
				switch {
				case networkRange.Route.Gw != nil:
					ipRangeScannerWg.Go(func() { scanV4WithoutHostDiscovery(scanCtx, networkRange) })
				case scanCtx.defaultGateway != nil:
					networkRange.Route.Gw = scanCtx.defaultGateway
					ipRangeScannerWg.Go(func() { scanV4WithoutHostDiscovery(scanCtx, networkRange) })
				default:
					return nil, fmt.Errorf("unable to determine a route to network range %s-%s (gateway required for no-host-discovery)", networkRange.Start, networkRange.End)
				}
			}
		} else {
			for _, networkRange := range scanCtx.IpRanges {
				if networkRange.Route.Gw == nil {
					ipRangeScannerWg.Go(func() { scanV4PointToPoint(scanCtx, networkRange) })
				} else {
					ipRangeScannerWg.Go(func() { scanV4OverGateway(scanCtx, networkRange) })
				}
			}
		}
	}

	// Wait for all scan goroutines to finish, then close channels.
	go func() {
		ipRangeScannerWg.Wait()
		close(scanCtx.findingsChan)
		close(scanCtx.errorChan)
	}()

	// Wrap internal channels into a unified Stream
	return wrapChannels(scanCtx.findingsChan, scanCtx.errorChan), nil
}

// wrapChannels merges internal findings and error channels into a single Stream.
// It launches two goroutines: one to forward scan findings, another to collect errors.
// The Wait() method of Stream waits until both finish and returns the first error (if any).
func wrapChannels(findings <-chan ScanFinding, errs <-chan error) *Stream {
	out := make(chan ScanFinding, 256)
	g, ctx := errgroup.WithContext(context.Background())

	// Forward all findings to a single output channel
	g.Go(func() error {
		defer close(out)
		for f := range findings {
			select {
			case out <- f:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	})

	// Collect and return the first error
	g.Go(func() error {
		for e := range errs {
			if e != nil {
				return e
			}
		}
		return nil
	})

	return &Stream{
		Findings: out,
		Wait:     g.Wait,
	}
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

	if r.Options.Pps == 0 {
		r.Options.Pps = constants.DefaultLocalPpsLimit
	}

	c.localLimiter = rate.NewLimiter(rate.Limit(r.Options.Pps), int(r.Options.Pps))

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

	c.IpRanges, err = r.Options.Router(c.routeTables, &r.Network,
		netlink.RouteGetOptions{OifIndex: r.Options.IpV6MulticastInterfaceIndex})
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
func interceptICMPPackets(c *scannerContext, r *router.IpRangeRouteContext, h hostDiscoveryInterceptorHints) {

	handle, err := pcap.OpenLive(
		r.SocketParameters.SourceInterface.Name,
		h.frameSize,
		true,
		constants.PcapCaptureTimeout,
	)
	if err != nil {
		c.errorChan <- err
		return
	}
	defer handle.Close()

	networkString := c.rule.Network.String()
	if err = handle.SetBPFFilter(fmt.Sprintf("net %s and %s", networkString, h.protoString)); err != nil {
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
			switch h.protoString {
			case protoStringIcmpv4:
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
					if !h.printMac {
						c.findingsChan <- Host{
							IP:        ip4Data.SrcIP,
							Network:   c.rule.Network,
							Mac:       nil,
							FQDN:      c.rule.FQDN,
							State:     "up",
							Technique: h.printTechniqueName,
						}
					} else {
						c.findingsChan <- Host{
							IP:        ip4Data.SrcIP,
							Network:   c.rule.Network,
							Mac:       srcMAC,
							FQDN:      c.rule.FQDN,
							State:     "up",
							Technique: h.printTechniqueName,
						}
					}

					r.UpHostsChan <- router.EthIPPairBytes{Ip: ip4Data.SrcIP, Eth: srcMAC}
				}
			case protoStringIcmpv6:
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
					if !h.printMac {
						c.findingsChan <- Host{
							IP:        ip6Data.SrcIP,
							Network:   c.rule.Network,
							Mac:       nil,
							FQDN:      c.rule.FQDN,
							State:     "up",
							Technique: h.printTechniqueName,
						}
					} else {
						c.findingsChan <- Host{
							IP:        ip6Data.SrcIP,
							Network:   c.rule.Network,
							Mac:       srcMAC,
							FQDN:      c.rule.FQDN,
							State:     "up",
							Technique: h.printTechniqueName,
						}
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

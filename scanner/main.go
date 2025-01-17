package scanner

import (
	"Vaverka/constants"
	"Vaverka/router"
	"Vaverka/rule"
	"Vaverka/utils"
	"bytes"
	"fmt"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/vishvananda/netlink"
	"golang.org/x/time/rate"
	"net"
	"sync"
	"syscall"
	"time"
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
}

func createScannerContext(r rule.Rule) (*scannerContext, error) {
	var c scannerContext
	var err error

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

func prepareIcmpEchoPacketTemplate(sourceMAC, destinationMAC net.HardwareAddr, sourceIP net.IP) [constants.MinFrameSize]byte {
	var icmpEchoPacketTemplate [constants.MinFrameSize]byte
	icmpEchoPacketTemplate = constants.PingPacketSkeleton

	copy(icmpEchoPacketTemplate[0:6], destinationMAC)
	copy(icmpEchoPacketTemplate[6:12], sourceMAC)
	copy(icmpEchoPacketTemplate[26:30], sourceIP)

	return icmpEchoPacketTemplate
}

// prepareArpPacketTemplate creates a minimal ARP packet,
// taking into account the specified local MAC and IP addresses.
func prepareArpPacketTemplate(localMAC net.HardwareAddr, localIP net.IP) [constants.MinFrameSize]byte {
	var arpPacketTemplate [constants.MinFrameSize]byte
	arpPacketTemplate = constants.ArpPacketSkeleton

	copy(arpPacketTemplate[6:], localMAC)
	copy(arpPacketTemplate[22:], localMAC)
	copy(arpPacketTemplate[28:], localIP)

	return arpPacketTemplate
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
		constants.ArpPacketPayloadSize,
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
		constants.IcmpV4PacketPayloadSize,
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

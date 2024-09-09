package main

import (
	"bytes"
	"fmt"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/routing"
	"github.com/jackpal/gateway"
	"github.com/libp2p/go-netroute"
	"log"
	"net"
	"syscall"
	"time"
)

var router routing.Router
var srcInterface *net.Interface
var srcIp net.IP
var srcNetwork *net.IPNet
var SourceMac net.HardwareAddr
var srcPort = uint16(54321)
var remoteMac net.HardwareAddr
var dstPort = uint16(80)
var dstGw net.IP
var dstAddr = net.IP{10, 0, 1, 20}
var readHandler *pcap.Handle

func sendRemoteMacAddrRequest(srcIp []byte, gwAddr []byte, srcMac *net.HardwareAddr, handle *pcap.Handle) {
	var err error

	eth := layers.Ethernet{
		SrcMAC:       *srcMac,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   *srcMac,
		SourceProtAddress: srcIp,
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    gwAddr,
	}

	buf := gopacket.NewSerializeBuffer()

	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err = gopacket.SerializeLayers(buf, opts, &eth, &arp)

	if err != nil {
		panic(err)
	}

	err = handle.WritePacketData(buf.Bytes())

	if err != nil {
		panic(err)
	}
}

func readRemoteMacAddr(handle *pcap.Handle, interfaces *net.Interface, stop chan struct{}, addrChan chan net.HardwareAddr) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()

	for {
		var packet gopacket.Packet

		select {
		case <-stop:
			return

		case packet = <-in:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arpData := arpLayer.(*layers.ARP)
			if arpData.Operation != layers.ARPReply || bytes.Equal(interfaces.HardwareAddr, arpData.SourceHwAddress) {
				// This is a packet I sent.
				continue
			}

			addrChan <- arpData.SourceHwAddress

		}
	}
}

func getRemoteMacAddr(srcNet *net.IPNet, remoteAddr net.IP, srcMac *net.HardwareAddr, handle *pcap.Handle, interfaces *net.Interface) net.HardwareAddr {
	stop := make(chan struct{})

	defer close(stop)

	var addrChan = make(chan net.HardwareAddr)

	go readRemoteMacAddr(handle, interfaces, stop, addrChan)

	sendRemoteMacAddrRequest(srcNet.IP, remoteAddr, srcMac, handle)

	select {
	case addr := <-addrChan:
		return addr
	}
}

func getNetAddrBySrcIP(srcIp net.IP) (*net.IPNet, error) {
	interfacesAddresses, err := net.InterfaceAddrs()

	if err != nil {
		panic(err)
	}

	for _, address := range interfacesAddresses {
		_, network, err := net.ParseCIDR(address.String())
		if err != nil {
			return nil, err
		}
		if network.Contains(srcIp) {
			return network, nil
		}
	}
	return nil, nil
}

func compileEthLayer(scrMac net.HardwareAddr, dstMac net.HardwareAddr) *layers.Ethernet {
	return &layers.Ethernet{
		SrcMAC:       scrMac,
		DstMAC:       dstMac,
		EthernetType: layers.EthernetTypeIPv4,
	}
}

func compileIP4layer(srcIp net.IP, dstIp net.IP) *layers.IPv4 {
	return &layers.IPv4{
		SrcIP:    srcIp,
		DstIP:    dstIp,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
}

func compileSyn(ip4l *layers.IPv4, srcPort uint16, dstPort uint16) layers.TCP {
	var err error
	var tcp layers.TCP

	tcp = layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
	}
	err = tcp.SetNetworkLayerForChecksum(ip4l)

	if err != nil {
		panic("Failed to set network layer checksum")
	}

	return tcp
}

func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func makeFd() int {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_IP)))

	if err != nil {
		panic(err)
	}
	return fd
}

func sendSyn(fd *int, packet []byte, interfaceIndex int, packetsToSend int) {
	addr := &syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_IP),
		Ifindex:  interfaceIndex,
	}
	startTime := time.Now()
	for i := 0; i < packetsToSend; i++ {
		err := syscall.Sendto(*fd, packet, 0, addr)
		if err != nil {
			panic(err)
		}
	}
	fmt.Println("Time to send", packetsToSend, "packets:", time.Since(startTime))
}

func produceSyn(eth *layers.Ethernet, ip4 *layers.IPv4, tcp *layers.TCP, packetsQuantity int) []byte {
	var err error
	var buffer gopacket.SerializeBuffer
	var opts gopacket.SerializeOptions
	buffer = gopacket.NewSerializeBuffer()

	opts = gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	startTime := time.Now()
	for i := 0; i < packetsQuantity; i++ {
		err = gopacket.SerializeLayers(buffer, opts, eth, ip4, tcp)
		if err != nil {
			panic("Failed to serialize buffer")
		}
	}
	fmt.Println("Time to produce", packetsQuantity, "packets:", time.Since(startTime))

	return buffer.Bytes()
}

func main() {
	//
	//fmt.Print("Enter addr and dstPort: ")
	//_, err := fmt.Scanf("%s %s", &rawDstAddr, &dstPort)
	var err error

	fmt.Println("Remote address :", dstAddr.String(), ", dstPort:", dstPort)
	router, err = netroute.New()

	if err != nil {
		fmt.Println("Failed to create router")
		panic(err)
	}

	srcInterface, dstGw, srcIp, err = router.Route(dstAddr)

	fmt.Println("Target interface:", srcInterface.Name)

	if srcIp == nil {
		panic("Unable to find Source ip")
	}
	srcNetwork, err = getNetAddrBySrcIP(srcIp)
	if err != nil {
		panic("Failed to get source network")
	}
	fmt.Println("Source ip network is:", srcNetwork)

	if dstGw == nil && !srcNetwork.Contains(dstAddr) {
		fmt.Println("Using default gateway")
		dstGw, err = gateway.DiscoverGateway()
		if err != nil {
			panic("Failed to determine default gateway")
		}
	}

	SourceMac = srcInterface.HardwareAddr
	fmt.Println("Source MAC:", SourceMac)

	readHandler, err = pcap.OpenLive(srcInterface.Name, 65536, false, pcap.BlockForever)
	defer readHandler.Close()
	if dstGw != nil {
		remoteMac = getRemoteMacAddr(srcNetwork, dstGw, &SourceMac, readHandler, srcInterface)
	} else {

		remoteMac = getRemoteMacAddr(srcNetwork, dstAddr, &SourceMac, readHandler, srcInterface)
	}
	fmt.Println("Remote MAC:", remoteMac)

	fmt.Println("Source Port:", srcPort)

	if err != nil {
		log.Fatalf("Failed to create afpacket handle: %v", err)
	}
	eth := compileEthLayer(SourceMac, remoteMac)
	ip := compileIP4layer(srcIp, dstAddr)
	tcp := compileSyn(ip, srcPort, dstPort)

	packetsQuantity := 1
	packet := produceSyn(eth, ip, &tcp, packetsQuantity) // the function produces packets to benchmark and returns one of them
	fd := makeFd()
	defer syscall.Close(fd)
	packetsToSend := 30000
	sendSyn(&fd, packet, srcInterface.Index, packetsToSend)
}

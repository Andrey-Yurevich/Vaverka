package main

import (
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"log"
	"math/rand"
	"net"
	"time"
)

const genCount = 1048576

func makePortsList() *[]uint16 {
	var portsList []uint16
	portsList = make([]uint16, 0)

	for i := 0; i < genCount; i++ {
		portsList = append(portsList, uint16(rand.Intn(65535-1)+1))
	}
	return &portsList
}

func buildBasicLayers(SrcMAC, DstMAC net.HardwareAddr, SrcIP, DstIP net.IP) (*layers.Ethernet, *layers.IPv4) {

	var ethLayer layers.Ethernet
	var ipLayer layers.IPv4

	ethLayer = layers.Ethernet{
		SrcMAC:       SrcMAC,
		DstMAC:       DstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipLayer = layers.IPv4{
		SrcIP:    SrcIP,
		DstIP:    DstIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	return &ethLayer, &ipLayer
}

func buildTCPPacket(ethLayer *layers.Ethernet, ipLayer *layers.IPv4, srcPort, dstPort uint16) ([]byte, error) {
	//const tcpSynTemplate = [255,255,255,255,0,0,0,0,0,0,0,0,80,2,0,0,0,0,0,0]
	var buffer gopacket.SerializeBuffer
	var bufferOpts gopacket.SerializeOptions
	var tcpLayer layers.TCP
	var err error

	buffer = gopacket.NewSerializeBuffer()
	bufferOpts = gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	tcpLayer = layers.TCP{
		SYN:     true,
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
	}

	err = tcpLayer.SetNetworkLayerForChecksum(ipLayer)
	if err != nil {
		log.Printf("Error setting network layer for checksum: %v", err)
		return nil, err
	}

	err = gopacket.SerializeLayers(buffer, bufferOpts, ethLayer, ipLayer, &tcpLayer)
	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), err
}

func main() {
	var startTime time.Time
	var portsList []uint16
	var ethLayer *layers.Ethernet
	var ipLayer *layers.IPv4
	var packet []byte
	var dstPort uint16
	var err error

	var srcMac, dstMac net.HardwareAddr
	var srcIP, dstIP net.IP
	var srcPort uint16
	srcMac, err = net.ParseMAC("18:01:88:09:98:26")

	if err != nil {
		panic(err)
	}

	dstMac, err = net.ParseMAC("34:c7:e2:a2:36:5f")

	if err != nil {
		panic(err)
	}

	srcIP = net.ParseIP("192.168.1.100")
	dstIP = net.ParseIP("192.168.1.200")

	srcPort = 65535

	portsList = *makePortsList()
	startTime = time.Now()
	ethLayer, ipLayer = buildBasicLayers(srcMac, dstMac, srcIP, dstIP)

	for _, dstPort = range portsList {
		packet, err = buildTCPPacket(ethLayer, ipLayer, srcPort, dstPort)
		if err != nil {
			panic(err)
		}

		log.Print(packet)
	}
	log.Printf("%d iterations took %s", genCount, time.Since(startTime))
}

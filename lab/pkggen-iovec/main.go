package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"log"
	"math/rand"
	"net"
	"syscall"
	"time"
	"unsafe"
)

const genCount = 1048576

type Mmsghdr struct {
	Msg syscall.Msghdr
	Len uint32
	_   [4]byte
}

func buildIOvecs(packets *[64][60]byte, sockaddr *syscall.RawSockaddrLinklayer) []Mmsghdr {
	//log.Printf("Building IO vectors for %d packets", len(packets))

	var iovecs []syscall.Iovec
	var msgs []Mmsghdr

	iovecs = make([]syscall.Iovec, 64)
	msgs = make([]Mmsghdr, 64)

	for i, packet := range *packets {
		iovecs[i] = syscall.Iovec{
			Base: &packet[0],
			Len:  uint64(60),
		}
		msgs[i].Msg = syscall.Msghdr{
			Iov:     &iovecs[i],
			Iovlen:  1,
			Name:    (*byte)(unsafe.Pointer(sockaddr)),
			Namelen: uint32(unsafe.Sizeof(*sockaddr)),
		}
		//log.Printf("Packet %d: length=%d bytes", i, len(packet))
	}
	return msgs
}

func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func validatePacket(srcMac, dstMac net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, packetBytes []byte) error {

	packet := gopacket.NewPacket(packetBytes, layers.LayerTypeEthernet, gopacket.Default)

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {

		// Get actual TCP data from this layer
		tcp, _ := tcpLayer.(*layers.TCP)
		if uint16(tcp.SrcPort) != srcPort {
			return fmt.Errorf("source port expected: %d, but got: %d", srcPort, tcp.SrcPort)
		}
		if uint16(tcp.DstPort) != dstPort {
			return fmt.Errorf("destination port expected: %d, but got: %d", dstPort, tcp.DstPort)
		}

	} else {
		return errors.New("no tcp layer found")
	}

	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {

		// Get actual TCP data from this layer
		ip, _ := ipLayer.(*layers.IPv4)
		if !ip.SrcIP.Equal(srcIP) {
			return fmt.Errorf("source ip expected: %s, but got: %s", srcIP, ip.SrcIP)
		}
		if !ip.DstIP.Equal(dstIP) {
			return fmt.Errorf("destination ip expected: %s, but got: %s", dstIP, ip.DstIP)
		}

		if ip.Protocol != 6 { // tcp/ip index
			return fmt.Errorf("ip protocol expected: %d, but got: %s", 6, ip.Protocol)
		}

		if ip.Version != 4 {
			return fmt.Errorf("ip version expected: %d, but got: %d", 4, ip.Version)
		}

	} else {
		return errors.New("no ip layer found")
	}

	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {

		// Get actual TCP data from this layer
		eth, _ := ethLayer.(*layers.Ethernet)
		if eth.SrcMAC.String() != srcMac.String() {
			return fmt.Errorf("source mac expected: %s, but got: %s", srcMac, eth.SrcMAC)
		}

		if eth.DstMAC.String() != dstMac.String() {
			return fmt.Errorf("source mac expected: %s, but got: %s", srcMac, eth.SrcMAC)
		}
		if eth.EthernetType != layers.EthernetTypeIPv4 {
			return fmt.Errorf("eth layer expected: %s, but got: %s", layers.EthernetTypeIPv4, eth.EthernetType)
		}
	} else {
		return errors.New("no eth layer found")
	}

	return nil
}

func makePortsList() []uint16 {
	portsList := make([]uint16, genCount)
	for i := 0; i < genCount; i++ {
		portsList[i] = uint16(rand.Intn(65535-1) + 1)
	}
	return portsList
}

func makeSkeleton(srcMac, dstMac net.HardwareAddr, srcIp, dstIp net.IP, srcPort uint16) [60]byte {
	base := [60]byte{
		0, 0, 0, 0, 0, 0, // dst mac
		0, 0, 0, 0, 0, 0, // src mac
		8, // Ethernet type
		0, // length
		// end eth
		69,    // version + header length
		0,     // tos
		0, 40, // packet length
		0, 0, // id
		0, 0, //Flags + Fragment Offset
		64,   // TTL
		6,    //IPProtocolTCP
		0, 0, // checksum
		0, 0, 0, 0, //src ip
		0, 0, 0, 0, // dst ip
		// end ip
		0, 0, //src port
		0, 0, //dst port
		0, 0, 0, 0, // seq
		0, 0, 0, 0, // ack
		80,   // headers length + flags
		2,    // syn flag
		0, 0, // window
		0, 0, // checksum
		0, 0, // urgent
		0, 0, 0, 0, 0, 0, // padding
	}
	copy(base[0:], dstMac)
	copy(base[6:], srcMac)
	copy(base[26:], srcIp[12:])
	copy(base[30:], dstIp[12:])
	binary.BigEndian.PutUint16(base[34:], srcPort)
	//log.Print(base)
	return base
}

func buildTCPPacket(skeleton *[60]byte, dstPort uint16) [60]byte {
	var packet [60]byte

	packet = *skeleton

	binary.BigEndian.PutUint16(packet[36:], dstPort)

	// ip checksum
	binary.BigEndian.PutUint16(packet[24:], gopacket.FoldChecksum(gopacket.ComputeChecksum(packet[14:33], 0)))
	// tcp checksum
	binary.BigEndian.PutUint16(packet[50:], gopacket.FoldChecksum(gopacket.ComputeChecksum(packet[34:53], 6)))
	return packet
}

func main() {
	var startTime time.Time
	var portsList []uint16

	var srcMac, dstMac net.HardwareAddr
	var srcIP, dstIP net.IP
	var srcPort uint16

	var packetsBuffer [64][60]byte
	srcMac, _ = net.ParseMAC("18:01:88:09:98:26")
	dstMac, _ = net.ParseMAC("34:c7:e2:a2:36:5f")

	srcIP = net.ParseIP("192.168.1.100")
	dstIP = net.ParseIP("192.168.1.200")

	srcPort = 65535

	portsList = makePortsList()

	invalidPackets := 0
	skeleton := makeSkeleton(srcMac, dstMac, srcIP, dstIP, srcPort)

	//for _, dstPort = range portsList {
	//	_ = buildTCPPacket(&skeleton, dstPort)
	//	//var err error
	//	//err = validatePacket(srcMac, dstMac, srcIP, dstIP, srcPort, dstPort, packet[:])
	//	//if err != nil {
	//	//	log.Printf("invalid packet: %b %e", packet, err)
	//	//	invalidPackets++
	//	//}
	//
	//}
	sockaddr := syscall.RawSockaddrLinklayer{
		Family:   syscall.AF_PACKET,
		Protocol: htons(syscall.ETH_P_IP),
		Ifindex:  int32(1),
	}
	totalPacketsBuilt := 0
	totalIovecsBuilt := 0
	startTime = time.Now()
	for i := 0; i < (genCount / 64); i++ {
		for j := 0; j < 64; j++ {
			packetsBuffer[j] = buildTCPPacket(&skeleton, portsList[i*64+j])
			totalPacketsBuilt++
		}
		_ = buildIOvecs(&packetsBuffer, &sockaddr)
		totalIovecsBuilt++
	}
	log.Printf("%d iterations took %s", genCount, time.Since(startTime))
	log.Printf("Invalid packets: %d", invalidPackets)
	log.Printf("Total packets built %d", totalPacketsBuilt)
	log.Printf("Total iovecs built %d", totalIovecsBuilt)
}

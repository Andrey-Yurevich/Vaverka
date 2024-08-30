package main

import (
	// "log"
	"net"

	// "github.com/google/gopacket"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	// Указываем адрес назначения
	dstIP := net.IPv4(127, 0, 0, 1)
	srcIP := net.IPv4(127, 0, 0, 1)
	ifname := "lo0"

	eth := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
		SrcPort: 54321,
		DstPort: 65535,
		SYN:     true,
	}
	tcp.SetNetworkLayerForChecksum(&ip4)

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}

	gopacket.SerializeLayers(buffer, opts, &eth, &ip4, &tcp)

	handle, err := pcap.OpenLive(ifname, 65536, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	handle.WritePacketData(buffer.Bytes())
}

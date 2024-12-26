package scanner

import (
	"bytes"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/routing"
	"log"
	"net"
	"syscall"
)

var MaxPPS = -1

type Mmsghdr struct {
	Msg syscall.Msghdr
	Len uint32
	_   [4]byte
}

func getRoute(dstIpAddress net.IP) (*net.Interface, net.IP, net.IP, error) {

	router, err := routing.New()
	if err != nil {
		log.Printf("Error creating router: %v", err)
		return nil, nil, nil, err
	}

	iface, gw, src, err := router.Route(dstIpAddress)
	if err != nil {
		return nil, nil, nil, err
	}

	return iface, gw, src, nil
}

func sendRemoteMacAddrRequest(srcIP []byte, dstIP []byte, srcMac net.HardwareAddr, handle *pcap.Handle) {
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
		panic(err)
	}

	err = handle.WritePacketData(buf.Bytes())

	if err != nil {
		panic(err)
	}
}

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

func getRemoteMacAddrSingleHost(sourceIP net.IP, remoteIP net.IP, sourceInterface *net.Interface) net.HardwareAddr {
	var handle *pcap.Handle
	var stop chan bool
	var err error
	var addr net.HardwareAddr
	stop = make(chan bool)
	defer close(stop)

	handle, err = pcap.OpenLive(sourceInterface.Name, 65536, false, pcap.BlockForever)
	if err != nil {
		panic(err)
	}

	var addrChan = make(chan net.HardwareAddr)

	go readRemoteMacAddr(handle, sourceInterface, stop, addrChan)

	sendRemoteMacAddrRequest(sourceIP, remoteIP, sourceInterface.HardwareAddr, handle)

	select {
	case addr = <-addrChan:
		return addr

	}
}

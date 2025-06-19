package scanner

import (
	"Vaverka/constants"
	"Vaverka/router"
	"fmt"
	"net"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

func interceptICMPv6Replies(handle *pcap.Handle, srcIP net.IP, ethIPPairChan chan router.EthIPPairBytes, timeout time.Duration) {
	defer close(ethIPPairChan)
	defer handle.Close()

	src := gopacket.NewPacketSource(handle, handle.LinkType())

	packets := src.Packets()

	t := time.NewTimer(timeout)
	defer t.Stop()

	for {
		select {

		case <-t.C:
			return

		case packet, ok := <-packets:
			if !ok {
				return
			}

			// Ethernet
			ethLayer := packet.Layer(layers.LayerTypeEthernet)
			if ethLayer == nil {
				continue
			}
			eth := ethLayer.(*layers.Ethernet)

			// IPv6
			ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
			if ipv6Layer == nil {
				continue
			}
			ipv6 := ipv6Layer.(*layers.IPv6)

			if !ipv6.DstIP.Equal(srcIP) {
				continue
			}

			// ICMPv6
			icmpLayer := packet.Layer(layers.LayerTypeICMPv6)
			if icmpLayer == nil {
				continue
			}
			icmp := icmpLayer.(*layers.ICMPv6)

			// Echo Reply?
			if icmp.TypeCode.Type() != layers.ICMPv6TypeEchoReply {
				continue
			}

			ethIPPairChan <- router.EthIPPairBytes{Eth: eth.SrcMAC, Ip: ipv6.SrcIP}

		}
	}
}

func sendICMPv6EchoRequestMulticast(handle *pcap.Handle, sourceMac net.HardwareAddr, srcAddress, dstAddress net.IP) error {

	dstMac := net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0x01}

	eth := &layers.Ethernet{
		SrcMAC:       sourceMac,
		DstMAC:       dstMac,
		EthernetType: layers.EthernetTypeIPv6}

	ipv6 := &layers.IPv6{
		Version:    6,
		SrcIP:      srcAddress,
		DstIP:      dstAddress,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   255,
	}
	icmpv6 := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(
			layers.ICMPv6TypeEchoRequest,
			0),
	}
	err := icmpv6.SetNetworkLayerForChecksum(ipv6)
	if err != nil {
		return err
	}
	icmpv6Payload := []byte("Vaverka")

	icmpv6echo := &layers.ICMPv6Echo{
		Identifier: 0x0908,
		SeqNumber:  2020,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	err = gopacket.SerializeLayers(buf, opts, eth, ipv6, icmpv6, icmpv6echo, gopacket.Payload(icmpv6Payload))

	if err != nil {
		return err
	}

	if err = handle.WritePacketData(buf.Bytes()); err != nil {
		return err
	}

	return nil
}

func FindIPv6NeighborsOnLink(sourceInterface *net.Interface, timeout time.Duration) (chan router.EthIPPairBytes, error) {
	var err error
	var sourceIP net.IP

	handle, err := pcap.OpenLive(sourceInterface.Name, constants.ICMPv6PacketMaxSize, false, time.Millisecond*20)
	if err != nil {
		return nil, err
	}

	interfaceAddresses, err := sourceInterface.Addrs()

	if err != nil {
		return nil, err
	}

	for _, address := range interfaceAddresses {
		sourceIP, _, err = net.ParseCIDR(address.String())

		if err != nil {
			return nil, err
		}

		if sourceIP.To4() == nil && sourceIP.To16() != nil {
			break // source ipv6 addr found
		}
	}

	ethIPPairChan := make(chan router.EthIPPairBytes, 16)

	go interceptICMPv6Replies(handle, sourceIP, ethIPPairChan, timeout)

	multicastAddrList, err := sourceInterface.MulticastAddrs()

	if err != nil {
		return nil, err
	}

	for _, sourceAddr := range multicastAddrList {
		mcastIP := net.ParseIP(sourceAddr.String())
		if mcastIP == nil {
			return nil, fmt.Errorf("failed to parse multicast address: %s", sourceAddr.String())
		}
		if mcastIP.To4() == nil && mcastIP.To16() != nil {
			err = sendICMPv6EchoRequestMulticast(handle, sourceInterface.HardwareAddr, sourceIP, mcastIP)
			if err != nil {
				return nil, err
			}
		}
	}

	return ethIPPairChan, nil
}

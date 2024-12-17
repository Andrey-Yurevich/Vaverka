package scanner

import (
	"Vaverka/rule"
	"Vaverka/utils"
	"fmt"
	"github.com/jackpal/gateway"
	"net"
	"sync"
)

func getLocalhostPorts() error { return nil }

func rawPacketsConsumer(packetsChan chan [IOvecPacketsChunkSize][]byte, wg *sync.WaitGroup, quitChan chan bool) {
	defer wg.Done()

	for {
		select {
		case <-quitChan:
			return
		case <-packetsChan:
			totalReceived++
			fmt.Println(totalReceived)
		}
	}
}

func arpScan(packetsChan chan [IOvecPacketsChunkSize][]byte, ipNet net.IPNet, sourceInterface net.Interface, sourceAddress net.IP, wg *sync.WaitGroup, quitChan chan bool) {

	defer wg.Done()

	var basePacket []byte
	var packets [IOvecPacketsChunkSize][]byte

	PacketSkeleton := []byte{
		// Ethernet header (14 bytes)
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // [0:6]   Destination MAC: FF:FF:FF:FF:FF:FF (broadcast)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // [6:12]  Source MAC - should be specified
		0x08, 0x06, // [12:14] EtherType: 0x0806 (ARP)

		// ARP header (28 bytes total)
		0x00, 0x01, // [14:16] Hardware Type: 1 (Ethernet)
		0x08, 0x00, // [16:18] Protocol Type: 0x0800 (IPv4)
		0x06,       // [18]    Hardware Address Size: 6 (MAC length)
		0x04,       // [19]    Protocol Address Size: 4 (IPv4 length)
		0x00, 0x01, // [20:22] Operation: 1 (ARP Request)

		// ARP body
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // [22:28] Sender HW address - should be specified
		0x00, 0x00, 0x00, 0x00, // [28:32] Sender IP - should be specified
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // [32:38] Target HW address
		0x00, 0x00, 0x00, 0x00, // [38:42] Target IP - should be specified

		// Padding (to reach the minimum Ethernet frame length of 60 bytes)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	basePacket = PacketSkeleton

	copy(basePacket[6:], sourceInterface.HardwareAddr)
	copy(basePacket[22:], sourceInterface.HardwareAddr)
	copy(basePacket[28:], sourceAddress)

	for chunkStartIp := ipNet.IP; ipNet.Contains(chunkStartIp); chunkStartIp = utils.IncIPv4(chunkStartIp, IOvecPacketsChunkSize) {

		var currentIpIndex = 0
		var chunkEndIP = utils.IncIPv4(chunkStartIp, IOvecPacketsChunkSize)

		if !ipNet.Contains(chunkEndIP) {
			for chunkEndIP = chunkStartIp; ipNet.Contains(chunkEndIP); chunkEndIP = utils.NextIPv4(chunkEndIP) {
			}
		}

		for addr := chunkStartIp; !addr.Equal(chunkEndIP); addr = utils.NextIPv4(addr) {
			packet := basePacket
			copy(packet[38:], addr.To4())

			packets[currentIpIndex] = packet
			currentIpIndex++

		}
		packetsChan <- packets

	}
	quitChan <- true

}

func scanOverGateway(gatewayEthernetAddress net.HardwareAddr, n net.IPNet) {}

func scanPointToPoint(packetsChan chan [IOvecPacketsChunkSize][]byte, sourceInterface net.Interface, n net.IPNet, sourceAddress net.IP, p []uint16, wg *sync.WaitGroup) error {

	var quitChan chan bool

	quitChan = make(chan bool)

	defer wg.Done()

	wg.Add(1)

	go arpScan(packetsChan, n, sourceInterface, sourceAddress, wg, quitChan)

	wg.Add(1)

	go rawPacketsConsumer(packetsChan, wg, quitChan)
	return nil
}

func VerticalPortScanner(r rule.Rule) error {
	var err error
	var sourceInterface *net.Interface
	var gatewayIP net.IP
	var gatewayHardwareAddress net.HardwareAddr
	var sourceIP net.IP
	var packetsChan chan [IOvecPacketsChunkSize][]byte
	var wg sync.WaitGroup

	packetsChan = make(chan [IOvecPacketsChunkSize][]byte, PacketsChanBufferSize)

	if r.Network.IP.IsLoopback() {
		err = getLocalhostPorts()
		if err != nil {
			return err
		}
		return nil
	}

	sourceInterface, gatewayIP, sourceIP, err = getRoute(r.Network.IP)
	if err != nil {
		return err
	}

	if sourceIP == nil {
		return fmt.Errorf("failed to find source ip for %s", r.Network.IP.String())
	}

	if sourceInterface == nil {
		return fmt.Errorf("failed to find source interface for %s", r.Network.IP.String())
	}

	//socketAddress = utils.GetSocket(sourceInterface)

	if gatewayIP == nil {
		var sourceNetwork *net.IPNet

		sourceNetwork, err = utils.GetNetAddrBySrcIP(sourceIP)

		if err != nil {
			return fmt.Errorf("failed to get network address by source IP for %s", sourceIP.String())
		}

		switch {
		case sourceNetwork.Contains(r.Network.IP):
			wg.Add(1)
			err = scanPointToPoint(packetsChan, *sourceInterface, r.Network, sourceIP, r.Ports, &wg)
			if err != nil {
				return fmt.Errorf("failed to fill out link layer table for network %s", r.Network.Network())
			}
		default:
			gatewayIP, err = gateway.DiscoverGateway()
			if err != nil {
				return fmt.Errorf("failed to get default gateway required to send packets to %s", r.Network.IP)
			}

			gatewayHardwareAddress = getRemoteMacAddrSingleHost(sourceIP, gatewayIP, sourceInterface)
			scanOverGateway(gatewayHardwareAddress, r.Network)
		}
	} else {
		gatewayHardwareAddress = getRemoteMacAddrSingleHost(sourceIP, gatewayIP, sourceInterface)
		scanOverGateway(gatewayHardwareAddress, r.Network)
	}

	wg.Wait()
	return nil

}

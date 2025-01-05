package scanner

import (
	"Vaverka/constants"
	"Vaverka/rule"
	"Vaverka/utils"
	"fmt"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/jackpal/gateway"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

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
func interceptArpPackets(
	networkInterface net.Interface,
	targetNetwork net.IPNet,
	errorChan chan error,
	readyToInterceptChan chan bool,
	doneChan chan bool,
	waitGroup *sync.WaitGroup,
) {
	defer waitGroup.Done()

	handle, err := pcap.OpenLive(
		networkInterface.Name,
		constants.ArpPacketPayloadSize,
		true,
		constants.PcapCaptureTimeout,
	)
	if err != nil {
		errorChan <- err
		return
	}
	defer handle.Close()

	err = handle.SetBPFFilter(fmt.Sprintf("net %s and arp", targetNetwork.String()))
	if err != nil {
		errorChan <- err
		return
	}

	err = handle.SetDirection(pcap.DirectionIn)
	if err != nil {
		errorChan <- err
		return
	}

	err = handle.SetLinkType(layers.LinkTypeEthernet)
	if err != nil {
		errorChan <- err
		return
	}

	packetSource := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	incomingPacketsChan := packetSource.Packets()

	// Notify that we are ready to capture ARP packets
	readyToInterceptChan <- true

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
				"{\"host\": \"%s\", \"state\": \"up\", \"technique\": \"arp\", \"network\": \"%s\", \"hardwareAddress\": \"%s\"}\n",
				net.IP(arpData.SourceProtAddress),
				targetNetwork.String(),
				net.HardwareAddr(arpData.SourceHwAddress),
			)
		case <-doneChan:
			return
		}
	}
}

// arpScan sends ARP requests for each IP address in the subnet and waits for replies.
func arpScan(
	socketFD int,
	socketAddressName *byte,
	socketAddressNameLen uint32,
	targetNetwork net.IPNet,
	networkInterface net.Interface,
	localIP net.IP,
	errorChan chan error,
	doneChan chan bool,
	waitGroup *sync.WaitGroup,
) {
	defer waitGroup.Done()

	readyToInterceptChan := make(chan bool)
	defer close(readyToInterceptChan)

	// Prepare slices of structures for the sendmmsg syscall
	var messageHeaders [constants.IOvecPacketsChunkSize]Mmsghdr
	var rawArpPackets [constants.IOvecPacketsChunkSize][constants.MinFrameSize]byte
	var ioVectors [constants.IOvecPacketsChunkSize]syscall.Iovec

	waitGroup.Add(1)
	go interceptArpPackets(
		networkInterface,
		targetNetwork,
		errorChan,
		readyToInterceptChan,
		doneChan,
		waitGroup,
	)

	// Wait until we can start capturing ARP packets
	<-readyToInterceptChan

	arpPacketTemplate := prepareArpPacketTemplate(networkInterface.HardwareAddr, localIP)
	packetLength := uint64(constants.MinFrameSize)

	// Generate ARP packets for each IP chunk in the subnet
	for ipChunk := range utils.IterateSubnetBlocksBytes(targetNetwork) {
		for i := range ipChunk {
			rawArpPackets[i] = arpPacketTemplate
			copy(rawArpPackets[i][38:], ipChunk[i][:])

			ioVectors[i] = syscall.Iovec{
				Base: &rawArpPackets[i][0],
				Len:  packetLength,
			}
			messageHeaders[i].Msg = syscall.Msghdr{
				Name:    socketAddressName,
				Namelen: socketAddressNameLen,
				Iov:     &ioVectors[i],
				Iovlen:  1,
			}
		}

		_, _, errno := syscall.RawSyscall(
			constants.SendMmsgSyscallIndex, // Syscall number for sendmmsg on some architectures
			uintptr(socketFD),
			uintptr(unsafe.Pointer(&messageHeaders[0])),
			uintptr(len(messageHeaders)),
		)
		if errno.Error() != "errno 0" {
			errorChan <- errno
		}
	}

	// Pause to give hosts time to respond to ARP requests
	time.Sleep(constants.ArpScanWaitResponseTime)
	doneChan <- true
}

// scanOverGateway is a placeholder for scanning through a gateway.
func scanOverGateway(gatewayMacAddress net.HardwareAddr, targetNetwork net.IPNet) {
	// TODO: implement scanning through a gateway
}

// scanPointToPoint performs point-to-point scanning within a single subnet.
func scanPointToPoint(
	networkInterface net.Interface,
	targetNetwork net.IPNet,
	localIP net.IP,
	targetPorts []uint16,
	waitGroup *sync.WaitGroup,
) error {
	errorChan := make(chan error, 2)
	doneChan := make(chan bool)

	socketParameters := utils.GetSocketParameters(&networkInterface)
	socketAddressName := (*byte)(unsafe.Pointer(&socketParameters))
	socketAddressNameLen := uint32(unsafe.Sizeof(socketParameters))

	socketFD, err := utils.GetSocket()
	if err != nil {
		return err
	}
	defer func(fd int) {
		_ = syscall.Close(fd)
	}(socketFD)

	waitGroup.Add(1)
	go arpScan(
		socketFD,
		socketAddressName,
		socketAddressNameLen,
		targetNetwork,
		networkInterface,
		localIP,
		errorChan,
		doneChan,
		waitGroup,
	)

	waitGroup.Wait()
	return nil
}

// VerticalPortScanner is the main function for port scanning using the provided rule.
func VerticalPortScanner(scanRule rule.Rule) error {
	// If dealing with a loopback interface, handle separately
	if scanRule.Network.IP.IsLoopback() {
		if err := getLocalhostPorts(); err != nil {
			return err
		}
		return nil
	}

	// Build the route
	networkInterface, gatewayIP, localIP, err := utils.GetRoute(scanRule.Network.IP)
	if err != nil {
		return err
	}
	if localIP == nil {
		return fmt.Errorf("failed to find source IP for %s", scanRule.Network.IP.String())
	}
	if networkInterface == nil {
		return fmt.Errorf("failed to find source interface for %s", scanRule.Network.IP.String())
	}

	var waitGroup sync.WaitGroup

	// If the route does not go through a gateway, check if it's a peer-to-peer network
	if gatewayIP == nil {
		sourceNetwork, err := utils.GetNetAddrBySrcIP(localIP)
		if err != nil {
			return fmt.Errorf("failed to get network address by source IP for %s", localIP.String())
		}

		switch {
		// If the target IP belongs to the same subnet, run a p2p scan
		case sourceNetwork.Contains(scanRule.Network.IP):
			err = scanPointToPoint(
				*networkInterface,
				scanRule.Network,
				localIP,
				scanRule.Ports,
				&waitGroup,
			)
			if err != nil {
				return fmt.Errorf("point-to-point scan failed: %w", err)
			}
		default:
			// If not in the same network, discover the default gateway
			gw, err := gateway.DiscoverGateway()
			if err != nil {
				return fmt.Errorf("failed to get default gateway required to send packets to %s", scanRule.Network.IP)
			}
			gatewayMAC := getRemoteMacAddrSingleHost(localIP, gw, networkInterface)
			scanOverGateway(gatewayMAC, scanRule.Network)
		}
	} else {
		// If a gateway exists, get its MAC address and scan through it
		gatewayMAC := getRemoteMacAddrSingleHost(localIP, gatewayIP, networkInterface)
		scanOverGateway(gatewayMAC, scanRule.Network)
	}

	return nil
}

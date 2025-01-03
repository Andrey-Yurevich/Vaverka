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

// iovecPacketsConsumer reads batches of Mmsghdr from the channel and sends them via sendmmsg.
//func iovecPacketsConsumer(sock int, iovecPacketsChan chan []Mmsghdr, wg *sync.WaitGroup, errChan chan error) {
//	defer wg.Done()
//
//	for {
//		select {
//		case messages, ok := <-iovecPacketsChan:
//			if !ok {
//				return
//			}
//			if len(messages) == 0 {
//				break
//			}
//			_, _, errno := syscall.RawSyscall(
//				269, // sendmmsg syscall number on some architectures
//				uintptr(sock),
//				uintptr(unsafe.Pointer(&messages[0])),
//				uintptr(len(messages)),
//			)
//			if errno.Error() != "errno 0" {
//				errChan <- errno
//			}
//			// Uncomment for debug:
//			// fmt.Printf("iovecPacketsConsumer received messages: %+v\n", messages)
//		}
//	}
//}

// prepareArpPacketTemplate constructs a minimal ARP packet with provided hardware and IP addresses.
func prepareArpPacketTemplate(hardwareAddress net.HardwareAddr, sourceAddress net.IP) [constants.MinFrameSize]byte {
	var arpTemplate [constants.MinFrameSize]byte
	arpTemplate = constants.ArpPacketSkeleton

	copy(arpTemplate[6:], hardwareAddress)
	copy(arpTemplate[22:], hardwareAddress)
	copy(arpTemplate[28:], sourceAddress)

	return arpTemplate
}

// interceptArpPackets listens on the given interface for ARP packets in the specified network.
func interceptArpPackets(
	sourceInterface net.Interface,
	network net.IPNet,
	errChan chan error,
	readyToIntercept chan bool,
	done chan bool,
	wg *sync.WaitGroup,
) {
	var (
		handle       *pcap.Handle
		packetSource *gopacket.PacketSource
		err          error
		in           chan gopacket.Packet
		packet       gopacket.Packet
		arpData      *layers.ARP
		ok           bool
	)

	defer wg.Done()

	handle, err = pcap.OpenLive(
		sourceInterface.Name,
		constants.ArpPacketPayloadSize,
		true,
		constants.PcapCaptureTimeout,
	)
	if err != nil {
		errChan <- err
		return
	}

	defer handle.Close()

	err = handle.SetBPFFilter(fmt.Sprintf("net %s and arp", network.String()))
	if err != nil {
		errChan <- err
		return
	}

	err = handle.SetDirection(pcap.DirectionIn)
	if err != nil {
		errChan <- err
		return
	}

	err = handle.SetLinkType(layers.LinkTypeEthernet)
	if err != nil {
		errChan <- err
		return
	}

	packetSource = gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in = packetSource.Packets()
	readyToIntercept <- true

	for {
		select {
		case packet, ok = <-in:
			if !ok {
				return
			}
			if packet.Layer(layers.LayerTypeARP) == nil {
				continue
			}
			arpData = packet.Layer(layers.LayerTypeARP).(*layers.ARP)
			fmt.Println(
				fmt.Sprintf(
					"{\"host\": \"%s\", \"state\": \"up\", \"technique\": \"arp\", \"network\": \"%s\", \"hardwareAddress\": \"%s\"}",
					net.IP(arpData.SourceProtAddress),
					network.String(),
					net.HardwareAddr(arpData.SourceHwAddress),
				),
			)
		case <-done:
			return
		}
	}
}

// arpScan sends ARP requests for each IP in the network and waits for responses.
func arpScan(
	sock int,
	sockAddrName *byte,
	nameLen uint32,
	network net.IPNet,
	sourceInterface net.Interface,
	sourceAddress net.IP,
	errChan chan error,
	doneChan chan bool,
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	var readyToInterceptChan chan bool

	readyToInterceptChan = make(chan bool)
	defer close(readyToInterceptChan)

	var msgs [constants.IOvecPacketsChunkSize]Mmsghdr
	var rawPacketsArray [constants.IOvecPacketsChunkSize][constants.MinFrameSize]byte
	var iovecs [constants.IOvecPacketsChunkSize]syscall.Iovec

	var arpPacketTemplate [constants.MinFrameSize]byte
	var packetLen uint64

	wg.Add(1)
	go interceptArpPackets(sourceInterface, network, errChan, readyToInterceptChan, doneChan, wg)
	<-readyToInterceptChan

	packetLen = uint64(constants.MinFrameSize)

	// Creating a targeted packet from the template
	arpPacketTemplate = prepareArpPacketTemplate(sourceInterface.HardwareAddr, sourceAddress)

	for addrBytesArray := range utils.IterateSubnetBlocksBytes(network) {
		for i := range addrBytesArray {
			rawPacketsArray[i] = arpPacketTemplate
			copy(rawPacketsArray[i][38:], addrBytesArray[i][:])

			iovecs[i] = syscall.Iovec{
				Base: &rawPacketsArray[i][0],
				Len:  packetLen,
			}
			msgs[i].Msg = syscall.Msghdr{
				Name:    sockAddrName,
				Namelen: nameLen,
				Iov:     &iovecs[i],
				Iovlen:  1,
			}
		}
		_, _, errno := syscall.RawSyscall(
			269, // sendmmsg syscall number on some architectures
			uintptr(sock),
			uintptr(unsafe.Pointer(&msgs[0])),
			uintptr(len(msgs)),
		)
		if errno.Error() != "errno 0" {
			errChan <- errno
		}
	}
	// Wait for a short period to allow hosts to respond
	time.Sleep(constants.ArpScanWaitResponseTime)
	doneChan <- true
}

// scanOverGateway is a placeholder for scanning via a gateway.
func scanOverGateway(gatewayEthernetAddress net.HardwareAddr, network net.IPNet) {
	// TODO: implement scanning through a gateway
}

// scanPointToPoint performs point-to-point scanning within the provided network.
func scanPointToPoint(
	sourceInterface net.Interface,
	network net.IPNet,
	sourceAddress net.IP,
	ports []uint16,
	wg *sync.WaitGroup,
) error {
	var (
		sock           int
		sockNameLen    uint32
		sockAddrName   *byte
		sockParameters syscall.RawSockaddrLinklayer
		err            error
		errChan        = make(chan error, 2) // Common channel for errors
		doneChan       = make(chan bool)
	)

	sockParameters = utils.GetSocketParameters(&sourceInterface)
	sockAddrName = (*byte)(unsafe.Pointer(&sockParameters))
	sockNameLen = uint32(unsafe.Sizeof(sockParameters))

	//iovecPacketsChan = make(chan []Mmsghdr, constants.PacketsChanBufferSize)

	// Obtain the socket
	sock, err = utils.GetSocket()
	if err != nil {
		return err
	}

	defer func(fd int) {
		_ = syscall.Close(fd)
	}(sock)

	wg.Add(1)
	go arpScan(sock, sockAddrName, sockNameLen, network, sourceInterface, sourceAddress, errChan, doneChan, wg)

	wg.Wait()
	return nil
}

// VerticalPortScanner is the primary function for port scanning using the given rule.
func VerticalPortScanner(r rule.Rule) error {
	var (
		err                 error
		sourceInterface     *net.Interface
		gatewayIP           net.IP
		gatewayHardwareAddr net.HardwareAddr
		sourceIP            net.IP
		wg                  sync.WaitGroup
	)

	// If we are dealing with the loopback interface, handle it separately
	if r.Network.IP.IsLoopback() {
		err = getLocalhostPorts()
		if err != nil {
			return err
		}
		return nil
	}

	// Build the route
	sourceInterface, gatewayIP, sourceIP, err = utils.GetRoute(r.Network.IP)
	if err != nil {
		return err
	}
	if sourceIP == nil {
		return fmt.Errorf("failed to find source IP for %s", r.Network.IP.String())
	}

	if sourceInterface == nil {
		return fmt.Errorf("failed to find source interface for %s", r.Network.IP.String())
	}

	// If the route does not go through the gateway, it is likely a peer-to-peer network
	if gatewayIP == nil {
		var sourceNetwork *net.IPNet

		// Attempt to retrieve our network address by source IP
		sourceNetwork, err = utils.GetNetAddrBySrcIP(sourceIP)
		if err != nil {
			return fmt.Errorf("failed to get network address by source IP for %s", sourceIP.String())
		}

		switch {
		// If we are in a peer-to-peer network, start p2p scanning
		case sourceNetwork.Contains(r.Network.IP):
			err = scanPointToPoint(*sourceInterface, r.Network, sourceIP, r.Ports, &wg)
			if err != nil {
				return fmt.Errorf("point-to-point scan failed with the following error: %s", err)
			}
		default:
			// If we are not on the same network, use the default gateway
			gatewayIP, err = gateway.DiscoverGateway()
			if err != nil {
				return fmt.Errorf("failed to get default gateway required to send packets to %s", r.Network.IP)
			}

			gatewayHardwareAddr = getRemoteMacAddrSingleHost(sourceIP, gatewayIP, sourceInterface)
			scanOverGateway(gatewayHardwareAddr, r.Network)
		}
	} else {
		// If a gateway exists, obtain its MAC address and start scanning through the gateway
		gatewayHardwareAddr = getRemoteMacAddrSingleHost(sourceIP, gatewayIP, sourceInterface)
		scanOverGateway(gatewayHardwareAddr, r.Network)
	}

	return nil
}

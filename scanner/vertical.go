package scanner

import (
	"Vaverka/constants"
	"Vaverka/rule"
	"Vaverka/utils"
	"fmt"
	"github.com/google/gopacket/pcap"
	"github.com/jackpal/gateway"
	"net"
	"strconv"
	"sync"
	"syscall"
	"unsafe"
)

func getLocalhostPorts() error { return nil }

func iovecPacketsConsumer(sock int, iovecPacketsChan chan []Mmsghdr, wg *sync.WaitGroup) {
	defer wg.Done()
	defer fmt.Println("end of iovecPacketsConsumer")
	for {
		select {
		case messages, ok := <-iovecPacketsChan:
			if !ok {
				return
			}
			if len(messages) == 0 {
				break
			}
			_, _, _ = syscall.RawSyscall(269, uintptr(sock), uintptr(unsafe.Pointer(&messages[0])), uintptr(len(messages)))

			//fmt.Println(errno)
			//fmt.Printf("iovecPacketsConsumer received messages: %+v\n", messages)
		}
	}
}

func prepareArpPacketTemplate(hardwareAddress net.HardwareAddr, sourceAddress net.IP) [constants.ArpPacketSize]byte {
	var arpTemplate [constants.ArpPacketSize]byte
	arpTemplate = constants.ArpPacketSkeleton

	copy(arpTemplate[6:], hardwareAddress)
	copy(arpTemplate[22:], hardwareAddress)
	copy(arpTemplate[28:], sourceAddress)

	return arpTemplate
}

func arpScan(sockAddrName *byte, nameLen uint32, network net.IPNet, sourceInterface net.Interface, sourceAddress net.IP, iovecPacketsChan chan []Mmsghdr, wg *sync.WaitGroup) {

	defer wg.Done()
	defer fmt.Println("end of arpScan")
	var arpPacketTemplate [constants.ArpPacketSize]byte

	var packetLen uint64

	packetLen = uint64(constants.ArpPacketSize)

	// creating targetted packet from template
	arpPacketTemplate = prepareArpPacketTemplate(sourceInterface.HardwareAddr, sourceAddress)

	for addrBytesArrey := range utils.IterateSubnetBlocksBytes(network) {
		var msgs [constants.IOvecPacketsChunkSize]Mmsghdr
		var rawPacketsArray [constants.IOvecPacketsChunkSize][constants.ArpPacketSize]byte
		var iovecs [constants.IOvecPacketsChunkSize]syscall.Iovec

		for i := range addrBytesArrey {
			rawPacketsArray[i] = arpPacketTemplate
			copy(rawPacketsArray[i][38:], addrBytesArrey[i][:])

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
		iovecPacketsChan <- msgs[:constants.IOvecPacketsChunkSize]
	}
	close(iovecPacketsChan)

}

func scanOverGateway(gatewayEthernetAddress net.HardwareAddr, n net.IPNet) {}

func scanPointToPoint(sourceInterface net.Interface, network net.IPNet, sourceAddress net.IP, p []uint16, wg *sync.WaitGroup) error {
	defer fmt.Println("end of scanPointToPoint")
	var sock int
	var iovecPacketsChan chan []Mmsghdr

	var err error

	var nameLen uint32
	var sockAddrName *byte
	var sockParameters syscall.RawSockaddrLinklayer

	sockParameters = utils.GetSocketParameters(&sourceInterface)
	sockAddrName = (*byte)(unsafe.Pointer(&sockParameters))
	nameLen = uint32(unsafe.Sizeof(sockParameters))

	iovecPacketsChan = make(chan []Mmsghdr, constants.PacketsChanBufferSize)

	sock, err = utils.GetSocket()

	if err != nil {
		return err
	}

	wg.Add(2)

	go arpScan(sockAddrName, nameLen, network, sourceInterface, sourceAddress, iovecPacketsChan, wg)
	go iovecPacketsConsumer(sock, iovecPacketsChan, wg)
	wg.Wait()
	fmt.Println("close p2p")
	return nil
}

func VerticalPortScanner(r rule.Rule) error {
	var err error
	var sourceInterface *net.Interface
	var gatewayIP net.IP
	var gatewayHardwareAddress net.HardwareAddr
	var sourceIP net.IP
	var wg sync.WaitGroup
	var handler pcap.Handle
	var BPFrules []string
	BPFrules = make([]string, 0)

	if r.Network.IP.IsLoopback() {
		err = getLocalhostPorts()
		if err != nil {
			return err
		}
		return nil
	}

	BPFrules = append(BPFrules, "net "+r.Network.String())
	if r.PortScanTechniques.Syn || r.PortScanTechniques.Fin {
		for port := range r.Ports {
			BPFrules = append(BPFrules, "tcp port "+strconv.Itoa(port)+"")
		}
	}

	if r.PortScanTechniques.Syn {
		BPFrules = append(BPFrules, "tcp.flags.syn==1")
	}

	if r.PortScanTechniques.Syn {
		BPFrules = append(BPFrules, "tcp.flags.fin==1")
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

	if gatewayIP == nil {
		var sourceNetwork *net.IPNet

		sourceNetwork, err = utils.GetNetAddrBySrcIP(sourceIP)

		if err != nil {
			return fmt.Errorf("failed to get network address by source IP for %s", sourceIP.String())
		}

		switch {
		case sourceNetwork.Contains(r.Network.IP):

			err = scanPointToPoint(*sourceInterface, r.Network, sourceIP, r.Ports, &wg)
			if err != nil {
				return fmt.Errorf("point to point scan failed with the following error: %s", err)
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

	return nil

}

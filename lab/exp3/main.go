package main

import (
	"bytes"
	"fmt"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/routing"
	"github.com/jackpal/gateway"
	"github.com/libp2p/go-netroute"
	"log"
	"net"
	"sync"
	"syscall"
	"time"
)

var router routing.Router
var srcInterface *net.Interface
var srcIp net.IP
var srcNetwork *net.IPNet
var SourceMac net.HardwareAddr
var srcPort = uint16(54321)
var remoteMac net.HardwareAddr
var dstPort = uint16(80)
var dstGw net.IP
var dstAddr = net.IP{10, 0, 1, 20}
var readHandler *pcap.Handle

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

func readRemoteMacAddr(handle *pcap.Handle, interfaces *net.Interface, stop chan struct{}, addrChan chan net.HardwareAddr) {
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
			if arpData.Operation != layers.ARPReply || bytes.Equal(interfaces.HardwareAddr, arpData.SourceHwAddress) {
				// This is a packet I sent.
				continue
			}

			addrChan <- arpData.SourceHwAddress

		}
	}
}

func getRemoteMacAddr(srcNet *net.IPNet, remoteAddr net.IP, srcMac *net.HardwareAddr, handle *pcap.Handle, interfaces *net.Interface) net.HardwareAddr {
	stop := make(chan struct{})

	defer close(stop)

	var addrChan = make(chan net.HardwareAddr)

	go readRemoteMacAddr(handle, interfaces, stop, addrChan)

	sendRemoteMacAddrRequest(srcNet.IP, remoteAddr, srcMac, handle)

	select {
	case addr := <-addrChan:
		return addr
	}
}

func getNetAddrBySrcIP(srcIp net.IP) (*net.IPNet, error) {
	interfacesAddresses, err := net.InterfaceAddrs()

	if err != nil {
		panic(err)
	}

	for _, address := range interfacesAddresses {
		_, network, err := net.ParseCIDR(address.String())
		if err != nil {
			return nil, err
		}
		if network.Contains(srcIp) {
			return network, nil
		}
	}
	return nil, nil
}

func compileEthLayer(scrMac net.HardwareAddr, dstMac net.HardwareAddr) *layers.Ethernet {
	return &layers.Ethernet{
		SrcMAC:       scrMac,
		DstMAC:       dstMac,
		EthernetType: layers.EthernetTypeIPv4,
	}
}

func compileIP4layer(srcIp net.IP, dstIp net.IP) *layers.IPv4 {
	return &layers.IPv4{
		SrcIP:    srcIp,
		DstIP:    dstIp,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
}

func compileSyn(ip4l *layers.IPv4, srcPort uint16, dstPort uint16) layers.TCP {
	var err error
	var tcp layers.TCP

	tcp = layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
	}
	err = tcp.SetNetworkLayerForChecksum(ip4l)

	if err != nil {
		panic("Failed to set network layer checksum")
	}

	return tcp
}

func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func makeFd() int {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_IP)))

	if err != nil {
		panic(err)
	}
	return fd
}

func sendSynBenchmark(fd *int, packet []byte, interfaceIndex int, rate int, quit chan bool, wg *sync.WaitGroup) {
	defer syscall.Close(*fd)
	defer wg.Done()
	addr := &syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_IP),
		Ifindex:  interfaceIndex,
	}

	var tSlice []time.Duration
	for i := 0; i < 11; i++ {
		startTime := time.Now()

		err := syscall.Sendto(*fd, packet, 0, addr)
		if err != nil {
			panic(err)
		}
		tSlice = append(tSlice, time.Since(startTime))
	}
	_, tSlice = tSlice[0], tSlice[1:] // remove first element because first send takes too much time
	averageSendDelay := countAverageDelay(tSlice)

	fmt.Println("syscall.send takes on average:", averageSendDelay)
	//interval := duration/time.Duration(rate) - averageSendDelay
	var interval time.Duration
	if averageSendDelay*time.Duration(rate) > time.Second {
		fmt.Println("It is impossible to send", rate, "packets per second. With this rate, a maximum of", time.Second/averageSendDelay, " packets can be sent.")
		fmt.Println("Rate won't be used")
		interval = time.Duration(0)
	} else {
		interval = time.Second/time.Duration(rate) - averageSendDelay
	}

	fmt.Println("Send interval:", interval)
	fmt.Println("Packet sent rate is", rate)
	i := 0
	startTime := time.Now()
	var perPacketTime time.Time
	var iterTime time.Time

	for {
		iterTime = time.Now()
		select {
		case <-quit:
			fmt.Println("Packets sent:", i, ".", "Took", time.Since(startTime))
			return
		default:
			perPacketTime = time.Now()
			err := syscall.Sendto(*fd, packet, 0, addr)
			fmt.Println("1 packet send took", time.Since(perPacketTime))
			//time.Sleep(interval)
			syscall.NsecToTimespec(interval.Nanoseconds())

			if err != nil {
				panic(err)
			}

			i++
			fmt.Println("1 iteration itself took", time.Since(iterTime))
			fmt.Println("Interval is", interval)
			/* 8375 nanosec per 1 packet with no sleep interval */
		}
	}
}

func makeSyn(eth *layers.Ethernet, ip4 *layers.IPv4, tcp *layers.TCP) []byte {
	var err error
	var buffer gopacket.SerializeBuffer
	var opts gopacket.SerializeOptions
	buffer = gopacket.NewSerializeBuffer()

	opts = gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err = gopacket.SerializeLayers(buffer, opts, eth, ip4, tcp)

	if err != nil {
		panic("Failed to serialize buffer")
	}

	return buffer.Bytes()
}

func countAverageDelay(tSlice []time.Duration) time.Duration {
	var sum int

	sum = 0
	for i := 0; i < len(tSlice); i++ {
		sum += int(tSlice[i])
	}
	return time.Duration(sum / len(tSlice))
}

func tick(duration time.Duration, quit chan bool) {
	time.Sleep(duration)
	quit <- true
	close(quit)
}

func main() {
	//
	//fmt.Print("Enter addr and dstPort: ")
	//_, err := fmt.Scanf("%s %s", &rawDstAddr, &dstPort)
	var err error
	var wg sync.WaitGroup

	fmt.Println("Remote address :", dstAddr.String(), ", dstPort:", dstPort)
	router, err = netroute.New()

	if err != nil {
		fmt.Println("Failed to create router")
		panic(err)
	}

	srcInterface, dstGw, srcIp, err = router.Route(dstAddr)

	fmt.Println("Target interface:", srcInterface.Name)

	if srcIp == nil {
		panic("Unable to find Source ip")
	}
	srcNetwork, err = getNetAddrBySrcIP(srcIp)
	if err != nil {
		panic("Failed to get source network")
	}
	fmt.Println("Source ip network is:", srcNetwork)

	if dstGw == nil && !srcNetwork.Contains(dstAddr) {
		fmt.Println("Using default gateway")
		dstGw, err = gateway.DiscoverGateway()
		if err != nil {
			panic("Failed to determine default gateway")
		}
	}

	SourceMac = srcInterface.HardwareAddr
	fmt.Println("Source MAC:", SourceMac)

	readHandler, err = pcap.OpenLive(srcInterface.Name, 65536, false, pcap.BlockForever)
	defer readHandler.Close()
	if dstGw != nil {
		remoteMac = getRemoteMacAddr(srcNetwork, dstGw, &SourceMac, readHandler, srcInterface)
	} else {

		remoteMac = getRemoteMacAddr(srcNetwork, dstAddr, &SourceMac, readHandler, srcInterface)
	}
	fmt.Println("Remote MAC:", remoteMac)

	fmt.Println("Source Port:", srcPort)

	if err != nil {
		log.Fatalf("Failed to create afpacket handle: %v", err)
	}
	eth := compileEthLayer(SourceMac, remoteMac)
	ip := compileIP4layer(srcIp, dstAddr)
	tcp := compileSyn(ip, srcPort, dstPort)

	packet := makeSyn(eth, ip, &tcp) // the function produces packets to benchmark and returns one of them
	fd := makeFd()
	rate := 10000
	duration := 1 * time.Second
	quit := make(chan bool)
	wg.Add(1)
	go tick(duration, quit)
	go sendSynBenchmark(&fd, packet, srcInterface.Index, rate, quit, &wg)
	wg.Wait()

}

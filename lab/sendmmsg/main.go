package main

import (
	"flag"
	"log"
	"net"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/routing"
)

type Mmsghdr struct {
	Msg syscall.Msghdr
	Len uint32
	_   [4]byte
}

func AverageDuration(durations []time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	var sum time.Duration
	for _, duration := range durations {
		sum += duration
	}
	average := sum / time.Duration(len(durations))
	return average
}

func getRoute(dstIpAddress net.IP) (*net.Interface, net.IP, net.IP, error) {
	log.Printf("Getting route to destination IP: %s", dstIpAddress.String())
	router, err := routing.New()
	if err != nil {
		log.Printf("Error creating router: %v", err)
		return nil, nil, nil, err
	}

	iface, gw, src, err := router.Route(dstIpAddress)
	if err != nil {
		log.Printf("Error finding route: %v", err)
		return nil, nil, nil, err
	}

	log.Printf("Route found: Interface=%s, Gateway=%s, Source IP=%s", iface.Name, gw, src)
	return iface, gw, src, nil
}

func buildBaseLayer(SrcMAC net.HardwareAddr, DstMAC net.HardwareAddr, SrcIP net.IP, DstIP net.IP) (layers.Ethernet, layers.IPv4, error) {
	log.Printf("Building base layers")
	log.Printf("SrcMAC: %s, DstMAC: %s, SrcIP: %s, DstIP: %s", SrcMAC.String(), DstMAC.String(), SrcIP.String(), DstIP.String())

	var ethLayer layers.Ethernet
	var ipLayer layers.IPv4
	var buffer gopacket.SerializeBuffer
	var bufferOpts gopacket.SerializeOptions
	var err error

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

	buffer = gopacket.NewSerializeBuffer()
	bufferOpts = gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err = gopacket.SerializeLayers(buffer, bufferOpts, &ethLayer, &ipLayer)
	if err != nil {
		log.Printf("Error serializing layers: %v", err)
		return layers.Ethernet{}, layers.IPv4{}, err
	}

	log.Printf("Base layers built successfully")
	return ethLayer, ipLayer, nil
}

func buildSynPackage(srcPort uint16, dstPort uint16, ethLayer *layers.Ethernet, ipLayer *layers.IPv4) ([]byte, error) {
	//log.Printf("Building SYN packet: SrcPort=%d, DstPort=%d", srcPort, dstPort)

	var tcpLayer layers.TCP
	var err error
	var buffer gopacket.SerializeBuffer
	var bufferOpts gopacket.SerializeOptions

	tcpLayer = layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
	}
	err = tcpLayer.SetNetworkLayerForChecksum(ipLayer)
	if err != nil {
		log.Printf("Error setting network layer for checksum: %v", err)
		return nil, err
	}

	buffer = gopacket.NewSerializeBuffer()
	bufferOpts = gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err = gopacket.SerializeLayers(buffer, bufferOpts, ethLayer, ipLayer, &tcpLayer)
	if err != nil {
		log.Printf("Error serializing SYN packet: %v", err)
		return nil, err
	}

	packetBytes := buffer.Bytes()
	//log.Printf("SYN packet built: %d bytes", len(packetBytes))
	return packetBytes, nil
}

func buildIOvecs(packets [][]byte, srcInterface net.Interface) []Mmsghdr {
	//log.Printf("Building IO vectors for %d packets", len(packets))

	var iovecs []syscall.Iovec
	var msgs []Mmsghdr

	iovecs = make([]syscall.Iovec, len(packets))
	msgs = make([]Mmsghdr, len(packets))

	sockaddr := syscall.RawSockaddrLinklayer{
		Family:   syscall.AF_PACKET,
		Protocol: htons(syscall.ETH_P_IP),
		Ifindex:  int32(srcInterface.Index),
	}

	for i, packet := range packets {
		iovecs[i] = syscall.Iovec{
			Base: &packet[0],
			Len:  uint64(len(packet)),
		}
		msgs[i].Msg = syscall.Msghdr{
			Iov:     &iovecs[i],
			Iovlen:  1,
			Name:    (*byte)(unsafe.Pointer(&sockaddr)),
			Namelen: uint32(unsafe.Sizeof(sockaddr)),
		}
		//log.Printf("Packet %d: length=%d bytes", i, len(packet))
	}
	return msgs
}

func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func sendPackets(msgsArray []Mmsghdr, resend int) (time.Duration, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_IP)))
	if err != nil {
		log.Printf("Error creating socket: %v", err)
		return time.Duration(0), err
	}
	defer func() {
		if err := syscall.Close(fd); err != nil {
			log.Printf("Error closing socket: %v", err)
		}
	}()

	startTime := time.Now()
	for round := 0; round < resend; round++ {
		//_, _, errno := syscall.RawSyscall(syscall.SYS_SENDMMSG, uintptr(fd), uintptr(unsafe.Pointer(&msgsArray[0])), uintptr(len(msgsArray)))
		_, _, errno := syscall.RawSyscall(269, uintptr(fd), uintptr(unsafe.Pointer(&msgsArray[0])), uintptr(len(msgsArray)))
		if errno != 0 {
			err = errno
			log.Printf("Error in sendmmsg syscall: %v", err)
			return time.Duration(0), err
		}
		runtime.KeepAlive(msgsArray)
		//log.Printf("Round %d: Sent %d messages", round+1, n)
	}
	durationTime := time.Since(startTime)
	log.Printf("Finished sending packets. Duration: %s. Total sent %d", durationTime.String(), resend*len(msgsArray))
	return durationTime, nil
}

func multipleRuns(srcInterface net.Interface, srcIpAddress net.IP, dstIpAddress net.IP, dstMac net.HardwareAddr, srcPort uint16, rounds int, resend int, chunkSize int) (time.Duration, error) {
	log.Printf("Starting multiple runs")
	log.Printf("Source Interface: %s", srcInterface.Name)
	log.Printf("Source IP Address: %s", srcIpAddress.String())
	log.Printf("Destination IP Address: %s", dstIpAddress.String())
	log.Printf("Source Port: %d", srcPort)
	log.Printf("Rounds: %d, Resend: %d, Chunk Size: %d", rounds, resend, chunkSize)

	var err error
	var ethLayer layers.Ethernet
	var ipLayer layers.IPv4
	var deltas []time.Duration
	var delta time.Duration
	var synPackets [][]byte
	deltas = make([]time.Duration, 0)
	ethLayer, ipLayer, err = buildBaseLayer(srcInterface.HardwareAddr, dstMac, srcIpAddress, dstIpAddress)
	if err != nil {
		log.Printf("Error building base layers: %v", err)
		return time.Duration(0), err
	}

	for j := 0; j < chunkSize; j++ {
		dstPort := uint16(1000 + j)
		packet, err := buildSynPackage(srcPort, dstPort, &ethLayer, &ipLayer)
		if err != nil {
			log.Printf("Error building SYN package: %v", err)
			return time.Duration(0), err
		}
		synPackets = append(synPackets, packet)
	}

	for i := 0; i < rounds; i++ {
		log.Printf("Round %d/%d", i+1, rounds)

		IOvecArray := buildIOvecs(synPackets, srcInterface)
		delta, err = sendPackets(IOvecArray, resend)
		if err != nil {
			log.Printf("Error sending packets: %v", err)
			return time.Duration(0), err
		}

		deltas = append(deltas, delta)
		time.Sleep(time.Second * 1)
	}

	return AverageDuration(deltas), nil
}

func main() {
	log.Print("Sendmmsg() syscall")
	dstFlag := flag.String("dst", "", "Destination IP")
	dstMacFlag := flag.String("mac", "0a:ff:cf:b6:1c:e3", "Destination Mac")
	chunkSizeFlag := flag.Int("chunkSize", 50, "Number of packets in one array")
	resendFlag := flag.Int("resend", 100, "Number of times to resend packets")
	srcPortFlag := flag.Uint("src-port", 54321, "Source port")
	roundsFlag := flag.Int("rounds", 1000, "Number of rounds")
	flag.Parse()

	log.Printf("Destination address: %s", *dstFlag)
	log.Printf("Chunk size: %d", *chunkSizeFlag)
	log.Printf("Resend count: %d", *resendFlag)
	log.Printf("Source port: %d", *srcPortFlag)
	log.Printf("Rounds: %d", *roundsFlag)

	dstIP := net.ParseIP(*dstFlag)
	if dstIP == nil {
		log.Fatalf("Invalid destination IP address: %s", *dstFlag)
	}

	srcInterface, _, srcIpAddress, err := getRoute(dstIP)
	if err != nil {
		log.Fatalf("Error getting route: %v", err)
	}

	log.Printf("Using source interface: %s", srcInterface.Name)
	log.Printf("Source IP address: %s", srcIpAddress.String())
	dstMac, err := net.ParseMAC(*dstMacFlag)
	if err != nil {
		log.Fatalf("Failed to parse dst mac: %v", err)
	}
	average, err := multipleRuns(*srcInterface, srcIpAddress, dstIP, dstMac, uint16(*srcPortFlag), *roundsFlag, *resendFlag, *chunkSizeFlag)
	if err != nil {
		log.Fatalf("Error in multipleRuns: %v", err)
	}
	log.Printf("packets per second: %d. Total rounds %d. Average time %s ", *chunkSizeFlag**resendFlag, *roundsFlag, average)
}

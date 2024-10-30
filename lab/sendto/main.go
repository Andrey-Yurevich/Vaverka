package main

import (
	"flag"
	"log"
	"net"
	"syscall"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/routing"
)

var srcInterface *net.Interface
var dstHardwareAddress net.HardwareAddr
var srcIpAddress net.IP
var gatewayIpAddress net.IP
var dstIpAddress net.IP
var synBytes []byte

func getDstHardwareAddress() (net.HardwareAddr, error) {
	mac, err := net.ParseMAC("0a:ff:cf:b6:1c:e3")
	return mac, err
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
	log.Printf("Entering getRoute with destination IP address: %s", dstIpAddress.String())
	router, err := routing.New()

	if err != nil {
		log.Printf("Failed to create router object: %v", err)
		return nil, nil, nil, err
	}

	srcInterface, gatewayIpAddress, srcIpAddress, err = router.Route(dstIpAddress)

	if err != nil {
		log.Printf("Failed to get route to destination %s: %v", dstIpAddress.String(), err)
		return nil, nil, nil, err
	}

	log.Printf("Route information obtained: srcInterface=%s, gatewayIpAddress=%s, srcIpAddress=%s",
		srcInterface.Name, gatewayIpAddress.String(), srcIpAddress.String())

	return srcInterface, gatewayIpAddress, srcIpAddress, err
}

func compileSyn(srcHardwareAddress net.HardwareAddr, local bool, dstHardwareAddress net.HardwareAddr,
	srcIpAddress net.IP, dstIpAddress net.IP,
	srcPort uint16, dstPort uint16) ([]byte, error) {

	log.Printf("Entering compileSyn with srcIpAddress=%s, dstIpAddress=%s, srcPort=%d, dstPort=%d, local=%v",
		srcIpAddress.String(), dstIpAddress.String(), srcPort, dstPort, local)

	var (
		eth  layers.Ethernet
		lo   layers.Loopback
		ip4  layers.IPv4
		tcp  layers.TCP
		opts gopacket.SerializeOptions
	)

	if local {
		lo = layers.Loopback{
			Family: layers.ProtocolFamilyIPv4,
		}
	} else {
		eth = layers.Ethernet{
			SrcMAC:       srcHardwareAddress,
			DstMAC:       dstHardwareAddress,
			EthernetType: layers.EthernetTypeIPv4,
		}
	}

	ip4 = layers.IPv4{
		SrcIP:    srcIpAddress,
		DstIP:    dstIpAddress,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp = layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
	}
	err := tcp.SetNetworkLayerForChecksum(&ip4)
	if err != nil {
		log.Printf("Failed to set network layer for checksum: %v", err)
		return nil, err
	}

	buffer := gopacket.NewSerializeBuffer()

	opts = gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if local {
		err = gopacket.SerializeLayers(buffer, opts, &lo, &ip4, &tcp)
	} else {
		err = gopacket.SerializeLayers(buffer, opts, &eth, &ip4, &tcp)
	}
	if err != nil {
		log.Printf("Failed to serialize SYN packet: %v", err)
		return nil, err
	}

	log.Printf("SYN packet serialized successfully")
	return buffer.Bytes(), nil
}

func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func multipleRuns(quantity int, bytes *[]byte, interfaceIndex int, rounds int) (time.Duration, error) {
	var dList []time.Duration
	var delta time.Duration
	dList = make([]time.Duration, 0)
	var err error
	for i := 0; i < rounds; i++ {
		log.Printf("Round %d/%d", i+1, rounds)
		delta, err = sendPackets(quantity, bytes, interfaceIndex)
		if err != nil {
			return 0, err
		}
		time.Sleep(time.Second * 1)
		dList = append(dList, delta)
	}

	return AverageDuration(dList), nil
}

func sendPackets(quantity int, bytes *[]byte, interfaceIndex int) (time.Duration, error) {
	var err error
	var fd int
	var startTime time.Time

	fd, err = syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_IP)))
	if err != nil {
		log.Printf("Failed to create socket: %v", err)
		return 0, err
	}

	addr := &syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_IP),
		Ifindex:  interfaceIndex,
	}

	defer func(fd int) {
		err = syscall.Close(fd)
		if err != nil {
			log.Printf("Failed to close socket: %v", err)
		}
	}(fd)
	startTime = time.Now()
	for i := 0; i < quantity; i++ {
		err = syscall.Sendto(fd, *bytes, 0, addr)
		if err != nil {
			return 0, err
		}
	}

	return time.Since(startTime), nil
}

func main() {
	var err error
	var average time.Duration
	log.Print("Sendto() syscall")
	dstFlag := flag.String("dst", "", "Destination address")
	quantityFlag := flag.Int("count", 1000, "Packets count")
	srcPortFlag := flag.Uint("src-port", 54321, "Source port")
	dstPortFlag := flag.Uint("dst-port", 80, "Source port")
	roundsFlag := flag.Uint("rounds", 1000, "Rounds")
	flag.Parse()
	dstIpAddress = net.ParseIP(*dstFlag)

	log.Printf("Destination IP address: %s", dstIpAddress.String())

	srcInterface, gatewayIpAddress, srcIpAddress, err = getRoute(dstIpAddress)
	if err != nil {
		log.Fatalf("Failed to get route to host %s: %v", dstIpAddress.String(), err)
	}

	log.Printf("Source interface name: %s", srcInterface.Name)
	log.Printf("Source interface index: %d", srcInterface.Index)
	log.Printf("Source hardware address is: %s", srcInterface.HardwareAddr.String())
	if gatewayIpAddress != nil {
		log.Printf("Gateway IP: %s", gatewayIpAddress.String())
	}
	log.Printf("Source IP: %s", srcIpAddress.String())
	switch {
	case dstIpAddress.Equal(srcIpAddress):
		dstHardwareAddress = srcInterface.HardwareAddr
		synBytes, err = compileSyn(srcInterface.HardwareAddr, true, dstHardwareAddress, srcIpAddress, dstIpAddress, uint16(*srcPortFlag), uint16(*dstPortFlag))
	case dstIpAddress.IsLoopback():
		dstHardwareAddress = nil
		synBytes, err = compileSyn(srcInterface.HardwareAddr, true, dstHardwareAddress, srcIpAddress, dstIpAddress, uint16(*srcPortFlag), uint16(*dstPortFlag))
	default:
		dstHardwareAddress, err = getDstHardwareAddress()
		if err != nil {
			log.Fatalf("Failed to get destination MAC address: %v", err)
		}
		log.Printf("Destination hardware address: %s", dstHardwareAddress.String())

		synBytes, err = compileSyn(srcInterface.HardwareAddr, false, dstHardwareAddress, srcIpAddress, dstIpAddress, uint16(*srcPortFlag), uint16(*dstPortFlag))
	}

	if err != nil {
		log.Fatalf("Failed to compile SYN packet: %v", err)
	}
	log.Printf("SYN packet bytes: %v", synBytes)

	average, err = multipleRuns(*quantityFlag, &synBytes, srcInterface.Index, int(*roundsFlag))
	if err != nil {
		panic(err)
	}
	log.Printf("Packets per second: %d. Total rounds: %d. Average time: %s", *quantityFlag, *roundsFlag, average)
}

package main

import (
	"fmt"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/routing"
	"github.com/jackpal/gateway"
	"net"
	"runtime"
	"strings"
	"syscall"
	"time"
)

var router routing.Router
var srcInterface *net.Interface
var srcIp net.IP
var srcNetwork *net.IPNet
var SourceMac net.HardwareAddr
var dstGw net.IP

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
		Protocol: layers.IPProtocolUDP,
	}
}

func compileUDP(ip4l *layers.IPv4, srcPort uint16, dstPort uint16) layers.UDP {
	var err error
	var udp layers.UDP
	udp = layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	err = udp.SetNetworkLayerForChecksum(ip4l)

	if err != nil {
		panic("Failed to set network layer checksum")
	}

	return udp
}

func sendUDPBenchmark(packet []byte, interfaceIndex int) {

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_IP)))

	if err != nil {
		fmt.Println("error", err.Error())
		return
	}

	defer syscall.Close(fd)

	addr := &syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_IP),
		Ifindex:  interfaceIndex,
	}

	for i := 0; i < 1000000; i++ {
		err = syscall.Sendto(fd, packet, 0, addr)
		if err != nil {
			fmt.Println("Error:", err.Error())
			return
		}
		if i%15000 == 0 {
			time.Sleep(100 * time.Millisecond)

		}
	}
	fmt.Println("Done")
}

func makePacket(eth *layers.Ethernet, ip4 *layers.IPv4, udp *layers.UDP) []byte {
	var err error
	var buffer gopacket.SerializeBuffer
	var opts gopacket.SerializeOptions
	var payload []byte
	buffer = gopacket.NewSerializeBuffer()

	opts = gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	payload = make([]byte, 60)
	err = gopacket.SerializeLayers(buffer, opts, eth, ip4, udp, gopacket.Payload(payload))

	if err != nil {
		panic("Failed to serialize buffer")
	}

	return buffer.Bytes()
}
func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func formatNumberWithDots(n int) string {
	// Преобразуем число в строку
	numStr := fmt.Sprintf("%d", n)
	var result strings.Builder

	// Двигаемся по строке с конца, добавляя точки каждые три цифры
	for i, digit := range numStr {
		if (len(numStr)-i)%3 == 0 && i != 0 {
			result.WriteRune('.')
		}
		result.WriteRune(digit)
	}

	return result.String()
}

func runBenchmark(remoteMac net.HardwareAddr, dstAddr net.IP, srcPort, dstPort uint16) {
	runtime.GOMAXPROCS(1)
	var err error

	fmt.Println("Remote address :", dstAddr.String(), ", dstPort:", dstPort)
	router, err = routing.New()

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

	//SourceMac = srcInterface.HardwareAddr
	SourceMac = net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe}
	fmt.Println("Source MAC:", SourceMac)

	eth := compileEthLayer(SourceMac, remoteMac)
	srcIp = net.IP{192, 168, 64, 1}
	ip := compileIP4layer(srcIp, dstAddr)
	udp := compileUDP(ip, srcPort, dstPort)

	packet := makePacket(eth, ip, &udp) // the function produces packets to benchmark and returns one of them

	sendUDPBenchmark(packet, srcInterface.Index)
}
func main() {
	//var remoteMac = net.HardwareAddr{0x00, 0x50, 0x56, 0x3e, 0x28, 0x78}
	remoteMac := net.HardwareAddr{0xc0, 0xff, 0xee, 0x00, 0x00, 0x00}
	var dstAddr = net.IP{10, 0, 1, 20}
	var srcPort = uint16(12345)
	var dstPort = uint16(12345)
	runBenchmark(remoteMac, dstAddr, srcPort, dstPort)
}

package main

import (
	"flag"
	"fmt"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"net"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

var srcInterface *net.Interface
var srcIp net.IP
var srcMac net.HardwareAddr
var srcPort uint16
var dstMac net.HardwareAddr
var dstPort uint16
var dstIp net.IP
var duration time.Duration

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

func sendSynBenchmark(packet []byte, interfaceIndex int, quit chan bool, wg *sync.WaitGroup, resultChan chan int, index int) {

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_IP)))

	if err != nil {
		panic(err)
	}

	defer syscall.Close(fd)
	defer wg.Done()

	addr := &syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_IP),
		Ifindex:  interfaceIndex,
	}

	i := 0
	startTime := time.Now()
	defer func() {
		resultChan <- i
	}()
	for {
		select {
		case <-quit:

			return
		default:
			err := syscall.Sendto(fd, packet, 0, addr)
			if err != nil {
				fmt.Println("Gorutine #", index, ".Packets sent:", i, ".", "Took", time.Since(startTime))
				panic(err)
			}
			i += 1
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

func tick(duration time.Duration, quit chan bool) {
	time.Sleep(duration)
	quit <- true
	close(quit)
}

func main() {

	var err error
	var wg sync.WaitGroup

	srcMacStr := flag.String("srcmac", "", "Source MAC address")
	dstMacStr := flag.String("dstmac", "", "Destination MAC address")
	srcIPStr := flag.String("srcip", "", "Source IP address")
	dstIPStr := flag.String("dstip", "", "Destination IP address")
	replicas := flag.Int("replicas", 1, "Number of replicas")
	threads := flag.Int("threads", 1, "Number of goroutines")
	durationSec := flag.Int("duration", 1, "duration in seconds")
	srcInterfaceStr := flag.String("ifname", "", "Network interface name")
	srcPortStr := flag.Int("srcport", 54321, "Source port")
	dstPortStr := flag.Int("dstport", 80, "Destination port")
	flag.Parse()

	runtime.GOMAXPROCS(*threads)

	srcMac, err = net.ParseMAC(*srcMacStr)

	if err != nil {
		fmt.Println("Failed to parse source mac")
		panic(err)
	}

	dstMac, err = net.ParseMAC(*dstMacStr)

	if err != nil {
		fmt.Println("Failed to parse destination mac")
		panic(err)
	}

	srcIp = net.ParseIP(*srcIPStr)
	dstIp = net.ParseIP(*dstIPStr)
	srcInterface, err = net.InterfaceByName(*srcInterfaceStr)

	if err != nil {
		fmt.Println("Failed to get interface by name:", srcInterface)
		panic(err)
	}

	srcPort = uint16(*srcPortStr)
	dstPort = uint16(*dstPortStr)

	resultChan := make(chan int, 256)

	eth := compileEthLayer(srcMac, dstMac)
	ip := compileIP4layer(srcIp, dstIp)
	tcp := compileSyn(ip, srcPort, dstPort)

	packet := makeSyn(eth, ip, &tcp) // the function produces packets to benchmark and returns one of them
	duration = time.Duration(*durationSec) * time.Second
	quit := make(chan bool)

	fmt.Println("Threads :", *threads)
	fmt.Println("Replicas:", *replicas)
	fmt.Println("Source mac:", *srcMacStr)
	fmt.Println("Destination mac:", *dstMacStr)
	fmt.Println("Source IP:", *srcIPStr)
	fmt.Println("Destination IP:", *dstIPStr)
	fmt.Println("Source Interface:", (*srcInterface).Name)
	fmt.Println("Duration:", *durationSec)
	fmt.Println("Source port:", srcPort)
	fmt.Println("Destination port:", dstPort)

	go tick(duration, quit)

	for i := 0; i < *replicas; i++ {
		wg.Add(1)
		go sendSynBenchmark(packet, srcInterface.Index, quit, &wg, resultChan, i)
	}
	wg.Wait()
	close(resultChan)
	total := 0
	for result := range resultChan {
		total += result
	}
	fmt.Println("Total sent:", formatNumberWithDots(total))
}

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
var dstMac net.HardwareAddr
var dstIp net.IP
var duration time.Duration
var maxRate int

const sigQuit = 1
const sigSlowDown = 2
const sigResume = 3

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
		Protocol: layers.IPProtocolICMPv4,
	}
}

func compileICMP() layers.ICMPv4 {
	var icmp layers.ICMPv4

	icmp = layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(8, 0),
		Id:       1,
		Seq:      1,
	}
	return icmp
}

func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func ICMPBenchmark(packet []byte, interfaceIndex int, control chan uint8, wg *sync.WaitGroup, resultChan chan int, index int, counter *int) {
	var unlocked bool

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_IP)))

	if err != nil {
		panic(err)
	}

	defer syscall.Close(fd)

	addr := &syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_IP),
		Ifindex:  interfaceIndex,
	}

	startTime := time.Now()

	defer func() {
		resultChan <- *(counter)
	}()
	unlocked = true
	for {
		select {
		case action := <-control:

			switch action {
			case sigQuit:
				fmt.Println("Goroutine #", index, ".Packets sent:", *counter, ".", "Took", time.Since(startTime))
				return
			case sigSlowDown:
				unlocked = false
				fmt.Println("Slow down signal received")
			case sigResume:
				unlocked = true
				fmt.Println("Resume signal received")
			}

		default:
			if unlocked {
				err = syscall.Sendto(fd, packet, 0, addr)
				if err != nil {
					fmt.Println("Goroutine #", index, ".Packets sent:", *counter, ".", "Took", time.Since(startTime))
					panic(err)
				}
				*counter += 1
			}
		}
	}
	return
}

func makePacket(eth *layers.Ethernet, ip4 *layers.IPv4, tcp *layers.ICMPv4) []byte {
	var err error
	var buffer gopacket.SerializeBuffer
	var opts gopacket.SerializeOptions
	var payloadArr []byte

	payloadArr = make([]byte, 60)

	buffer = gopacket.NewSerializeBuffer()

	opts = gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err = gopacket.SerializeLayers(buffer, opts, eth, ip4, tcp, gopacket.Payload(payloadArr))

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

func durationTick(sleepTime time.Duration, controlChan chan uint8, wg *sync.WaitGroup) {
	time.Sleep(sleepTime)
	controlChan <- sigQuit
	wg.Done()
}

func benchmarkOrchestrator(packet []byte, interfaceIndex int, wg *sync.WaitGroup, resultChan chan int, index int) {
	var counter int
	var maxAllowedSpeed float64
	var currentSpeed float64
	var controlChan chan uint8
	var counterDelta int
	maxAllowedSpeed = float64(maxRate) / float64(time.Second)

	currentSpeed = 0

	controlChan = make(chan uint8)
	defer close(controlChan)

	go durationTick(duration, controlChan, wg)
	go ICMPBenchmark(packet, interfaceIndex, controlChan, wg, resultChan, index, &counter)

	for {
		time.Sleep(10 * time.Millisecond)

		counterDeltaOld := counterDelta
		fmt.Println(counterDeltaOld, counterDelta)
		counterDelta = counterDelta - counterDeltaOld

		fmt.Println("Packets sent last 10 ms:", counterDelta)
		currentSpeed = float64(100*counterDelta) / float64(1*time.Second) // packets per second
		fmt.Println("Current speed:", currentSpeed)
		if currentSpeed > maxAllowedSpeed*0.80 {
			controlChan <- sigSlowDown
			time.Sleep(10 * time.Millisecond)
			controlChan <- sigResume
		}
	}
}

func main() {

	var err error
	var wg sync.WaitGroup

	srcMacStr := flag.String("srcmac", "", "Source MAC address")
	dstMacStr := flag.String("dstmac", "", "Destination MAC address")
	srcIPStr := flag.String("srcip", "", "Source IP address")
	dstIPStr := flag.String("dstip", "", "Destination IP address")
	replicas := flag.Int("replicas", 1, "Number of replicas")
	threads := flag.Int("threads", 2, "Number of goroutines")
	durationSec := flag.Int("duration", 1, "duration in seconds")
	srcInterfaceStr := flag.String("ifname", "", "Network interface name")
	maxRate = *flag.Int("maxrate", 65535, "Max rate per host per second")

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

	resultChan := make(chan int, 256)

	eth := compileEthLayer(srcMac, dstMac)
	ip := compileIP4layer(srcIp, dstIp)
	icmp := compileICMP()

	packet := makePacket(eth, ip, &icmp) // the function produces packets to benchmark and returns one of them
	duration = time.Duration(*durationSec) * time.Second

	fmt.Println("Threads :", *threads)
	fmt.Println("Replicas:", *replicas)
	fmt.Println("Replicas:", *replicas)
	fmt.Println("Source mac:", *srcMacStr)
	fmt.Println("Destination mac:", *dstMacStr)
	fmt.Println("Source IP:", *srcIPStr)
	fmt.Println("Destination IP:", *dstIPStr)
	fmt.Println("Source Interface:", (*srcInterface).Name)
	fmt.Println("Duration:", *durationSec)
	fmt.Println("Max rate per host per second:", maxRate)

	for i := 0; i < *replicas; i++ {
		wg.Add(1)
		go benchmarkOrchestrator(packet, srcInterface.Index, &wg, resultChan, i)
	}
	wg.Wait()
	close(resultChan)
	total := 0
	for result := range resultChan {
		total += result
	}
	fmt.Println("Total sent:", formatNumberWithDots(total))
}

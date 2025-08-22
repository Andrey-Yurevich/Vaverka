package scanner

import (
	"Vaverka/constants"
	"Vaverka/router"
	"Vaverka/utils"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

func solicitedNode(ip net.IP) (net.IP, net.HardwareAddr) {
	v6 := ip.To16()
	last3 := v6[13:] // last 24 bites

	mIP := net.IP{255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 255, 0, 0, 0} // this is ff02::1:ff00:0
	copy(mIP[13:], last3)
	mMAC := net.HardwareAddr{0x33, 0x33, 0xff, last3[0], last3[1], last3[2]}
	return mIP, mMAC
}

// sendNsRequest broadcasts an ICMPv6 Neighbor Solicitation for the given IPv6 address.
func sendNsRequest(srcIP net.IP, dstIP net.IP, srcMAC net.HardwareAddr, handle *pcap.Handle) error {

	mIP, mMAC := solicitedNode(dstIP)

	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       mMAC,
		EthernetType: layers.EthernetTypeIPv6,
	}

	ip6 := layers.IPv6{
		Version:    6,
		SrcIP:      srcIP,
		DstIP:      mIP,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   255,
	}
	icmp6 := layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborSolicitation, 0),
	}

	err := icmp6.SetNetworkLayerForChecksum(&ip6)

	if err != nil {
		return err
	}

	ns := layers.ICMPv6NeighborSolicitation{
		TargetAddress: dstIP,
		Options: []layers.ICMPv6Option{
			{
				Type: 1,
				Data: []byte(srcMAC), // source MAC
			},
		},
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts,
		&eth,
		&ip6,
		&icmp6,
		&ns,
	); err != nil {
		return err
	}

	return handle.WritePacketData(buf.Bytes())
}

// readNsResponse listens for ICMPv6 Neighbor Advertisements
// and sends the discovered MAC address back on addrChan.
func readNsResponse(handle *pcap.Handle, stop chan bool, expectedIP net.IP, addrChan chan net.HardwareAddr) {
	var dstEth net.HardwareAddr

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	in := src.Packets()

	for {
		select {
		case <-stop:
			return
		case packet, ok := <-in:

			if !ok {
				return
			}

			ethLayer := packet.Layer(layers.LayerTypeEthernet)

			if ethLayer == nil {
				continue
			}

			ip6L := packet.Layer(layers.LayerTypeIPv6)
			if ip6L == nil || ip6L.(*layers.IPv6).HopLimit != 255 {
				continue
			}

			dstEth = packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet).SrcMAC

			naLayer := packet.Layer(layers.LayerTypeICMPv6NeighborAdvertisement)

			if naLayer == nil {
				continue
			}

			na := naLayer.(*layers.ICMPv6NeighborAdvertisement)

			if na.TargetAddress.Equal(expectedIP) {
				addrChan <- dstEth
				return
			}
		}
	}
}

// GetRemoteMacAddrSingleV6Host sends a Neighbor Solicitation and waits for
// a Neighbor Advertisement to learn the remote MAC, or times out.
func GetRemoteMacAddrSingleV6Host(sourceIP net.IP, remoteIP net.IP, sourceInterface *net.Interface) (net.HardwareAddr, error) {
	stop := make(chan bool)
	defer close(stop)

	handle, err := pcap.OpenLive(sourceInterface.Name, constants.IPv6NASnapLen, false, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	defer handle.Close()

	addrChan := make(chan net.HardwareAddr, 1)
	go readNsResponse(handle, stop, remoteIP, addrChan)

	if err = sendNsRequest(
		sourceIP,
		remoteIP,
		sourceInterface.HardwareAddr,
		handle,
	); err != nil {
		return nil, err
	}

	select {
	case mac := <-addrChan:
		return mac, nil
	case <-time.After(constants.GatewayMacRequestTimeout):
		return nil, fmt.Errorf("unable to get hardware address of %s. timed out", remoteIP)
	}
}

func interceptICMPv6Replies(handle *pcap.Handle, srcIP net.IP, ethIPPairChan chan router.EthIPPairBytes, timeout time.Duration) {
	defer close(ethIPPairChan)
	defer handle.Close()

	src := gopacket.NewPacketSource(handle, handle.LinkType())

	packets := src.Packets()

	t := time.NewTimer(timeout)
	defer t.Stop()

	for {
		select {

		case <-t.C:
			return

		case packet, ok := <-packets:
			if !ok {
				return
			}

			// Ethernet
			ethLayer := packet.Layer(layers.LayerTypeEthernet)
			if ethLayer == nil {
				continue
			}
			eth := ethLayer.(*layers.Ethernet)

			// IPv6
			ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
			if ipv6Layer == nil {
				continue
			}
			ipv6 := ipv6Layer.(*layers.IPv6)

			if !ipv6.DstIP.Equal(srcIP) {
				continue
			}

			// ICMPv6
			icmpLayer := packet.Layer(layers.LayerTypeICMPv6)
			if icmpLayer == nil {
				continue
			}
			icmp := icmpLayer.(*layers.ICMPv6)

			// Echo Reply?
			if icmp.TypeCode.Type() != layers.ICMPv6TypeEchoReply {
				continue
			}

			ethIPPairChan <- router.EthIPPairBytes{Eth: eth.SrcMAC, Ip: ipv6.SrcIP}

		}
	}
}

func sendICMPv6EchoRequestMulticast(handle *pcap.Handle, sourceMac net.HardwareAddr, srcAddress, dstAddress net.IP) error {

	dstMac := net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0x01}

	eth := &layers.Ethernet{
		SrcMAC:       sourceMac,
		DstMAC:       dstMac,
		EthernetType: layers.EthernetTypeIPv6}

	ipv6 := &layers.IPv6{
		Version:    6,
		SrcIP:      srcAddress,
		DstIP:      dstAddress,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   255,
	}
	icmpv6 := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(
			layers.ICMPv6TypeEchoRequest,
			0),
	}
	err := icmpv6.SetNetworkLayerForChecksum(ipv6)
	if err != nil {
		return err
	}
	icmpv6Payload := []byte("Vaverka")

	icmpv6echo := &layers.ICMPv6Echo{
		Identifier: 0x0908,
		SeqNumber:  2020,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	err = gopacket.SerializeLayers(buf, opts, eth, ipv6, icmpv6, icmpv6echo, gopacket.Payload(icmpv6Payload))

	if err != nil {
		return err
	}

	if err = handle.WritePacketData(buf.Bytes()); err != nil {
		return err
	}

	return nil
}

func FindIPv6NeighborsOnLink(sourceInterface *net.Interface, timeout time.Duration) (chan router.EthIPPairBytes, error) {
	var err error
	var sourceIP net.IP

	handle, err := pcap.OpenLive(sourceInterface.Name, constants.ICMPv6PacketMaxSize, false, time.Millisecond*20)
	if err != nil {
		return nil, err
	}

	interfaceAddresses, err := sourceInterface.Addrs()

	if err != nil {
		return nil, err
	}

	for _, address := range interfaceAddresses {
		sourceIP, _, err = net.ParseCIDR(address.String())

		if err != nil {
			return nil, err
		}

		if sourceIP.To4() == nil && sourceIP.To16() != nil {
			break // source ipv6 addr found
		}
	}

	ethIPPairChan := make(chan router.EthIPPairBytes, 16)

	go interceptICMPv6Replies(handle, sourceIP, ethIPPairChan, timeout)

	multicastAddrList, err := sourceInterface.MulticastAddrs()

	if err != nil {
		return nil, err
	}

	for _, sourceAddr := range multicastAddrList {
		mcastIP := net.ParseIP(sourceAddr.String())
		if mcastIP == nil {
			return nil, fmt.Errorf("failed to parse multicast address: %s", sourceAddr.String())
		}
		if mcastIP.To4() == nil && mcastIP.To16() != nil {
			err = sendICMPv6EchoRequestMulticast(handle, sourceInterface.HardwareAddr, sourceIP, mcastIP)
			if err != nil {
				return nil, err
			}
		}
	}

	return ethIPPairChan, nil
}

// prepareIpv4PartTemplate creates an IPv4 header template with the given source,
// total length, and transport layer protocol (e.g., TCP/ICMP).
func prepareIpv6PartTemplate(sourceIP net.IP, length uint16, transportLayer byte) []byte {
	IPPartTemplate := make([]byte, constants.IPv4HeaderSize)

	copy(IPPartTemplate, constants.IPv4Header[:])

	copy(IPPartTemplate[12:], sourceIP.To4())
	IPPartTemplate[9] = transportLayer

	binary.BigEndian.PutUint16(IPPartTemplate[2:], length)
	return IPPartTemplate
}

// ─────────────────────────────────────────────────────────────────────────────
//
//	scanV6WithoutHostDiscovery
//
// ─────────────────────────────────────────────────────────────────────────────
// Starts a port-scan against an IPv6 address range without first checking
// host reachability (no ICMPv6 echo).  Structure and variable names mirror the
// original IPv4 routine; only those parts that MUST differ for IPv6 were
// changed.
//
// IPv6-specific notes
// ───────────────────
//   - Ethernet EtherType is 0x86DD.
//   - IPv6 header size is a fixed 40 B; it has no header checksum.
//   - TCP and UDP checksums are *mandatory* in IPv6; each is calculated with the
//     40-byte IPv6 pseudo-header.
//   - ARP is not used.  Instead, we consult the neighbour cache and, if needed,
//     send a Neighbor Solicitation to discover the gateway’s MAC.
//
// ─────────────────────────────────────────────────────────────────────────────
func scanV6WithoutHostDiscovery(c *scannerContext, r *router.IpRangeRouteContext, ipRangeScannerWg *sync.WaitGroup) {
	defer ipRangeScannerWg.Done()

	var (
		// Gateway MAC address.
		gatewayMacAddress net.HardwareAddr

		// Compiled BPF filter.
		bpfExpression *pcap.BPF

		// IPv6 header templates for each scan technique.
		ipTcpSynTemplate []byte
		ipTcpVavTemplate []byte
		ipUdpTemplate    []byte

		// Ethernet header template.
		ethHeader []byte

		// Source IP in 16-byte form.
		sourceIPBytes = r.Route.Src.To16()

		// Checksum helpers.
		checksum     uint16
		pseudoHeader []byte

		// Scratch buffers: pseudo-hdr + transport-hdr.
		pseudoHeaderAndTcpHeaderSyn []byte
		pseudoHeaderAndTcpHeaderVav []byte
		pseudoHeaderAndUdpHeader    []byte

		// Transport-layer header templates (source port already filled).
		tcpSynHeaderTemplate [constants.TCPSynHeaderSize]byte
		tcpVavHeaderTemplate [constants.TCPSynVavHeaderSize]byte
		udpHeaderTemplate    [constants.UDPHeaderSize]byte

		// sendmmsg() arrays.
		messageHeaders [constants.IOVecPacketsChunkSize]mmsghdr
		ioVectors      [constants.IOVecPacketsChunkSize][4]syscall.Iovec

		currentIndex int
		err          error
	)

	// Obtain gateway MAC (neighbour cache -> NDP solicitation). ──────────
	gatewayMacAddress, err = utils.GetHardwareAddrFromNeighborCache(r.Route.ILinkIndex, r.Route.Gw)

	if err != nil {
		c.errorChan <- err
		return
	}
	if gatewayMacAddress == nil {
		gatewayMacAddress, err = GetRemoteMacAddrSingleV6Host(r.Route.Src, r.Route.Gw, r.SocketParameters.SourceInterface)
		if err != nil {
			c.errorChan <- err
			return
		}
		if gatewayMacAddress == nil {
			c.errorChan <- fmt.Errorf("cannot find gateway MAC for %s", r.Route.Gw)
			return
		}
	}

	// Compile BPF filter and start interceptor. ─────────────────────────
	bpfExpression, err = compileTransportStateDetectionBPF(c, r)
	if err != nil {
		c.errorChan <- err
		return
	}
	ipRangeScannerWg.Add(1)
	go interceptTransportResponses(c, r, bpfExpression, ipRangeScannerWg)

	// ── 3. Ethernet header (EtherType = IPv6). ───────────────────────────────
	ethHeader = prepareEthernetPart(
		r.SocketParameters.SourceInterface.HardwareAddr,
		gatewayMacAddress,
		constants.EtherTypeIPv6,
	)

	// 4. Transport-header templates (source port pre-filled). ──────────────
	if c.rule.PortScanTechniques.Syn {
		tcpSynHeaderTemplate = constants.TCPSynHeader
		binary.BigEndian.PutUint16(tcpSynHeaderTemplate[0:2], r.SourcePort)
	}
	if c.rule.PortScanTechniques.Vav {
		tcpVavHeaderTemplate = constants.TCPSynVavHeader
		binary.BigEndian.PutUint16(tcpVavHeaderTemplate[0:2], r.SourcePort)
	}
	if c.rule.PortScanTechniques.Udp {
		udpHeaderTemplate = constants.UdpHeader
		binary.BigEndian.PutUint16(udpHeaderTemplate[0:2], r.SourcePort)
	}

	// IPv6 header templates. ────────────────────────────────────────────
	if c.rule.PortScanTechniques.Syn {
		ipTcpSynTemplate = prepareIpv6PartTemplate(
			r.Route.Src, constants.TCPSynHeaderSize, constants.TrafficTCP)
	}
	if c.rule.PortScanTechniques.Vav {
		ipTcpVavTemplate = prepareIpv6PartTemplate(
			r.Route.Src,
			constants.TCPSynVavHeaderSize+constants.AcornSize,
			constants.TrafficTCP)
	}
	if c.rule.PortScanTechniques.Udp {
		ipUdpTemplate = prepareIpv6PartTemplate(
			r.Route.Src, constants.UDPHeaderSize, constants.TrafficUDP)
	}

	// Allocate scratch buffers for checksum calculation. ────────────────
	pseudoHeaderAndTcpHeaderSyn = make(
		[]byte, constants.IPv6PseudoHeaderSize+constants.TCPSynHeaderSize)
	pseudoHeaderAndTcpHeaderVav = make(
		[]byte, constants.IPv6PseudoHeaderSize+
			constants.TCPSynVavHeaderSize+constants.AcornSize)
	pseudoHeaderAndUdpHeader = make(
		[]byte, constants.IPv6PseudoHeaderSize+constants.UDPHeaderSize)

	// Wait for interceptor readiness.
	<-r.ReadyToInterceptPortsStateChan

	// Iterate through IPv6 address chunks. ──────────────────────────────
	for ipChunk := range utils.IPv6RangeBytesChunks(r.Start, r.End, c.rule.Options.Shuffle) {

		chunkLen := len(ipChunk)

		// Chunk-local IPv6 header buffers.
		var synIPBuffer, vavIPBuffer, udpIPBuffer []byte
		if c.rule.PortScanTechniques.Syn {
			synIPBuffer = make([]byte, constants.IPv6HeaderSize*chunkLen)
		}
		if c.rule.PortScanTechniques.Vav {
			vavIPBuffer = make([]byte, constants.IPv6HeaderSize*chunkLen)
		}
		if c.rule.PortScanTechniques.Udp {
			udpIPBuffer = make([]byte, constants.IPv6HeaderSize*chunkLen)
		}

		// Fill per-destination IPv6 headers.
		for ipIndex, ip := range ipChunk {
			if c.rule.PortScanTechniques.Syn {
				buf := synIPBuffer[ipIndex*constants.IPv6HeaderSize : (ipIndex+1)*constants.IPv6HeaderSize]
				copy(buf, ipTcpSynTemplate)
				copy(buf[24:], ip[:]) // dst address
			}
			if c.rule.PortScanTechniques.Vav {
				buf := vavIPBuffer[ipIndex*constants.IPv6HeaderSize : (ipIndex+1)*constants.IPv6HeaderSize]
				copy(buf, ipTcpVavTemplate)
				copy(buf[24:], ip[:])
			}
			if c.rule.PortScanTechniques.Udp {
				buf := udpIPBuffer[ipIndex*constants.IPv6HeaderSize : (ipIndex+1)*constants.IPv6HeaderSize]
				copy(buf, ipUdpTemplate)
				copy(buf[24:], ip[:])
			}

			// ───────────────────────────── SYN scan ───────────────────────
			if c.rule.PortScanTechniques.Syn {
				tcpSynHeaders := make([][constants.TCPSynHeaderSize]byte, len(c.ports))
				pseudoHeader = prepareIp6TransportPseudoHeader(
					sourceIPBytes, ip[:], constants.TrafficTCP, constants.TCPSynHeaderSize)

				for i, port := range c.ports {
					tcpSynHeaders[i] = tcpSynHeaderTemplate
					binary.BigEndian.PutUint16(tcpSynHeaders[i][2:4], port)

					copy(pseudoHeaderAndTcpHeaderSyn[0:constants.IPv6PseudoHeaderSize],
						pseudoHeader)
					copy(pseudoHeaderAndTcpHeaderSyn[constants.IPv6PseudoHeaderSize:],
						tcpSynHeaders[i][:])

					checksum = computeChecksum(pseudoHeaderAndTcpHeaderSyn)
					binary.BigEndian.PutUint16(tcpSynHeaders[i][16:18], checksum)

					ioVectors[currentIndex][0] = syscall.Iovec{
						Base: &ethHeader[0],
						Len:  constants.EthernetHeaderSize,
					}
					ioVectors[currentIndex][1] = syscall.Iovec{
						Base: &synIPBuffer[ipIndex*constants.IPv6HeaderSize],
						Len:  uint64(constants.IPv6HeaderSize),
					}
					ioVectors[currentIndex][2] = syscall.Iovec{
						Base: &tcpSynHeaders[i][0],
						Len:  uint64(constants.TCPSynHeaderSize),
					}
					messageHeaders[currentIndex].Msg = syscall.Msghdr{
						Name:    r.SocketParameters.SocketAddressName,
						Namelen: r.SocketParameters.SocketAddressNameLen,
						Iov:     &ioVectors[currentIndex][0],
						Iovlen:  3,
					}
					currentIndex++

					if currentIndex == constants.IOVecPacketsChunkSize {
						if err = Limiter.Wait(context.Background()); err != nil {
							c.errorChan <- err
							return
						}
						_, _, errno := syscall.RawSyscall(
							constants.SendMmsgSyscallIndex,
							c.socketFD,
							uintptr(unsafe.Pointer(&messageHeaders[0])),
							uintptr(currentIndex),
						)
						if errno != 0 {
							c.errorChan <- errno
							return
						}
						currentIndex = 0
					}
				}
			}

			// ───────────────────────────── VAV scan ───────────────────────
			if c.rule.PortScanTechniques.Vav {
				tcpVavHeaders := make([][constants.TCPSynVavHeaderSize]byte, len(c.ports))
				pseudoHeader = prepareIp6TransportPseudoHeader(
					sourceIPBytes, ip[:], constants.TrafficTCP,
					constants.TCPSynVavHeaderSize+constants.AcornSize)

				for i, port := range c.ports {
					tcpVavHeaders[i] = tcpVavHeaderTemplate
					binary.BigEndian.PutUint16(tcpVavHeaders[i][2:4], port)

					copy(pseudoHeaderAndTcpHeaderVav[0:constants.IPv6PseudoHeaderSize],
						pseudoHeader)
					copy(pseudoHeaderAndTcpHeaderVav[constants.IPv6PseudoHeaderSize:constants.IPv6PseudoHeaderSize+constants.TCPSynVavHeaderSize],
						tcpVavHeaders[i][:])
					copy(pseudoHeaderAndTcpHeaderVav[constants.IPv6PseudoHeaderSize+
						constants.TCPSynVavHeaderSize:],
						constants.Acorn[:])

					checksum = computeChecksum(pseudoHeaderAndTcpHeaderVav)
					binary.BigEndian.PutUint16(tcpVavHeaders[i][16:18], checksum)

					ioVectors[currentIndex][0] = syscall.Iovec{
						Base: &ethHeader[0],
						Len:  constants.EthernetHeaderSize,
					}
					ioVectors[currentIndex][1] = syscall.Iovec{
						Base: &vavIPBuffer[ipIndex*constants.IPv6HeaderSize],
						Len:  uint64(constants.IPv6HeaderSize),
					}
					ioVectors[currentIndex][2] = syscall.Iovec{
						Base: &tcpVavHeaders[i][0],
						Len:  uint64(constants.TCPSynVavHeaderSize),
					}
					ioVectors[currentIndex][3] = syscall.Iovec{
						Base: &constants.Acorn[0],
						Len:  constants.AcornSize,
					}
					messageHeaders[currentIndex].Msg = syscall.Msghdr{
						Name:    r.SocketParameters.SocketAddressName,
						Namelen: r.SocketParameters.SocketAddressNameLen,
						Iov:     &ioVectors[currentIndex][0],
						Iovlen:  4,
					}
					currentIndex++

					if currentIndex == constants.IOVecPacketsChunkSize {
						if err = Limiter.Wait(context.Background()); err != nil {
							c.errorChan <- err
							return
						}
						_, _, errno := syscall.RawSyscall(
							constants.SendMmsgSyscallIndex,
							c.socketFD,
							uintptr(unsafe.Pointer(&messageHeaders[0])),
							uintptr(currentIndex),
						)
						if errno != 0 {
							c.errorChan <- errno
							return
						}
						currentIndex = 0
					}
				}
			}

			// ───────────────────────────── UDP scan ────────────────────────
			if c.rule.PortScanTechniques.Udp {
				udpHeaders := make([][constants.UDPHeaderSize]byte, len(c.ports))
				for i, port := range c.ports {
					udpHeaders[i] = udpHeaderTemplate
					binary.BigEndian.PutUint16(udpHeaders[i][2:4], port)

					// Calculate mandatory UDP checksum.
					pseudoHeader = prepareIp6TransportPseudoHeader(
						sourceIPBytes, ip[:], constants.TrafficUDP, constants.UDPHeaderSize)
					copy(pseudoHeaderAndUdpHeader[0:constants.IPv6PseudoHeaderSize],
						pseudoHeader)
					copy(pseudoHeaderAndUdpHeader[constants.IPv6PseudoHeaderSize:],
						udpHeaders[i][:])

					checksum = computeChecksum(pseudoHeaderAndUdpHeader)
					binary.BigEndian.PutUint16(udpHeaders[i][6:8], checksum)

					ioVectors[currentIndex][0] = syscall.Iovec{
						Base: &ethHeader[0],
						Len:  constants.EthernetHeaderSize,
					}
					ioVectors[currentIndex][1] = syscall.Iovec{
						Base: &udpIPBuffer[ipIndex*constants.IPv6HeaderSize],
						Len:  uint64(constants.IPv6HeaderSize),
					}
					ioVectors[currentIndex][2] = syscall.Iovec{
						Base: &udpHeaders[i][0],
						Len:  uint64(constants.UDPHeaderSize),
					}
					messageHeaders[currentIndex].Msg = syscall.Msghdr{
						Name:    r.SocketParameters.SocketAddressName,
						Namelen: r.SocketParameters.SocketAddressNameLen,
						Iov:     &ioVectors[currentIndex][0],
						Iovlen:  3,
					}
					currentIndex++

					if currentIndex == constants.IOVecPacketsChunkSize {
						if err = Limiter.Wait(context.Background()); err != nil {
							c.errorChan <- err
							return
						}
						_, _, errno := syscall.RawSyscall(
							constants.SendMmsgSyscallIndex,
							c.socketFD,
							uintptr(unsafe.Pointer(&messageHeaders[0])),
							uintptr(currentIndex),
						)
						if errno != 0 {
							c.errorChan <- errno
							return
						}
						currentIndex = 0
					}
				}
			}
		} // loop over addresses in chunk
	} // chunks loop

	// Flush any remaining packets. ──────────────────────────────────────
	if currentIndex > 0 {
		if err = Limiter.Wait(context.Background()); err != nil {
			c.errorChan <- err
			return
		}
		_, _, errno := syscall.RawSyscall(
			constants.SendMmsgSyscallIndex,
			c.socketFD,
			uintptr(unsafe.Pointer(&messageHeaders[0])),
			uintptr(currentIndex),
		)
		if errno != 0 {
			c.errorChan <- errno
			return
		}
	}

	// Allow time for responses, then signal completion.
	time.Sleep(constants.DefaultTimeout)
	r.PortsDiscoveryDoneChan <- true
}

// scanV6OverGateway scanning through a gateway if network is not local.
func scanV6OverGateway(c *scannerContext, r *router.IpRangeRouteContext, ipRangeScannerWg *sync.WaitGroup) {
}

// pingV6Scan sends ICMPv6 echo requests (pings) to each IP in the range.
// It uses a fixed per-chunk buffer for IP headers to avoid reusing the same
// memory for multiple IPs, which was causing all packets to use the same destination IP.
func pingV6Scan(c *scannerContext, r *router.IpRangeRouteContext, gatewayMac net.HardwareAddr, pingWg *sync.WaitGroup) {
}

// scanPortsV6OverGateway scans hosts via a gateway.
// The r.UpHostsChan channel carries only target IP addresses.
// The constructed packets include an Ethernet header built from the source interface
// and the provided gatewayMac. Buffers and header templates are reused to minimize allocations.
func scanPortsV6OverGateway(c *scannerContext, r *router.IpRangeRouteContext, portsScanWg *sync.WaitGroup, gatewayMac net.HardwareAddr) {
}

// scanV6PointToPoint performs direct scanning in a single subnet without a gateway.
func scanV6PointToPoint(c *scannerContext, r *router.IpRangeRouteContext, ipRangeScannerWg *sync.WaitGroup) {
	defer ipRangeScannerWg.Done()
	//defer fmt.Println("DEBUG: scanPointToPoint is done")

	var p2pWg sync.WaitGroup

	// Start ARP-based host discovery
	p2pWg.Add(1)
	go arpScan(c, r, &p2pWg)

	// Start port scanning (TCP/UDP)
	p2pWg.Add(1)
	go pointToPointV4PortsScan(c, r, &p2pWg)

	p2pWg.Wait()
}

// pointToPointV6PortsScan sends TCP SYN/VAV packets and UDP packets (if enabled) to discovered hosts.
func pointToPointV6PortsScan(c *scannerContext, r *router.IpRangeRouteContext, portsScanWg *sync.WaitGroup) {
}

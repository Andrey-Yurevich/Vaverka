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

// interceptTransportV6Responses captures packets for TCP/UDP discovery when network is IPv6.
// For TCP, it listens for SYN+ACK; for UDP, it captures all packets.
func interceptTransportV6Responses(c *scannerContext, r *router.IpRangeRouteContext, bpf *pcap.BPF, wg *sync.WaitGroup) {
	defer wg.Done()

	pcapHandle, err := pcap.OpenLive(
		r.SocketParameters.SourceInterface.Name,
		constants.IPv6NASnapLen, // minimal snap length
		true,                    // promiscuous mode
		constants.PcapCaptureTimeout,
	)
	if err != nil {
		c.errorChan <- err
		return
	}
	defer pcapHandle.Close()

	filterStr := bpf.String()
	if err = pcapHandle.SetBPFFilter(filterStr); err != nil {
		c.errorChan <- err
		return
	}
	if err = pcapHandle.SetDirection(pcap.DirectionIn); err != nil {
		c.errorChan <- err
		return
	}
	if err = pcapHandle.SetLinkType(layers.LinkTypeEthernet); err != nil {
		c.errorChan <- err
		return
	}

	packetSource := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())
	packetSource.NoCopy = true
	packetChan := packetSource.Packets()

	// Signal that we're ready to intercept TCP/UDP packets
	r.ReadyToInterceptPortsStateChan <- true

	for {
		select {
		case packet, open := <-packetChan:
			if !open {
				return
			}
			ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
			if ipv6Layer == nil {
				continue
			}
			ipv6, ok := ipv6Layer.(*layers.IPv6)
			if !ok {
				continue
			}

			// Check for TCP layer
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, ok := tcpLayer.(*layers.TCP)
				if !ok {
					continue
				}

				if tcp.RST {
					continue
				}

				// Only process SYN+ACK
				if tcp.SYN && tcp.ACK {
					serviceName, identified := layers.TCPPortNames(tcp.SrcPort)
					if !identified {
						serviceName = "unknown"
					}
					if c.rule.FQDN != "" {
						printPortInfo(c.rule.FQDN, uint16(tcp.SrcPort), &serviceName, c.rule.Network, protoTypeTcp)
					} else {
						printPortInfo(ipv6.SrcIP.String(), uint16(tcp.SrcPort), &serviceName, c.rule.Network, protoTypeTcp)
					}

				}
			} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
				udp, ok := udpLayer.(*layers.UDP)
				if !ok {
					continue
				}

				serviceName, identified := layers.UDPPortNames(udp.SrcPort)
				if !identified {
					serviceName = "unknown"
				}
				if c.rule.FQDN != "" {
					printPortInfo(c.rule.FQDN, uint16(udp.SrcPort), &serviceName, c.rule.Network, protoTypeUdp)
				} else {
					printPortInfo(ipv6.SrcIP.String(), uint16(udp.SrcPort), &serviceName, c.rule.Network, protoTypeUdp)
				}

			}

		case <-r.PortsDiscoveryDoneChan:
			// Stop interception when signaled
			return
		}
	}
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

func FindIPv6NeighborsOnLink(c *scannerContext, r *router.IpRangeRouteContext, p2pwg *sync.WaitGroup) {
	defer p2pwg.Done()
	defer close(r.UpHostsChan)

	var err error
	var sourceIP net.IP

	handle, err := pcap.OpenLive(r.SocketParameters.SourceInterface.Name, constants.ICMPv6PacketMaxSize, false, time.Millisecond*20)
	if err != nil {
		c.errorChan <- err
		return
	}

	interfaceAddresses, err := r.SocketParameters.SourceInterface.Addrs()

	if err != nil {
		c.errorChan <- err
		return
	}

	for _, address := range interfaceAddresses {
		sourceIP, _, err = net.ParseCIDR(address.String())

		if err != nil {
			c.errorChan <- err
			return
		}

		if sourceIP.To4() == nil && sourceIP.To16() != nil {
			break // source ipv6 addr found
		}
	}

	p2pwg.Add(1)
	go interceptICMPPackets(c, r, p2pwg, protoTypeICMP6)
	// Waiting for the function to signal that it is ready to receive available hosts from the channel: r.UpHostsChan
	<-r.ReadyToInterceptHostsStateChan

	err = sendICMPv6EchoRequestMulticast(handle, r.SocketParameters.SourceInterface.HardwareAddr, sourceIP, net.ParseIP("ff02::1"))
	if err != nil {
		c.errorChan <- err
		return
	}
	// Allow time for responses, then signal completion.
	time.Sleep(c.rule.Options.Timeout)
	r.HostDiscoveryDoneChan <- true
}

// prepareICMPv6PseudoHeaderTemplate This function prepares a pseudo-header template for ICMPv6, leaving only the destination IP unset, since this value is not reused.
func prepareICMPv6PseudoHeaderTemplate(srcIP net.IP) [constants.IcmpV6PseudoHeaderSize]byte {
	var pseudoheaderTemplate [constants.IcmpV6PseudoHeaderSize]byte

	copy(pseudoheaderTemplate[0:16], srcIP.To16())

	binary.BigEndian.PutUint32(pseudoheaderTemplate[32:36], constants.IcmpV6Size)

	pseudoheaderTemplate[39] = constants.TrafficICMPv6

	return pseudoheaderTemplate
}

// prepareIpv6PartTemplate creates an IPv6 header template with the given source,
// total length, and transport layer protocol (e.g., TCP/ICMP).
func prepareIpv6PartTemplate(sourceIP net.IP, length uint16, transportLayer byte) []byte {
	IPPartTemplate := make([]byte, constants.IPv6HeaderSize)

	copy(IPPartTemplate, constants.IPv6Header[:])

	IPPartTemplate[6] = transportLayer

	copy(IPPartTemplate[8:], sourceIP.To16())

	binary.BigEndian.PutUint16(IPPartTemplate[4:], length)
	return IPPartTemplate
}

// scanV6WithoutHostDiscovery
// Starts a port-scan against an IPv6 address range without first checking
// host reachability (no ICMPv6 echo).  Structure and variable names mirror the
// original IPv4 routine; only those parts that MUST differ for IPv6 were
// changed.
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
	go interceptTransportV6Responses(c, r, bpfExpression, ipRangeScannerWg)

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
		[]byte, constants.IPv6TransportPseudoHeaderSize+constants.TCPSynHeaderSize)
	pseudoHeaderAndTcpHeaderVav = make(
		[]byte, constants.IPv6TransportPseudoHeaderSize+
			constants.TCPSynVavHeaderSize+constants.AcornSize)
	pseudoHeaderAndUdpHeader = make(
		[]byte, constants.IPv6TransportPseudoHeaderSize+constants.UDPHeaderSize)

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

					copy(pseudoHeaderAndTcpHeaderSyn[0:constants.IPv6TransportPseudoHeaderSize],
						pseudoHeader)
					copy(pseudoHeaderAndTcpHeaderSyn[constants.IPv6TransportPseudoHeaderSize:],
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

					copy(pseudoHeaderAndTcpHeaderVav[0:constants.IPv6TransportPseudoHeaderSize],
						pseudoHeader)
					copy(pseudoHeaderAndTcpHeaderVav[constants.IPv6TransportPseudoHeaderSize:constants.IPv6TransportPseudoHeaderSize+constants.TCPSynVavHeaderSize],
						tcpVavHeaders[i][:])
					copy(pseudoHeaderAndTcpHeaderVav[constants.IPv6TransportPseudoHeaderSize+
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
					copy(pseudoHeaderAndUdpHeader[0:constants.IPv6TransportPseudoHeaderSize],
						pseudoHeader)
					copy(pseudoHeaderAndUdpHeader[constants.IPv6TransportPseudoHeaderSize:],
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
	time.Sleep(c.rule.Options.Timeout)
	r.PortsDiscoveryDoneChan <- true
}

// scanV6OverGateway scanning through a gateway if network is not local.
func scanV6OverGateway(c *scannerContext, r *router.IpRangeRouteContext, ipRangeScannerWg *sync.WaitGroup) {
	defer ipRangeScannerWg.Done()

	var pingWg sync.WaitGroup
	var gatewayMacAddress net.HardwareAddr
	var err error

	// Obtain the gateway MAC address.
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
			c.errorChan <- fmt.Errorf("cannot find gateway mac for %s", r.Route.Gw)
			return
		}
	}

	pingWg.Add(1)
	go pingV6Scan(c, r, gatewayMacAddress, &pingWg)

	//Start port scanning (TCP/UDP)
	pingWg.Add(1)
	scanPortsV6OverGateway(c, r, &pingWg, gatewayMacAddress)

	pingWg.Wait()

}

// pingV6Scan sends ICMPv6 echo requests (pings) to each IPv6 in the range.
// Structure mirrors the IPv4 version; entities/bitness renamed to IPv6.
func pingV6Scan(c *scannerContext, r *router.IpRangeRouteContext, gatewayMac net.HardwareAddr, pingWg *sync.WaitGroup) {
	defer close(r.ReadyToInterceptHostsStateChan)
	defer close(r.UpHostsChan)
	defer pingWg.Done()

	// Start goroutine to intercept ping replies.
	pingWg.Add(1)
	go interceptICMPPackets(c, r, pingWg, protoTypeICMP6)

	// Wait until ReadyToInterceptHostsStateChan is ready.
	<-r.ReadyToInterceptHostsStateChan

	var (
		messageHeaders                 [constants.IOVecPacketsChunkSize]mmsghdr
		ioVectors                      [constants.IOVecPacketsChunkSize][3]syscall.Iovec
		ICMPv6HeaderICMPv6Pseudoheader [constants.IcmpV6PseudoHeaderSize + constants.IcmpV6Size]byte
		ICMPv6Checksum                 uint16
	)

	// Prepare the Ethernet header (constant for all messages).
	EthernetPart := prepareEthernetPart(
		r.SocketParameters.SourceInterface.HardwareAddr,
		gatewayMac,
		constants.EtherTypeIPv6,
	)

	// Prepare the IPv6 header template for ICMPv6 (will be copied per IP).
	Ipv6Part := prepareIpv6PartTemplate(
		r.Route.Src, // IPv6 source
		constants.IcmpV6Size,
		constants.TrafficICMPv6,
	)

	ICMPv6PseudoHeaderTemplate := prepareICMPv6PseudoHeaderTemplate(r.Route.Src)

	// Process IPv6 addresses in chunks.
	for ipChunk := range utils.IPv6RangeBytesChunks(r.Start, r.End, c.rule.Options.Shuffle) {
		chunkLen := len(ipChunk)
		// Allocate a fixed buffer for ICMPv6 IP headers for the entire chunk.
		ipBuffer := make([]byte, constants.IPv6HeaderSize*chunkLen)

		icmpBuffer := make([]byte, constants.IcmpV6Size*chunkLen)

		// For each IPv6 in the chunk, create its own IPv6 header in the fixed buffer.
		for i, ip := range ipChunk {
			// Create a slice for the i-th IPv6 header.
			ipSlice := ipBuffer[i*constants.IPv6HeaderSize : (i+1)*constants.IPv6HeaderSize]
			// Copy the IPv6 header template.
			copy(ipSlice, Ipv6Part)
			// Overwrite the destination IPv6 (offset 24..40 in the header).
			copy(ipSlice[24:], ip[:])

			icmpSlice := icmpBuffer[i*constants.IcmpV6Size : (i+1)*constants.IcmpV6Size]

			copy(icmpSlice[0:], constants.IcmpV6Header[:])

			copy(ICMPv6HeaderICMPv6Pseudoheader[0:], ICMPv6PseudoHeaderTemplate[:])
			copy(ICMPv6HeaderICMPv6Pseudoheader[16:32], ip[:])
			copy(ICMPv6HeaderICMPv6Pseudoheader[constants.IcmpV6PseudoHeaderSize:], constants.IcmpV6Header[:])

			ICMPv6Checksum = computeChecksum(ICMPv6HeaderICMPv6Pseudoheader[:])

			if ICMPv6Checksum == 0 {
				ICMPv6Checksum = 0xFFFF
			}

			binary.BigEndian.PutUint16(icmpSlice[2:4], ICMPv6Checksum)

			// Prepare the iovec for this IP.
			ioVectors[i][0] = syscall.Iovec{
				Base: &EthernetPart[0],
				Len:  constants.EthernetHeaderSize,
			}
			ioVectors[i][1] = syscall.Iovec{
				Base: &ipSlice[0],
				Len:  uint64(constants.IPv6HeaderSize),
			}
			ioVectors[i][2] = syscall.Iovec{
				Base: &icmpSlice[0],
				Len:  constants.IcmpV6Size,
			}

			messageHeaders[i].Msg = syscall.Msghdr{
				Name:    r.SocketParameters.SocketAddressName,
				Namelen: r.SocketParameters.SocketAddressNameLen,
				Iov:     &ioVectors[i][0],
				Iovlen:  3,
			}
		}

		// Rate limit before sending the chunk.
		if err := Limiter.Wait(context.Background()); err != nil {
			c.errorChan <- err
			return
		}

		// Send the chunk using sendmmsg with the number of messages equal to chunkLen.
		_, _, errno := syscall.RawSyscall(
			constants.SendMmsgSyscallIndex,
			c.socketFD,
			uintptr(unsafe.Pointer(&messageHeaders[0])),
			uintptr(chunkLen),
		)
		if errno != 0 {
			c.errorChan <- errno
			return
		}
	}

	// Allow some time to receive ping responses.
	time.Sleep(c.rule.Options.Timeout)

	// Signal that host discovery via ping is done.
	r.HostDiscoveryDoneChan <- true
}

// scanV6PointToPoint performs direct scanning in a single subnet without a gateway.
func scanV6PointToPoint(c *scannerContext, r *router.IpRangeRouteContext, ipRangeScannerWg *sync.WaitGroup) {
	defer ipRangeScannerWg.Done()
	var p2pWg sync.WaitGroup

	p2pWg.Add(1)
	go FindIPv6NeighborsOnLink(c, r, &p2pWg)

	//Start port scanning (TCP/UDP)
	p2pWg.Add(1)
	pointToPointV6PortsScan(c, r, &p2pWg)

	p2pWg.Wait()
}

// pointToPointV6PortsScan sends TCP SYN/VAV packets and UDP packets (if enabled) to discovered hosts over IPv6.
func pointToPointV6PortsScan(c *scannerContext, r *router.IpRangeRouteContext, portsScanWg *sync.WaitGroup) {
	// Defer cleanup actions.
	defer portsScanWg.Done()
	defer close(r.ReadyToInterceptPortsStateChan)

	var (
		// IP header templates for each scan type.
		ipTcpSynTemplate []byte
		ipTcpVavTemplate []byte
		ipUdpTemplate    []byte

		// EthernetTemplate Ethernet header template.
		EthernetTemplate []byte

		// Combined Ethernet+IP buffers for each scan type.
		ethIpBufferSyn []byte
		ethIpBufferVav []byte
		ethIpBufferUdp []byte

		// Source IP in 4-byte format.
		sourceIPBytes = r.Route.Src.To16()

		// Static lengths for iovec segments.
		lenEthernetAndIp uint64 = constants.EthernetHeaderSize + constants.IPv6HeaderSize
		lenTcpVavHeader  uint64 = constants.TCPSynVavHeaderSize
		lenAcorn         uint64 = constants.AcornSize

		pseudoHeader []byte

		// Buffers for concatenating pseudo-header with TCP/UDP headers for checksum calculation.
		pseudoHeaderAndTcpHeaderSyn []byte
		pseudoHeaderAndTcpHeaderVav []byte
		pseudoHeaderAndUdpHeader    []byte

		// Slice of TCP headers for SYN scanning.
		tcpSynHeaders [][constants.TCPSynHeaderSize]byte
		// TCP header template for SYN scan (with predefined source port).
		tcpSynHeaderTemplate [constants.TCPSynHeaderSize]byte

		// Slice of TCP headers for VAV scanning.
		tcpVavHeaders [][constants.TCPSynVavHeaderSize]byte
		// TCP header template for VAV scan (with predefined source port).
		tcpVavHeaderTemplate [constants.TCPSynVavHeaderSize]byte

		// Slice of UDP headers.
		udpHeaders [][constants.UDPHeaderSize]byte
		// UDP header template (with predefined source port).
		udpHeaderTemplate [constants.UDPHeaderSize]byte

		// Message headers and I/O vectors for the sendmmsg syscall.
		messageHeaders [constants.IOVecPacketsChunkSize]mmsghdr
		ioVectors      [constants.IOVecPacketsChunkSize][3]syscall.Iovec

		// Counter for the number of scan types enabled.
		scanTypesCount int

		// BPF filter for capturing responses.
		bpfExpression *pcap.BPF

		checksum uint16
		err      error
	)

	// Compile the BPF filter for detecting transport-layer responses.
	bpfExpression, err = compileTransportStateDetectionBPF(c, r)
	if err != nil {
		c.errorChan <- err
		return
	}

	// Start a goroutine to intercept TCP/UDP responses.
	portsScanWg.Add(1)
	go interceptTransportV6Responses(c, r, bpfExpression, portsScanWg)

	// Wait until the interceptor is ready.
	<-r.ReadyToInterceptPortsStateChan

	// Prepare headers and buffers for each enabled scan technique.
	if c.rule.PortScanTechniques.Syn {
		scanTypesCount++
		// Build a base IPv6 header template for SYN scan (IP header + TCP header).
		ipTcpSynTemplate = prepareIpv6PartTemplate(r.Route.Src, constants.TCPSynHeaderSize, constants.TrafficTCP)

		// Allocate Ethernet+IP buffer for SYN scan.
		ethIpBufferSyn = make([]byte, constants.EthernetHeaderSize+constants.IPv6HeaderSize)

		// Allocate buffer for concatenating pseudo-header with TCP SYN header.
		pseudoHeaderAndTcpHeaderSyn = make([]byte, constants.IPv6TransportPseudoHeaderSize+constants.TCPSynHeaderSize)
		// Allocate slice for TCP headers for all ports.
		tcpSynHeaders = make([][constants.TCPSynHeaderSize]byte, len(c.ports))

		// Initialize the SYN header template and set the source port.
		tcpSynHeaderTemplate = constants.TCPSynHeader
		binary.BigEndian.PutUint16(tcpSynHeaderTemplate[0:2], r.SourcePort)
	}

	if c.rule.PortScanTechniques.Vav {
		// Allocate Ethernet+IP buffer for VAV scan.
		ethIpBufferVav = make([]byte, constants.EthernetHeaderSize+constants.IPv6HeaderSize)

		pseudoHeaderAndTcpHeaderVav = make([]byte,
			constants.IPv6TransportPseudoHeaderSize+constants.TCPSynVavHeaderSize+constants.AcornSize)

		scanTypesCount++
		// Build a base IPv6 header template for VAV scan (IP header + TCP VAV header + payload length).
		ipTcpVavTemplate = prepareIpv6PartTemplate(
			r.Route.Src, constants.TCPSynVavHeaderSize+constants.AcornSize,
			constants.TrafficTCP,
		)
		// Allocate slice for TCP VAV headers for all ports.
		tcpVavHeaders = make([][constants.TCPSynVavHeaderSize]byte, len(c.ports))

		// Initialize the VAV header template and set the source port.
		tcpVavHeaderTemplate = constants.TCPSynVavHeader
		binary.BigEndian.PutUint16(tcpVavHeaderTemplate[0:2], r.SourcePort)
	}

	if c.rule.PortScanTechniques.Udp {
		scanTypesCount++

		// Allocate Ethernet+IP buffer for UDP scan.
		ethIpBufferUdp = make([]byte, constants.EthernetHeaderSize+constants.IPv6HeaderSize)

		pseudoHeaderAndUdpHeader = make([]byte, constants.IPv6TransportPseudoHeaderSize+constants.UDPHeaderSize)

		// Build a base IPv6 header template for UDP scan (IP header + UDP header).
		ipUdpTemplate = prepareIpv6PartTemplate(
			r.Route.Src,
			constants.UDPHeaderSize,
			constants.TrafficUDP,
		)
		// Allocate slice for UDP headers for all ports.
		udpHeaders = make([][constants.UDPHeaderSize]byte, len(c.ports))
		// Initialize the UDP header template and set the source port.
		udpHeaderTemplate = constants.UdpHeader
		binary.BigEndian.PutUint16(udpHeaderTemplate[0:2], r.SourcePort)
	}

	// Build a base Ethernet header template with a zeroed destination MAC.
	EthernetTemplate = prepareEthernetPart(
		r.SocketParameters.SourceInterface.HardwareAddr,
		net.HardwareAddr{0, 0, 0, 0, 0, 0},
		constants.EtherTypeIPv6,
	)

	switch {
	// If the total number of packets (ports * scan types) is less than the chunk size,
	// process them as a single batch.
	case len(c.ports)*scanTypesCount < constants.IOVecPacketsChunkSize:
		// Process each discovered host.
		for host := range r.UpHostsChan {
			currentIndex := 0

			// ----- SYN Scan Branch -----
			if c.rule.PortScanTechniques.Syn {
				// Prepare Ethernet+IP buffer for SYN scan.
				copy(ethIpBufferSyn[0:6], host.Eth)                                        // Set destination MAC.
				copy(ethIpBufferSyn[6:constants.EthernetHeaderSize], EthernetTemplate[6:]) // Copy rest of Ethernet header.
				// Copy the SYN IP header template.
				copy(ethIpBufferSyn[constants.EthernetHeaderSize:constants.EthernetHeaderSize+constants.IPv6HeaderSize], ipTcpSynTemplate)
				// Overwrite destination IP (IPv6 dst at bytes 24..40 of IPv6 header).
				copy(ethIpBufferSyn[constants.EthernetHeaderSize+24:constants.EthernetHeaderSize+40], host.Ip)

				// Prepare the TCP pseudo-header for SYN scan.
				pseudoHeader = prepareIp6TransportPseudoHeader(sourceIPBytes, host.Ip, constants.TrafficTCP, constants.TCPSynHeaderSize)

				// Loop through each port for SYN scan.
				for i, port := range c.ports {
					// Initialize TCP header from the SYN template.
					tcpSynHeaders[i] = tcpSynHeaderTemplate
					// Set destination port.
					binary.BigEndian.PutUint16(tcpSynHeaders[i][2:4], port)

					// Build buffer for checksum calculation: pseudo-header + TCP header.
					copy(pseudoHeaderAndTcpHeaderSyn[0:constants.IPv6TransportPseudoHeaderSize], pseudoHeader)
					copy(pseudoHeaderAndTcpHeaderSyn[constants.IPv6TransportPseudoHeaderSize:], tcpSynHeaders[i][:])

					// Compute TCP checksum and set it.
					checksum = computeChecksum(pseudoHeaderAndTcpHeaderSyn)
					binary.BigEndian.PutUint16(tcpSynHeaders[i][16:18], checksum)

					// Set up I/O vectors.
					ioVectors[currentIndex][0] = syscall.Iovec{
						Base: &ethIpBufferSyn[0],
						Len:  lenEthernetAndIp,
					}
					ioVectors[currentIndex][1] = syscall.Iovec{
						Base: &tcpSynHeaders[i][0],
						Len:  uint64(constants.TCPSynHeaderSize),
					}
					// Create message header with 2 segments.
					messageHeaders[currentIndex].Msg = syscall.Msghdr{
						Name:    r.SocketParameters.SocketAddressName,
						Namelen: r.SocketParameters.SocketAddressNameLen,
						Iov:     &ioVectors[currentIndex][0],
						Iovlen:  2,
					}
					currentIndex++
				}
			}

			// ----- VAV Scan Branch -----
			if c.rule.PortScanTechniques.Vav {
				// Prepare Ethernet+IP buffer for VAV scan.
				copy(ethIpBufferVav[0:6], host.Eth)                                        // Set destination MAC.
				copy(ethIpBufferVav[6:constants.EthernetHeaderSize], EthernetTemplate[6:]) // Copy rest of Ethernet header.
				// Copy the VAV IP header template.
				copy(ethIpBufferVav[constants.EthernetHeaderSize:constants.EthernetHeaderSize+constants.IPv6HeaderSize], ipTcpVavTemplate)
				// Overwrite destination IP.
				copy(ethIpBufferVav[constants.EthernetHeaderSize+24:constants.EthernetHeaderSize+40], host.Ip)

				// Prepare the TCP pseudo-header for SYN scan.
				pseudoHeader = prepareIp6TransportPseudoHeader(sourceIPBytes,
					host.Ip,
					constants.TrafficTCP,
					constants.TCPSynVavHeaderSize+constants.AcornSize)

				// Loop through each port for VAV scan.
				for i, port := range c.ports {
					// Initialize TCP header from the VAV template.
					tcpVavHeaders[i] = tcpVavHeaderTemplate
					// Set destination port.
					binary.BigEndian.PutUint16(tcpVavHeaders[i][2:4], port)

					copy(pseudoHeaderAndTcpHeaderVav[0:constants.IPv6TransportPseudoHeaderSize],
						pseudoHeader)
					copy(pseudoHeaderAndTcpHeaderVav[constants.IPv6TransportPseudoHeaderSize:constants.IPv6TransportPseudoHeaderSize+constants.TCPSynVavHeaderSize],
						tcpVavHeaders[i][:])
					copy(pseudoHeaderAndTcpHeaderVav[constants.IPv6TransportPseudoHeaderSize+
						constants.TCPSynVavHeaderSize:],
						constants.Acorn[:])

					checksum = computeChecksum(pseudoHeaderAndTcpHeaderVav)
					binary.BigEndian.PutUint16(tcpVavHeaders[i][16:18], checksum)

					// Set up I/O vectors.
					ioVectors[currentIndex][0] = syscall.Iovec{
						Base: &ethIpBufferVav[0],
						Len:  lenEthernetAndIp,
					}
					ioVectors[currentIndex][1] = syscall.Iovec{
						Base: &tcpVavHeaders[i][0],
						Len:  lenTcpVavHeader,
					}
					ioVectors[currentIndex][2] = syscall.Iovec{
						Base: &constants.Acorn[0],
						Len:  lenAcorn,
					}
					// Create message header with 3 segments.
					messageHeaders[currentIndex].Msg = syscall.Msghdr{
						Name:    r.SocketParameters.SocketAddressName,
						Namelen: r.SocketParameters.SocketAddressNameLen,
						Iov:     &ioVectors[currentIndex][0],
						Iovlen:  3,
					}
					currentIndex++
				}
			}

			// ----- UDP Scan Branch -----
			if c.rule.PortScanTechniques.Udp {
				// Prepare Ethernet+IP buffer for UDP scan.
				copy(ethIpBufferUdp[0:6], host.Eth)                                        // Set destination MAC.
				copy(ethIpBufferUdp[6:constants.EthernetHeaderSize], EthernetTemplate[6:]) // Copy rest of Ethernet header.
				// Copy the UDP IP header template.
				copy(ethIpBufferUdp[constants.EthernetHeaderSize:constants.EthernetHeaderSize+constants.IPv6HeaderSize], ipUdpTemplate)
				// Overwrite destination IP.
				copy(ethIpBufferUdp[constants.EthernetHeaderSize+24:constants.EthernetHeaderSize+40], host.Ip)

				// Prepare the TCP pseudo-header for SYN scan.
				pseudoHeader = prepareIp6TransportPseudoHeader(sourceIPBytes, host.Ip, constants.TrafficUDP, constants.UDPHeaderSize)

				// Loop through each port for UDP scan.
				for i, port := range c.ports {
					// Initialize UDP header from the template.
					udpHeaders[i] = udpHeaderTemplate
					// Set destination port.
					binary.BigEndian.PutUint16(udpHeaders[i][2:4], port)

					// Calculate mandatory UDP checksum.
					pseudoHeader = prepareIp6TransportPseudoHeader(
						sourceIPBytes, host.Ip, constants.TrafficUDP, constants.UDPHeaderSize)
					copy(pseudoHeaderAndUdpHeader[0:constants.IPv6TransportPseudoHeaderSize],
						pseudoHeader)
					copy(pseudoHeaderAndUdpHeader[constants.IPv6TransportPseudoHeaderSize:],
						udpHeaders[i][:])

					checksum = computeChecksum(pseudoHeaderAndUdpHeader)
					binary.BigEndian.PutUint16(udpHeaders[i][6:8], checksum)

					// Set up I/O vectors.
					ioVectors[currentIndex][0] = syscall.Iovec{
						Base: &ethIpBufferUdp[0],
						Len:  lenEthernetAndIp,
					}
					ioVectors[currentIndex][1] = syscall.Iovec{
						Base: &udpHeaders[i][0],
						Len:  uint64(constants.UDPHeaderSize),
					}
					// Create message header with 2 segments.
					messageHeaders[currentIndex].Msg = syscall.Msghdr{
						Name:    r.SocketParameters.SocketAddressName,
						Namelen: r.SocketParameters.SocketAddressNameLen,
						Iov:     &ioVectors[currentIndex][0],
						Iovlen:  2,
					}
					currentIndex++
				}
			}

			// Wait for the rate limiter before sending the batch.
			if err = Limiter.Wait(context.Background()); err != nil {
				c.errorChan <- err
				return
			}

			// Send the batch of messages using the sendmmsg syscall.
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

	// Default: total number of packets is greater or equal to constants.IOVecPacketsChunkSize.
	default:
		// Process each discovered host.
		for host := range r.UpHostsChan {
			currentIndex := 0

			// ----- SYN Scan Branch -----
			if c.rule.PortScanTechniques.Syn {
				// Prepare Ethernet+IP buffer for SYN scan.
				copy(ethIpBufferSyn[0:6], host.Eth)                                        // Set destination MAC.
				copy(ethIpBufferSyn[6:constants.EthernetHeaderSize], EthernetTemplate[6:]) // Copy rest of Ethernet header.
				// Copy the SYN IP header template.
				copy(ethIpBufferSyn[constants.EthernetHeaderSize:constants.EthernetHeaderSize+constants.IPv6HeaderSize], ipTcpSynTemplate)
				// Overwrite destination IP.
				copy(ethIpBufferSyn[constants.EthernetHeaderSize+24:constants.EthernetHeaderSize+40], host.Ip)

				// Prepare the TCP pseudo-header for SYN scan.
				pseudoHeader = prepareIp6TransportPseudoHeader(sourceIPBytes, host.Ip, constants.TrafficTCP, constants.TCPSynHeaderSize)

				// Loop through each port for SYN scan.
				for i, port := range c.ports {
					tcpSynHeaders[i] = tcpSynHeaderTemplate
					// Set destination port.
					binary.BigEndian.PutUint16(tcpSynHeaders[i][2:4], port)

					// Build buffer for checksum calculation: pseudo-header + TCP header.
					copy(pseudoHeaderAndTcpHeaderSyn[0:constants.IPv6TransportPseudoHeaderSize], pseudoHeader)
					copy(pseudoHeaderAndTcpHeaderSyn[constants.IPv6TransportPseudoHeaderSize:], tcpSynHeaders[i][:])

					// Compute TCP checksum and set it.
					checksum = computeChecksum(pseudoHeaderAndTcpHeaderSyn)
					binary.BigEndian.PutUint16(tcpSynHeaders[i][16:18], checksum)

					// Set up I/O vectors.
					ioVectors[currentIndex][0] = syscall.Iovec{
						Base: &ethIpBufferSyn[0],
						Len:  uint64(constants.EthernetHeaderSize + constants.IPv6HeaderSize),
					}
					ioVectors[currentIndex][1] = syscall.Iovec{
						Base: &tcpSynHeaders[i][0],
						Len:  uint64(constants.TCPSynHeaderSize),
					}
					messageHeaders[currentIndex].Msg = syscall.Msghdr{
						Name:    r.SocketParameters.SocketAddressName,
						Namelen: r.SocketParameters.SocketAddressNameLen,
						Iov:     &ioVectors[currentIndex][0],
						Iovlen:  2,
					}
					currentIndex++

					// If block is full, commit the block.
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

			// ----- VAV Scan Branch -----
			if c.rule.PortScanTechniques.Vav {
				// Prepare Ethernet+IP buffer for VAV scan.
				copy(ethIpBufferVav[0:6], host.Eth)                                        // Set destination MAC.
				copy(ethIpBufferVav[6:constants.EthernetHeaderSize], EthernetTemplate[6:]) // Copy rest of Ethernet header.
				// Copy the VAV IP header template.
				copy(ethIpBufferVav[constants.EthernetHeaderSize:constants.EthernetHeaderSize+constants.IPv6HeaderSize], ipTcpVavTemplate)
				// Overwrite destination IP.
				copy(ethIpBufferVav[constants.EthernetHeaderSize+24:constants.EthernetHeaderSize+40], host.Ip)

				// Prepare the TCP pseudo-header for SYN scan.
				pseudoHeader = prepareIp6TransportPseudoHeader(sourceIPBytes,
					host.Ip,
					constants.TrafficTCP,
					constants.TCPSynVavHeaderSize+constants.AcornSize)

				// Loop through each port for VAV scan.
				for i, port := range c.ports {
					tcpVavHeaders[i] = tcpVavHeaderTemplate
					// Set destination port.
					binary.BigEndian.PutUint16(tcpVavHeaders[i][2:4], port)

					copy(pseudoHeaderAndTcpHeaderVav[0:constants.IPv6TransportPseudoHeaderSize],
						pseudoHeader)
					copy(pseudoHeaderAndTcpHeaderVav[constants.IPv6TransportPseudoHeaderSize:constants.IPv6TransportPseudoHeaderSize+constants.TCPSynVavHeaderSize],
						tcpVavHeaders[i][:])
					copy(pseudoHeaderAndTcpHeaderVav[constants.IPv6TransportPseudoHeaderSize+
						constants.TCPSynVavHeaderSize:],
						constants.Acorn[:])

					checksum = computeChecksum(pseudoHeaderAndTcpHeaderVav)
					binary.BigEndian.PutUint16(tcpVavHeaders[i][16:18], checksum)

					// Set up I/O vectors.
					ioVectors[currentIndex][0] = syscall.Iovec{
						Base: &ethIpBufferVav[0],
						Len:  lenEthernetAndIp,
					}
					ioVectors[currentIndex][1] = syscall.Iovec{
						Base: &tcpVavHeaders[i][0],
						Len:  lenTcpVavHeader,
					}
					ioVectors[currentIndex][2] = syscall.Iovec{
						Base: &constants.Acorn[0],
						Len:  lenAcorn,
					}
					messageHeaders[currentIndex].Msg = syscall.Msghdr{
						Name:    r.SocketParameters.SocketAddressName,
						Namelen: r.SocketParameters.SocketAddressNameLen,
						Iov:     &ioVectors[currentIndex][0],
						Iovlen:  3,
					}
					currentIndex++

					// If block is full, commit the block.
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

			// ----- UDP Scan Branch -----
			if c.rule.PortScanTechniques.Udp {
				// Prepare Ethernet+IP buffer for UDP scan.
				copy(ethIpBufferUdp[0:6], host.Eth)                                        // Set destination MAC.
				copy(ethIpBufferUdp[6:constants.EthernetHeaderSize], EthernetTemplate[6:]) // Copy rest of Ethernet header.
				// Copy the UDP IP header template.
				copy(ethIpBufferUdp[constants.EthernetHeaderSize:constants.EthernetHeaderSize+constants.IPv6HeaderSize], ipUdpTemplate)
				// Overwrite destination IP.
				copy(ethIpBufferUdp[constants.EthernetHeaderSize+24:constants.EthernetHeaderSize+40], host.Ip)

				// Prepare the TCP pseudo-header for SYN scan.
				pseudoHeader = prepareIp6TransportPseudoHeader(sourceIPBytes, host.Ip, constants.TrafficUDP, constants.UDPHeaderSize)

				// Loop through each port for UDP scan.
				for i, port := range c.ports {
					udpHeaders[i] = udpHeaderTemplate
					// Set destination port.
					binary.BigEndian.PutUint16(udpHeaders[i][2:4], port)

					// Calculate mandatory UDP checksum.
					pseudoHeader = prepareIp6TransportPseudoHeader(
						sourceIPBytes, host.Ip, constants.TrafficUDP, constants.UDPHeaderSize)
					copy(pseudoHeaderAndUdpHeader[0:constants.IPv6TransportPseudoHeaderSize],
						pseudoHeader)
					copy(pseudoHeaderAndUdpHeader[constants.IPv6TransportPseudoHeaderSize:],
						udpHeaders[i][:])

					checksum = computeChecksum(pseudoHeaderAndUdpHeader)
					binary.BigEndian.PutUint16(udpHeaders[i][6:8], checksum)

					// Set up I/O vectors.
					ioVectors[currentIndex][0] = syscall.Iovec{
						Base: &ethIpBufferUdp[0],
						Len:  lenEthernetAndIp,
					}
					ioVectors[currentIndex][1] = syscall.Iovec{
						Base: &udpHeaders[i][0],
						Len:  constants.UDPHeaderSize,
					}
					messageHeaders[currentIndex].Msg = syscall.Msghdr{
						Name:    r.SocketParameters.SocketAddressName,
						Namelen: r.SocketParameters.SocketAddressNameLen,
						Iov:     &ioVectors[currentIndex][0],
						Iovlen:  2,
					}
					currentIndex++

					// If block is full, commit the block.
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

			// Commit any leftover messages for the current host.
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
		}
	}

	// Allow some time to receive responses before finishing.
	time.Sleep(c.rule.Options.Timeout)

	// Signal that port scanning is complete.
	r.PortsDiscoveryDoneChan <- true
}

// scanPortsV6OverGateway scans IPv6 hosts via a gateway.
// The r.UpHostsChan channel carries only target IP addresses.
// The constructed packets include an Ethernet header built from the source interface
// and the provided gatewayMac. Buffers and header templates are reused to minimize allocations.
func scanPortsV6OverGateway(c *scannerContext, r *router.IpRangeRouteContext, portsScanWg *sync.WaitGroup, gatewayMac net.HardwareAddr) {
	// Defer cleanup actions.
	defer portsScanWg.Done()
	defer close(r.ReadyToInterceptPortsStateChan)
	//defer fmt.Println("DEBUG: ScanPortsOverGateway is done")

	var (
		// IP header templates for each scan type.
		ipTcpSynTemplate []byte
		ipTcpVavTemplate []byte
		ipUdpTemplate    []byte

		// Ethernet header template.
		ethHeader []byte

		// IP header buffers (reused per host).
		ipBufferSyn []byte
		ipBufferVav []byte
		ipBufferUdp []byte

		// Source IP in 4-byte format.
		sourceIPBytes = r.Route.Src.To16()

		// Temporary variable for computing checksums.
		checksum uint16
		// Buffer for concatenating pseudo-header with transport headers.
		pseudoHeader []byte

		// Buffers for concatenating pseudo-header with TCP/UDP headers for checksum calculation.
		pseudoHeaderAndTcpHeaderSyn []byte
		pseudoHeaderAndTcpHeaderVav []byte
		pseudoHeaderAndUdpHeader    []byte

		// Slices of transport headers for all ports.
		tcpSynHeaders [][constants.TCPSynHeaderSize]byte
		tcpVavHeaders [][constants.TCPSynVavHeaderSize]byte
		udpHeaders    [][constants.UDPHeaderSize]byte

		// Header templates (with predefined source port).
		tcpSynHeaderTemplate [constants.TCPSynHeaderSize]byte
		tcpVavHeaderTemplate [constants.TCPSynVavHeaderSize]byte
		udpHeaderTemplate    [constants.UDPHeaderSize]byte

		// Message headers and I/O vectors for the sendmmsg syscall.
		messageHeaders [constants.IOVecPacketsChunkSize]mmsghdr
		ioVectors      [constants.IOVecPacketsChunkSize][4]syscall.Iovec

		// Counter for the number of scan types enabled.
		scanTypesCount int

		// Error and other temporary variables.
		err error
	)

	// Compile BPF filter for capturing transport-layer responses.
	var bpfExpression *pcap.BPF
	bpfExpression, err = compileTransportStateDetectionBPF(c, r)
	if err != nil {
		c.errorChan <- err
		return
	}

	// Start a goroutine to intercept TCP/UDP responses.
	portsScanWg.Add(1)
	go interceptTransportV6Responses(c, r, bpfExpression, portsScanWg)

	// Prepare Ethernet header.
	ethHeader = prepareEthernetPart(r.SocketParameters.SourceInterface.HardwareAddr, gatewayMac, constants.EtherTypeIPv6)

	// Wait until the interceptor is ready.
	<-r.ReadyToInterceptPortsStateChan

	// Prepare headers and buffers for each enabled scan technique.
	if c.rule.PortScanTechniques.Syn {
		scanTypesCount++
		// Build IP header template for SYN scan (IP header + TCP SYN header).
		ipTcpSynTemplate = prepareIpv6PartTemplate(
			r.Route.Src,
			constants.IPv6HeaderSize+constants.TCPSynHeaderSize,
			constants.TrafficTCP,
		)
		// Allocate IP header buffer for SYN scan.
		ipBufferSyn = make([]byte, constants.IPv6HeaderSize)
		// Allocate buffer for pseudo-header + TCP SYN header.
		pseudoHeaderAndTcpHeaderSyn = make([]byte, constants.IPv6TransportPseudoHeaderSize+constants.TCPSynHeaderSize)
		// Allocate slice for TCP SYN headers (one per port).
		tcpSynHeaders = make([][constants.TCPSynHeaderSize]byte, len(c.ports))
		// Initialize the SYN header template with the source port.
		tcpSynHeaderTemplate = constants.TCPSynHeader
		binary.BigEndian.PutUint16(tcpSynHeaderTemplate[0:2], r.SourcePort)
	}

	if c.rule.PortScanTechniques.Vav {
		scanTypesCount++
		// Build IP header template for VAV scan (IP header + TCP VAV header + payload).
		ipTcpVavTemplate = prepareIpv6PartTemplate(
			r.Route.Src,
			constants.TCPSynVavHeaderSize+constants.AcornSize,
			constants.TrafficTCP,
		)
		// Allocate IP header buffer for VAV scan.
		ipBufferVav = make([]byte, constants.IPv6HeaderSize)
		// Allocate buffer for pseudo-header + TCP VAV header + payload.
		pseudoHeaderAndTcpHeaderVav = make([]byte, constants.IPv6TransportPseudoHeaderSize+constants.TCPSynVavHeaderSize+constants.AcornSize)
		// Allocate slice for TCP VAV headers (one per port).
		tcpVavHeaders = make([][constants.TCPSynVavHeaderSize]byte, len(c.ports))
		// Initialize the VAV header template with the source port.
		tcpVavHeaderTemplate = constants.TCPSynVavHeader
		binary.BigEndian.PutUint16(tcpVavHeaderTemplate[0:2], r.SourcePort)
	}

	if c.rule.PortScanTechniques.Udp {
		scanTypesCount++
		// Build IP header template for UDP scan (IP header + UDP header).
		ipUdpTemplate = prepareIpv6PartTemplate(
			r.Route.Src,
			constants.UDPHeaderSize,
			constants.TrafficUDP,
		)
		// Allocate IP header buffer for UDP scan.
		ipBufferUdp = make([]byte, constants.IPv6HeaderSize)
		// Allocate slice for UDP headers (one per port).
		udpHeaders = make([][constants.UDPHeaderSize]byte, len(c.ports))
		// Initialize the UDP header template with the source port.
		udpHeaderTemplate = constants.UdpHeader
		binary.BigEndian.PutUint16(udpHeaderTemplate[0:2], r.SourcePort)
	}

	// Determine batching strategy based on total packets.
	totalPackets := len(c.ports) * scanTypesCount

	switch {
	// If total packets is less than the chunk size, process each host as a single batch.
	case totalPackets < constants.IOVecPacketsChunkSize:
		for host := range r.UpHostsChan {
			currentIndex := 0

			// ----- SYN Scan Branch -----
			if c.rule.PortScanTechniques.Syn {
				copy(ipBufferSyn, ipTcpSynTemplate)
				// Overwrite destination IP (offset 16).
				copy(ipBufferSyn[24:40], host.Ip)

				pseudoHeader = prepareIp6TransportPseudoHeader(sourceIPBytes, host.Ip, constants.TrafficTCP, constants.TCPSynHeaderSize)

				for i, port := range c.ports {
					tcpSynHeaders[i] = tcpSynHeaderTemplate
					binary.BigEndian.PutUint16(tcpSynHeaders[i][2:4], port)

					copy(pseudoHeaderAndTcpHeaderSyn[0:constants.IPv6TransportPseudoHeaderSize], pseudoHeader)
					copy(pseudoHeaderAndTcpHeaderSyn[constants.IPv6TransportPseudoHeaderSize:], tcpSynHeaders[i][:])

					checksum = computeChecksum(pseudoHeaderAndTcpHeaderSyn)
					binary.BigEndian.PutUint16(tcpSynHeaders[i][16:18], checksum)

					// IOVec: Ethernet, IP, TCP.
					ioVectors[currentIndex][0] = syscall.Iovec{
						Base: &ethHeader[0],
						Len:  constants.EthernetHeaderSize,
					}
					ioVectors[currentIndex][1] = syscall.Iovec{
						Base: &ipBufferSyn[0],
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
				}
			}

			// ----- VAV Scan Branch -----
			if c.rule.PortScanTechniques.Vav {
				copy(ipBufferVav, ipTcpVavTemplate)
				copy(ipBufferVav[24:40], host.Ip)

				pseudoHeader = prepareIp6TransportPseudoHeader(sourceIPBytes, host.Ip, constants.TrafficTCP, constants.TCPSynVavHeaderSize+constants.AcornSize)

				for i, port := range c.ports {
					tcpVavHeaders[i] = tcpVavHeaderTemplate
					binary.BigEndian.PutUint16(tcpVavHeaders[i][2:4], port)

					copy(pseudoHeaderAndTcpHeaderVav[0:constants.IPv6TransportPseudoHeaderSize], pseudoHeader)
					copy(pseudoHeaderAndTcpHeaderVav[constants.IPv6TransportPseudoHeaderSize:constants.IPv6TransportPseudoHeaderSize+constants.TCPSynVavHeaderSize], tcpVavHeaders[i][:])
					copy(pseudoHeaderAndTcpHeaderVav[constants.IPv6TransportPseudoHeaderSize+constants.TCPSynVavHeaderSize:], constants.Acorn[:])
					checksum = computeChecksum(pseudoHeaderAndTcpHeaderVav)
					binary.BigEndian.PutUint16(tcpVavHeaders[i][16:18], checksum)

					// IOVec: Ethernet, IP, TCP VAV header, payload.
					ioVectors[currentIndex][0] = syscall.Iovec{
						Base: &ethHeader[0],
						Len:  uint64(constants.EthernetHeaderSize),
					}
					ioVectors[currentIndex][1] = syscall.Iovec{
						Base: &ipBufferVav[0],
						Len:  uint64(constants.IPv6HeaderSize),
					}
					ioVectors[currentIndex][2] = syscall.Iovec{
						Base: &tcpVavHeaders[i][0],
						Len:  uint64(constants.TCPSynVavHeaderSize),
					}
					ioVectors[currentIndex][3] = syscall.Iovec{
						Base: &constants.Acorn[0],
						Len:  uint64(constants.AcornSize),
					}
					messageHeaders[currentIndex].Msg = syscall.Msghdr{
						Name:    r.SocketParameters.SocketAddressName,
						Namelen: r.SocketParameters.SocketAddressNameLen,
						Iov:     &ioVectors[currentIndex][0],
						Iovlen:  4,
					}
					currentIndex++
				}
			}

			// ----- UDP Scan Branch -----
			if c.rule.PortScanTechniques.Udp {
				copy(ipBufferUdp, ipUdpTemplate)
				copy(ipBufferUdp[24:40], host.Ip)

				for i, port := range c.ports {
					udpHeaders[i] = udpHeaderTemplate
					binary.BigEndian.PutUint16(udpHeaders[i][2:4], port)

					pseudoHeader = prepareIp6TransportPseudoHeader(sourceIPBytes, host.Ip, constants.TrafficUDP, constants.UDPHeaderSize)
					pseudoHeaderAndUdpHeader = pseudoHeaderAndUdpHeader[:0]
					pseudoHeaderAndUdpHeader = append(pseudoHeaderAndUdpHeader, pseudoHeader...)
					pseudoHeaderAndUdpHeader = append(pseudoHeaderAndUdpHeader, udpHeaders[i][:]...)
					checksum = computeChecksum(pseudoHeaderAndUdpHeader)
					binary.BigEndian.PutUint16(udpHeaders[i][6:8], checksum)

					// IOVec: Ethernet, IP, UDP.
					ioVectors[currentIndex][0] = syscall.Iovec{
						Base: &ethHeader[0],
						Len:  uint64(constants.EthernetHeaderSize),
					}
					ioVectors[currentIndex][1] = syscall.Iovec{
						Base: &ipBufferUdp[0],
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
				}
			}

			// Wait for the rate limiter before sending the batch.
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

		// Default: total packets is greater or equal to constants.IOVecPacketsChunkSize.
	default:
		for host := range r.UpHostsChan {
			currentIndex := 0

			// ----- SYN Scan Branch -----
			if c.rule.PortScanTechniques.Syn {
				copy(ipBufferSyn, ipTcpSynTemplate)
				copy(ipBufferSyn[24:40], host.Ip)

				pseudoHeader = prepareIp6TransportPseudoHeader(sourceIPBytes, host.Ip, constants.TrafficTCP, constants.TCPSynHeaderSize)

				for i, port := range c.ports {
					tcpSynHeaders[i] = tcpSynHeaderTemplate
					binary.BigEndian.PutUint16(tcpSynHeaders[i][2:4], port)

					copy(pseudoHeaderAndTcpHeaderSyn[0:constants.IPv6TransportPseudoHeaderSize], pseudoHeader)
					copy(pseudoHeaderAndTcpHeaderSyn[constants.IPv6TransportPseudoHeaderSize:], tcpSynHeaders[i][:])
					checksum = computeChecksum(pseudoHeaderAndTcpHeaderSyn)
					binary.BigEndian.PutUint16(tcpSynHeaders[i][16:18], checksum)

					ioVectors[currentIndex][0] = syscall.Iovec{
						Base: &ethHeader[0],
						Len:  constants.EthernetHeaderSize,
					}
					ioVectors[currentIndex][1] = syscall.Iovec{
						Base: &ipBufferSyn[0],
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
					// If block is full, send batch.
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

			// ----- VAV Scan Branch -----
			if c.rule.PortScanTechniques.Vav {
				copy(ipBufferVav, ipTcpVavTemplate)
				copy(ipBufferVav[24:40], host.Ip)

				pseudoHeader = prepareIp4TransportPseudoHeader(sourceIPBytes, host.Ip, constants.TrafficTCP,
					constants.TCPSynVavHeaderSize+constants.AcornSize)

				for i, port := range c.ports {
					tcpVavHeaders[i] = tcpVavHeaderTemplate
					binary.BigEndian.PutUint16(tcpVavHeaders[i][2:4], port)

					copy(pseudoHeaderAndTcpHeaderVav[0:constants.IPv6TransportPseudoHeaderSize], pseudoHeader)
					copy(pseudoHeaderAndTcpHeaderVav[constants.IPv6TransportPseudoHeaderSize:constants.IPv6TransportPseudoHeaderSize+constants.TCPSynVavHeaderSize], tcpVavHeaders[i][:])
					copy(pseudoHeaderAndTcpHeaderVav[constants.IPv6TransportPseudoHeaderSize+constants.TCPSynVavHeaderSize:], constants.Acorn[:])
					checksum = computeChecksum(pseudoHeaderAndTcpHeaderVav)
					binary.BigEndian.PutUint16(tcpVavHeaders[i][16:18], checksum)

					ioVectors[currentIndex][0] = syscall.Iovec{
						Base: &ethHeader[0],
						Len:  uint64(constants.EthernetHeaderSize),
					}
					ioVectors[currentIndex][1] = syscall.Iovec{
						Base: &ipBufferVav[0],
						Len:  uint64(constants.IPv6HeaderSize),
					}
					ioVectors[currentIndex][2] = syscall.Iovec{
						Base: &tcpVavHeaders[i][0],
						Len:  uint64(constants.TCPSynVavHeaderSize),
					}
					ioVectors[currentIndex][3] = syscall.Iovec{
						Base: &constants.Acorn[0],
						Len:  uint64(constants.AcornSize),
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

			// ----- UDP Scan Branch -----
			if c.rule.PortScanTechniques.Udp {
				copy(ipBufferUdp, ipUdpTemplate)
				copy(ipBufferUdp[24:40], host.Ip)

				for i, port := range c.ports {
					udpHeaders[i] = udpHeaderTemplate
					binary.BigEndian.PutUint16(udpHeaders[i][2:4], port)

					pseudoHeader = prepareIp4TransportPseudoHeader(sourceIPBytes, host.Ip, constants.TrafficUDP, constants.UDPHeaderSize)
					pseudoHeaderAndUdpHeader = pseudoHeaderAndUdpHeader[:0]
					pseudoHeaderAndUdpHeader = append(pseudoHeaderAndUdpHeader, pseudoHeader...)
					pseudoHeaderAndUdpHeader = append(pseudoHeaderAndUdpHeader, udpHeaders[i][:]...)
					checksum = computeChecksum(pseudoHeaderAndUdpHeader)
					binary.BigEndian.PutUint16(udpHeaders[i][6:8], checksum)

					ioVectors[currentIndex][0] = syscall.Iovec{
						Base: &ethHeader[0],
						Len:  uint64(constants.EthernetHeaderSize),
					}
					ioVectors[currentIndex][1] = syscall.Iovec{
						Base: &ipBufferUdp[0],
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

			// Commit any leftover messages.
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
		}
	}

	// Allow some time to receive responses before finishing.
	time.Sleep(c.rule.Options.Timeout)

	// Signal that port scanning is complete.
	r.PortsDiscoveryDoneChan <- true
}

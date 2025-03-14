package constants

// EtherTypeIPv4 indicates IPv4 traffic
const EtherTypeIPv4 uint16 = 0x0800

// EtherTypeARP indicates ARP traffic
const EtherTypeARP uint16 = 0x0806

// TrafficICMPv4 is the protocol number for ICMP for v4
const TrafficICMPv4 = byte(1)

const ArpPacketPaddingSize = MinFrameSize - ArpBodySize - ArpHeaderHeaderSize - EthernetHeaderSize

var ArpPacketPadding [ArpPacketPaddingSize]byte

const IcmpV4PacketPaddingSize = MinFrameSize - IcmpV4Size - IPv4HeaderSize - EthernetHeaderSize

var IcmpV4PacketPadding [IcmpV4PacketPaddingSize]byte

// ArpBodySize is the size of the ARP body (20 bytes)
const ArpBodySize = 20

// IPv4HeaderSize indicates the size of the IPv4 header (20 bytes)
const IPv4HeaderSize = 20

// IcmpV4Size indicates the size of the ICMPv4 packet
const IcmpV4Size = 12

// ArpHeaderHeaderSize is the size of the first part of the ARP header after Ethernet (8 bytes)
const ArpHeaderHeaderSize = 8

// ArpHeaderPart is the first 8 bytes of the ARP header following the Ethernet header.
// This data includes Hardware Type, Protocol Type, Hardware Size, Protocol Size, and Operation.
var ArpHeaderPart = [ArpHeaderHeaderSize]byte{
	0x00, 0x01, // Hardware Type: 1 (Ethernet)
	0x08, 0x00, // Protocol Type: 0x0800 (IPv4)
	0x06,       // Hardware Address Size: 6
	0x04,       // Protocol Address Size: 4
	0x00, 0x01, // Operation: 1 (ARP Request)
}

// ArpBody is the remaining 20 bytes of the ARP packet, containing sender/target HW and IP addresses.
var ArpBody = [ArpBodySize]byte{
	// Sender HW address (6 bytes)
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// Sender IP (4 bytes)
	0x00, 0x00, 0x00, 0x00,
	// Target HW address (6 bytes)
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// Target IP (4 bytes)
	0x00, 0x00, 0x00, 0x00,
}

// IPv4Header is a 20-byte minimal IPv4 header
// Indices for dynamic fields:
//
//	IpHeaderIndexTotalLengthHigh (2), IpHeaderIndexTotalLengthLow (3), IpHeaderIndexProtocol (9)
//	Source IP (12..15), Destination IP (16..19)
var IPv4Header = [IPv4HeaderSize]byte{
	// [0:1]   Version & IHL (0x45), Type of Service (0)
	0x45, 0x00,
	// [2:3]   Total Length (default set to 28 here, can be modified)
	0x00, 0x1C,
	// [4:5]   Identification (0)
	0x00, 0x00,
	// [6:7]   Flags, Fragment Offset (64, 0)
	0x40, 0x00,
	// [8]     Time To Live (64)
	0x40,
	// [9]     Protocol
	0x00,
	// [10:11] Header Checksum (0, 0)
	0x00, 0x00,
	// [12:15] Source IP (0.0.0.0)
	0x00, 0x00, 0x00, 0x00,
	// [16:19] Destination IP (255.0.0.0)
	0xFF, 0x00, 0x00, 0x00,
}

// IcmpV4Header is a 26-byte ICMPv4 Echo Request (Type 8) with a small payload.
var IcmpV4Header = [IcmpV4Size]byte{
	// [0:1]   Type (8), Code (0)
	0x08, 0x00,
	// [2:3]   ICMP Checksum (71, 58)
	0x47, 0x3A,
	// [4:5]   Identifier (18, 52)
	0x12, 0x34,
	// [6:7]   Sequence (0, 1)
	0x00, 0x01,
	// [8:11]  Payload ("PING")
	0x50, 0x49, 0x4E, 0x47,
	// [12:25] Additional space or padding can be added here if needed
}

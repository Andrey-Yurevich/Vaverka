package constants

import (
	"net"
	"time"
)

// -------------------------------------------------------------------------------------------------
// TIME AND BUFFER CONSTANTS
// -------------------------------------------------------------------------------------------------
const (
	// LimiterBuffersBurstLimit Maximum burst for limiter buffers
	LimiterBuffersBurstLimit = 4

	// DefaultTimeout is the default wait duration
	DefaultTimeout = time.Second * 2

	// ErrorChanBufferSize is the channel buffer size for errors
	ErrorChanBufferSize = 4

	// GatewayMacRequestTimeout is the timeout for ARP responses
	GatewayMacRequestTimeout = time.Second * 1

	// PcapCaptureTimeout is the capture wait duration for PCAP
	PcapCaptureTimeout = time.Millisecond * 30

	// IOVecPacketsChunkSize is the chunk size of packet arrays
	IOVecPacketsChunkSize = 64

	// UpHostsChanSize is the size of the channel that processes up-host results
	UpHostsChanSize = 1024
	MinFrameSize    = 64
)

// -------------------------------------------------------------------------------------------------
// ETHER TYPE CONSTANTS

// EtherTypeIPv4 indicates IPv4 traffic
const EtherTypeIPv4 uint16 = 0x0800

// EtherTypeIPv6 indicates IPv6 traffic
const EtherTypeIPv6 uint16 = 0x86DD

// EtherTypeARP indicates ARP traffic
const EtherTypeARP uint16 = 0x0806

// -------------------------------------------------------------------------------------------------
// IP PROTOCOL TYPE CONSTANTS
// -------------------------------------------------------------------------------------------------
const (
	// TrafficICMP is the protocol number for ICMP
	TrafficICMP = byte(1)
	// TrafficTCP is the protocol number for TCP
	TrafficTCP = byte(6)
	// TrafficUDP is the protocol number for UDP
	TrafficUDP = byte(17)
)

// EthernetPartSize indicates the size of an Ethernet header (14 bytes)
const EthernetPartSize = 14

// ArpHeaderPartSize is the size of the first part of the ARP header after Ethernet (8 bytes)
const ArpHeaderPartSize = 8

const UDPHeaderPartSize = 8

const ArpPacketPaddingSize = MinFrameSize - ArpBodyPartSize - ArpHeaderPartSize - EthernetPartSize

var ArpPacketPadding [ArpPacketPaddingSize]byte

const IcmpPacketPaddingSize = MinFrameSize - IcmpV4PartSize - IPv4HeaderSize - EthernetPartSize

var IcmpPacketPadding [IcmpPacketPaddingSize]byte

// ArpBodyPartSize is the size of the ARP body (20 bytes)
const ArpBodyPartSize = 20

// IPv4HeaderSize indicates the size of the IPv4 header (20 bytes)
const IPv4HeaderSize = 20

// IcmpV4PartSize indicates the size of the ICMPv4 packet
const IcmpV4PartSize = 12

// EthernetPart is a 14-byte skeleton for the Ethernet header.
// The last two bytes (indexes 12 and 13) can be set to EtherTypeARP, EtherTypeIPv4, or EtherTypeIPv6.
var EthernetPart = [EthernetPartSize]byte{
	// [0:6] Destination MAC - should be specified
	0, 0, 0, 0, 0, 0,
	// [6:12] Source MAC - should be specified
	0, 0, 0, 0, 0, 0,
	// [12:14] EtherType (default 0x0800 for IPv4)
	0x08, 0x00,
}

// ArpHeaderPart is the first 8 bytes of the ARP header following the Ethernet header.
// This data includes Hardware Type, Protocol Type, Hardware Size, Protocol Size, and Operation.
var ArpHeaderPart = [ArpHeaderPartSize]byte{
	0x00, 0x01, // Hardware Type: 1 (Ethernet)
	0x08, 0x00, // Protocol Type: 0x0800 (IPv4)
	0x06,       // Hardware Address Size: 6
	0x04,       // Protocol Address Size: 4
	0x00, 0x01, // Operation: 1 (ARP Request)
}

// ArpBodyPart is the remaining 20 bytes of the ARP packet, containing sender/target HW and IP addresses.
var ArpBodyPart = [ArpBodyPartSize]byte{
	// Sender HW address (6 bytes)
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// Sender IP (4 bytes)
	0x00, 0x00, 0x00, 0x00,
	// Target HW address (6 bytes)
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// Target IP (4 bytes)
	0x00, 0x00, 0x00, 0x00,
}

// IPv4Part is a 20-byte minimal IPv4 header
// Indices for dynamic fields:
//
//	IpHeaderIndexTotalLengthHigh (2), IpHeaderIndexTotalLengthLow (3), IpHeaderIndexProtocol (9)
//	Source IP (12..15), Destination IP (16..19)
var IPv4Part = [IPv4HeaderSize]byte{
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

// IcmpV4Part is a 26-byte ICMPv4 Echo Request (Type 8) with a small payload.
var IcmpV4Part = [IcmpV4PartSize]byte{
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

const TCPHeaderPartSize = 20

var TCPHeaderPart = [TCPHeaderPartSize]byte{
	0x0, 0x0, 0x00, 0x00, // Source Port , Destination Port
	0x00, 0x00, 0x22, 0xEF, // SEQ number
	0x00, 0x00, 0x00, 0x00, // ACK number
	0x50, 0x02, // Data Offset (5), Flags (SYN)
	0x39, 0x08, // Window Size
	0x00, 0x00, // Checksum (placeholder)
	0x00, 0x00, // Urgent Pointer
}

// TCPPseudoHeaderSize required to calculate tcp checksum
const TCPPseudoHeaderSize = 12

var EthernetBroadcastAddress = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// CommonPorts is a list of frequently used service ports.
var CommonPorts = []uint16{
	21,    // FTP
	22,    // SSH
	25,    // SMTP
	53,    // DNS
	80,    // HTTP
	110,   // POP3
	111,   // RPCBind
	135,   // DCE/RPC
	139,   // NetBIOS
	143,   // IMAP
	161,   // SNMP
	162,   // SNMP Trap
	443,   // HTTPS
	445,   // SMB
	993,   // IMAPS
	995,   // POP3S
	1433,  // Microsoft SQL Server
	1521,  // Oracle DB
	3306,  // MySQL
	3389,  // Microsoft RDP
	5060,  // SIP
	5432,  // PostgreSQL
	5672,  // RabbitMQ (AMQP)
	6379,  // Redis
	8000,  // HTTP Alternative
	8080,  // HTTP Alternative
	8081,  // HTTP Alternative
	8082,  // HTTP Alternative
	8443,  // HTTPS Alternative
	8888,  // HTTP Alternative
	9090,  // Prometheus, HTTP Alternative
	9091,  // HTTP Alternative
	27017, // MongoDB
}

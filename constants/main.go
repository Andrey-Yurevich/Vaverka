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

// Define ANSI color codes
const (
	ColorReset = "\033[0m"
	ColorBlue  = "\033[34m"
	ColorRed   = "\033[31m"
	ColorGreen = "\033[32m"
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

// EthernetHeaderSize indicates the size of an Ethernet header (14 bytes)
const EthernetHeaderSize = 14

const ArpPacketPaddingSize = MinFrameSize - ArpBodySize - ArpHeaderHeaderSize - EthernetHeaderSize

var ArpPacketPadding [ArpPacketPaddingSize]byte

const IcmpPacketPaddingSize = MinFrameSize - IcmpV4Size - IPv4HeaderSize - EthernetHeaderSize

var IcmpPacketPadding [IcmpPacketPaddingSize]byte

// ArpBodySize is the size of the ARP body (20 bytes)
const ArpBodySize = 20

// IPv4HeaderSize indicates the size of the IPv4 header (20 bytes)
const IPv4HeaderSize = 20

// IcmpV4Size indicates the size of the ICMPv4 packet
const IcmpV4Size = 12

// EthernetHeader is a 14-byte skeleton for the Ethernet header.
// The last two bytes (indexes 12 and 13) can be set to EtherTypeARP, EtherTypeIPv4, or EtherTypeIPv6.
var EthernetHeader = [EthernetHeaderSize]byte{
	// [0:6] Destination MAC - should be specified
	0, 0, 0, 0, 0, 0,
	// [6:12] Source MAC - should be specified
	0, 0, 0, 0, 0, 0,
	// [12:14] EtherType (default 0x0800 for IPv4)
	0x08, 0x00,
}

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

const TCPSynHeaderSize = 20

var TCPSynHeader = [TCPSynHeaderSize]byte{
	0x0, 0x0, 0x00, 0x00, // Source Port , Destination Port
	0x00, 0x00, 0x22, 0xEF, // SEQ number
	0x00, 0x00, 0x00, 0x00, // ACK number
	0x50, 0x02, // Data Offset (5), Flags (SYN)
	0x39, 0x08, // Window Size
	0x00, 0x00, // Checksum (placeholder)
	0x00, 0x00, // Urgent Pointer
}

const TCPSynVavHeaderSize = 24

// TCPSynVavHeader is the TCP header for SYN/VAV scanning.
// It is based on the standard SYN header, but with a modified data offset,
// SYN+URG flags, a non-zero urgent pointer, and an appended MSS option (4 bytes)
// for a total header length of 24 bytes.
// The MSS option is defined as: Kind=2, Length=4, MSS=1460 (0x05B4).
var TCPSynVavHeader = [TCPSynVavHeaderSize]byte{
	0x00, 0x00, 0x00, 0x00, // Source Port and Destination Port (first 4 bytes; placeholders to be set later)
	0x00, 0x00, 0x22, 0xEF, // Sequence Number (4 bytes)
	0x00, 0x00, 0x00, 0x00, // Acknowledgment Number (4 bytes)
	0x60, 0x22, // Data Offset (6 << 4 = 0x60) and Flags (SYN (0x02) | URG (0x20) = 0x22)
	0x39, 0x08, // Window Size (2 bytes)
	0x00, 0x00, // Checksum (2 bytes, placeholder)
	0x00, 0x01, // Urgent Pointer (2 bytes, set to 1 to indicate urgent data)
	0x02, 0x04, 0x05, 0xB4, // MSS Option: Kind (2), Length (4), MSS value (1460 = 0x05B4)
}

// TCPPseudoHeaderSize required to calculate tcp checksum
const TCPPseudoHeaderSize = 12

const AcornSize = 147

// Acorn Hex interpretation of the ASCII art of the Acorn logo
// vaverka  _
//
//	    _/-\_
//	 .-`-:-:-`-.
//	/-:-:-:-:-:-\
//	\:-:-:-:-:-:/
//	 |`       `|
//	 |         |
//	 `\       /'
//	   `-._.-'
//	      `
var Acorn = [AcornSize]byte{
	0x76, 0x61, 0x76, 0x65, 0x72, 0x6B, 0x61, 0x20, 0x20, 0x5F,
	0x0A, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x5F, 0x2F,
	0x2D, 0x5C, 0x5F, 0x20, 0x0A, 0x20, 0x20, 0x20, 0x20, 0x2E,
	0x2D, 0x60, 0x2D, 0x3A, 0x2D, 0x3A, 0x2D, 0x60, 0x2D, 0x2E,
	0x0A, 0x20, 0x20, 0x20, 0x2F, 0x2D, 0x3A, 0x2D, 0x3A, 0x2D,
	0x3A, 0x2D, 0x3A, 0x2D, 0x3A, 0x2D, 0x5C, 0x0A, 0x20, 0x20,
	0x20, 0x5C, 0x3A, 0x2D, 0x3A, 0x2D, 0x3A, 0x2D, 0x3A, 0x2D,
	0x3A, 0x2D, 0x3A, 0x2F, 0x0A, 0x20, 0x20, 0x20, 0x20, 0x7C,
	0x60, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x60, 0x7C,
	0x0A, 0x20, 0x20, 0x20, 0x20, 0x7C, 0x20, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x7C, 0x0A, 0x20, 0x20, 0x20,
	0x20, 0x60, 0x5C, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x2F, 0x27, 0x0A, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x60,
	0x2D, 0x2E, 0x5F, 0x2E, 0x2D, 0x27, 0x0A, 0x20, 0x20, 0x20,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x60,
}

const UDPHeaderSize = 15

// UdpHeader is a 15-byte UDP datagram part consisting of the UDP header and payload "vaverka".
// It is structured as follows:
// [0:1]  UDP Source Port
// [2:3]  UDP Destination Port
// [4:5]  UDP Length (15 bytes: 8 bytes header + 7 bytes payload)
// [6:7]  UDP Checksum
// [8:14] UDP Payload ("vaverka")
var UdpHeader = [UDPHeaderSize]byte{
	// [0:1] UDP Source Port
	0x00, 0x00,
	// [2:3] UDP Destination Port (55555)
	0x00, 0x00,
	// [4:5] UDP Length (15 bytes)
	0x00, 0x0F,
	// [6:7] UDP Checksum
	0x00, 0x00,
	// [8:14] UDP Payload ("vaverka")
	0x76, 0x61, 0x76, 0x65, 0x72, 0x6B, 0x61,
}

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
	8001,  // HTTP Alternative
	8080,  // HTTP Alternative
	8081,  // HTTP Alternative
	8443,  // HTTPS Alternative
	8888,  // HTTP Alternative
	9090,  // Prometheus, HTTP Alternative
	9091,  // HTTP Alternative
	27017, // MongoDB
}

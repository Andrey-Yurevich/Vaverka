package constants

import "time"

const (
	EthIpv4ArpPacketSize     = 42
	LimiterBuffersBurstLimit = 4
	DefaultTimeout           = time.Second * 2
	ErrorChanBufferSize      = 4
	GatewayMacRequestTimeout = time.Second * 1
	IOVecPacketsChunkSize    = 64
	EthIpv4IcmpV4PacketSize  = 42
	PcapCaptureTimeout       = time.Millisecond * 30
	UpHostsChanSize          = 1024
)

const EthernetAndArpHeadersSize = 22

// EthernetAndArpHeadersPart This array covers bytes [0..22) of the original skeleton (Ethernet + first part of ARP header).
var EthernetAndArpHeadersPart = [EthernetAndArpHeadersSize]byte{
	// Ethernet header (14 bytes)
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // [0:6]   Destination MAC (was [0:6])
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // [6:12]  Source MAC (was [6:12])
	0x08, 0x06, // [12:14] EtherType: 0x0806 (ARP) (was [12:14])

	// ARP header (part of the 28 bytes)
	0x00, 0x01, // [14:16] Hardware Type: 1 (Ethernet) (was [14:16])
	0x08, 0x00, // [16:18] Protocol Type: 0x0800 (IPv4) (was [16:18])
	0x06,       // [18]    Hardware Address Size: 6 (was [18])
	0x04,       // [19]    Protocol Address Size: 4 (was [19])
	0x00, 0x01, // [20:22] Operation: 1 (ARP Request) (was [20:22])
}

const ArpPacketPayloadSize = 20

// ArpPacketPayloadPart This array covers bytes [22..42) of the original skeleton (the ARP body).
var ArpPacketPayloadPart = [ArpPacketPayloadSize]byte{
	// ARP body
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // [0:6]   Sender HW address (was [22:28])
	0x00, 0x00, 0x00, 0x00, // [6:10]  Sender IP (was [28:32])
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // [10:16] Target HW address (was [32:38])
	0x00, 0x00, 0x00, 0x00, // [16:20] Target IP (was [38:42])
}

const PacketEthernetV4PartSize = 14

const EighteenBytesPaddingPartSize = 18

var EighteenBytesPaddingPart = [EighteenBytesPaddingPartSize]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

// EthernetV4Part is the Ethernet header (14 bytes).
var EthernetV4Part = [PacketEthernetV4PartSize]byte{
	// [0:6]   Destination MAC - should be specified
	0, 0, 0, 0, 0, 0,
	// [6:12]  Source MAC - should be specified
	0, 0, 0, 0, 0, 0,
	// [12:14] EtherType: 0x0800 (IPv4)
	8, 0,
}

const IPv4PartSize = 20

// IPv4TCPPart is the IPv4 header (20 bytes for a minimal header).
var IPv4TCPPart = [IPv4PartSize]byte{
	// [0:4]   IPv4 TCP Version, IHL, Type of Service, Total Length(should be specified)
	69, 0, 0, 28,
	// [4:6]   Identification
	0, 0,
	// [6:8]   Flags, Fragment Offset
	64, 0,
	// [8:12]  TTL, Protocol (ICMP), Header Checksum
	64, 1, 0, 0,
	// [12:16] Source IP - should be specified
	0, 0, 0, 0,
	// [16:20] Destination IP - should be specified
	255, 0, 0, 0,
}

var IPv4UDPPart = [IPv4PartSize]byte{
	// [0:4]   IPv4UDP Version, IHL, Type of Service, Total Length
	17, 0, 0, 16,
	// [4:6]   Identification
	0, 0,
	// [6:8]   Flags, Fragment Offset
	64, 0,
	// [8:12]  TTL, Protocol (ICMP), Header Checksum
	64, 1, 0, 0,
	// [12:16] Source IP - should be specified
	0, 0, 0, 0,
	// [16:20] Destination IP - should be specified
	255, 0, 0, 0,
}

const IcmpV4PartSize = 26

// IcmpV4Part is the ICMP header plus payload and padding (26 bytes).
var IcmpV4Part = [IcmpV4PartSize]byte{
	// [0:2]   ICMP Type (8 for Echo Request), Code (0)
	8, 0,
	// [2:4]   ICMP Checksum
	71, 58,
	// [4:8]   Identifier and Sequence
	18, 52, 0, 1,
	// [8:12]  Payload ("PING")
	80, 73, 78, 71,
}

// CommonPorts is a list of common service ports.
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
	5060,  // SIP (Session Initiation Protocol)
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

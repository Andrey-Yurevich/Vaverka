package constants

import "time"

const IOVecPacketsChunkSize = 64
const ArpPacketPayloadSize = 42
const IcmpV4PacketPayloadSize = 42
const TcpV4PacketPayloadSize = 54
const UdpV4PacketPayloadSize = 42

const IpV4HeaderStart = 14
const IpHeaderLength = 20
const ChecksumOffset = 24

const SendMmsgSyscallIndex = 269

const MinFrameSize = 60
const BuffersBurstLimit = 4

const ErrorChanBufferSize = 4

const DefaultTimeout = time.Second * 2
const PcapCaptureTimeout = time.Millisecond * 30

var ArpPacketSkeleton = [MinFrameSize]byte{
	// Ethernet header (14 bytes)
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // [0:6]   Destination MAC: FF:FF:FF:FF:FF:FF (broadcast)
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // [6:12]  Source MAC - should be specified
	0x08, 0x06, // [12:14] EtherType: 0x0806 (ARP)

	// ARP header (28 bytes total)
	0x00, 0x01, // [14:16] Hardware Type: 1 (Ethernet)
	0x08, 0x00, // [16:18] Protocol Type: 0x0800 (IPv4)
	0x06,       // [18]    Hardware Address Size: 6 (MAC length)
	0x04,       // [19]    Protocol Address Size: 4 (IPv4 length)
	0x00, 0x01, // [20:22] Operation: 1 (ARP Request)

	// ARP body
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // [22:28] Sender HW address - should be specified
	0x00, 0x00, 0x00, 0x00, // [28:32] Sender IP - should be specified
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // [32:38] Target HW address
	0x00, 0x00, 0x00, 0x00, // [38:42] Target IP - should be specified

	// Padding (to reach the minimum Ethernet frame length of 60 bytes)
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

var PingPacketSkeleton = [MinFrameSize]byte{
	// Ethernet header (14 bytes)
	0, 0, 0, 0, 0, 0, // [0:6]   Destination MAC - should be specified
	0, 0, 0, 0, 0, 0, // [6:12]  Source MAC - should be specified
	8, 0, // [12:14] EtherType: 0x0800 (IPv4)

	// IPv4 header (20 bytes for a minimal header)
	69, 0, 0, 32, // [14:18] IPv4 Version, IHL, Type of Service, Total Length
	0, 0, // [18:20] Identification
	64, 0, // [20:22] Flags, Fragment Offset
	64, 1, 0, 0, // [22:26] TTL, Protocol (ICMP), Header Checksum
	0, 0, 0, 0, // [26:30] Source IP - should be specified
	255, 0, 0, 0, // [30:34] Destination - should be specified

	// ICMP header and payload
	8, 0, // [34:36] ICMP Type (8 for Echo Request), Code (0)
	71, 58, // [36:38] Checksum of ICMP packet
	18, 52, 0, 1, // [38:42] Identifier and Sequence (part of payload)
	80, 73, 78, 71, // [42:46] Payload ("PING")

	// Padding to reach minimum Ethernet frame size (rest of bytes)
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
}

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

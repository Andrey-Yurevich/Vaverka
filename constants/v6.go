package constants

// ICMPv6PacketMaxSize usually the request and reply lenght is 69 bytes, but it's better to increase the value to 128
const ICMPv6PacketMaxSize = 128

// EtherTypeIPv6 indicates IPv6 traffic
const EtherTypeIPv6 uint16 = 0x86DD

const IPv6PseudoHeaderSize = 40
const IPv6HeaderSize = 40

const IPv6NASnapLen = 128

// IPv6Header is a 40-byte fixed IPv6 header
// Indices for dynamic fields:
//
//	Payload Length (4..5), Next Header (6), Hop Limit (7)
//	Source IP (8..23), Destination IP (24..39)
//	Также: Version/Traffic Class/Flow Label (0..3)
var IPv6Header = [IPv6PseudoHeaderSize]byte{
	// [0]     Version(4 bits)=6 (0x6)<<4 | Traffic Class high nibble (0)
	0x60,
	// [1]     Traffic Class low nibble | Flow Label high nibble
	0x00,
	// [2:3]   Flow Label low 16 bits
	0x00, 0x00,
	// [4:5]   Payload Length (TCP header+payload), 0x0014 = 20 bytes
	0x00, 0x00,
	// [6]     Next Header (0x06 = TCP)
	0x00,
	// [7]     Hop Limit (64)
	0x40,
	// [8:23]  Source IPv6 Address
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// [24:39] Destination IPv6 Address
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

// IcmpV6PseudoHeaderSize : SrcIP(16) + DstIP(16) + Upper-Layer Packet Length(4) + Zeros(3) + Next Header(1)
const IcmpV6PseudoHeaderSize = 40

// IcmpV6Size the same as  for IcmpV4
const IcmpV6Size = IcmpV4Size

// TrafficICMPv6 is the protocol number for ICMP for v6
const TrafficICMPv6 = byte(58)

// IcmpV6Header : Type(128), Code(0), Checksum(0), Identifier(0x1234), Sequence(0x0001), Payload "PING"
var IcmpV6Header = [IcmpV6Size]byte{
	0x80, 0x00, // Type=128 (Echo Request), Code=0
	0x00, 0x00, // Checksum (placeholder, must compute)
	0x12, 0x34, // Identifier
	0x00, 0x01, // Sequence
	0x50, 0x49, 0x4E, 0x47, // "PING"
}

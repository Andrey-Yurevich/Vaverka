package constants

// ICMPv6PacketMaxSize usually the request and reply lenght is 69 bytes, but it's better to increase the value to 128
const ICMPv6PacketMaxSize = 128

// EtherTypeIPv6 indicates IPv6 traffic
const EtherTypeIPv6 uint16 = 0x86DD

const IPv6PseudoHeaderSize = 40
const IPv6HeaderSize = 40

const IPv6NASnapLen = 128

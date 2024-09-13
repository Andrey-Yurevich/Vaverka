package main

import (
	"net"
	"testing"
)

var remoteMac = net.HardwareAddr{0x00, 0x50, 0x56, 0x3e, 0x28, 0x78}
var dstAddr = net.IP{10, 0, 1, 20}
var srcPort = uint16(54321)
var dstPort = uint16(80)

func TestRunBenchmark(t *testing.T) {
	runBenchmark(remoteMac, dstAddr, srcPort, dstPort)
}

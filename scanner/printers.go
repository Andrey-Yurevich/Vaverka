package scanner

import (
	"Vaverka/constants"
	"fmt"
	"github.com/gopacket/gopacket/layers"
	"net"
)

// printTCPInfo prints information about an open TCP port in colored JSON.
// "port" key is in red, other keys in blue, and values in green.
func printTCPInfo(srcIP net.IP, port layers.TCPPort, serviceName *string, network net.IPNet) {
	fmt.Printf(
		"{%s\"port\"%s: %s%d%s, %s\"host\"%s: %s\"%s\"%s, %s\"state\"%s: %s\"open\"%s, %s\"type\"%s: %s\"tcp\"%s, %s\"service\"%s: %s\"%s\"%s, %s\"network\"%s: %s\"%s\"%s}\n",
		// "port" key in red
		constants.ColorRed, constants.ColorReset,
		// port value in green
		constants.ColorGreen, port, constants.ColorReset,

		// "host" key in blue
		constants.ColorBlue, constants.ColorReset,
		// host value in green
		constants.ColorGreen, srcIP, constants.ColorReset,

		// "state" key in blue
		constants.ColorBlue, constants.ColorReset,
		// state value in green
		constants.ColorGreen, constants.ColorReset,

		// "type" key in blue
		constants.ColorBlue, constants.ColorReset,
		// type value in green
		constants.ColorGreen, constants.ColorReset,

		// "service" key in blue
		constants.ColorBlue, constants.ColorReset,
		// service value in green
		constants.ColorGreen, *serviceName, constants.ColorReset,

		// "network" key in blue
		constants.ColorBlue, constants.ColorReset,
		// network value in green
		constants.ColorGreen, network.String(), constants.ColorReset,
	)
}

// printUDPInfo prints information about an open UDP port in colored JSON.
// "port" key is in red, other keys in blue, and values in green.
func printUDPInfo(srcIP net.IP, port layers.UDPPort, serviceName *string, network net.IPNet) {
	fmt.Printf(
		"{%s\"port\"%s: %s%d%s, %s\"host\"%s: %s\"%s\"%s, %s\"state\"%s: %s\"open\"%s, %s\"type\"%s: %s\"udp\"%s, %s\"service\"%s: %s\"%s\"%s, %s\"network\"%s: %s\"%s\"%s}\n",
		// "port" key in red
		constants.ColorRed, constants.ColorReset,
		// port value in green
		constants.ColorGreen, port, constants.ColorReset,

		// "host" key in blue
		constants.ColorBlue, constants.ColorReset,
		// host value in green
		constants.ColorGreen, srcIP, constants.ColorReset,

		// "state" key in blue
		constants.ColorBlue, constants.ColorReset,
		// state value in green
		constants.ColorGreen, constants.ColorReset,

		// "type" key in blue
		constants.ColorBlue, constants.ColorReset,
		// type value in green
		constants.ColorGreen, constants.ColorReset,

		// "service" key in blue
		constants.ColorBlue, constants.ColorReset,
		// service value in green
		constants.ColorGreen, *serviceName, constants.ColorReset,

		// "network" key in blue
		constants.ColorBlue, constants.ColorReset,
		// network value in green
		constants.ColorGreen, network.String(), constants.ColorReset,
	)
}

// printARPDiscovery prints host discovery result for ARP in colored JSON.
// All JSON keys (with quotes) are in blue, and all values are in green.
func printARPDiscovery(srcIP net.IP, network net.IPNet) {
	fmt.Printf(
		"{%s\"host\"%s: %s\"%s\"%s, %s\"state\"%s: %s\"up\"%s, %s\"technique\"%s: %s\"arp\"%s, %s\"network\"%s: %s\"%s\"%s}\n",
		// "host" key in blue
		constants.ColorBlue, constants.ColorReset,
		// host value in green
		constants.ColorGreen, srcIP, constants.ColorReset,

		// "state" key in blue
		constants.ColorBlue, constants.ColorReset,
		// state value in green
		constants.ColorGreen, constants.ColorReset,

		// "technique" key in blue
		constants.ColorBlue, constants.ColorReset,
		// technique value in green
		constants.ColorGreen, constants.ColorReset,

		// "network" key in blue
		constants.ColorBlue, constants.ColorReset,
		// network value in green
		constants.ColorGreen, network.String(), constants.ColorReset,
	)
}

// printPingDiscovery prints host discovery result for ping in colored JSON.
// All JSON keys (with quotes) are in blue, and all values are in green.
func printPingDiscovery(srcIP net.IP, network net.IPNet) {
	fmt.Printf(
		"{%s\"host\"%s: %s\"%s\"%s, %s\"state\"%s: %s\"up\"%s, %s\"technique\"%s: %s\"ping4\"%s, %s\"network\"%s: %s\"%s\"%s}\n",
		// "host" key in blue
		constants.ColorBlue, constants.ColorReset,
		// host value in green
		constants.ColorGreen, srcIP, constants.ColorReset,

		// "state" key in blue
		constants.ColorBlue, constants.ColorReset,
		// state value in green
		constants.ColorGreen, constants.ColorReset,

		// "technique" key in blue
		constants.ColorBlue, constants.ColorReset,
		// technique value in green
		constants.ColorGreen, constants.ColorReset,

		// "network" key in blue
		constants.ColorBlue, constants.ColorReset,
		// network value in green
		constants.ColorGreen, network.String(), constants.ColorReset,
	)
}

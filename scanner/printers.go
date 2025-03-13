package scanner

import (
	"Vaverka/constants"
	"fmt"
	"net"
)

const protoTypeUdp = 1
const protoTypeTcp = 2
const protoTypeICMP4 = 3
const protoTypeArp = 4

func printPortInfo(host string, port uint16, serviceName *string, network net.IPNet, protoType int) {
	var protoStr string
	switch protoType {
	case protoTypeUdp:
		protoStr = "udp"
	case protoTypeTcp:
		protoStr = "tcp"
	}

	fmt.Printf(
		"{%s\"port\"%s: %s%d%s, %s\"host\"%s: %s\"%s\"%s, %s\"state\"%s: %s\"open\"%s, %s\"type\"%s: %s\"%s\"%s, %s\"service\"%s: %s\"%s\"%s, %s\"network\"%s: %s\"%s\"%s}\n",
		// "port" key in blue
		constants.ColorBlue, constants.ColorReset,
		// port value in green
		constants.ColorGreen, port, constants.ColorReset,

		// "host" key in blue
		constants.ColorBlue, constants.ColorReset,
		// host value in green
		constants.ColorGreen, host, constants.ColorReset,

		// "state" key in blue
		constants.ColorBlue, constants.ColorReset,
		// state value in green
		constants.ColorGreen, constants.ColorReset,

		// "type" key in blue
		constants.ColorBlue, constants.ColorReset,
		// type value in green
		constants.ColorGreen, protoStr, constants.ColorReset,

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

func printDiscovery(host string, network net.IPNet, techType int) {
	var techniqueStr string
	if techType == protoTypeArp {
		techniqueStr = "arp"
	} else if techType == protoTypeICMP4 {
		techniqueStr = "ping4"
	}

	fmt.Printf(
		"{%s\"host\"%s: %s\"%s\"%s, %s\"state\"%s: %s\"up\"%s, %s\"technique\"%s: %s\"%s\"%s, %s\"network\"%s: %s\"%s\"%s}\n",
		// "host" key in blue
		constants.ColorBlue, constants.ColorReset,
		// host value in green
		constants.ColorGreen, host, constants.ColorReset,

		// "state" key in blue
		constants.ColorBlue, constants.ColorReset,
		// state value in green
		constants.ColorGreen, constants.ColorReset,

		// "technique" key in blue
		constants.ColorBlue, constants.ColorReset,
		// technique value in green
		constants.ColorGreen, techniqueStr, constants.ColorReset,

		// "network" key in blue
		constants.ColorBlue, constants.ColorReset,
		// network value in green
		constants.ColorGreen, network.String(), constants.ColorReset,
	)
}

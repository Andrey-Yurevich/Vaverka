package rule

import (
	"net"
	"time"

	"github.com/Andrey-Yurevich/Vaverka/router"

	"github.com/vishvananda/netlink"
)

type Options struct {
	Timeout                     time.Duration
	Router                      func([]netlink.Route, *net.IPNet, netlink.RouteGetOptions) ([]*router.IpRangeRouteContext, error)
	IpV6MulticastInterfaceIndex int
	Shuffle                     bool
	NoHostDiscovery             bool
	NoIpV6Multicast             bool
	Pps                         uint64
}

// Rule defines a scanning rule. The user can specify only Network, Ports, portsScanTechniques, and options.
type Rule struct {
	FQDN               string
	Network            net.IPNet
	Ports              []uint16
	PortsRanges        []PortsRange
	PortScanTechniques PortsScanTechniques
	Options            Options
}

type PortsScanTechniques struct {
	Syn bool
	Udp bool
	Vav bool
}

type PortsRange struct {
	Start uint16
	End   uint16
}

package rule

import (
	"Vaverka/router"
	"net"
	"time"

	"github.com/vishvananda/netlink"
)

type Options struct {
	Timeout         time.Duration
	Router          func([]netlink.Route, *net.IPNet) ([]*router.IpRangeRouteContext, error)
	Shuffle         bool
	NoHostDiscovery bool
	NoIpV6Multicast bool
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

package router

import (
	"math/rand"
	"net"

	"github.com/Andrey-Yurevich/Vaverka/constants"

	"github.com/vishvananda/netlink"
)

func makeIpRangeRoute(StartIP, EndIP net.IP, route netlink.Route) (*IpRangeRouteContext, error) {
	var r IpRangeRouteContext
	var err error

	r.UpHostsChan = make(chan EthIPPairBytes, constants.UpHostsChanSize)
	r.Start = StartIP
	r.End = EndIP
	r.Route = route
	r.HostDiscoveryDoneChan = make(chan bool)
	r.PortsDiscoveryDoneChan = make(chan bool)
	r.ReadyToInterceptHostsStateChan = make(chan bool)
	r.ReadyToInterceptPortsStateChan = make(chan bool)

	if route.Src.To4() == nil && route.Src.To16() != nil {
		r.SocketParameters, err = getV6SocketParameters(route.LinkIndex)
	} else {
		r.SocketParameters, err = getV4SocketParameters(route.LinkIndex)
	}

	r.SourcePort = uint16(rand.Intn(65535-49152) + 49152)
	return &r, err
}

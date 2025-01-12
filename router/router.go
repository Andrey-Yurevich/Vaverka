package router

import (
	"Vaverka/utils"
	"bytes"
	"fmt"
	"github.com/vishvananda/netlink"
	"net"
	"sort"
	"syscall"
	"unsafe"
)

type SocketParameters struct {
	Parameters           syscall.RawSockaddrLinklayer
	SourceInterface      *net.Interface
	SocketAddressName    *byte
	SocketAddressNameLen uint32
}

type IpRangeRouteContext struct {
	Route                netlink.Route
	Start, End           net.IP
	SocketParameters     SocketParameters
	DoneChan             chan bool
	ReadyToInterceptChan chan bool
}

func GetSocketParameters(sourceInterfaceIndex int) (SocketParameters, error) {
	var p SocketParameters
	var err error

	p.SourceInterface, err = net.InterfaceByIndex(sourceInterfaceIndex)

	if err != nil {
		return p, err
	}

	p.Parameters = syscall.RawSockaddrLinklayer{
		Family:   syscall.AF_PACKET,
		Protocol: utils.Htons(syscall.ETH_P_IP),
		Ifindex:  int32(sourceInterfaceIndex),
	}

	p.SocketAddressName = (*byte)(unsafe.Pointer(&p.Parameters))
	p.SocketAddressNameLen = uint32(unsafe.Sizeof(p.Parameters))

	return p, nil
}

func SimpleRoute(_ []netlink.Route, n *net.IPNet) ([]*IpRangeRouteContext, error) {
	var routeRanges []*IpRangeRouteContext
	var route []netlink.Route
	var routeRange *IpRangeRouteContext
	var err error

	route, err = netlink.RouteGet(n.IP)

	if err != nil {
		return routeRanges, fmt.Errorf("failed to get route for %v: %v", n.IP, err)
	}

	routeRange, err = MakeIpRangeRoute(n.IP, utils.LastIP(n), route[0])

	routeRanges = append(routeRanges, routeRange)
	return routeRanges, nil
}

func MakeIpRangeRoute(StartIP, EndIP net.IP, route netlink.Route) (*IpRangeRouteContext, error) {
	var r IpRangeRouteContext
	var err error
	var doneChan chan bool
	var readyToInterceptChan chan bool
	doneChan = make(chan bool)
	readyToInterceptChan = make(chan bool)
	r.Start = StartIP
	r.End = EndIP
	r.Route = route
	r.DoneChan = doneChan
	r.ReadyToInterceptChan = readyToInterceptChan
	r.SocketParameters, err = GetSocketParameters(route.LinkIndex)

	return &r, err
}

func SmartRoute(routes []netlink.Route, n *net.IPNet) ([]*IpRangeRouteContext, error) {
	var defaultRoute netlink.Route
	var specificRoutes []netlink.Route
	var ranges []*IpRangeRouteContext
	var networkEnd net.IP
	var defaultRouteFound bool

	// Search for the most specific route that fully covers network n.
	var bestRoute *netlink.Route
	for _, route := range routes {
		if route.Dst != nil && utils.ContainsSubnet(route.Dst, n) {
			if bestRoute == nil {
				bestRoute = &route
			} else {
				onesBest, _ := bestRoute.Dst.Mask.Size()
				onesCurrent, _ := route.Dst.Mask.Size()
				if onesCurrent > onesBest {
					bestRoute = &route
				}
			}
		}
	}

	if bestRoute != nil {
		defaultRoute = *bestRoute
		defaultRouteFound = true
	}

	// If no route fully covers network n, fall back to default gateway logic.
	if !defaultRouteFound {
		// Use the default gateway route.
		for _, route := range routes {
			if route.Dst == nil && route.LinkIndex != 0 && route.Src != nil {
				defaultRoute = route
				defaultRouteFound = true
				break
			}
		}

		if !defaultRouteFound {
			return nil, fmt.Errorf("no route found for main network %s", n.IP.String())
		}
	}

	// Regardless of how defaultRoute was found, gather specific routes inside n.
	for _, r := range routes {
		if r.Dst == nil {
			continue
		}
		// Собираем маршруты, которые не совпадают с n, но находятся внутри n.
		if r.Dst.String() != n.String() && n.Contains(r.Dst.IP) {
			specificRoutes = append(specificRoutes, r)
		}
	}

	// Sort specific routes by their starting IP.
	sort.Slice(specificRoutes, func(i, j int) bool {
		return bytes.Compare(specificRoutes[i].Dst.IP, specificRoutes[j].Dst.IP) < 0
	})

	networkEnd = utils.LastIP(n)

	// Initialize ranges with the whole network n using the default route.

	firstRange, err := MakeIpRangeRoute(n.IP, networkEnd, defaultRoute)

	if err != nil {
		return nil, err
	}

	ranges = append(ranges, firstRange)

	// Split the ranges using specific routes.
	for _, spec := range specificRoutes {
		specStart := spec.Dst.IP
		specEnd := utils.LastIP(spec.Dst)
		var newRanges []*IpRangeRouteContext
		var err error
		var rangeToAppend *IpRangeRouteContext
		for _, r := range ranges {

			// If there's no intersection, keep the current range as is.
			if bytes.Compare(r.End, utils.PreviousIP(specStart)) < 0 || bytes.Compare(r.Start, utils.NextIPv4(specEnd)) > 0 {
				newRanges = append(newRanges, r)
			} else {
				// Handle part before the specific route.
				if bytes.Compare(r.Start, specStart) < 0 {

					rangeToAppend, err = MakeIpRangeRoute(r.Start, utils.PreviousIP(specStart), r.Route)

					if err != nil {
						return nil, err
					}

					newRanges = append(newRanges, rangeToAppend)
				}

				// Determine overlapping range.
				overlapStart := r.Start
				if bytes.Compare(specStart, r.Start) > 0 {
					overlapStart = specStart
				}
				overlapEnd := r.End
				if bytes.Compare(specEnd, r.End) < 0 {
					overlapEnd = specEnd
				}
				rangeToAppend, err = MakeIpRangeRoute(overlapStart, overlapEnd, r.Route)

				if err != nil {
					return nil, err
				}

				newRanges = append(newRanges, rangeToAppend)

				// Handle part after the specific route.
				if bytes.Compare(utils.NextIPv4(specEnd), r.End) <= 0 {
					rangeToAppend, err = MakeIpRangeRoute(utils.NextIPv4(specEnd), r.End, r.Route)

					if err != nil {
						return nil, err
					}

					newRanges = append(newRanges, rangeToAppend)
				}
			}
		}
		ranges = newRanges
	}
	return ranges, nil
}

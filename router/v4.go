package router

import (
	"Vaverka/constants"
	"Vaverka/utils"
	"bytes"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"syscall"
	"unsafe"

	"github.com/vishvananda/netlink"
)

func GetV4SocketParameters(sourceInterfaceIndex int) (SocketParameters, error) {
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

func SimpleV4Route(_ []netlink.Route, n *net.IPNet) ([]*IpRangeRouteContext, error) {
	var routeRanges []*IpRangeRouteContext
	var route []netlink.Route
	var routeRange *IpRangeRouteContext
	var err error
	route, err = netlink.RouteGet(n.IP)

	if err != nil {
		return routeRanges, fmt.Errorf("failed to get route for %v: %v", n.IP, err)
	}
	// TODO exclude net address and broadcast address from the range
	routeRange, err = MakeIpv4RangeRoute(n.IP, utils.LastIPv4(n), route[0])

	routeRanges = append(routeRanges, routeRange)
	return routeRanges, nil
}

func MakeIpv4RangeRoute(StartIP, EndIP net.IP, route netlink.Route) (*IpRangeRouteContext, error) {
	var r IpRangeRouteContext
	var err error

	r.UpHostsChan = make(chan UpHostsEthIPChan, constants.UpHostsChanSize)
	r.Start = StartIP
	r.End = EndIP
	r.Route = route
	r.HostDiscoveryDoneChan = make(chan bool)
	r.PortsDiscoveryDoneChan = make(chan bool)
	r.ReadyToInterceptHostsStateChan = make(chan bool)
	r.ReadyToInterceptPortsStateChan = make(chan bool)
	r.SocketParameters, err = GetV4SocketParameters(route.LinkIndex)
	r.SourcePort = uint16(rand.Intn(65535-49152) + 49152)
	return &r, err
}

// SmartV4Route splits a given CIDR (n) into sub-ranges based on the provided routes.
// It applies more specific routes (narrower subnets) inside the main CIDR and uses
// a default or best matching route to cover the rest.
func SmartV4Route(routes []netlink.Route, n *net.IPNet) ([]*IpRangeRouteContext, error) {

	var defaultRoute netlink.Route
	var specificRoutes []netlink.Route
	var ranges []*IpRangeRouteContext
	var networkEnd net.IP
	var defaultRouteFound bool

	// 1. Find the most specific route that fully covers network n.
	var bestRoute *netlink.Route
	for _, route := range routes {
		if route.Dst != nil && utils.ContainsSubnetV4(route.Dst, n) {
			if bestRoute == nil {
				bestRoute = &route
			} else {

				if bestRoute.Dst == nil || route.Dst == nil {
					continue
				}

				bestOnes, _ := bestRoute.Dst.Mask.Size()
				currentOnes, _ := route.Dst.Mask.Size()
				if currentOnes > bestOnes {
					bestRoute = &route
				}
			}
		}
	}

	// 2. If bestRoute is found, use it as the defaultRoute.
	if bestRoute != nil {
		defaultRoute = *bestRoute
		defaultRouteFound = true
	}

	// 3. If no covering route was found, fall back to a default gateway route.
	if !defaultRouteFound {
		for _, route := range routes {
			// A "default route" in Linux netlink often has route.Dst == nil
			// and a valid LinkIndex with a non-nil Src.
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

	// 4. Gather "specific routes" that lie fully inside n but are not exactly equal to n.
	for _, r := range routes {
		if r.Dst == nil {
			continue
		}
		if r.Dst.String() != n.String() && n.Contains(r.Dst.IP) {
			specificRoutes = append(specificRoutes, r)
		}
	}

	// Sort these specific routes by starting IP.
	sort.Slice(specificRoutes, func(i, j int) bool {
		return bytes.Compare(specificRoutes[i].Dst.IP, specificRoutes[j].Dst.IP) < 0
	})

	// Last IP of the main CIDR.
	networkEnd = utils.LastIPv4(n)

	// 5. Initialize the ranges with the entire CIDR covered by defaultRoute.
	firstRange, err := MakeIpv4RangeRoute(n.IP, networkEnd, defaultRoute)
	if err != nil {
		return nil, err
	}
	ranges = append(ranges, firstRange)

	// 6. Refine (split) ranges using each specific route.
	for _, spec := range specificRoutes {
		specStart := spec.Dst.IP
		specEnd := utils.LastIPv4(spec.Dst)

		var newRanges []*IpRangeRouteContext

		for _, r := range ranges {
			// If the current range does not intersect with spec, keep it as is.
			if bytes.Compare(r.End, utils.PreviousIPv4(specStart)) < 0 ||
				bytes.Compare(r.Start, utils.NextIPv4(specEnd)) > 0 {
				newRanges = append(newRanges, r)
				continue
			}

			// Otherwise, we need to split r into up to three parts:
			//   1) The portion before spec,
			//   2) The overlapping portion (which uses 'spec'),
			//   3) The portion after spec.

			// ---- 1) Before the specific route ----
			// We only create "before" part if r.Start < specStart.
			beforeEnd := utils.PreviousIPv4(specStart)
			if bytes.Compare(r.Start, specStart) < 0 &&
				bytes.Compare(r.Start, beforeEnd) <= 0 {
				beforeRange, err := MakeIpv4RangeRoute(r.Start, beforeEnd, r.Route)
				if err != nil {
					return nil, err
				}
				// Only append if it does not invert boundaries.
				if bytes.Compare(beforeRange.Start, beforeRange.End) <= 0 {
					newRanges = append(newRanges, beforeRange)
				}
			}

			// ---- 2) Overlapping portion ----
			// Overlap is from max(r.Start, specStart) to min(r.End, specEnd).
			overlapStart := utils.MaxIP(r.Start, specStart)
			overlapEnd := utils.MinIP(r.End, specEnd)
			if bytes.Compare(overlapStart, overlapEnd) <= 0 {
				// Use the specific route here to reflect that spec is more specific.
				overlapRange, err := MakeIpv4RangeRoute(overlapStart, overlapEnd, spec)
				if err != nil {
					return nil, err
				}
				newRanges = append(newRanges, overlapRange)
			}

			// ---- 3) After the specific route ----
			afterStart := utils.NextIPv4(specEnd)
			if bytes.Compare(afterStart, r.End) <= 0 {
				afterRange, err := MakeIpv4RangeRoute(afterStart, r.End, r.Route)
				if err != nil {
					return nil, err
				}
				// Only append if it does not invert boundaries.
				if bytes.Compare(afterRange.Start, afterRange.End) <= 0 {
					newRanges = append(newRanges, afterRange)
				}
			}
		}

		// Replace old ranges with newRanges after processing the current spec.
		ranges = newRanges
	}
	// Post-process ranges to clean up invalid or unnecessary entries.

	for _, iprange := range ranges {

		if iprange.Start.Equal(iprange.End) {

			// проверяем является ли диапазон простой записью об одном хосте(маска 32)
			if utils.IsSingleV4HostMask(iprange.Route.Dst.Mask) {
				iprange.End = nil
				continue
			}

			// удаляем диапозоны которые не имеют ни одного хостового адреса
			if utils.IsV4NetworkAddress(iprange.Start, routes) {
				iprange.Start = nil
				iprange.End = nil
				continue
			}
		}

		// проверяем является ли конечный адрес broadcast адресом
		if utils.IsV4BroadcastAddress(iprange.End, routes) && iprange.End[3] < 255 {

			// уменьшаем конечный адрес
			iprange.End = utils.PreviousIPv4(iprange.End)

			// проверяем сравнялись ли адреса
			if iprange.Start.Equal(iprange.End) {
				iprange.End = nil
				continue
			}
		}

		// проверяем сетевой ли это адрес
		if utils.IsV4NetworkAddress(iprange.Start, routes) && iprange.Start[3] < 255 {

			// увеличиваем адрес что бы исключить нехостовую часть
			iprange.Start = utils.NextIPv4(iprange.Start)

			// проверяем не сравнялся ли начальный адрес с конечным
			if iprange.Start.Equal(iprange.End) {
				iprange.End = nil
			}

		}

	}

	return ranges, nil
}

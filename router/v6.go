package router

import (
	"Vaverka/utils"
	"bytes"
	"fmt"
	"net"
	"sort"
	"syscall"
	"unsafe"

	"github.com/vishvananda/netlink"
)

func GetV6SocketParameters(sourceInterfaceIndex int) (SocketParameters, error) {
	var p SocketParameters
	var err error

	p.SourceInterface, err = net.InterfaceByIndex(sourceInterfaceIndex)

	if err != nil {
		return p, err
	}

	p.Parameters = syscall.RawSockaddrLinklayer{
		Family:   syscall.AF_PACKET,
		Protocol: utils.Htons(syscall.ETH_P_IPV6),
		Ifindex:  int32(sourceInterfaceIndex),
	}

	p.SocketAddressName = (*byte)(unsafe.Pointer(&p.Parameters))
	p.SocketAddressNameLen = uint32(unsafe.Sizeof(p.Parameters))

	return p, nil
}

func SimpleV6Route(_ []netlink.Route, n *net.IPNet) ([]*IpRangeRouteContext, error) {
	var routeRanges []*IpRangeRouteContext
	var route []netlink.Route
	var routeRange *IpRangeRouteContext
	var err error
	route, err = netlink.RouteGet(n.IP)

	if err != nil {
		return routeRanges, fmt.Errorf("failed to get route for %v: %v", n.IP, err)
	}
	// TODO exclude net address and broadcast address from the range
	routeRange, err = MakeIpRangeRoute(n.IP, utils.LastIPv6(n), route[0])

	routeRanges = append(routeRanges, routeRange)
	return routeRanges, nil
}

// SmartV6Route splits the given IPv6 CIDR (n) into IP-ranges,
// assigning the “best” route to each range.
// The logic mirrors SmartV4Route 1-for-1, minus IPv4-specific details.
func SmartV6Route(routes []netlink.Route, n *net.IPNet) ([]*IpRangeRouteContext, error) {

	var (
		defaultRoute      netlink.Route
		specificRoutes    []netlink.Route
		ranges            []*IpRangeRouteContext
		networkEnd        net.IP
		defaultRouteFound bool
	)

	// 1. Find the narrowest route that fully covers n.
	var bestRoute *netlink.Route
	for _, route := range routes {
		if route.Dst != nil && utils.ContainsSubnetV6(route.Dst, n) {
			if bestRoute == nil {
				bestRoute = &route
			} else {
				bestOnes, _ := bestRoute.Dst.Mask.Size()
				currOnes, _ := route.Dst.Mask.Size()
				if currOnes > bestOnes {
					bestRoute = &route
				}
			}
		}
	}

	// 2. If found, use it as the defaultRoute.
	if bestRoute != nil {
		defaultRoute = *bestRoute
		defaultRouteFound = true
	}

	// 3. Otherwise fall back to the system default (Dst == nil).
	if !defaultRouteFound {
		for _, route := range routes {
			if route.Dst == nil && route.LinkIndex != 0 {
				defaultRoute = route
				defaultRouteFound = true
				break
			}
		}
		if !defaultRouteFound {
			return nil, fmt.Errorf("no route found for main network %s", n)
		}
	}

	// 4. Collect more-specific routes completely inside n.
	for _, r := range routes {
		if r.Dst == nil {
			continue
		}
		if r.Dst.String() != n.String() && n.Contains(r.Dst.IP) {
			specificRoutes = append(specificRoutes, r)
		}
	}

	// Sort them by starting IP (ascending).
	sort.Slice(specificRoutes, func(i, j int) bool {
		return bytes.Compare(specificRoutes[i].Dst.IP, specificRoutes[j].Dst.IP) < 0
	})

	// 5. Seed ranges with the full network served by defaultRoute.
	networkEnd = utils.LastIPv6(n)
	firstRange, err := MakeIpRangeRoute(n.IP, networkEnd, defaultRoute)
	if err != nil {
		return nil, err
	}
	ranges = append(ranges, firstRange)

	// 6. Refine (split) ranges using each specific route in turn.
	for _, spec := range specificRoutes {
		specStart := spec.Dst.IP
		specEnd := utils.LastIPv6(spec.Dst)

		var newRanges []*IpRangeRouteContext
		for _, r := range ranges {
			// No overlap — keep the range as-is.
			if bytes.Compare(r.End, utils.PreviousIPv6(specStart)) < 0 ||
				bytes.Compare(r.Start, utils.NextIPv6(specEnd)) > 0 {
				newRanges = append(newRanges, r)
				continue
			}

			// 1) Part before the specific route
			beforeEnd := utils.PreviousIPv6(specStart)
			if bytes.Compare(r.Start, specStart) < 0 &&
				bytes.Compare(r.Start, beforeEnd) <= 0 {
				br, err := MakeIpRangeRoute(r.Start, beforeEnd, r.Route)
				if err != nil {
					return nil, err
				}
				newRanges = append(newRanges, br)
			}

			// 2) Overlapping part
			overlapStart := utils.MaxIP(r.Start, specStart)
			overlapEnd := utils.MinIP(r.End, specEnd)
			if bytes.Compare(overlapStart, overlapEnd) <= 0 {
				or, err := MakeIpRangeRoute(overlapStart, overlapEnd, spec)
				if err != nil {
					return nil, err
				}
				newRanges = append(newRanges, or)
			}

			// 3) Part after the specific route
			afterStart := utils.NextIPv6(specEnd)
			if bytes.Compare(afterStart, r.End) <= 0 {
				ar, err := MakeIpRangeRoute(afterStart, r.End, r.Route)
				if err != nil {
					return nil, err
				}
				newRanges = append(newRanges, ar)
			}
		}
		ranges = newRanges
	}

	// Minimal post-processing: if Start == End, treat as a single host.
	for _, ipr := range ranges {
		if ipr.Start.Equal(ipr.End) {
			ipr.End = nil
		}
	}

	return ranges, nil
}

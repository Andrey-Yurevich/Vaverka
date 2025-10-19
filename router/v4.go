package router

import (
	"bytes"
	"fmt"
	"net"
	"sort"
	"syscall"
	"unsafe"

	"github.com/Andrey-Yurevich/Vaverka/utils"

	"github.com/vishvananda/netlink"
)

func getV4SocketParameters(sourceInterfaceIndex int) (SocketParameters, error) {
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
	routeRange, err = makeIpRangeRoute(n.IP, utils.LastIPv4(n), route[0])

	routeRanges = append(routeRanges, routeRange)
	return routeRanges, nil
}

// SmartV4Route splits a given CIDR (n) into sub-ranges based on the provided routes.
// It applies more specific routes (narrower subnets) inside the main CIDR and uses
// a default or best matching route to cover the rest. If the chosen route has no
// Src, the function derives Src from the outgoing interface (like the kernel does).
func SmartV4Route(routes []netlink.Route, n *net.IPNet) ([]*IpRangeRouteContext, error) {
	var (
		defaultRoute      netlink.Route
		defaultRouteFound bool
		specificRoutes    []netlink.Route
		ranges            []*IpRangeRouteContext
	)

	// Small helper: fill r.Src from interface addresses without querying the kernel.
	// Preference order:
	// 1) address on-link with r.Gw;
	// 2) address whose IPNet contains r.Dst.IP (for connected routes);
	// 3) first IPv4 address of the interface.
	pickSrc := func(r *netlink.Route) error {
		if r.Src != nil && r.Src.To4() != nil {
			return nil
		}
		if r.LinkIndex == 0 {
			return fmt.Errorf("no route to host (no link index)")
		}
		link, err := netlink.LinkByIndex(r.LinkIndex)
		if err != nil {
			return fmt.Errorf("no route to host (%w)", err)
		}
		if link.Attrs().Flags&net.FlagUp == 0 {
			return fmt.Errorf("no route to host (link down)")
		}
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			return fmt.Errorf("no route to host (%w)", err)
		}
		if len(addrs) == 0 {
			return fmt.Errorf("no route to host (no IPv4 on link)")
		}
		// Prefer address that is on-link with the gateway.
		if r.Gw != nil {
			for _, a := range addrs {
				if a.IPNet != nil && a.IPNet.Contains(r.Gw) {
					r.Src = a.IP
					return nil
				}
			}
		}
		// Prefer address that matches the destination subnet (connected route).
		if r.Dst != nil {
			for _, a := range addrs {
				if a.IPNet != nil && a.IPNet.Contains(r.Dst.IP) {
					r.Src = a.IP
					return nil
				}
			}
		}
		// Fallback: first IPv4 address on the interface.
		r.Src = addrs[0].IP
		return nil
	}

	// 1) Find the most specific route that fully covers network n.
	var bestRoute *netlink.Route
	for i := range routes {
		r := &routes[i]
		if r.Dst != nil && utils.ContainsSubnetV4(r.Dst, n) {
			if bestRoute == nil {
				bestRoute = r
				continue
			}
			bestOnes, _ := bestRoute.Dst.Mask.Size()
			currentOnes, _ := r.Dst.Mask.Size()
			if currentOnes > bestOnes {
				bestRoute = r
			}
		}
	}

	// 2) Use the best covering route as default if found.
	if bestRoute != nil {
		defaultRoute = *bestRoute
		defaultRouteFound = true
	}

	// 3) Otherwise, pick a system default route (Dst == nil or 0.0.0.0/0).
	if !defaultRouteFound {
		for i := range routes {
			r := routes[i]
			if r.Dst == nil {
				defaultRoute = r
				defaultRouteFound = true
				break
			}
			if r.Dst != nil && r.Dst.IP.IsUnspecified() {
				ones, bits := r.Dst.Mask.Size()
				if ones == 0 && bits == 32 {
					defaultRoute = r
					defaultRouteFound = true
					break
				}
			}
		}
		if !defaultRouteFound {
			return nil, fmt.Errorf("no route to host for %s (no default and no covering route)", n.String())
		}
	}

	// 4) Ensure the chosen defaultRoute has a valid Src.
	if err := pickSrc(&defaultRoute); err != nil {
		return nil, fmt.Errorf("no route to host for %s: %w", n.String(), err)
	}

	// 5) Collect specific routes that lie fully inside n (excluding n itself),
	//    and ensure each has Src; skip those that cannot produce a Src.
	for i := range routes {
		r := routes[i]
		if r.Dst == nil {
			continue
		}
		if r.Dst.String() != n.String() && n.Contains(r.Dst.IP) {
			if err := pickSrc(&r); err != nil {
				// Skip unusable route (treat as no-path for that subrange).
				continue
			}
			specificRoutes = append(specificRoutes, r)
		}
	}

	// Sort specific routes by starting IP (ascending).
	sort.Slice(specificRoutes, func(i, j int) bool {
		return bytes.Compare(specificRoutes[i].Dst.IP, specificRoutes[j].Dst.IP) < 0
	})

	// 6) Seed ranges with the entire CIDR covered by defaultRoute.
	networkEnd := utils.LastIPv4(n)
	firstRange, err := makeIpRangeRoute(n.IP, networkEnd, defaultRoute)
	if err != nil {
		return nil, err
	}
	ranges = append(ranges, firstRange)

	// 7) Refine ranges using each specific route.
	for _, spec := range specificRoutes {
		specStart := spec.Dst.IP
		specEnd := utils.LastIPv4(spec.Dst)

		var newRanges []*IpRangeRouteContext
		for _, r := range ranges {
			// If no intersection, keep the range as-is.
			if bytes.Compare(r.End, utils.PreviousIPv4(specStart)) < 0 ||
				bytes.Compare(r.Start, utils.NextIPv4(specEnd)) > 0 {
				newRanges = append(newRanges, r)
				continue
			}

			// Split into up to three parts: before, overlap (uses spec), after.

			// 1) Before
			beforeEnd := utils.PreviousIPv4(specStart)
			if bytes.Compare(r.Start, specStart) < 0 &&
				bytes.Compare(r.Start, beforeEnd) <= 0 {
				beforeRange, err := makeIpRangeRoute(r.Start, beforeEnd, r.Route)
				if err != nil {
					return nil, err
				}
				if bytes.Compare(beforeRange.Start, beforeRange.End) <= 0 {
					newRanges = append(newRanges, beforeRange)
				}
			}

			// 2) Overlap (use spec route)
			overlapStart := utils.MaxIP(r.Start, specStart)
			overlapEnd := utils.MinIP(r.End, specEnd)
			if bytes.Compare(overlapStart, overlapEnd) <= 0 {
				overlapRange, err := makeIpRangeRoute(overlapStart, overlapEnd, spec)
				if err != nil {
					return nil, err
				}
				newRanges = append(newRanges, overlapRange)
			}

			// 3) After
			afterStart := utils.NextIPv4(specEnd)
			if bytes.Compare(afterStart, r.End) <= 0 {
				afterRange, err := makeIpRangeRoute(afterStart, r.End, r.Route)
				if err != nil {
					return nil, err
				}
				if bytes.Compare(afterRange.Start, afterRange.End) <= 0 {
					newRanges = append(newRanges, afterRange)
				}
			}
		}
		ranges = newRanges
	}

	// 8) Post-process: sanitize singletons, network/broadcast edges.
	for _, iprange := range ranges {
		if iprange.Start.Equal(iprange.End) {
			if utils.IsSingleV4HostMask(iprange.Route.Dst.Mask) {
				iprange.End = nil
				continue
			}
			if utils.IsV4NetworkAddress(iprange.Start, routes) {
				iprange.Start = nil
				iprange.End = nil
				continue
			}
		}
		if utils.IsV4BroadcastAddress(iprange.End, routes) && iprange.End[3] < 255 {
			iprange.End = utils.PreviousIPv4(iprange.End)
			if iprange.Start.Equal(iprange.End) {
				iprange.End = nil
				continue
			}
		}
		if utils.IsV4NetworkAddress(iprange.Start, routes) && iprange.Start[3] < 255 {
			iprange.Start = utils.NextIPv4(iprange.Start)
			if iprange.Start.Equal(iprange.End) {
				iprange.End = nil
			}
		}
	}

	return ranges, nil
}

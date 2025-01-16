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

// SmartRoute splits a given CIDR (n) into sub-ranges based on the provided routes.
// It applies more specific routes (narrower subnets) inside the main CIDR and uses
// a default or best matching route to cover the rest.
func SmartRoute(routes []netlink.Route, n *net.IPNet) ([]*IpRangeRouteContext, error) {
	var defaultRoute netlink.Route
	var specificRoutes []netlink.Route
	var ranges []*IpRangeRouteContext
	var networkEnd net.IP
	var defaultRouteFound bool

	// 1. Find the most specific route that fully covers network n.
	var bestRoute *netlink.Route
	for _, route := range routes {
		if route.Dst != nil && utils.ContainsSubnet(route.Dst, n) {
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
	networkEnd = utils.LastIP(n)

	// 5. Initialize the ranges with the entire CIDR covered by defaultRoute.
	firstRange, err := MakeIpRangeRoute(n.IP, networkEnd, defaultRoute)
	if err != nil {
		return nil, err
	}
	ranges = append(ranges, firstRange)

	// 6. Refine (split) ranges using each specific route.
	for _, spec := range specificRoutes {
		specStart := spec.Dst.IP
		specEnd := utils.LastIP(spec.Dst)

		var newRanges []*IpRangeRouteContext

		for _, r := range ranges {
			// If the current range does not intersect with spec, keep it as is.
			if bytes.Compare(r.End, utils.PreviousIP(specStart)) < 0 ||
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
			beforeEnd := utils.PreviousIP(specStart)
			if bytes.Compare(r.Start, specStart) < 0 &&
				bytes.Compare(r.Start, beforeEnd) <= 0 {
				beforeRange, err := MakeIpRangeRoute(r.Start, beforeEnd, r.Route)
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
				overlapRange, err := MakeIpRangeRoute(overlapStart, overlapEnd, spec)
				if err != nil {
					return nil, err
				}
				newRanges = append(newRanges, overlapRange)
			}

			// ---- 3) After the specific route ----
			afterStart := utils.NextIPv4(specEnd)
			if bytes.Compare(afterStart, r.End) <= 0 {
				afterRange, err := MakeIpRangeRoute(afterStart, r.End, r.Route)
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

	return ranges, nil
}

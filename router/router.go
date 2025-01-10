package router

import (
	"Vaverka/utils"
	"bytes"
	"fmt"
	"github.com/vishvananda/netlink"
	"net"
	"sort"
)

type IpRangeRoute struct {
	Route      netlink.Route
	start, end net.IP
}

func SplitNetworkToRouteRanges(routes []netlink.Route, n *net.IPNet) ([]IpRangeRoute, error) {
	var defaultRoute netlink.Route

	var specificRoutes []netlink.Route
	var ranges []IpRangeRoute
	var networkEnd net.IP
	var defaultRouteFound bool

	//Searching for a route which exactly matches destination network
	for _, route := range routes {
		if route.Dst != nil && route.Dst.String() == n.String() {
			defaultRoute = route
			defaultRouteFound = true
			break
		}
	}

	if !defaultRouteFound { // using default gateway
		for _, route := range routes {
			if route.Dst == nil && route.LinkIndex != 0 && route.Src != nil {
				defaultRoute = route
				defaultRouteFound = true
				break
			}
		}

		if !defaultRouteFound {
			return nil, fmt.Errorf("no route to host")
		}

		for _, r := range routes {
			if r.Dst == nil {
				continue
			}
			if r.Dst.String() != n.String() && n.Contains(r.Dst.IP) {
				specificRoutes = append(specificRoutes, r)
			}
		}
	}

	sort.Slice(specificRoutes, func(i, j int) bool {
		return bytes.Compare(specificRoutes[i].Dst.IP, specificRoutes[j].Dst.IP) < 0
	})

	networkEnd = utils.LastIP(n)

	ranges = []IpRangeRoute{
		{start: n.IP, end: networkEnd, Route: defaultRoute},
	}

	for _, spec := range specificRoutes {
		var specStart = spec.Dst.IP
		var specEnd = utils.LastIP(spec.Dst)
		var newRanges []IpRangeRoute

		for _, r := range ranges {

			if bytes.Compare(r.end, utils.PreviousIP(specStart)) < 0 || bytes.Compare(r.start, utils.NextIPv4(specEnd)) > 0 {

				newRanges = append(newRanges, r)
			} else {

				if bytes.Compare(r.start, specStart) < 0 {
					newRanges = append(newRanges, IpRangeRoute{
						start: r.start,
						end:   utils.PreviousIP(specStart),
						Route: r.Route,
					})
				}

				overlapStart := r.start
				if bytes.Compare(specStart, r.start) > 0 {
					overlapStart = specStart
				}
				overlapEnd := r.end
				if bytes.Compare(specEnd, r.end) < 0 {
					overlapEnd = specEnd
				}
				newRanges = append(newRanges, IpRangeRoute{
					start: overlapStart,
					end:   overlapEnd,
					Route: spec,
				})

				if bytes.Compare(utils.NextIPv4(specEnd), r.end) <= 0 {
					newRanges = append(newRanges, IpRangeRoute{
						start: utils.NextIPv4(specEnd),
						end:   r.end,
						Route: r.Route,
					})
				}
			}
		}
		ranges = newRanges
	}
	return ranges, nil
}

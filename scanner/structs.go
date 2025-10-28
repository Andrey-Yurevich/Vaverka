package scanner

import (
	"net"
	"syscall"

	"github.com/Andrey-Yurevich/Vaverka/constants"
	"github.com/Andrey-Yurevich/Vaverka/router"
	"github.com/Andrey-Yurevich/Vaverka/rule"
	"golang.org/x/time/rate"

	"github.com/vishvananda/netlink"
)

// mmsghdr is a wrapper for syscall.mmsghdr used with sendmmsg.
type mmsghdr struct {
	Msg syscall.Msghdr
	Len uint32
	_   [4]byte
}

// Stream represents a unified output stream for scan results.
// It hides internal channels and provides a simple interface:
//   - Findings: a single channel for all discoveries (hosts, ports, etc.)
//   - Wait(): blocks until all scanning goroutines finish, and returns the first error (if any)
type Stream struct {
	Findings <-chan ScanFinding
	Wait     func() error
}

// scannerContext holds overall state for scanning, including error channels,
// routes, and a raw socket descriptor.
type scannerContext struct {
	errorChan      chan error
	findingsChan   chan ScanFinding
	IpRanges       []*router.IpRangeRouteContext
	routeTables    []netlink.Route
	socketFD       uintptr
	rule           *rule.Rule
	ports          []uint16
	defaultGateway net.IP
	localLimiter   *rate.Limiter
}

const protoStringIcmpv4 = "icmp"
const protoStringIcmpv6 = "icmp6"
const protoStringArp = "arp"

const frameSizeArp = constants.MinFrameSize
const frameSizeIcmpv4 = constants.MinFrameSize
const frameSizeIcmpv6 = 128

const techniqueNameIcmp4 = "icmp4"
const techniqueNameIcmp6 = "icmp6"
const techniqueNameArp = "arp"
const techniqueNameIcmp6Multicast = "icmp6+multicast"

type hostDiscoveryInterceptorHints struct {
	protoString        string
	frameSize          int32
	printMac           bool
	printTechniqueName string
}

// ScanFinding Interface for both findings: port and host
type ScanFinding interface{}

type Host struct {
	IP        net.IP
	Network   net.IPNet
	Mac       net.HardwareAddr
	FQDN      string
	State     string
	Technique string
}

type Port struct {
	Host     net.IP
	Service  string
	State    string
	Protocol string
	Port     uint16
}

package scanner

import (
	"Vaverka/router"
	"Vaverka/rule"
	"net"
	"syscall"

	"github.com/vishvananda/netlink"
)

// mmsghdr is a wrapper for syscall.mmsghdr used with sendmmsg.
type mmsghdr struct {
	Msg syscall.Msghdr
	Len uint32
	_   [4]byte
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
}

// ScanFinding Interface for both findings: port and host
type ScanFinding interface{}

type Host struct {
	IP        net.IP           `json:"ip"`
	Network   net.IPNet        `json:"network"`
	Mac       net.HardwareAddr `json:"mac"`
	FQDN      string           `json:"fqdn"`
	State     string           `json:"state"`
	Technique string           `json:"technique"`
}

type Port struct {
	Host     net.IP `json:"host"`
	Service  string `json:"service"`
	State    string `json:"state"`
	Protocol string `json:"protocol"`
	Port     uint16 `json:"port"`
}

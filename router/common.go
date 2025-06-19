package router

import (
	"net"
	"syscall"

	"github.com/vishvananda/netlink"
)

// EthIPPairBytes is used for linking MAC and IP addresses together.
type EthIPPairBytes struct {
	Eth []byte
	Ip  []byte
}

type SocketParameters struct {
	Parameters           syscall.RawSockaddrLinklayer
	SourceInterface      *net.Interface
	SocketAddressName    *byte
	SocketAddressNameLen uint32
}

type IpRangeRouteContext struct {
	Start, End                     net.IP
	Route                          netlink.Route
	SocketParameters               SocketParameters
	SourcePort                     uint16
	HostDiscoveryDoneChan          chan bool
	PortsDiscoveryDoneChan         chan bool
	ReadyToInterceptHostsStateChan chan bool
	ReadyToInterceptPortsStateChan chan bool
	UpHostsChan                    chan EthIPPairBytes
}

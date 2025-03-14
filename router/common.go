package router

import (
	"github.com/vishvananda/netlink"
	"net"
	"syscall"
)

type UpHostsEthIPChan struct {
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
	UpHostsChan                    chan UpHostsEthIPChan
}

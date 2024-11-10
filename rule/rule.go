package rule

import (
	"Vaverka/utils"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

type extraOptions struct {
	Pps int
}

type PortScanTechniques struct {
	syn bool
	fin bool
	udp bool
}

type HostStateDetection struct {
	ping bool
	arp  bool
	snmp bool
	top  bool
}

type Rule struct {
	Network            net.IPNet
	SockFD             int
	Ports              []uint16
	HostStateDetection HostStateDetection
	PortScanTechniques PortScanTechniques
	IOVecs             chan []syscall.Iovec
	Packets            chan []byte
	ExtraOptions       extraOptions
}

func parseHostStateDetection(s string) (HostStateDetection, error) {
	var H HostStateDetection
	for _, char := range s {
		switch char {
		case 'p':
			H.ping = true
		case 'a':
			H.arp = true
		case 's':
			H.snmp = true
		case 't':
			H.top = true
		default:
			return HostStateDetection{}, fmt.Errorf("unknown Host state dedection type: %c", char)
		}
	}
	return H, nil
}

func parsePortScanTechniques(s string) (PortScanTechniques, error) {
	var P PortScanTechniques
	for _, char := range s {
		switch char {
		case 's':
			P.syn = true
		case 'f':
			P.fin = true
		case 'u':
			P.udp = true
		default:
			return PortScanTechniques{}, fmt.Errorf("unknown Host state dedection type: %c", char)
		}
	}
	return P, nil
}

func parseAddress(s string) (net.IPNet, error) {
	var address net.IP
	var network *net.IPNet
	var err error
	var addresses []net.IP

	if utils.IsValidDomain(s) {
		addresses, err = net.LookupIP(s)
		if err != nil {
			return net.IPNet{}, errors.New("unable to resolve domain name")
		}
		return utils.IPtoIPNet(addresses[0]), nil
	}

	address = net.ParseIP(s)

	if address != nil {
		return utils.IPtoIPNet(address), nil
	}

	address, network, err = net.ParseCIDR(s)
	if err == nil {
		return *network, nil
	}
	return net.IPNet{},
		fmt.Errorf("\"%s\" is not a valid IPv4 address or CIDR, nor an IPv6 address or CIDR, nor a valid FQDN", s)
}

func parsePortsRange(s string) ([]uint16, error) {
	var start int
	var end int
	var err error
	var portsRange []uint16
	var startPortString string
	var endPortString string
	portsRange = make([]uint16, 0)

	if strings.Count(s, "-") > 1 {
		return nil, fmt.Errorf("ports range must contain only one \"-\"")
	}
	startPortString = strings.Split(s, "-")[0]
	endPortString = strings.Split(s, "-")[1]

	start, err = strconv.Atoi(startPortString)

	if err != nil {
		return nil, fmt.Errorf("start port %s is not a digit", startPortString)
	}

	end, err = strconv.Atoi(endPortString)

	if err != nil {
		return nil, fmt.Errorf("end port %s is not a digit", endPortString)
	}

	if start <= 0 || end <= 0 || start > 65535 || end > 65535 || start > end {
		return nil, fmt.Errorf("%s is not valid ports range", s)
	}

	for i := start; i < end; i++ {
		portsRange = append(portsRange, uint16(i))
	}

	return portsRange, nil
}

func parseExtraOptions(s string) (extraOptions, error) {
	var E extraOptions
	for _, parameter := range strings.Split(s, ",") {
		parameterSplitted := strings.Split(parameter, "=")
		switch parameterSplitted[0] {
		case "pps":
			pps, err := strconv.Atoi(parameterSplitted[0])
			if err != nil {
				E.Pps = pps
			}
		default:
			return extraOptions{}, fmt.Errorf("unknown parameter \"%s\"", parameterSplitted[0])
		}
	}
	return E, nil
}

func parsePorts(s string) ([]uint16, error) {
	var portsList []uint16
	var err error
	var port int
	portsList = make([]uint16, 0)

	for _, portDefinition := range strings.Split(s, ",") {
		if strings.Contains(portDefinition, "-") {

			portsList, err = parsePortsRange(portDefinition)

			if err != nil {
				return nil, err
			}

		}
		port, err = strconv.Atoi(portDefinition)

		if err != nil {
			return nil, err
		}

		if port > 65535 {
			return nil, fmt.Errorf("port number %d is higher then 65535", port)
		}
		portsList = append(portsList, uint16(port))

	}
	portsList = slices.Compact(portsList)
	return portsList, nil
}

// NewRule rule structure: <address>:<ports>:<scan technique>:<options>
// simple rule example: 192.168.1.1:80
// another example: example.com:80
// full rule example. It will start scanning 80,443 ports plus ports in range from 1000 to 2000 for all hosts in range of 192.168.1.100-255. host detection type is "ping". scan technique is Syn scan: 192.168.1.100/24:80,443,1000-2000:p:s:pps=1000000
func NewRule(s string) (Rule, error) {
	var R Rule
	var RuleList []string
	var err error
	var address net.IPNet
	var portsList []uint16
	var hostStateDetectionList HostStateDetection
	var portScanTechniquesList PortScanTechniques
	var extraOptionsList extraOptions
	var ruleLen int

	RuleList = strings.Split(s, ":")

	ruleLen = len(RuleList)

	address, err = parseAddress(RuleList[0])
	if err != nil {
		return Rule{}, err
	}
	R.Network = address

	if ruleLen > 1 {
		portsList, err = parsePorts(RuleList[1])
		if err != nil {
			return Rule{}, err
		}
		R.Ports = portsList
	}

	if ruleLen > 2 {
		hostStateDetectionList, err = parseHostStateDetection(RuleList[2])
		if err != nil {
			return Rule{}, err
		}
		R.HostStateDetection = hostStateDetectionList
	}

	if ruleLen > 3 {
		portScanTechniquesList, err = parsePortScanTechniques(RuleList[3])
		if err != nil {
			return Rule{}, err
		}
		R.PortScanTechniques = portScanTechniquesList
	}

	if ruleLen > 4 {
		extraOptionsList, err = parseExtraOptions(RuleList[4])

		if err != nil {
			return Rule{}, err
		}
		R.ExtraOptions = extraOptionsList

	}
	return R, nil
}

package rule

import (
	"Vaverka/utils"
	"errors"
	"fmt"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

const (
	minPacketsToUseIOVEC    = 64
	maxIovecsBuffersPerRule = 1024
	maxPacketsBufferPerRule = 65535
)

type ExtraOptions struct {
	Pps int
}

type PortScanTechniques struct {
	Syn bool
	Fin bool
	Udp bool
}

type HostStateDetection struct {
	Ping bool
	Arp  bool
	Snmp bool
	Top  bool
}

// Rule defines a scanning rule. The user can specify only Network, Ports,
// HostStateDetection, PortScanTechniques, and ExtraOptions.
// The fields sockFD, pause, ioVecs, and packets are unexported and encapsulated.
type Rule struct {
	Network            net.IPNet
	sockFD             int
	Ports              []uint16
	HostStateDetection HostStateDetection
	PortScanTechniques PortScanTechniques
	ioVecs             chan []syscall.Iovec // If ports count is higher than 64, sendmmsg syscall will be used
	packets            chan []byte          // If ports count is less than 64, sendto syscall will be used
	pause              chan bool
	ExtraOptions       ExtraOptions
	isV6               bool
}

func getRawSockFD() (int, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(utils.Htons(syscall.ETH_P_IP)))
	if err != nil {
		return -1, fmt.Errorf("failed to create raw socket: %v", err)
	}
	return fd, nil
}

func parseHostStateDetection(s string) (HostStateDetection, error) {
	var H HostStateDetection
	for _, char := range s {
		switch char {
		case 'p':
			H.Ping = true
		case 'a':
			H.Arp = true
		case 's':
			H.Snmp = true
		case 't':
			H.Top = true
		default:
			return HostStateDetection{}, fmt.Errorf("unknown host state detection type: %c", char)
		}
	}
	return H, nil
}

func parsePortScanTechniques(s string) (PortScanTechniques, error) {
	var P PortScanTechniques
	for _, char := range s {
		switch char {
		case 's':
			P.Syn = true
		case 'f':
			P.Fin = true
		case 'u':
			P.Udp = true
		default:
			return PortScanTechniques{}, fmt.Errorf("unknown port scan technique type: %c", char)
		}
	}
	return P, nil
}

func parsePortsRange(s string) ([]uint16, error) {
	var start, end int
	var err error
	var portsRange []uint16
	var startPortString, endPortString string

	if strings.Count(s, "-") > 1 {
		return nil, fmt.Errorf("port range must contain only one \"-\"")
	}
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid port range format")
	}
	startPortString = parts[0]
	endPortString = parts[1]

	start, err = strconv.Atoi(startPortString)
	if err != nil {
		return nil, fmt.Errorf("start port \"%s\" is not a valid number", startPortString)
	}

	end, err = strconv.Atoi(endPortString)
	if err != nil {
		return nil, fmt.Errorf("end port \"%s\" is not a valid number", endPortString)
	}

	if start <= 0 || end <= 0 || start > 65535 || end > 65535 || start > end {
		return nil, fmt.Errorf("\"%s\" is not a valid port range", s)
	}

	portsRange = make([]uint16, 0, end-start+1)
	for i := start; i <= end; i++ {
		portsRange = append(portsRange, uint16(i))
	}

	return portsRange, nil
}

func parseExtraOptions(s string) (ExtraOptions, error) {
	var E ExtraOptions
	for _, parameter := range strings.Split(s, ",") {
		parameterSplit := strings.Split(parameter, "=")
		if len(parameterSplit) != 2 {
			return ExtraOptions{}, fmt.Errorf("invalid parameter format: %s", parameter)
		}
		switch parameterSplit[0] {
		case "pps":
			pps, err := strconv.Atoi(parameterSplit[1])
			if err == nil {
				E.Pps = pps
			} else {
				return ExtraOptions{}, fmt.Errorf("invalid value for pps: %s", parameterSplit[1])
			}
		default:
			return ExtraOptions{}, fmt.Errorf("unknown parameter \"%s\"", parameterSplit[0])
		}
	}
	return E, nil
}

func trimAddrFromRuleStr(s *string, addrString string) {
	switch {
	case strings.Contains(*s, "["+addrString+"]:"):
		*s = strings.TrimPrefix(*s, "["+addrString+"]:")
	case strings.Contains(*s, "["+addrString+"]"):
		*s = ""
	case strings.Contains(*s, addrString+":"):
		*s = strings.TrimPrefix(*s, addrString+":")
	case strings.Contains(*s, addrString):
		*s = strings.TrimPrefix(*s, addrString)
	}
}

func parseAddress(s *string) (net.IPNet, bool, error) {
	*s = strings.TrimSpace(*s)

	if strings.HasPrefix(*s, "[") {
		// IPv6 address enclosed in brackets
		bracketIndex := strings.Index(*s, "]")
		if bracketIndex == -1 {
			return net.IPNet{}, true, fmt.Errorf("missing closing bracket in IPv6 address")
		}
		ipv6Str := (*s)[1:bracketIndex]
		IPv6Address := net.ParseIP(ipv6Str)

		if IPv6Address != nil {
			// Remove the IPv6 address from the input string
			trimAddrFromRuleStr(s, ipv6Str)
			return utils.IPtoIPNet(IPv6Address), true, nil
		}

		IPv6Address, IPv6Net, err := net.ParseCIDR(ipv6Str)
		if err == nil {
			// Remove the IPv6 CIDR from the input string
			trimAddrFromRuleStr(s, (*s)[:bracketIndex+2])
			return net.IPNet{IP: IPv6Address, Mask: IPv6Net.Mask}, true, nil
		}

		return net.IPNet{}, true, fmt.Errorf("%s is not a correct IPv6 address or CIDR", ipv6Str)
	}

	// Check for IPv4 address or domain name
	parts := strings.SplitN(*s, ":", 2)

	if parts[0] == "" {
		return net.IPNet{}, false, fmt.Errorf("invalid input string")
	}

	if utils.IsValidDomain(parts[0]) {
		addresses, err := net.LookupIP(parts[0])
		if err != nil || len(addresses) == 0 {
			return net.IPNet{}, false, errors.New("unable to resolve domain name")
		}

		// Remove the domain name from the input string
		trimAddrFromRuleStr(s, parts[0])

		if len(addresses[0]) == net.IPv6len {
			return utils.IPtoIPNet(addresses[0]), false, nil
		} else {
			return utils.IPtoIPNet(addresses[0]), false, nil
		}
	}

	IPv4AddrStr := parts[0]

	IPv4Addr := net.ParseIP(IPv4AddrStr)
	if IPv4Addr != nil {
		// Remove the IPv4 address from the input string
		trimAddrFromRuleStr(s, IPv4AddrStr)
		return utils.IPtoIPNet(IPv4Addr), false, nil
	}

	IPv4Addr, IPv4Net, err := net.ParseCIDR(IPv4AddrStr)
	if err == nil {
		// Remove the IPv4 CIDR from the input string
		trimAddrFromRuleStr(s, IPv4AddrStr)
		return net.IPNet{IP: IPv4Addr, Mask: IPv4Net.Mask}, false, nil
	}

	return net.IPNet{}, false, fmt.Errorf("incorrect network address received")
}

func parsePorts(s string) ([]uint16, error) {
	var portsList []uint16
	portsList = make([]uint16, 0)

	for _, portDefinition := range strings.Split(s, ",") {
		if strings.Contains(portDefinition, "-") {
			rangePorts, err := parsePortsRange(portDefinition)
			if err != nil {
				return nil, err
			}
			portsList = append(portsList, rangePorts...)
			continue
		}
		port, err := strconv.Atoi(portDefinition)
		if err != nil {
			return nil, err
		}
		if port <= 0 || port > 65535 {
			return nil, fmt.Errorf("port number %d is out of valid range (1-65535)", port)
		}
		portsList = append(portsList, uint16(port))
	}
	sort.Slice(portsList, func(i, j int) bool { return portsList[i] < portsList[j] })
	portsList = slices.Compact(portsList)
	return portsList, nil
}

// ParseRule creates a new scanning rule from a string.
// Rule structure: <address>:<ports>:<host state detection>:<scan technique>:<options>
//
// Examples:
//
//  1. Simple rule:
//     "192.168.1.1:80"
//
//  2. Using a domain name:
//     "example.com:80,443"
//
//  3. Full rule with port range and additional options:
//     "192.168.1.100/24:80,443,1000-2000:p:s:pps=1000000"
//
//  4. IPv6 address with scan technique and options:
//     "[2001:db8::1]:22:p:s:pps=500000"
//
//  5. Rule with multiple host state detection techniques:
//     "10.0.0.0/8:22,80,443:psa:su"
//
//  6. Scanning using all options:
//     "[2001:db8::]/64:1-1024:past:sfu:pps=1000000"
//
//  7. Scanning without specifying detection or scan techniques (defaults will be used):
//     "example.com"
//
// Notes:
// - `<address>`: IP address, range, or domain name.
// - `<ports>`: List of ports or port ranges, separated by commas.
// - `<host state detection>`: Host state detection techniques (`p` - ping, `a` - arp, `s` - snmp, `t` - top).
// - `<scan technique>`: Port scanning techniques (`s` - syn, `f` - fin, `u` - udp).
// - `<options>`: Additional parameters, e.g., `pps=1000000`.
//
// - IPv6 addresses should be enclosed in square brackets `[]` when ports are specified.
// - Missing fields can be omitted; default values will be used for detection and scanning techniques.
// - Colons `:` are used to separate different parts of the rule.
func ParseRule(s string) (Rule, error) {
	var R Rule
	var err error
	var address net.IPNet
	var portsList []uint16
	var isV6 bool
	var hostStateDetectionList HostStateDetection
	var portScanTechniquesList PortScanTechniques
	var extraOptionsList ExtraOptions

	address, isV6, err = parseAddress(&s)

	if err != nil {
		return Rule{}, err
	}

	R.Network = address
	R.isV6 = isV6

	if len(s) == 0 {
		return R, nil
	}
	RuleSplit := strings.Split(s, ":")

	// Process the rest of the rule
	ruleLen := len(RuleSplit)
	if ruleLen > 0 {
		portsList, err = parsePorts(RuleSplit[0])
		if err != nil {
			return Rule{}, err
		}
		R.Ports = portsList
	}

	if ruleLen > 1 {
		hostStateDetectionList, err = parseHostStateDetection(RuleSplit[1])
		if err != nil {
			return Rule{}, err
		}
		R.HostStateDetection = hostStateDetectionList
	}

	if ruleLen > 2 {
		portScanTechniquesList, err = parsePortScanTechniques(RuleSplit[2])
		if err != nil {
			return Rule{}, err
		}
		R.PortScanTechniques = portScanTechniquesList
	}

	if ruleLen > 3 {
		extraOptionsList, err = parseExtraOptions(RuleSplit[3])
		if err != nil {
			return Rule{}, err
		}
		R.ExtraOptions = extraOptionsList
	}

	R.sockFD, err = getRawSockFD()
	if err != nil {
		return Rule{}, err
	}

	R.pause = make(chan bool)

	// Ensure buffer sizes are appropriate
	if len(R.Ports) >= minPacketsToUseIOVEC {
		R.ioVecs = make(chan []syscall.Iovec, maxIovecsBuffersPerRule)
	} else {
		R.packets = make(chan []byte, maxPacketsBufferPerRule)
	}

	return R, nil
}

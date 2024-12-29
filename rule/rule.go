package rule

import (
	"Vaverka/constants"
	"Vaverka/utils"
	"fmt"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Options struct {
	PortScannerName string
	Pps             int
	HostTimeout     time.Duration
}

type PortsScanTechniques struct {
	Syn bool
	Fin bool
	Udp bool
}

// Rule defines a scanning rule. The user can specify only Network, Ports, PortsScanTechniques, and Options.
type Rule struct {
	Network            net.IPNet
	Ports              []uint16
	PortsRanges        []PortsRange
	PortScanTechniques PortsScanTechniques
	Options            Options
}

type PortsRange struct {
	Start uint16
	End   uint16
}

func (pr PortsRange) expand() []uint16 {
	var ports []uint16
	ports = make([]uint16, 0)

	for port := pr.Start; port < pr.End; port++ {
		ports = append(ports, port)
	}
	return ports
}

func (pr PortsRange) validate() bool {
	if pr.End > pr.Start && pr.End != pr.Start {
		return true
	} else {
		return false
	}
}

func parsePortScanTechniques(s string) (PortsScanTechniques, error) {
	var P PortsScanTechniques
	for _, char := range s {
		switch char {
		case 's':
			P.Syn = true
		case 'f':
			P.Fin = true
		case 'u':
			P.Udp = true
		default:
			return PortsScanTechniques{}, fmt.Errorf("unknown port scan technique type: \"%c\"", char)
		}
	}
	return P, nil
}

func parsePortsRange(s string) (PortsRange, error) {
	var start, end uint16
	var tmpStartInt, tmpEndInt int
	var err error
	var startPortString, endPortString string

	if strings.Count(s, "-") > 1 {
		return PortsRange{}, fmt.Errorf("port range must contain only one \"-\"")
	}
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return PortsRange{}, fmt.Errorf("invalid port range format")
	}
	startPortString = parts[0]
	endPortString = parts[1]

	tmpStartInt, err = strconv.Atoi(startPortString)
	if err != nil {
		return PortsRange{}, fmt.Errorf("start port \"%s\" is not a valid number", startPortString)
	}
	start = uint16(tmpStartInt)

	tmpEndInt, err = strconv.Atoi(endPortString)
	if err != nil {
		return PortsRange{}, fmt.Errorf("end port \"%s\" is not a valid number", endPortString)
	}
	end = uint16(tmpEndInt)
	if start <= 0 || end <= 0 || start > 65535 || end > 65535 || start > end {
		return PortsRange{}, fmt.Errorf("\"%s\" is not a valid port range", s)
	}

	return PortsRange{
		Start: start,
		End:   end,
	}, nil
}

func parseOptions(s string) (Options, error) {
	var O Options
	for _, parameter := range strings.Split(s, ",") {
		parameterSplit := strings.Split(parameter, "=")
		if len(parameterSplit) != 2 {
			return Options{}, fmt.Errorf("invalid parameter format: %s", parameter)
		}
		switch parameterSplit[0] {
		case "pps":
			pps, err := strconv.Atoi(parameterSplit[1])
			if err == nil {
				O.Pps = pps
			} else {
				return Options{}, fmt.Errorf("invalid value for pps: %s", parameterSplit[1])
			}
		case "host_timeout":
			hostTimeout, err := strconv.Atoi(parameterSplit[1])
			if err == nil {
				O.HostTimeout = time.Duration(int64(time.Second) * int64(hostTimeout))
			} else {
				return Options{}, fmt.Errorf("invalid value for pps: %s", parameterSplit[1])
			}
		case "scanner":
			switch parameterSplit[1] {
			case "p":
				O.PortScannerName = "plain"
			case "s":
				O.PortScannerName = "soft"
			}

		default:
			return Options{}, fmt.Errorf("unknown parameter \"%s\"", parameterSplit[0])
		}
	}
	return O, nil
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

func parseAddress(s *string) (net.IPNet, error) {
	*s = strings.TrimSpace(*s)

	if strings.HasPrefix(*s, "[") {
		// IPv6 address enclosed in brackets
		bracketIndex := strings.Index(*s, "]")
		if bracketIndex == -1 {
			return net.IPNet{}, fmt.Errorf("missing closing bracket in IPv6 address")
		}
		ipv6Str := (*s)[1:bracketIndex]
		IPv6Address := net.ParseIP(ipv6Str)

		if IPv6Address != nil {
			// Remove the IPv6 address from the input string
			trimAddrFromRuleStr(s, ipv6Str)
			return utils.IPtoIPNet(IPv6Address), nil
		}

		IPv6Address, IPv6Net, err := net.ParseCIDR(ipv6Str)
		if err == nil {
			// Remove the IPv6 CIDR from the input string
			trimAddrFromRuleStr(s, (*s)[:bracketIndex+2])
			return net.IPNet{IP: IPv6Address, Mask: IPv6Net.Mask}, nil
		}

		return net.IPNet{}, fmt.Errorf("%s is not a correct IPv6 address or CIDR", ipv6Str)
	}

	// Check for IPv4 address or domain name
	parts := strings.SplitN(*s, ":", 2)

	if parts[0] == "" {
		return net.IPNet{}, fmt.Errorf("invalid input string")
	}

	IPv4Addr := net.ParseIP(parts[0])
	if IPv4Addr != nil {
		// Remove the IPv4 address from the input string
		trimAddrFromRuleStr(s, parts[0])
		return utils.IPtoIPNet(IPv4Addr), nil
	}

	_, IPv4Net, err := net.ParseCIDR(parts[0])
	if err == nil {
		// Remove the IPv4 CIDR from the input string
		trimAddrFromRuleStr(s, parts[0])
		return *IPv4Net, nil
	}

	resolvedAddr, err := utils.ResolveHost(parts[0])
	if err == nil {
		trimAddrFromRuleStr(s, parts[0])
		return utils.IPtoIPNet(resolvedAddr), nil
	} else {
		return net.IPNet{}, fmt.Errorf("failed to resolve network \"%s\" address . error %s", parts[0], err)
	}

}

func parsePorts(s string) ([]uint16, []PortsRange, error) {
	var portsList []uint16
	var portRanges []PortsRange
	var portRange PortsRange
	var err error

	portsList = make([]uint16, 0)
	portRanges = make([]PortsRange, 0)

	for _, portDefinition := range strings.Split(s, ",") {
		if strings.Contains(portDefinition, "-") {
			portRange, err = parsePortsRange(portDefinition)
			if err != nil {
				return nil, nil, err
			}
			portRanges = append(portRanges, portRange)
			continue
		}
		port, err := strconv.Atoi(portDefinition)
		if err != nil {
			return nil, nil, err
		}
		if port <= 0 || port > 65535 {
			return nil, nil, fmt.Errorf("port number %d is out of valid range (1-65535)", port)
		}
		portsList = append(portsList, uint16(port))
	}
	sort.Slice(portsList, func(i, j int) bool { return portsList[i] < portsList[j] })
	portsList = slices.Compact(portsList)
	return portsList, portRanges, nil
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
//     "[2001:db8::1]:22:s:pps=500000"
//
//  5. Rule with multiple host state detection techniques:
//     "10.0.0.0/8:22,80,443:su"
//
//  6. Scanning using all options:
//     "[2001:db8::]/64:1-1024:sfu:pps=1000000"
//
//  7. Scanning without specifying detection or scan techniques (defaults will be used):
//     "example.com"
//
// Notes:
// - `<address>`: IP address, range, or domain name.
// - `<ports>`: List of ports or port ranges, separated by commas.
// - `<port scan technique>`: Port scanning techniques (`s` - syn, `f` - fin, `u` - udp).
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
	var portsRanges []PortsRange
	var portScanTechniques PortsScanTechniques
	var optionsList Options
	address, err = parseAddress(&s)

	if err != nil {
		return Rule{}, err
	}

	R.Network = address

	if len(s) == 0 {
		AutocompleteRule(&R)
		return R, nil
	}
	RuleSplit := strings.Split(s, ":")

	// Process the rest of the rule
	ruleLen := len(RuleSplit)

	if ruleLen > 0 && RuleSplit[0] != "" {
		portsList, portsRanges, err = parsePorts(RuleSplit[0])
		if err != nil {
			return Rule{}, err
		}
		R.Ports = portsList
		R.PortsRanges = portsRanges
	}

	if ruleLen > 1 && RuleSplit[1] != "" {
		portScanTechniques, err = parsePortScanTechniques(RuleSplit[1])
		if err != nil {
			return Rule{}, err
		}
		R.PortScanTechniques = portScanTechniques
	}

	if ruleLen > 2 && RuleSplit[2] != "" {
		optionsList, err = parseOptions(RuleSplit[2])
		if err != nil {
			return Rule{}, err
		}
		R.Options = optionsList
	}

	AutocompleteRule(&R)
	return R, nil

}

func AutocompleteRule(r *Rule) {
	if len(r.Ports) == 0 && r.PortsRanges == nil {
		r.Ports = constants.CommonPorts
	}

	if r.PortScanTechniques.Fin == false && r.PortScanTechniques.Syn == false && r.PortScanTechniques.Udp == false {
		r.PortScanTechniques.Syn = true
	}

	if r.Options.PortScannerName == "" {
		r.Options.PortScannerName = "vertical"
	}

	if r.Options.HostTimeout == 0 {
		r.Options.HostTimeout = constants.DefaultHostTimeout
	}
}

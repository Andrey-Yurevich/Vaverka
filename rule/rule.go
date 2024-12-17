package rule

import (
	"Vaverka/utils"
	"fmt"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

const defaultHostTimeout = time.Second * 2

var CommonPorts = []uint16{
	21,    // FTP
	22,    // SSH
	25,    // SMTP
	53,    // DNS
	80,    // HTTP
	110,   // POP3
	111,   // RPCBind
	135,   // DCE/RPC
	139,   // NetBIOS
	143,   // IMAP
	161,   // SNMP
	162,   // SNMP Trap
	443,   // HTTPS
	445,   // SMB
	993,   // IMAPS
	995,   // POP3S
	1433,  // Microsoft SQL Server
	1521,  // Oracle DB
	3306,  // MySQL
	3389,  // Microsoft RDP
	5060,  // SIP (Session Initiation Protocol)
	5432,  // PostgreSQL
	5672,  // RabbitMQ (AMQP)
	6379,  // Redis
	8000,  // HTTP Alternative
	8080,  // HTTP Alternative
	8081,  // HTTP Alternative
	8082,  // HTTP Alternative
	8443,  // HTTPS Alternative
	8888,  // HTTP Alternative
	9090,  // Prometheus, HTTP Alternative
	9091,  // HTTP Alternative
	27017, // MongoDB
}

type Options struct {
	PortScannerName string
	Pps             int
	HostTimeout     time.Duration
}

type PortScanTechniques struct {
	Syn bool
	Fin bool
	Udp bool
}

type HostStateDetection struct {
	Ping bool
	Arp  bool
}

// Rule defines a scanning rule. The user can specify only Network, Ports,
// HostStateDetection, PortScanTechniques, and Options.
// The fields sockFD, pause, ioVecs, and packets are unexported and encapsulated.
type Rule struct {
	Network            net.IPNet
	Ports              []uint16
	HostStateDetection HostStateDetection
	PortScanTechniques PortScanTechniques
	Options            Options
	IsV6               bool
}

func parseHostStateDetection(s string) (HostStateDetection, error) {
	var H HostStateDetection

	for _, char := range s {
		switch char {
		case 'p':
			H.Ping = true
		case 'a':
			H.Arp = true
		default:
			return HostStateDetection{}, fmt.Errorf("unknown host state detection type: \"%c\"", char)
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
			return PortScanTechniques{}, fmt.Errorf("unknown port scan technique type: \"%c\"", char)
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

	IPv4Addr := net.ParseIP(parts[0])
	if IPv4Addr != nil {
		// Remove the IPv4 address from the input string
		trimAddrFromRuleStr(s, parts[0])
		return utils.IPtoIPNet(IPv4Addr), false, nil
	}

	IPv4Addr, IPv4Net, err := net.ParseCIDR(parts[0])
	if err == nil {
		// Remove the IPv4 CIDR from the input string
		trimAddrFromRuleStr(s, parts[0])
		return net.IPNet{IP: IPv4Addr, Mask: IPv4Net.Mask}, false, nil
	}

	resolvedAddr, err := utils.ResolveHost(parts[0])
	if err == nil {
		trimAddrFromRuleStr(s, parts[0])
		return utils.IPtoIPNet(resolvedAddr), false, nil
	} else {
		return net.IPNet{}, false, fmt.Errorf("failed to resolve network \"%s\" address . error %s", parts[0], err)
	}

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
//     "10.0.0.0/8:22,80,443:pa:su"
//
//  6. Scanning using all options:
//     "[2001:db8::]/64:1-1024:pa:sfu:pps=1000000"
//
//  7. Scanning without specifying detection or scan techniques (defaults will be used):
//     "example.com"
//
// Notes:
// - `<address>`: IP address, range, or domain name.
// - `<ports>`: List of ports or port ranges, separated by commas.
// - `<host state detection>`: Host state detection techniques (`p` - ping, `a` - arp).
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
	var hostStateDetection HostStateDetection
	var portScanTechniques PortScanTechniques
	var optionsList Options
	address, isV6, err = parseAddress(&s)

	if err != nil {
		return Rule{}, err
	}

	R.Network = address
	R.IsV6 = isV6

	if len(s) == 0 {
		AutocompleteRule(&R)
		return R, nil
	}
	RuleSplit := strings.Split(s, ":")

	// Process the rest of the rule
	ruleLen := len(RuleSplit)

	if ruleLen > 0 && RuleSplit[0] != "" {
		portsList, err = parsePorts(RuleSplit[0])
		if err != nil {
			return Rule{}, err
		}
		R.Ports = portsList
	}

	if ruleLen > 1 && RuleSplit[1] != "" {
		hostStateDetection, err = parseHostStateDetection(RuleSplit[1])
		if err != nil {
			return Rule{}, err
		}
		R.HostStateDetection = hostStateDetection
	}

	if ruleLen > 2 && RuleSplit[2] != "" {
		portScanTechniques, err = parsePortScanTechniques(RuleSplit[2])
		if err != nil {
			return Rule{}, err
		}
		R.PortScanTechniques = portScanTechniques
	}

	if ruleLen > 3 && RuleSplit[3] != "" {
		optionsList, err = parseOptions(RuleSplit[3])
		if err != nil {
			return Rule{}, err
		}
		R.Options = optionsList
	}

	AutocompleteRule(&R)
	return R, nil

}

func AutocompleteRule(r *Rule) {
	if len(r.Ports) == 0 {
		r.Ports = CommonPorts
	}

	if r.HostStateDetection.Ping == false && r.HostStateDetection.Arp == false {
		r.HostStateDetection.Ping = true
	}

	if r.PortScanTechniques.Fin == false && r.PortScanTechniques.Syn == false && r.PortScanTechniques.Udp == false {
		r.PortScanTechniques.Syn = true
	}

	if r.Options.PortScannerName == "" {
		r.Options.PortScannerName = "plain"
	}

	if r.Options.HostTimeout == 0 {
		r.Options.HostTimeout = defaultHostTimeout
	}
}

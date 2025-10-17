package rule_test

import (
	"net"
	"slices"
	"testing"
	"time"

	"github.com/Andrey-Yurevich/Vaverka/router"
	"github.com/Andrey-Yurevich/Vaverka/rule"
)

func TestParseRule(t *testing.T) {
	testCases := []struct {
		name      string
		input     string
		expected  rule.Rule
		expectErr bool
	}{
		// Valid rules
		{
			name:  "Simple IPv4 rule",
			input: "192.168.1.1:80",
			expected: rule.Rule{
				Network:            ipNetFromString("192.168.1.1/32"),
				Ports:              []uint16{80},
				PortsRanges:        nil,
				PortScanTechniques: rule.PortsScanTechniques{Syn: true},
				Options: rule.Options{
					Router:  router.SimpleV4Route,
					Timeout: time.Second * 2,
				},
			},
			expectErr: false,
		},
		{
			name:  "IPv4 CIDR with small port range",
			input: "192.168.1.100/24:80,443,1000-1005:s",
			expected: rule.Rule{
				Network:            ipNetFromString("192.168.1.0/24"),
				Ports:              []uint16{80, 443},
				PortsRanges:        []rule.PortsRange{{Start: 1000, End: 1005}},
				PortScanTechniques: rule.PortsScanTechniques{Syn: true},
				Options: rule.Options{
					Router:  router.SimpleV4Route,
					Timeout: time.Second * 2,
				},
			},
			expectErr: false,
		},
		{
			name:  "Domain with multiple ports",
			input: "ip6-localhost:80,443",
			expected: rule.Rule{
				Network:            ipNetFromString("::1"),
				Ports:              []uint16{80, 443},
				PortsRanges:        nil,
				PortScanTechniques: rule.PortsScanTechniques{Syn: true},
				Options: rule.Options{
					Router:  router.SimpleV4Route,
					Timeout: time.Second * 2,
				},
			},
			expectErr: false,
		},
		{
			name:  "IPv6 with options",
			input: "[2001:db8::1]:22:s:router=smart,no-ipv6-multicast=true",
			expected: rule.Rule{
				Network:            ipNetFromString("2001:db8::1/128"),
				Ports:              []uint16{22},
				PortsRanges:        nil,
				PortScanTechniques: rule.PortsScanTechniques{Syn: true},
				Options: rule.Options{
					Router:          router.SmartV4Route,
					Timeout:         time.Second * 2,
					NoIpV6Multicast: true,
				},
			},
			expectErr: false,
		},
		{
			name:  "IPv6 CIDR with small port range",
			input: "[2001:db8::/64]:1-5:svu",
			expected: rule.Rule{
				Network:            ipNetFromString("2001:db8::/64"),
				Ports:              []uint16{},
				PortsRanges:        []rule.PortsRange{{Start: 1, End: 5}},
				PortScanTechniques: rule.PortsScanTechniques{Syn: true, Vav: true, Udp: true},
				Options: rule.Options{
					Router:  router.SimpleV4Route,
					Timeout: time.Second * 2,
				},
			},
			expectErr: false,
		},
		// Invalid rules
		{
			name:      "Invalid CIDR",
			input:     "192.168.1.100/33:80",
			expectErr: true,
		},
		{
			name:      "Invalid port range",
			input:     "192.168.1.1:1000-999",
			expectErr: true,
		},
		{
			name:      "Empty input",
			input:     "",
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := rule.ParseRule(tc.input)
			if tc.expectErr {
				if err == nil {
					t.Errorf("Expected an error, but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if !rulesEqual(r, tc.expected) {
				t.Errorf("Expected %+v, but got %+v", tc.expected, r)
			}
		})
	}
}

func ipNetFromString(input string) net.IPNet {
	ip, network, err := net.ParseCIDR(input)
	if err == nil {
		return net.IPNet{IP: ip, Mask: network.Mask}
	}
	ip = net.ParseIP(input)
	if ip == nil {
		panic("Invalid IP or CIDR string: " + input)
	}
	if ip.To4() != nil {
		return net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
	}
	return net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
}

func rulesEqual(a, b rule.Rule) bool {
	// Compare networks
	if !ipNetsEqual(a.Network, b.Network) {
		return false
	}
	// Compare ports slice
	if !slices.Equal(a.Ports, b.Ports) {
		return false
	}
	// Compare PortScanTechniques (assuming it's a comparable struct or basic type)
	if a.PortScanTechniques != b.PortScanTechniques {
		return false
	}
	// Compare Options fields individually, skipping the incomparable Router function.
	if a.Options.Timeout != b.Options.Timeout {
		return false
	}
	// If there are other comparable fields in Options, compare them here.

	return true
}

func ipNetsEqual(a, b net.IPNet) bool {
	return a.IP.Equal(b.IP) && a.Mask.String() == b.Mask.String()
}

package rule_test

import (
	"Vaverka/rule"
	"net"
	"slices"
	"testing"
	"time"
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
				HostStateDetection: rule.HostStateDetection{Ping: true},
				PortScanTechniques: rule.PortScanTechniques{Syn: true},
				Options: rule.Options{
					PortScannerName: "plain",
					Pps:             0,
					HostTimeout:     time.Second * 2,
				},
				IsV6: false,
			},
			expectErr: false,
		},
		{
			name:  "Missing fields with defaults",
			input: "localhost::p",
			expected: rule.Rule{
				Network:            ipNetFromString("127.0.0.1/32"),
				Ports:              rule.CommonPorts,
				HostStateDetection: rule.HostStateDetection{Ping: true},
				PortScanTechniques: rule.PortScanTechniques{Syn: true},
				Options: rule.Options{
					PortScannerName: "plain",
					Pps:             0,
					HostTimeout:     time.Second * 2,
				},
				IsV6: false,
			},
			expectErr: false,
		},
		{
			name:  "IPv4 CIDR with small port range",
			input: "192.168.1.100/24:80,443,1000-1005:p:s:pps=1000000",
			expected: rule.Rule{
				Network:            ipNetFromString("192.168.1.100/24"),
				Ports:              []uint16{80, 443, 1000, 1001, 1002, 1003, 1004, 1005},
				HostStateDetection: rule.HostStateDetection{Ping: true},
				PortScanTechniques: rule.PortScanTechniques{Syn: true},
				Options: rule.Options{
					PortScannerName: "plain",
					Pps:             1000000,
					HostTimeout:     time.Second * 2,
				},
				IsV6: false,
			},
			expectErr: false,
		},
		{
			name:  "Domain with multiple ports",
			input: "localhost:80,443",
			expected: rule.Rule{
				Network:            ipNetFromString("127.0.0.1/32"),
				Ports:              []uint16{80, 443},
				HostStateDetection: rule.HostStateDetection{Ping: true},
				PortScanTechniques: rule.PortScanTechniques{Syn: true},
				Options: rule.Options{
					PortScannerName: "plain",
					Pps:             0,
					HostTimeout:     time.Second * 2,
				},
				IsV6: false,
			},
			expectErr: false,
		},
		{
			name:  "IPv6 with options",
			input: "[2001:db8::1]:22:p:s:pps=500000",
			expected: rule.Rule{
				Network:            ipNetFromString("2001:db8::1/128"),
				Ports:              []uint16{22},
				HostStateDetection: rule.HostStateDetection{Ping: true},
				PortScanTechniques: rule.PortScanTechniques{Syn: true},
				Options: rule.Options{
					PortScannerName: "plain",
					Pps:             500000,
					HostTimeout:     time.Second * 2,
				},
				IsV6: true,
			},
			expectErr: false,
		},
		{
			name:  "IPv6 CIDR with small port range",
			input: "[2001:db8::/64]:1-5:pa:sfu:pps=1000000",
			expected: rule.Rule{
				Network:            ipNetFromString("2001:db8::/64"),
				Ports:              []uint16{1, 2, 3, 4, 5},
				HostStateDetection: rule.HostStateDetection{Ping: true, Arp: true},
				PortScanTechniques: rule.PortScanTechniques{Syn: true, Fin: true, Udp: true},
				Options: rule.Options{
					PortScannerName: "plain",
					Pps:             1000000,
					HostTimeout:     time.Second * 2,
				},
				IsV6: true,
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
	if !ipNetsEqual(a.Network, b.Network) {
		return false
	}
	if !slices.Equal(a.Ports, b.Ports) {
		return false
	}
	if a.HostStateDetection != b.HostStateDetection {
		return false
	}
	if a.PortScanTechniques != b.PortScanTechniques {
		return false
	}
	if a.Options != b.Options {
		return false
	}
	if a.IsV6 != b.IsV6 {
		return false
	}
	return true
}

func ipNetsEqual(a, b net.IPNet) bool {
	return a.IP.Equal(b.IP) && a.Mask.String() == b.Mask.String()
}

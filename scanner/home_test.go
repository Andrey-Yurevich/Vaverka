package scanner

import (
	"net"
	"os"
	"testing"

	"github.com/Andrey-Yurevich/Vaverka/rule"
)

func TestScan_Home_LocalIPv4_ARP(t *testing.T) {
	if os.Getenv("SCAN_TEST_ENV") != "HOME" {
		t.Skip("Testing: Skipping home-network test")
	}

	_, targetNetwork, err := net.ParseCIDR(os.Getenv("TARGET_NETWORK"))

	if err != nil {
		t.Fatalf("Testing: Unable to parse TARGET_NETWORK: %v", err)
	}

	routerIP := net.ParseIP(os.Getenv("ROUTER_IP"))

	if routerIP == nil {
		t.Fatalf("Testing: Unable to parse Router IP from environment variable ROUTER_IP")
	}

	selfIP := net.ParseIP(os.Getenv("SELF_IP"))

	if selfIP == nil {
		t.Fatalf("Testing: Unable to parse Router IP from environment variable ROUTER_IP")
	}

	var r rule.Rule

	r.Network = *targetNetwork

	r.PortScanTechniques = rule.PortsScanTechniques{Vav: true, Syn: true}
	err = SetPps(16000)
	if err != nil {
		t.Fatalf("Testing: Failed to set PPS: %v", err)
	}

	rule.AutocompleteRule(&r)

	hosts := make([]Host, 16)
	ports := make([]Port, 16)

	if len(hosts) == 0 {
		t.Fatal("Testing: No hosts discovered via ARP in local network range")
	}

	foundRouter := false
	foundRouterHttp := false
	foundRouterSSH := false

	foundSelf := false
	foundSelfHttp := false
	foundSelfSSH := false
	foundSelfRedis := false

	stream, err := Scan(r)
	if err != nil {
		t.Fatalf("Testing: Scan start error: %v", err)
	}

	for f := range stream.Findings {
		switch v := f.(type) {
		case Host:
			t.Log(v)
			hosts = append(hosts, v)
			switch {
			case v.IP.Equal(selfIP):
				foundSelf = true
			case v.IP.Equal(routerIP):
				foundRouter = true
			}
		case Port:
			t.Log(v)
			ports = append(ports, v)
			switch v.Host.String() {

			case selfIP.String():
				switch v.Port {
				case 80:
					foundSelfHttp = true
				case 22:
					foundSelfSSH = true
				case 6379:
					foundSelfRedis = true
				}
			case routerIP.String():
				switch v.Port {
				case 80:
					foundRouterHttp = true
				case 22:
					foundRouterSSH = true

				}
			}
		}
	}

	if err = stream.Wait(); err != nil {
		t.Fatalf("Testing: Error while scanning network %s: %v\n", r.Network, err)
	}

	if foundSelf && foundRouter && foundSelfHttp && foundSelfSSH && foundSelfRedis && foundRouterSSH && foundRouterHttp {
		return
	}
	t.Errorf("At least one condition was not met:\n"+
		"Self found: %t\n"+
		"Router found: %t\n"+
		"Self Http found: %t\n"+
		"Self SSH found: %t\n"+
		"Self Redis found: %t\n"+
		"Router HTTP found: %t\n"+
		"Router SSH found: %t\n", foundSelf, foundRouter, foundSelfHttp, foundSelfSSH, foundSelfRedis, foundRouterHttp, foundRouterSSH)
}

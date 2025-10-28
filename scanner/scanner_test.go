package scanner

import (
	"fmt"
	"math"
	"net"
	"os"
	"testing"
	"time"

	"github.com/Andrey-Yurevich/Vaverka/rule"
)

func TestScan_Home_LocalIPv6_NS(t *testing.T) {
	if os.Getenv("SCAN_TEST_ENV") != "DOCKER_HOME_HOST" {
		t.Skip("Testing: Skipping...")
	}
	_, targetNetwork, err := net.ParseCIDR(os.Getenv("TARGET_NETWORK"))

	if err != nil {
		t.Fatalf("Testing: Unable to parse TARGET_NETWORK: %v", err)
	}

	targetInterface, err := net.InterfaceByName(os.Getenv("TARGET_INTERFACE"))

	if err != nil {
		t.Fatalf("Testing: Unable to parse TARGET_INTERFACE: %v", err)
	}

	routerIP := net.ParseIP(os.Getenv("ROUTER_IP"))

	if routerIP == nil {
		t.Fatalf("Testing: Unable to parse Router IP from environment variable ROUTER_IP")
	}

	var r rule.Rule

	r.Network = *targetNetwork
	r.Ports = []uint16{53, 80}

	r.Options.IpV6MulticastInterfaceIndex = targetInterface.Index

	r.PortScanTechniques = rule.PortsScanTechniques{Vav: true}

	rule.AutocompleteRule(&r)

	hosts := make([]Host, 16)
	ports := make([]Port, 16)

	if len(hosts) == 0 {
		t.Fatal("Testing: No hosts discovered via ARP in local network range")
	}

	foundRouter := false
	foundRouterHttp := false
	foundRouterDNS := false

	startTime := time.Now()

	stream, err := Scan(r)
	if err != nil {
		t.Fatalf("Testing: Scan start error: %v", err)
	}

	for f := range stream.Findings {
		switch v := f.(type) {
		case Host:
			if v.IP.Equal(routerIP) {
				foundRouter = true
			}
		case Port:
			ports = append(ports, v)
			if v.Host.String() == routerIP.String() {
				switch v.Port {
				case 53:
					foundRouterDNS = true
				case 80:
					foundRouterHttp = true
				}
			}
		}
	}

	if err = stream.Wait(); err != nil {
		t.Fatalf("Testing: Error while scanning network %s: %v\n", r.Network, err)
	}

	t.Logf("Elapsed time: %v", time.Since(startTime))

	if foundRouter && foundRouterHttp && foundRouterDNS {
		return
	}
	t.Errorf("At least one condition was not met:\n"+
		"Router found: %t\n"+
		"Router HTTP found: %t\n"+
		"Router DNS found: %t\n", foundRouter, foundRouterHttp, foundRouterDNS)
}

func TestScan_Docker_Home_LocalIPv4_ARP(t *testing.T) {
	if os.Getenv("SCAN_TEST_ENV") != "DOCKER_HOME_BRIDGE" {
		t.Skip("Testing: Skipping...")
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
	r.Ports = []uint16{22, 80, 6379}
	r.PortScanTechniques = rule.PortsScanTechniques{Vav: true}

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

	startTime := time.Now()

	stream, err := Scan(r)
	if err != nil {
		t.Fatalf("Testing: Scan start error: %v", err)
	}

	for f := range stream.Findings {
		switch v := f.(type) {
		case Host:
			hosts = append(hosts, v)
			switch {
			case v.IP.Equal(selfIP):
				foundSelf = true
			case v.IP.Equal(routerIP):
				foundRouter = true
			}
		case Port:
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
	t.Logf("Elapsed time: %v", time.Since(startTime))
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

func TestScan_Vav_CloudRange_HTTP80_AllEnv(t *testing.T) {
	_, targetNet, err := net.ParseCIDR("1.1.1.128/25")
	if err != nil {
		t.Fatalf("Unable to parse target CIDR: %v", err)
	}
	var r rule.Rule

	r.Network = *targetNet
	r.PortScanTechniques = rule.PortsScanTechniques{Vav: true}
	r.Ports = []uint16{80}
	r.Options.Pps = 64
	rule.AutocompleteRule(&r)

	hostHTTP := make(map[string]bool, 256)

	startTime := time.Now()

	stream, err := Scan(r)
	if err != nil {
		t.Fatalf("Scan start error: %v", err)
	}

	for f := range stream.Findings {
		switch v := f.(type) {
		case Host:
			if _, ok := hostHTTP[v.IP.String()]; !ok {
				hostHTTP[v.IP.String()] = false
			}
		case Port:
			if v.Port == 80 {
				if _, ok := hostHTTP[v.Host.String()]; ok {
					hostHTTP[v.Host.String()] = true
				}
			}
		}
	}

	if err := stream.Wait(); err != nil {
		t.Fatalf("Error while scanning network %s: %v", r.Network, err)
	}
	t.Logf("Elapsed time: %v", time.Since(startTime))
	maxFailures := 5

	failures := 0
	missingHosts := make([]string, 0, 128)
	missingPorts := make([]string, 0, 128)

	var walk func(int)
	walk = func(oct int) {
		if oct > 255 {
			return
		}
		ip := fmt.Sprintf("1.1.1.%d", oct)
		if ok, seen := hostHTTP[ip]; !seen {
			t.Logf("%s: host not found", ip)
			missingHosts = append(missingHosts, ip)
			failures++
		} else if !ok {
			t.Logf("%s: host found, port 80 not responding", ip)
			missingPorts = append(missingPorts, ip)
			failures++
		}
		walk(oct + 1)
	}
	walk(128)

	t.Logf("Checked 1.1.1.128/25 (128..255): failures=%d (limit=%d). Missing hosts=%d, missing ports=%d",
		failures, maxFailures, len(missingHosts), len(missingPorts))

	if failures > maxFailures {
		t.Fatalf("Too many issues: %d > %d\nMissing hosts: %v\nMissing TCP/80: %v",
			failures, maxFailures, missingHosts, missingPorts)
	}
}

func TestScan_Pps_Docker_Home_Host(t *testing.T) {
	if os.Getenv("SCAN_TEST_ENV") != "DOCKER_HOME_BRIDGE" {
		t.Skip("Testing: Skipping...")
	}

	_, targetNetwork, err := net.ParseCIDR(os.Getenv("TARGET_NETWORK"))
	if err != nil {
		t.Fatalf("Testing: Unable to parse target CIDR: %v", err)
	}

	var r rule.Rule
	r.Network = *targetNetwork

	r.Ports = []uint16{80}

	r.PortScanTechniques = rule.PortsScanTechniques{Vav: true}

	r.Options.Pps = 512

	r.Options.NoHostDiscovery = true

	rule.AutocompleteRule(&r)

	start := time.Now()

	stream, err := Scan(r)
	if err != nil {
		t.Fatalf("Testing: Scan start error: %v", err)
	}

	for range stream.Findings {
	}

	if err = stream.Wait(); err != nil {
		t.Fatalf("Testing: Error while scanning network %s: %v\n", r.Network, err)
	}

	elapsed := time.Since(start)
	elapsedSec := elapsed.Seconds()

	const expectedSec = 128.0
	const toleranceSec = 2.0

	diff := math.Abs(elapsedSec - expectedSec)

	t.Logf("Testing: PPS timing check: elapsed=%.3fs expected=%.3fs ±%.3fs (diff=%.3fs)",
		elapsedSec, expectedSec, toleranceSec, diff)

	if diff > toleranceSec {
		t.Fatalf("Testing: PPS timing mismatch. Took %.3fs, expected %.3fs ± %.3fs",
			elapsedSec, expectedSec, toleranceSec)
	}
}

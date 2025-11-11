package main

// Package vaverka provides a high-performance, stateless network scanning
// engine backed by vectored I/O and Layer 2 packet processing.
//
// This package is intended for users who want to embed Vavёrka as a library
// rather than use the CLI. For most use cases you only need two packages:
//
//   - github.com/Andrey-Yurevich/Vaverka/rule
//   - github.com/Andrey-Yurevich/Vaverka/scanner
//
// The CLI syntax described in the README is directly reflected in the Rule
// structure and options documented here.
//
// # Quickstart
//
// The minimal workflow is:
//
//   1. Construct a rule.Rule describing what to scan.
//   2. Call rule.AutocompleteRule(&r) to fill required defaults.
//   3. Call scanner.Scan(r) to start the scan.
//   4. Read Hosts/Ports from stream.Findings.
//   5. Call stream.Wait() to wait for completion and check for errors.
//
// Example:
//
//   package main
//
//   import (
//       "fmt"
//       "net"
//       "os"
//
//       "github.com/Andrey-Yurevich/Vaverka/rule"
//       "github.com/Andrey-Yurevich/Vaverka/scanner"
//   )
//
//   func main() {
//       // Define target network (required)
//       _, netCIDR, err := net.ParseCIDR("192.168.1.0/24")
//       if err != nil {
//           fmt.Fprintf(os.Stderr, "failed to parse CIDR: %v\n", err)
//           os.Exit(1)
//       }
//
//       r := rule.Rule{
//           Network: *netCIDR,
//           // All other fields are optional; see AutocompleteRule note below.
//       }
//
//       // IMPORTANT: always call AutocompleteRule.
//       // It fills defaults for options, techniques, ports, router, etc.
//       // This allows you to keep your code minimal and avoid missing
//       // required attributes.
//       rule.AutocompleteRule(&r)
//
//       stream, err := scanner.Scan(r)
//       if err != nil {
//           fmt.Fprintf(os.Stderr, "scan start error: %v\n", err)
//           os.Exit(1)
//       }
//
//       for f := range stream.Findings {
//           switch v := f.(type) {
//           case scanner.Host:
//               fmt.Printf("Host: %s (%s) state=%s via=%s\n",
//                   v.IP, v.FQDN, v.State, v.Technique)
//           case scanner.Port:
//               fmt.Printf("Port: %s:%d/%s state=%s service=%s\n",
//                   v.Host, v.Port, v.Protocol, v.State, v.Service)
//           }
//       }
//
//       if err := stream.Wait(); err != nil {
//           fmt.Fprintf(os.Stderr, "scan error: %v\n", err)
//           os.Exit(1)
//       }
//   }
//
// # Rule model
//
// The rule.Rule type is the core configuration object.
//
// Only Network is strictly required. All other fields are optional.
//
// It is strongly recommended to call rule.AutocompleteRule(&r) before
// passing a Rule to scanner.Scan. AutocompleteRule:
//
//   - sets a default port list (CommonPorts) if no ports or ranges are provided,
//   - enables the Vav (custom SYN) technique if no scan techniques are set,
//   - selects an appropriate routing strategy based on IP family, prefix size
//     and whether the target is IPv4, IPv6, host-range or link-local,
//   - sets a default timeout if none is provided.
//
// AutocompleteRule never overwrites values explicitly set by the user;
// it only fills missing essentials so you don't have to specify everything
// from scratch.
//
// Fields:
//
//   type Rule struct {
//       // FQDN is an optional label for the target. In library usage it is not
//       // used for resolution: if you need to scan a hostname, you must resolve
//       // it yourself and put the resulting prefix into Network.
//       //
//       // If FQDN is set, it will be propagated to scanner.Host in findings.
//       FQDN string
//
//       // Network is the target network or host (CIDR or single address).
//       // This is the only mandatory field.
//       Network net.IPNet
//
//       // Ports is a list of individual ports to scan.
//       // Mirrors the CLI's explicit port list semantics.
//       Ports []uint16
//
//       // PortsRanges is a list of inclusive port ranges.
//       // Mirrors the "start-end" range syntax from the CLI.
//       PortsRanges []PortsRange
//
//       // PortScanTechniques enables scan types:
//       //   Vav (custom SYN), Syn (classic SYN), Udp (UDP probe).
//       // These are equivalent to the scan technique flags used in the CLI.
//       PortScanTechniques PortsScanTechniques
//
//       // Options contains per-rule behaviour such as timeouts, PPS, routing
//       // mode and discovery settings. Defaults are filled by AutocompleteRule.
//       Options Options
//   }
//
// # Scan techniques
//
// The PortsScanTechniques struct corresponds to the scan modes described in
// the CLI documentation:
//
//   type PortsScanTechniques struct {
//       Syn bool // classic TCP SYN scan
//       Udp bool // UDP probe (usually low signal; use with care)
//       Vav bool // Vavёrka custom SYN scan (default in CLI)
//   }
//
// In most cases you should enable exactly one technique per rule. If all fields
// are false, AutocompleteRule will select a default.
//
// # Ports and ranges
//
// Ports and PortsRanges match the CLI behaviour:
//
//   type PortsRange struct {
//       Start uint16
//       End   uint16
//   }
//
// If you leave both Ports and PortsRanges empty and run AutocompleteRule,
// a default set of common ports will be used.
//
// # Options
//
// Options configures low-level scanning behaviour. It mirrors the CLI options.
//
//   type Options struct {
//       Timeout                     time.Duration
//       Router                      func([]netlink.Route, *net.IPNet, netlink.RouteGetOptions) ([]*router.IpRangeRouteContext, error)
//       IpV6MulticastInterfaceIndex int
//       Shuffle                     bool
//       NoHostDiscovery             bool
//       NoIpV6Multicast             bool
//       Pps                         uint64
//   }
//
// Typical usage patterns:
//
//   - Set Pps for per-rule rate limits; combine with a global limiter in your
//     application if needed.
//   - Use NoHostDiscovery to skip ARP/ICMP discovery and scan all targets
//     directly.
//   - Use NoIpV6Multicast when scanning link-local IPv6 ranges in environments
//     where multicast is blocked.
//   - Leave Router nil and let AutocompleteRule choose the recommended routing
//     strategy.
//
// # Results and Stream
//
// The scanner returns a Stream, which provides a channel of findings and a
// Wait method:
//
//   type Stream struct {
//       Findings <-chan ScanFinding
//       Wait     func() error
//   }
//
// Findings are reported as concrete types:
//
//   type Host struct {
//       IP        net.IP
//       Network   net.IPNet
//       Mac       net.HardwareAddr
//       FQDN      string
//       State     string
//       Technique string
//   }
//
//   type Port struct {
//       Host     net.IP
//       Service  string
//       State    string
//       Protocol string
//       Port     uint16
//   }
//
// Your code should:
//
//   - range over stream.Findings until the channel is closed,
//   - type-switch on scanner.Host and scanner.Port,
//   - call stream.Wait() afterwards to ensure all workers have finished and
//     to get the final error (if any).
//
// # Recommended usage
//
//   - Always set Rule.Network correctly (CIDR or single-IP).
//   - Optionally set FQDN if you want it echoed in Host results.
//   - Always call rule.AutocompleteRule(&r) unless you fully manage all fields
//     yourself; it helps avoid missing required defaults.
//   - You may fully configure Ports, techniques and Options manually, but
//     AutocompleteRule is designed to safely complement, not override, your
//     choices.
//   - Treat output as a stream of events and perform deduplication on your side
//     if required.
//
// ⚠️  Note: Vavёrka is stateless and does not track already discovered ports or
// hosts. Some remote services retransmit responses (especially TCP ACKs), so
// duplicates are normal and should always be filtered by the consumer.
//
//   - Refer to the README for CLI examples; the same concepts map directly to
//     the Rule and Options structures here.

# Vavёrka — The Fastest Vector Network Scanner

[![License](https://img.shields.io/github/license/Andrey-Yurevich/Vaverka.svg)](https://github.com/Andrey-Yurevich/Vaverka/blob/develop/LICENSE)
![Tests](https://github.com/Andrey-Yurevich/Vaverka/actions/workflows/tests.yml/badge.svg?branch=develop)
![Latest Version](https://img.shields.io/github/v/release/Andrey-Yurevich/Vaverka?sort=semver)
[![Go Reference](https://pkg.go.dev/badge/github.com/Andrey-Yurevich/Vaverka.svg)](https://pkg.go.dev/github.com/Andrey-Yurevich/Vaverka)

---

**Vavёrka** is a portable, high-performance network scanner that uses **Vectorized I/O** and a **custom routing system** for packet generation and transmission — dramatically increasing scan speed and reducing CPU and memory usage.  
It operates at **Layer 2** and supports both **IPv4** and **IPv6** scanning.  

Vavёrka works in two modes:
1. **Command-line utility**
2. **API mode**

---

## Table of Contents
- [Quickstart](#quickstart)
  - [CLI](#cli)
  - [Golang API](#golang)
  - [Docker](#docker)
- [Quick Examples](#quick-examples)
- [CLI Usage](#cli-usage)
  - [Flags](#global-flags)
  - [Rule structure](#rule-positional-argument-syntax)
    - [Targets](#target-field--possible-values)
    - [Ports](#ports-field--possible-values)
    - [Scan techniques](#scan-techniques-field--possible-values)
    - [Options](#options-field--possible-values)
- [API Usage (Golang)](#api-usage-golang)
- [Architecture](#architecture)
- [Benchmarks](#benchmarks)
- [Disclaimer](#disclaimer)
- [Support](#support)

---

## Quickstart
### CLI

Install Vavёrka binary:

```shell
VERSION=$(curl -s https://api.github.com/repos/Andrey-Yurevich/Vaverka/releases/latest | grep tag_name | cut -d '"' -f 4)

sudo curl -L -o /usr/local/bin/vaverka \
  "https://github.com/Andrey-Yurevich/Vaverka/releases/download/${VERSION}/vaverka-linux-$(uname -m)"

sudo chmod +x /usr/local/bin/vaverka
```

#### Command structure:

```shell
vaverka "<target>:<ports>:<scan_techniques>:<options>"
```

Example — discover live hosts in `192.168.1.0/24` and scan the 32 most common ports:

```shell
vaverka 192.168.1.0/24
```

### Golang

You can also use Vavёrka directly in your Go application.
For example, scanning a local IPv6 network:

```go
package main

import (
	"fmt"
	"net"
	"os"

	"github.com/Andrey-Yurevich/Vaverka/rule"
	"github.com/Andrey-Yurevich/Vaverka/scanner"
)

func main() {
	var r rule.Rule

	// Target network (link-local IPv6 /64)
	_, mynet, err := net.ParseCIDR("fe80::/64")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse CIDR: %v\n", err)
		os.Exit(1)
	}
	r.Network = *mynet

	// Interface to send multicast packets
	iface, err := net.InterfaceByName("wlan0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get interface: %v\n", err)
		os.Exit(1)
	}
	r.Options.IpV6MulticastInterfaceIndex = iface.Index

	// Autocomplete rule with default options
	rule.AutocompleteRule(&r)

	// Start scanning
	stream, err := scanner.Scan(r)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while starting scan of %s: %v\n", r.Network, err)
		os.Exit(1)
	}

	// Print results
	for f := range stream.Findings {
		switch v := f.(type) {
		case scanner.Host:
			fmt.Println(v)
		case scanner.Port:
			fmt.Println(v)
		}
	}

	// Wait for scan to complete
	if err = stream.Wait(); err != nil {
		fmt.Fprintf(os.Stderr, "Error while scanning %s: %v\n", r.Network, err)
	}
}
```

### Docker

Vavёrka runs only on **Linux**, but you can use Docker if you’re on **macOS** or **Windows**.
Make sure to include `--net host`, otherwise the behavior may be unpredictable:

```shell
docker run --net host yurevich/vaverka example.com
```

---

## Quick Examples

Quick examples to help you understand Vavёrka’s rule syntax and common options. See the CLI reference below for full details.

Scan top 32 common ports for each *reachable* host in the network:

```shell
sudo vaverka 192.168.0.0/16
```

Scan ports `22`, `53`, `80` for reachable hosts in the network:

```shell
sudo vaverka 192.168.0.0/16:22,53,80
```

Scan the top 32 ports for **every IP** in the network (skip host discovery):

```shell
sudo vaverka 192.168.0.0/16:::no-host-discovery=true
```

Multicast link-local discovery on `wlan0` and shuffle the port order:

```shell
sudo vaverka "[fe80::%wlan0]:::shuffle=true"
```

Scan the top 32 ports in a small IPv6 range (example /121):

```shell
sudo vaverka "[2606:4700:4700:0000:0000:0000:0000:0000/121]"
```

Find IPv4 and IPv6 services running on the local host:

```shell
sudo vaverka 127.0.0.1 "[::1]"
```

Run Vav (custom SYN) **and** UDP probes for all IPs in `10.0.0.0/8`, skip discovery, target ports `22,80,6379`, overall rate 200 000 PPS:

```shell
sudo vaverka --pps 200000 10.0.0.0/8:22,80,6379:vu:no-host-discovery=true,pps=200000
```

> Note: UDP probing (`u`) is often unreliable — use only when you expect a UDP service that will respond.

Combined example — multiple rules in one command:

* scan `192.168.1.0/24` for ports `1521,5432,22,80` using **SYN** (`s`), router mode `simple`, per-rule `pps=10000`
* scan domain `example.com` for ports `80,443` using both `v` (custom SYN) and `s` (SYN)
* link-local scan on `eth0` (top 32 ports, `pps=10000`)

```shell
sudo vaverka --pps 20000 \
  192.168.1.0/24:1521,5432,22,80:s:router=simple,pps=10000 \
  example.com:80,443:vs \
  "[fe80::%wlan0]:::pps=10000"
```

## CLI Usage

This section describes how to run **Vavёrka** from the command line: flags, positional rules, and the rule syntax.
If a sentence below seems unclear, it has been rephrased for clarity.

---

### Synopsis

Vavёrka accepts one or more **positional arguments** (scan rules) and a small set of global **flags**:

```
vaverka [flags] <rule1> <rule2> ...
```

#### Global flags

* `--pps <value>`
  Global packet-per-second cap for the entire Vavёrka instance. The **sum** of per-rule sending rates will be clamped to this value. Use this when you run multiple rules in parallel and want to limit overall outgoing packet rate on the host.

  **Examples**

  ```shell
  # Global PPS = 10000, rule requests 20000 -> effective rate = 10000
  vaverka --pps 10000 10.0.0.0/8:::pps=20000

  # Two rules each request 15000, global cap is 10000 -> effective total rate = 10000
  vaverka --pps 10000 \
    10.0.0.0/8:::pps=15000 \
    172.0.0.0/8:::pps=15000
  ```

  Use-case: run many rules without exceeding host/network capacity.

* `--threads <N>`
  Maximum number of worker goroutines (concurrency) Vavёrka will spawn.
  Default: `runtime.GOMAXPROCS(0)` — the number of available OS threads on the host.

  We generally **do not** recommend changing the default unless you know what you're doing. See Go documentation for goroutines and concurrency for background: [https://go.dev/doc/](https://go.dev/doc/)

### Rule (positional argument) syntax

Each positional argument is a **scan rule**. You may pass several rules — Vavёrka runs them concurrently.

```
<target>:<ports>:<scan_techniques>:<options>
```

Only `target` is mandatory; other fields may be empty. Examples:

* `192.168.1.0/24`
* `example.com:80`
* `[fe80::%eth0]`

Below are the allowed `target` forms and their behavior.

#### `target` field — possible values

1. **FQDN** (domain name)
   Example: `example.com`

2. **IPv4 address**
   Example: `192.168.1.1`

3. **IPv4 CIDR**
   Example: `192.168.0.0/16`
   *Note:* Make sure network and mask are correct. An invalid CIDR may cause unexpected scanning behavior.

4. **IPv6 address**
   IPv6 addresses **must** be enclosed in square brackets. Both compressed and full forms are accepted.

  * Compressed: `[2606:4700:4700::1001]`
  * Full:      `[2606:4700:4700:0000:0000:0000:0000:1001]`

5. **IPv6 CIDR**

   IPv6 CIDRs must also be enclosed in square brackets, e.g.:
   `[2606:4700:4700::/121]` or full form `[2606:4700:4700:0000:.../121]`

6. **Link-local IPv6 (multicast-ping trigger)**
   Format: `[fe80::%<interface>]` — for example: `[fe80::%eth0]`

   When a `target` matches the regex `^fe80::.*` (inside brackets and with `%<iface>`), Vavёrka performs a **special multicast-ping discovery**:

  * It sends an ICMP ping to the link-local all-nodes multicast address on the specified interface.
  * Hosts that reply are treated as live and then port-scanned.

   **Important notes**

  * The string **must** be exactly in the format `[fe80::%<interface>]`. Otherwise, parsing fails.
  * Multicast-based discovery **usually does not work** in cloud virtual networks (AWS, Azure, GCP, Vultr, etc.). It typically works on physical/local LANs (home/lab networks) where L2 multicast is supported.  You can use the option `no-ipv6-multicast=true` to disable sending multicast packets in such networks and force a full recursive scan of the address space; however, this is pointless if your network prefix is longer than /103.

7. **Local / host interface addresses**
   If Vavёrka detects that a `target` resolves to a local interface (i.e. the route does not leave the host), it will use a local discovery mode (introspection) instead of active network probing — e.g. enumerating listening sockets on the host that match the requested address range. This is useful for scanning `127.0.0.1` or addresses assigned to local interfaces.

#### `ports` field — possible values

You may specify which ports to scan, or leave the field empty. If omitted, Vavёrka will scan the 32 most common ports ([full list here](https://github.com/Andrey-Yurevich/Vaverka/blob/a4e93f97e76305b925f5f6bfaec24d2a241349ef/constants/common.go#L147)).

Accepted formats:

* **Single ports** (comma-separated):
  `22,80,443,1521`

* **Port ranges**:
  `1000-2000`

* **Mix of single ports and ranges**:
  `22,80,443,1521,1000-2000`

Example rule:

```shell
vaverka 192.168.1.0/24:22,80,443,1521,1000-2000
```
#### `Scan techniques` field — possible values

Vavёrka supports **three** scan techniques. Specify them in the `scan_techniques` field using short codes (examples below).

1. **Vav** (`v`) — *custom SYN* (default)
   Sends a customized TCP SYN: a few TCP flags are set and a small TCP payload is included. This can sometimes help bypass very simple network filters or packet-modifying devices. **This is the default technique.**

2. **SYN** (`s`) — *classic SYN*
   Sends a plain TCP SYN (empty TCP payload) — the classic half-open TCP scan.

3. **UDP** (`u`) — *UDP probe*
   Sends a UDP datagram containing the ASCII string `"vaverka"`. **Not recommended** in most cases: many UDP services ignore unexpected payloads, so this method often yields no responses and can just waste network capacity.

You may combine multiple techniques in one rule (e.g. `vu`), but that is usually inefficient and not recommended.

##### Examples

```shell
# For discovered hosts, run Vav (custom SYN) and UDP probes
vaverka 10.0.0.0/8::vu

# For discovered hosts, run plain TCP SYN scan
vaverka 172.0.1.0/16::s
```

##### Notes

* `v` is the default because it often improves discovery when simple middleboxes are present.
* Use `u` only when you have a reason to believe the target UDP service will respond to arbitrary probes.
* Combining techniques will increase traffic and complexity; prefer a single appropriate technique per rule.

#### `Options` field — possible values

Vavёrka supports a set of per-rule options (passed in the `options` field as `key=value` pairs). Below are the commonly used options and their exact behavior.

##### `timeout`

* **What it is:** Response-collection timeout (seconds) used both for host discovery replies and for port-scan replies.
* **Default:** `2` (seconds)
* **Behavior:** After Vavёrka finishes sending discovery probes (ARP/ICMP), it waits `timeout` seconds for discovery replies. After port scanning completes, it again waits `timeout` seconds for late port replies. With the default value this results in up to `2 + 2 = 4` seconds of waiting (one `timeout` after discovery, one `timeout` after port scanning).

##### `router`

* **What it is:** Routing mode. Two modes are available: `smart` (default) and `simple`.
* **Default:** `smart`
* **When to use:**

  * `smart` is the default and should be used for normal/routed networks — it attempts to pick the best path and routing behavior for the scanning task.
  * `simple` is a minimal fallback mode appropriate for very small or trivial networks or a single target address. Use `simple` if `smart` produces incorrect results.
* **More:** See the [Architecture](#architecture) section for details about the routing engine.

##### `shuffle`

* **What it is:** Randomizes port order before scanning.
* **Default:** `false`
* **Behavior:** Ports are shuffled **once** before the scan starts. The same shuffled port list is applied to every discovered host. Note that `shuffle` **does not** randomize the order of IP addresses — IP-order randomization would require significantly more memory and is intentionally not performed.

##### `no-host-discovery`

* **What it is:** Disable host discovery phase (ARP/ICMP).
* **Default:** `false`
* **Behavior:** When set to `true`, Vavёrka skips ARP/ICMP discovery and proceeds directly to port scanning. In this mode all packets are routed via the configured gateway (no link-local ARP/ICMP probing).

##### `no-ipv6-multicast`

* **What it is:** Disable IPv6 link-local multicast discovery (for `fe80::` targets).
* **Default:** `false`
* **Behavior:** When scanning link-local IPv6 targets (e.g. `[fe80::%eth0]`), this option prevents sending the multicast ping discovery probe. Use it when scanning link-local ranges in environments where multicast is blocked (cloud providers such as AWS/GCP/Azure, or other virtual networks).

##### `pps`

* **What it is:** Requested packets-per-second for the rule. This is a per-rule request; the actual sending rate will be clamped by the global `--pps` flag (if provided).
* **Default:** `4096`
* **Behavior:** Vavёrka attempts to honor the per-rule `pps` but will never exceed the global `--pps` cap. Use this to request a target rate per rule; control overall instance-wide rate with the `--pps` command-line flag.

---

## API Usage (Golang)

> Examples of using Vavёrka as a library, configuration of rules, and handling scan streams will be added here.

---

## Architecture


### Vectored I/O

Vavёrka is built on vectored I/O (scatter/gather I/O). While this approach is not trivial to implement or maintain, it delivers a big win when most packet bytes are repetitive. In a scanner, probes sent to different hosts share >90% of their layout; for TCP this typically varies only by destination IP, destination port, and checksums. Instead of rebuilding full buffers every time, we pre-build the common fragments once, treat them as templates, and pass the kernel pointers to those fragments.

With sendmmsg(), each message is described as a set of iovec fragments. The packet is assembled in kernel space from these fragments (one complete packet per message), and multiple messages are sent in a single syscall. In practice this works like a JIT-style packet builder in the kernel: we reuse templates in user space and rely on the kernel to stitch the fragments together at send time. The performance gain comes from template reuse and batching (fewer syscalls, less per-packet work) rather than reconstructing full buffers for every destination.


### Layer 2 (Ethernet) scanning

Unlike typical socket-based scanners that rely on the kernel's IP stack, Vavёrka opens **raw Ethernet sockets**.
This gives direct control over packet framing and eliminates the need for kernel-managed ARP resolution or routing lookups.

This design provides several advantages:

* **Bypass of ARP and connection tracking:** No kernel state is created for each target.
* **No per-host socket creation:** A single raw socket can transmit to millions of destinations.
* **No ARP table overflow:** Kernel ARP caches are typically limited to a few thousand entries.
* **Direct control of packet routing and rate limiting.**

This low-level approach makes Vavёrka highly scalable when scanning very large networks, but it also means that packet crafting and routing must be handled entirely in user space.


### Custom routing engine

Because Vavёrka operates at Layer 2, it cannot rely on the kernel's automatic routing decisions.
Instead, it implements its own **routing engine** that pre-loads the system's routing table and builds optimized sub-ranges of addresses.

For example, if the host routing table looks like:

```
192.168.0.0/16 dev eth0 scope link
192.168.65.0/24 dev eth1 scope link
```

Vavёrka internally constructs three scan segments:

```
192.168.0.0  – 192.168.64.255  → eth0
192.168.65.0 – 192.168.65.255  → eth1
192.168.66.0 – 192.168.255.255 → eth0
```

This approach minimizes per-address route lookups (which could otherwise reach millions of identical queries) and allows packets to be sent efficiently through the correct interface.

However, due to its complexity, route inference can behave incorrectly in some environments.
To mitigate this, Vavёrka provides two router modes:

| Mode              | Description                                                                                                                        |
|-------------------|------------------------------------------------------------------------------------------------------------------------------------|
| `smart` (default) | Uses the internal routing table aggregation for performance.                                                                       |
| `simple`          | Uses one route for the entire range, obtained via `ip route get <first IP>`. Recommended if `smart` produces inconsistent results. |


### Packet capture and BPF filtering

Vavёrka uses **libpcap** to capture incoming responses.
Before packet transmission begins, it compiles and attaches a **BPF (Berkeley Packet Filter)** to the selected interface, matching only relevant replies.

This reduces kernel-to-user traffic and improves efficiency when scanning high-speed networks.

> **Note:** Because Vavёrka operates outside the kernel's TCP state machine, the local host does not recognize the outbound SYN packets as part of an established flow.
> When SYN-ACK arrive, the kernel TCP stack interprets them as unsolicited and may respond with an **RST**.
> This behaviour is normal and expected for stateless scanners.


### Stateless design and deduplication

Vavёrka is a **stateless** scanner — it does not store intermediate connection state or port discovery results in memory.
This minimizes RAM usage, allowing large-scale parallel scans.

However, due to retransmissions from remote TCP stacks (which may resend ACKs if the handshake is incomplete), duplicate detections can occur.

It is **strongly recommended** to perform deduplication when processing results:

> Always deduplicate discovered hosts and ports — some TCP stacks retransmit acknowledgments, leading to duplicate detections.


### Summary

| Subsystem                 | Role                                                        | Key benefit                               |
|---------------------------|-------------------------------------------------------------|-------------------------------------------|
| **Vectored I/O**          | Efficient userland packet batching via `sendmmsg` + `iovec` | Reduces syscall count and CPU load        |
| **Raw Layer 2 sockets**   | Direct control over Ethernet frames                         | Avoids kernel routing and ARP overhead    |
| **Custom routing engine** | Route aggregation and per-interface segmentation            | Scales linearly across large networks     |
| **BPF filtering**         | Selective capture of relevant responses                     | Lowers CPU and memory overhead            |
| **Stateless core**        | No per-connection tracking                                  | Minimal memory footprint, high throughput |

## Benchmarks

### Test 1 — 192.168.0.0/16 (Vultr VPC)

**Stand**

- Network: local `192.168.0.0/16` (Vultr VPC)
- Known live hosts: `192.168.0.4`, `192.168.64.1`, `192.168.128.254`, `192.168.200.200`
- Open ports on each known host: `22, 80, 6379`
- Scan port list:
  `21,22,25,53,80,110,111,135,139,143,161,162,443,445,993,995,1433,1521,3306,3389,5060,5432,5672,6379,8000,8001,8080,8081,8443,8888,9090,9091,27017`
- Configured PPS: `2,000,000`

#### Commands used

```shell
# nmap
nmap -p21,22,25,53,80,110,111,135,139,143,161,162,443,445,993,995,1433,1521,3306,3389,5060,5432,5672,6379,8000,8001,8080,8081,8443,8888,9090,9091,27017 \
  -sS -n -T4 --min-rate 2000000 192.168.0.0/16

# masscan
masscan --rate=2000000 192.168.0.0/16 \
  -p21,22,25,53,80,110,111,135,139,143,161,162,443,445,993,995,1433,1521,3306,3389,5060,5432,5672,6379,8000,8001,8080,8081,8443,8888,9090,9091,27017

# Vaverka
vaverka --pps=2000000 192.168.0.0/16::v:pps=2000000
```


#### Total execution time

![Test 1 — Execution time breakdown](.doc_assets/test1_execution_time.png)

#### Memory and CPU utilization
![Test 1 — Memory and CPU utilization](.doc_assets/test1_cpu_mem.png)

#### Result summary
- **Vaverka**: ✅ found all hosts and all expected ports.
- **nmap**: ✅ found all hosts and all expected ports.
- **masscan**: ❌ did not discover any hosts or ports due to incorrect routing(traffic left via the wrong path).

### Test 2 — external IPv6 network (AWS)

**Stand**
- Network: `2a05:d012:1b2:6000:ec38:80b0:e280::/106` (4,194,304 addresses. Part of AWS IPv6 pool)
- Known live hosts count: 4
- Open ports (on each machine, port 22 and one of the following are open): `80, 3306, 5432, 6379`
- Scan port list:
  `21,22,25,53,80,110,111,135,139,143,161,162,443,445,993,995,1433,1521,3306,3389,5060,5432,5672,6379,8000,8001,8080,8081,8443,8888,9090,9091,27017`
- Configured PPS: `4096`

#### Commands used
```shell
#nmap
/usr/bin/time -v nmap -6 -d0 -p21,22,25,53,80,110,111,135,139,143,161,162,443,445,993,995,1433,1521,3306,3389,5060,5432,5672,6379,8000,8001,8080,8081,8443,8888,9090,9091,27017 -sS -n -T4 --min-rate 4096 --max-rate 4096 -oA nmap_equiv 2a05:d012:1b2:6000:ec38:80b0:e280::/106
#vaverka
vaverka [2a05:d012:1b2:6000:ec38:80b0:e280::/106]::v:no-ipv6-multicast=true
```
#### Total execution time

![Test 2 — Execution time breakdown](.doc_assets/test2_execution_time.png)

#### Memory and CPU utilization
![Test 2 — Memory and CPU utilization](.doc_assets/test2_cpu_mem.png)

#### Total packets sent and data volume
![Test 2 — Total packets sent and data volume](.doc_assets/test2_packets_data.png)

#### Result summary
- **Vaverka**: ✅ found all hosts and all expected ports.
- **nmap**: ✅ found all hosts and all expected ports.

### Test 3 — Pure TCP packets transmission speed
**Stand**

- Network: local `172.0.0.0/16` (AWS VPC)
- Configured PPS: `2,000,000`
#### Commands used

```shell
#nmap
nmap -p80 -n -Pn --min-rate 2000000 --max-rate 2000000 --max-retries 0 --initial-rtt-timeout 100ms --max-rtt-timeout 500ms --max-scan-delay 0 --min-parallelism 200 172.0.0.0/16
#vaverka
vaverka --pps 2000000 172.0.0.0/16:80:v:no-host-discovery=true,pps=2000000
#masscan
masscan -p80 172.0.0.0/16 --rate 2000000
```
![pps speed](./.doc_assets/test3_pps_only.png)
---

## Disclaimer

The author assumes **no responsibility** for the reliability, safety, or correctness of this application, nor for **how, where, or by whom** it is used.
By using this software, you acknowledge that you **fully understand what you are doing** and accept all possible consequences of your actions.
Use it responsibly — **users are strongly discouraged from acting like idiots.**
---

## Support

I’ve invested a lot of time and effort into **Vavёrka**, and I’d greatly appreciate your support and feedback:

* ⭐ Star the project on [GitHub](https://github.com/Andrey-Yurevich/Vaverka)
* 🧩 Contribute by submitting pull requests or reporting issues
* 💬 Share ideas and feedback in Discussions
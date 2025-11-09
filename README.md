# Vavёrka — The Fastest Vector Network Scanner

[![License](https://img.shields.io/github/license/Andrey-Yurevich/Vaverka.svg)](https://github.com/Andrey-Yurevich/Vaverka/blob/main/LICENSE)
![Tests](https://github.com/Andrey-Yurevich/Vaverka/actions/workflows/tests.yml/badge.svg?branch=develop)
![Latest Version](https://img.shields.io/github/v/release/Andrey-Yurevich/Vaverka?sort=semver)

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
  - [Golang API](#golang-api)
  - [Docker](#docker)
- [CLI Usage](#cli-usage)
- [API Usage (Golang)](#api-usage-golang)
- [Capabilities and Options](#capabilities-and-options)
- [Architecture](#architecture)
- [Benchmarks](#benchmarks)
- [Disclaimer](#disclaimer)
- [Support](#support)

---

## Quickstart
### CLI

Install Vavёrka binary:

```bash
VERSION=$(curl -s https://api.github.com/repos/Andrey-Yurevich/Vaverka/releases/latest | grep tag_name | cut -d '"' -f 4)

curl -L -o /usr/local/bin/vaverka \
  "https://github.com/Andrey-Yurevich/Vaverka/releases/download/${VERSION}/vaverka-linux-$(uname -m)"

chmod +x /usr/local/bin/vaverka
```

#### Command structure:

```bash
vaverka "<target>:<ports>:<scan_types>:<options>"
```

Example — discover live hosts in `192.168.1.0/24` and scan the 32 most common ports:

```bash
vaverka 192.168.1.0/24
```

### Golang API

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

```bash
docker run --net host yurevich/vaverka example.com
```

---

## CLI Usage

> Detailed CLI argument descriptions, scan types, and configuration examples will be placed here.

---

## API Usage (Golang)

> Examples of using Vavёrka as a library, configuration of rules, and handling scan streams will be added here.

---

## Capabilities and Options

> Overview of supported protocols, port scanning modes, and customization parameters.

---

## Architecture

> Technical details of Vavёrka’s core — vectorized IO engine, routing system, and concurrency model.

---

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

```bash
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
```bash
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
![Test 2 — Total packets sent and data bolume](.doc_assets/test2_packets_data.png)

#### Result summary
- **Vaverka**: ✅ found all hosts and all expected ports.
- **nmap**: ✅ found all hosts and all expected ports.

### Test 3 — Pure TCP packets transmission speed
**Stand**

- Network: local `172.0.0.0/16` (AWS VPC)
- Configured PPS: `2,000,000`
#### Commands used

```bash
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
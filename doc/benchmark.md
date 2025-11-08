# Benchmark of Vaverka and comparison with nmap and masscan

## Test 1 — 192.168.0.0/16 (Vultr VPC)

**Stand**

- Network: local `192.168.0.0/16` (Vultr VPC)
- Known live hosts: `192.168.0.4`, `192.168.64.1`, `192.168.128.254`, `192.168.200.200`
- Open ports on each known host: `22, 80, 6379`
- Scan port list:
  `21,22,25,53,80,110,111,135,139,143,161,162,443,445,993,995,1433,1521,3306,3389,5060,5432,5672,6379,8000,8001,8080,8081,8443,8888,9090,9091,27017`
- Configured PPS: `2,000,000`

### Commands used

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


### Total execution time

![Test 1 — Execution time breakdown](images/test1_execution_time.png)

### Memory and CPU utilization
![Test 1 — Memory and CPU utilization](images/test1_cpu_mem.png)

### Result summary
- **Vaverka**: ✅ found all hosts and all expected ports.
- **nmap**: ✅ found all hosts and all expected ports.
- **masscan**: ❌ did not discover any hosts or ports due to incorrect routing(traffic left via the wrong path).

## Test 2 — external IPv6 network (AWS)

**Stand**
- Network: `2a05:d012:1b2:6000:ec38:80b0:e280::/106` (4,194,304 addresses. Part of AWS IPv6 pool)
- Known live hosts count: 4
- Open ports (on each machine, port 22 and one of the following are open): `80, 3306, 5432, 6379`
- Scan port list:
  `21,22,25,53,80,110,111,135,139,143,161,162,443,445,993,995,1433,1521,3306,3389,5060,5432,5672,6379,8000,8001,8080,8081,8443,8888,9090,9091,27017`
- Configured PPS: `4096`

### Commands used
```bash
#nmap
/usr/bin/time -v nmap -6 -d0 -p21,22,25,53,80,110,111,135,139,143,161,162,443,445,993,995,1433,1521,3306,3389,5060,5432,5672,6379,8000,8001,8080,8081,8443,8888,9090,9091,27017 -sS -n -T4 --min-rate 4096 --max-rate 4096 -oA nmap_equiv 2a05:d012:1b2:6000:ec38:80b0:e280::/106
#vaverka
vaverka [2a05:d012:1b2:6000:ec38:80b0:e280::/106]::v:no-ipv6-multicast=true
```
### Total execution time

![Test 2 — Execution time breakdown](images/test2_execution_time.png)

### Memory and CPU utilization
![Test 2 — Memory and CPU utilization](images/test2_cpu_mem.png)

### Total packets sent and data volume
![Test 2 — Total packets sent and data bolume](images/test2_packets_data.png)

### Result summary
- **Vaverka**: ✅ found all hosts and all expected ports.
- **nmap**: ✅ found all hosts and all expected ports.

## Test 3 — Pure TCP packets transmission speed
**Stand**

- Network: local `172.0.0.0/16` (AWS VPC)
- Configured PPS: `2,000,000`
### Commands used

```bash
#nmap
nmap -p80 -n -Pn --min-rate 2000000 --max-rate 2000000 --max-retries 0 --initial-rtt-timeout 100ms --max-rtt-timeout 500ms --max-scan-delay 0 --min-parallelism 200 172.0.0.0/16
#vaverka
vaverka --pps 2000000 172.0.0.0/16:80:v:no-host-discovery=true,pps=2000000
#masscan
masscan -p80 172.0.0.0/16 --rate 2000000
```
![pps speed](images/test3_pps_only.png)
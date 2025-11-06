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
/usr/bin/time -v nmap -p21,22,25,53,80,110,111,135,139,143,161,162,443,445,993,995,1433,1521,3306,3389,5060,5432,5672,6379,8000,8001,8080,8081,8443,8888,9090,9091,27017 \
  -sS -n -T4 --min-rate 2000000 192.168.0.0/16

# masscan
/usr/bin/time -v masscan --rate=2000000 192.168.0.0/16 \
  -p21,22,25,53,80,110,111,135,139,143,161,162,443,445,993,995,1433,1521,3306,3389,5060,5432,5672,6379,8000,8001,8080,8081,8443,8888,9090,9091,27017

# Vaverka
/usr/bin/time -v /root/Vaverka/Vaverka --pps=2000000 192.168.0.0/16::v:pps=2000000
```


### Total execution time

![Test 1 — Execution time breakdown](images/test1_execution_time.png)

### Memory and CPU utilization:
![Test 1 — Execution time breakdown](images/test1_cpu_mem.png)

### Result summary
- **Vaverka**: ✅ found all hosts and all expected ports.
- **nmap**: ✅ found all hosts and all expected ports.
- **masscan**: ❌ did not discover any hosts or ports due to incorrect routing(traffic left via the wrong path).


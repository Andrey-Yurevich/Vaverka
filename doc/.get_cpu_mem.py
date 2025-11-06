#!/usr/bin/env python3
import matplotlib.pyplot as plt
import numpy as np

# Order: Vaverka, nmap, masscan
tools = ["Vaverka", "nmap", "masscan"]

# CPU % (“Percent of CPU this job got”)
cpu = np.array([6, 37, 32])

# Memory (kB -> MB) using your time -v values in same order
mem_kb = np.array([13824, 33596, 42264])
mem_mb = mem_kb / 1024.0

x = np.arange(len(tools))
width = 0.35

fig, ax1 = plt.subplots(figsize=(6, 4))

# CPU bars (left Y axis)
cpu_bars = ax1.bar(x - width/2, cpu, width,
                   color="#2196F3", label="CPU usage (%)")
ax1.set_ylabel("CPU usage (%)", color="#2196F3")
ax1.set_ylim(0, max(cpu) * 1.3)
ax1.tick_params(axis="y", labelcolor="#2196F3")

# Memory bars (right Y axis)
ax2 = ax1.twinx()
mem_bars = ax2.bar(x + width/2, mem_mb, width,
                   color="#F44336", label="Memory usage (MB)")
ax2.set_ylabel("Memory usage (MB)", color="#F44336")
ax2.set_ylim(0, max(mem_mb) * 1.3)
ax2.tick_params(axis="y", labelcolor="#F44336")

# X axis & title
ax1.set_xticks(x)
ax1.set_xticklabels(tools)
ax1.set_title("Test 1 - CPU and Memory usage")

# Labels on bars
for bar in cpu_bars:
    h = bar.get_height()
    ax1.text(bar.get_x() + bar.get_width()/2, h + 1,
             f"{h:.0f}%", ha="center", va="bottom",
             fontsize=8, color="#0D47A1")

for bar in mem_bars:
    h = bar.get_height()
    ax2.text(bar.get_x() + bar.get_width()/2, h + 0.5,
             f"{h:.1f} MB", ha="center", va="bottom",
             fontsize=8, color="#B71C1C")

# Correct legend: берём label только от двух серий
handles = [cpu_bars, mem_bars]
labels = [h.get_label() for h in handles]
ax1.legend(handles, labels, loc="upper left")

fig.tight_layout()
plt.savefig("images/test1_cpu_mem.png", dpi=200)
plt.show()
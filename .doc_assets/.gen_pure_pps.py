#!/usr/bin/env python3
import matplotlib.pyplot as plt
import numpy as np

# --- Data ---
tools = ["Vaverka", "masscan", "nmap"]

# PPS (packets per second)
pps = np.array([
    139554.94,  # Vaverka
    134269.62,  # masscan
    4859.30     # nmap
])

x = np.arange(len(tools))
width = 0.5

# --- Plot ---
fig, ax = plt.subplots(figsize=(7, 5))

bars = ax.bar(x, pps, width, color=["#2196F3", "#F44336", "#9E9E9E"])

ax.set_ylabel("Packets per second (PPS)")
ax.set_title("Scan throughput — PPS comparison")
ax.set_xticks(x)
ax.set_xticklabels(tools)
ax.set_ylim(0, max(pps) * 1.3)

# --- Labels on bars ---
for bar in bars:
    h = bar.get_height()
    ax.text(
        bar.get_x() + bar.get_width() / 2,
        h + max(pps) * 0.02,
        f"{h:,.0f}",
        ha="center",
        va="bottom",
        fontsize=10,
        color="#0D47A1"
    )

# --- Styling ---
ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)

fig.tight_layout()
plt.savefig(".doc_assets/test3_pps_only.png", dpi=200)
plt.show()
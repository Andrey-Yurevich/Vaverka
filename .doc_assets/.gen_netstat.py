#!/usr/bin/env python3
import matplotlib.pyplot as plt
import numpy as np

# --- Data ---
tools = ["Vaverka", "nmap"]


# number of packets expressed in *thousands*
packets_sent = np.array([4194.68, 25167.94])

data_mb = np.array([276, 1796])

x = np.arange(len(tools))
width = 0.35

fig, ax1 = plt.subplots(figsize=(6, 4))

# ---- Packets (левая ось) ----
bars1 = ax1.bar(x - width/2, packets_sent, width,
                color="#4CAF50", label="Packets sent (Thousands) ")
ax1.set_ylabel("Packets sent (thousands)", color="#4CAF50")
ax1.tick_params(axis="y", labelcolor="#4CAF50")
ax1.set_ylim(0, max(packets_sent) * 1.3)

# ---- Data volume (правая ось) ----
ax2 = ax1.twinx()
bars2 = ax2.bar(x + width/2, data_mb, width,
                color="#F44336", label="Data volume (MB)")
ax2.set_ylabel("Data volume (MB)", color="#F44336")
ax2.tick_params(axis="y", labelcolor="#F44336")
ax2.set_ylim(0, max(data_mb) * 1.3)

# ---- X axis & title ----
ax1.set_xticks(x)
ax1.set_xticklabels(tools)
ax1.set_title("Test 1 — Packets sent and data volume")

# ---- Labels on bars ----
for bar in bars1:
    h = bar.get_height()
    ax1.text(bar.get_x() + bar.get_width()/2, h + max(packets_sent) * 0.02,
             f"{h:,.2f}k", ha="center", va="bottom", fontsize=8, color="#1B5E20")

for bar in bars2:
    h = bar.get_height()
    ax2.text(bar.get_x() + bar.get_width()/2, h + max(data_mb) * 0.02,
             f"{h:.1f} MB", ha="center", va="bottom", fontsize=8, color="#B71C1C")

# ---- Legend ----
handles = [bars1, bars2]
labels = [h.get_label() for h in handles]
ax1.legend(handles, labels, loc="upper left")

fig.tight_layout()
plt.savefig(".doc_assets/test2_packets_data.png", dpi=200)
plt.show()
#!/usr/bin/env python3
import matplotlib.pyplot as plt
import numpy as np

# --- Data ---
tools = ["Vaverka", "nmap"]
elapsed = np.array([17.12, 109.65])
active = np.array([17.06, 109.65])
wait = elapsed - active

x = np.arange(len(tools))

# --- Plot setup ---
fig, ax = plt.subplots(figsize=(6, 5))

ax.bar(x, active, label="Active scan", color="#2196F3")
ax.bar(x, wait, bottom=active, label="Waiting", color="#BDBDBD")

ax.set_xticks(x)
ax.set_xticklabels(tools)
ax.set_ylabel("Time (minutes)")
ax.set_title("Test 2 - Execution time breakdown")

# --- Neat labels without arrows ---
for i, (a, w, total) in enumerate(zip(active, wait, elapsed)):
    # total time — above the top
    ax.text(i, total + 0.5, f"{total:.2f} minutes total",
            ha="center", va="bottom", fontsize=9, color="black")

    # active time — inside or just above green block
    y_pos_active = a / 2 if a > 0.8 else a + 0.3
    ax.text(i, y_pos_active, f"{a:.2f} minutes active",
            ha="center", va="center", fontsize=8, color="#0D47A1")

    # wait time — inside or just above yellow block
    if w > 0.05:
        y_pos_wait = a + w / 2 if w > 0.8 else a + w + 0.3
        ax.text(i, y_pos_wait, f"{w:.2f} minutes wait",
                ha="center", va="center", fontsize=8, color="#424242")

ax.legend()
ax.grid(axis="y", linestyle="--", alpha=0.4)
plt.margins(y=0.1)
plt.tight_layout()
plt.savefig(".doc_assets/test2_execution_time.png", dpi=200)
plt.show()
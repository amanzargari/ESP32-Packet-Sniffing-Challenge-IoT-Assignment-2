"""
CQ8 — Distribution of MQTT topic depth for PUBLISH messages directed to the
local broker in A.pcapng and B.pcapng.

For each capture we isolate PUBLISH messages (mqtt.msgtype == 3) whose
destination is the local broker:
    - A.pcapng: IPv4 loopback 127.0.0.1, TCP port 1883
    - B.pcapng: IPv6 loopback ::1,       TCP port 1883

Topic depth is computed as  (number of '/' in the topic) + 1, so that a topic
like "room1/device/temperature" has depth 3. The two distributions are drawn
side-by-side as a grouped bar chart and saved to cq8_histogram.png.

Usage:
    python3 cq8_plot.py        # expects A.pcapng and B.pcapng in the CWD
Requirements:
    - tshark on PATH (Wireshark CLI)
    - matplotlib, numpy
"""

import subprocess
from collections import Counter

import matplotlib.pyplot as plt
import numpy as np


def topic_depths(pcap: str, broker_filter: str) -> list[int]:
    """Return the topic depth of every PUBLISH to the local broker.

    Parameters
    ----------
    pcap : str
        Path to the capture file.
    broker_filter : str
        Wireshark display filter that selects the local broker for this
        capture (e.g. "ip.dst==127.0.0.1 and tcp.dstport==1883").
    """
    # Run tshark with:
    #   -r <pcap>                read the capture
    #   -Y <filter>              keep only PUBLISH messages to the broker
    #   -T fields -e mqtt.topic  print one topic per matching packet
    out = subprocess.run(
        [
            "tshark", "-r", pcap,
            "-Y", f"mqtt.msgtype==3 and {broker_filter}",
            "-T", "fields", "-e", "mqtt.topic",
        ],
        capture_output=True, text=True,
    ).stdout

    # Depth = number of '/' characters + 1. Empty lines (no topic) are skipped.
    return [t.count("/") + 1 for t in out.splitlines() if t.strip()]


# --- Collect topic-depth statistics for both captures ------------------------
a = Counter(topic_depths("A.pcapng", "ip.dst==127.0.0.1 and tcp.dstport==1883"))
b = Counter(topic_depths("B.pcapng", "ipv6.dst==::1 and tcp.dstport==1883"))

# Print totals and per-depth breakdown to the console (used as CQ8a / CQ8b).
print(f"A.pcapng: total={sum(a.values())}, per-depth={dict(sorted(a.items()))}")
print(f"B.pcapng: total={sum(b.values())}, per-depth={dict(sorted(b.items()))}")

# --- Grouped bar chart --------------------------------------------------------
depths = sorted(set(a) | set(b))         # union of depths observed in A and B
x = np.arange(len(depths))               # bar group centres
w = 0.38                                 # bar width (leaves a small gap)

fig, ax = plt.subplots(figsize=(9, 5.5))
ba = ax.bar(x - w / 2, [a[d] for d in depths], w, label="A.pcapng", color="#1f77b4")
bb = ax.bar(x + w / 2, [b[d] for d in depths], w, label="B.pcapng", color="#ff7f0e")

# Annotate each bar with its count.
ax.bar_label(ba, fmt="%d")
ax.bar_label(bb, fmt="%d")

# Axis / legend / grid cosmetics.
ax.set_xticks(x, depths)
ax.set_xlabel("Number of topic layers")
ax.set_ylabel("Number of PUBLISH messages")
ax.set_title("Distribution of MQTT topic depth for local broker")
ax.legend()
ax.grid(axis="y", linestyle="--", alpha=0.5)
ax.set_axisbelow(True)

plt.tight_layout()
plt.savefig("cq8_histogram.png", dpi=150, bbox_inches="tight")

#!/usr/bin/env python3
"""
CQ8: Compare local broker usage in A.pcapng and B.pcapng.
Produce histogram of topic layer depth for PUBLISH messages
directed to the local broker.

CQ8a) Total publish messages in A.pcapng
CQ8b) Total publish messages in B.pcapng

Usage: python3 cq8_topic_layers.py <A.pcapng> <B.pcapng>
Requires: tshark, matplotlib
"""

import subprocess
import sys
from collections import Counter

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

A_PCAP = sys.argv[1] if len(sys.argv) > 1 else "data/A.pcapng"
B_PCAP = sys.argv[2] if len(sys.argv) > 2 else "data/B.pcapng"


def run_tshark(pcap, filt, fields):
    cmd = (
        f'tshark -r {pcap} -Y "{filt}" -T fields '
        + " ".join(f"-e {f}" for f in fields)
        + " 2>/dev/null"
    )
    out = subprocess.check_output(cmd, shell=True).decode().strip()
    return [l.split("\t") for l in out.split("\n")] if out else []


def count_layers(pubs):
    """Count topic layers (number of '/' separated segments)."""
    c = Counter()
    for p in pubs:
        topic = p[1]
        if topic:
            c[len(topic.split("/"))] += 1
    return c


def main():
    # ── Extract PUBLISH messages to local broker ──
    # A.pcapng: local broker = 127.0.0.1:1883
    a_pubs = run_tshark(
        A_PCAP,
        "mqtt.msgtype == 3 && ip.dst == 127.0.0.1 && tcp.dstport == 1883",
        ["frame.number", "mqtt.topic"],
    )
    # B.pcapng: local broker = ::1:1883
    b_pubs = run_tshark(
        B_PCAP,
        "mqtt.msgtype == 3 && ipv6.dst == ::1 && tcp.dstport == 1883",
        ["frame.number", "mqtt.topic"],
    )

    a_layers = count_layers(a_pubs)
    b_layers = count_layers(b_pubs)

    print(f"CQ8a (A.pcapng total publishes to local broker): {len(a_pubs)}")
    print(f"CQ8b (B.pcapng total publishes to local broker): {len(b_pubs)}")
    print(f"\nA layer distribution: {dict(sorted(a_layers.items()))}")
    print(f"B layer distribution: {dict(sorted(b_layers.items()))}")

    # ── Plot histogram ──
    all_keys = sorted(set(a_layers.keys()) | set(b_layers.keys()))
    a_vals = [a_layers.get(k, 0) for k in all_keys]
    b_vals = [b_layers.get(k, 0) for k in all_keys]

    fig, ax = plt.subplots(figsize=(10, 6))
    x = np.arange(len(all_keys))
    width = 0.35

    bars1 = ax.bar(x - width / 2, a_vals, width, label="A.pcapng", color="#1f77b4")
    bars2 = ax.bar(x + width / 2, b_vals, width, label="B.pcapng", color="#ff7f0e")

    ax.set_xlabel("Number of topic layers", fontsize=13)
    ax.set_ylabel("Number of PUBLISH messages", fontsize=13)
    ax.set_title("Distribution of MQTT topic depth for local broker", fontsize=14)
    ax.set_xticks(x)
    ax.set_xticklabels(all_keys)
    ax.legend(fontsize=12)

    for bar in list(bars1) + list(bars2):
        h = bar.get_height()
        if h > 0:
            ax.text(
                bar.get_x() + bar.get_width() / 2.0,
                h + 2,
                str(int(h)),
                ha="center",
                va="bottom",
                fontsize=10,
            )

    ax.set_ylim(0, max(max(a_vals), max(b_vals)) * 1.15)
    plt.tight_layout()
    plt.savefig("figures/cq8_histogram.png", dpi=150)
    print("\nHistogram saved to figures/cq8_histogram.png")


if __name__ == "__main__":
    main()

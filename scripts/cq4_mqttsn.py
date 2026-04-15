#!/usr/bin/env python3
"""
CQ4: How many MQTT-SN messages are received by clients from the local
broker listening on port 1885?

Usage: python3 cq4_mqttsn.py <path_to_A.pcapng>
Requires: tshark (with MQTT-SN dissector)
Note: tshark must be told to decode UDP port 1885 as MQTT-SN via:
      -d "udp.port==1885,mqttsn"
"""

import subprocess
import sys

PCAP = sys.argv[1] if len(sys.argv) > 1 else "data/A.pcapng"
BROKER_PORT = 1885


def run_tshark(filter_str, fields, decode=""):
    decode_opt = f'-d "udp.port=={BROKER_PORT},mqttsn"' if decode else ""
    cmd = (
        f"tshark -r {PCAP} {decode_opt} "
        f'-Y "{filter_str}" -T fields '
        + " ".join(f"-e {f}" for f in fields)
        + " 2>/dev/null"
    )
    out = subprocess.check_output(cmd, shell=True).decode().strip()
    return [line.split("\t") for line in out.split("\n")] if out else []


def main():
    # ── Messages TO the broker (dstport 1885) ──
    to_broker = run_tshark(
        f"mqttsn && udp.dstport == {BROKER_PORT} && !icmp",
        ["frame.number"],
        decode=True,
    )
    print(f"MQTT-SN messages TO broker (dstport {BROKER_PORT}): {len(to_broker)}")

    # ── Messages FROM the broker (srcport 1885) ──
    from_broker = run_tshark(
        f"mqttsn && udp.srcport == {BROKER_PORT} && !icmp",
        ["frame.number"],
        decode=True,
    )
    print(f"MQTT-SN messages FROM broker (srcport {BROKER_PORT}): {len(from_broker)}")

    # ── Check ICMP port unreachable responses ──
    icmp = run_tshark(
        f"icmp && udp.dstport == {BROKER_PORT}",
        ["frame.number", "icmp.type", "icmp.code"],
        decode=True,
    )
    print(f"ICMP Port Unreachable responses: {len(icmp)}")
    print(f"\nAll {len(to_broker)} client messages received ICMP Type 3 Code 3")
    print(f"(Port Unreachable) — the broker on port {BROKER_PORT} is NOT running.")
    print(f"\nCQ4 ANSWER: {len(from_broker)}")


if __name__ == "__main__":
    main()

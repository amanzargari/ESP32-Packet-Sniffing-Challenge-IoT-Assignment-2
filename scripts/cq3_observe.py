#!/usr/bin/env python3
"""
CQ3: Observe notifications for /dining_room/temperature in A.pcapng.
CQ3a) How many separate observe notifications (ignoring retransmissions)?
CQ3b) How many are useless (waste of traffic)?

Usage: python3 cq3_observe.py <path_to_A.pcapng>
Requires: tshark
"""

import subprocess
import sys
from collections import OrderedDict

PCAP = sys.argv[1] if len(sys.argv) > 1 else "data/A.pcapng"


def run_tshark(filter_str, fields):
    cmd = (
        f'tshark -r {PCAP} -Y "{filter_str}" -T fields '
        + " ".join(f"-e {f}" for f in fields)
        + " 2>/dev/null"
    )
    out = subprocess.check_output(cmd, shell=True).decode().strip()
    return [line.split("\t") for line in out.split("\n")] if out else []


def main():
    # ── Step 1: Find the observe registration ──
    regs = run_tshark(
        "coap && coap.code == 1 && coap.opt.observe == 0 "
        '&& coap.opt.uri_path contains "dining_room" '
        '&& coap.opt.uri_path contains "temperature" '
        "&& udp.dstport == 5683",
        ["frame.number", "coap.mid", "coap.token", "coap.opt.uri_path"],
    )
    print("Observe registrations:")
    for r in regs:
        print(f"  Frame {r[0]}: MID={r[1]}, token={r[2]}, uri={r[3]}")
    token = regs[0][2]  # 89b9

    # ── Step 2: Get all notifications (from server, matching token, with observe opt) ──
    token_hex = ":".join(token[i : i + 2] for i in range(0, len(token), 2))
    notifs = run_tshark(
        f"coap && coap.token == {token_hex} && udp.srcport == 5683 "
        "&& coap.code >= 64 && coap.opt.observe",
        ["frame.number", "coap.type", "coap.mid", "coap.opt.observe", "json.value.string"],
    )

    # ── Step 3: Group by MID to remove retransmissions ──
    unique = OrderedDict()
    for n in notifs:
        frame, ctype, mid, obs, val = n[0], n[1], n[2], n[3], n[4] if len(n) > 4 else ""
        if mid not in unique:
            unique[mid] = {"frame": frame, "type": ctype, "obs": obs, "val": val, "retx": 0}
        else:
            unique[mid]["retx"] += 1

    # ── Step 4: Check which CON notifications were ACKed ──
    for mid in unique:
        if unique[mid]["type"] == "0":  # CON
            acks = run_tshark(
                f"coap && coap.type == 2 && coap.mid == {mid} && udp.dstport == 5683",
                ["frame.number"],
            )
            unique[mid]["acked"] = len(acks) > 0
        else:
            unique[mid]["acked"] = True  # ACK type is inherently acknowledged

    # ── Step 5: Parse temperature and determine useless ──
    type_names = {"0": "CON", "1": "NON", "2": "ACK", "3": "RST"}
    print(f"\n{'#':<3} {'MID':<8} {'Type':<5} {'Obs':<5} {'Temp':<8} {'ACKed':<7} {'Retx':<5} {'Status'}")
    print("-" * 65)

    useless = 0
    for i, (mid, info) in enumerate(unique.items()):
        parts = info["val"].split(",") if info["val"] else []
        temp = parts[1] if len(parts) > 1 else "?"
        acked = "Yes" if info["acked"] else "NO"
        status = ""
        if not info["acked"]:
            useless += 1
            status = "USELESS"
        print(
            f"{i+1:<3} {mid:<8} {type_names.get(info['type'], '?'):<5} "
            f"{info['obs']:<5} {temp:<8} {acked:<7} {info['retx']:<5} {status}"
        )

    print(f"\nCQ3a: {len(unique)} separate notifications (ignoring retransmissions)")
    print(f"CQ3b: {useless} useless (never ACKed by client)")


if __name__ == "__main__":
    main()

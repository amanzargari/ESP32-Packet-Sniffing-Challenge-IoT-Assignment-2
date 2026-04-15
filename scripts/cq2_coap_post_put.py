#!/usr/bin/env python3
"""
CQ2: How many CoAP resources in the local server received the same number
of unique unsuccessful Confirmable POST and PUT requests? (X=Y, X>0)

Only count as unsuccessful if there is an actual unsuccessful response.

Usage: python3 cq2_coap_post_put.py <path_to_A.pcapng>
Requires: tshark
"""

import subprocess
import sys
from collections import defaultdict

PCAP = sys.argv[1] if len(sys.argv) > 1 else "data/A.pcapng"
LOCAL_IP = "127.0.0.1"
SERVER_PORT = "5683"


def run_tshark(filter_str, fields):
    """Run tshark with given display filter and return parsed rows."""
    cmd = (
        f'tshark -r {PCAP} -Y "{filter_str}" -T fields '
        + " ".join(f"-e {f}" for f in fields)
        + " 2>/dev/null"
    )
    out = subprocess.check_output(cmd, shell=True).decode().strip()
    return [line.split("\t") for line in out.split("\n")] if out else []


def main():
    # ── Step 1: Get all CON (type=0) POST (code=2) and PUT (code=3) to local server ──
    requests = run_tshark(
        f"coap && ip.dst == {LOCAL_IP} && (coap.code == 2 || coap.code == 3) "
        f"&& coap.type == 0 && udp.dstport == {SERVER_PORT}",
        ["frame.number", "coap.mid", "coap.token", "coap.code", "coap.opt.uri_path"],
    )
    print(f"Total CON POST/PUT requests to local server: {len(requests)}")

    # ── Step 2: Get all responses FROM local server (code >= 64, srcport 5683) ──
    responses = run_tshark(
        f"coap && ip.src == {LOCAL_IP} && coap.code >= 64 && udp.srcport == {SERVER_PORT}",
        ["frame.number", "coap.token", "coap.code"],
    )
    resp_by_token = defaultdict(list)
    for r in responses:
        resp_by_token[r[1]].append(int(r[2]))

    # ── Step 3: Match and count unique unsuccessful requests per resource ──
    # Unique = different MID (retransmissions share the same MID)
    post_unsucc = defaultdict(set)  # resource -> set of unique MIDs
    put_unsucc = defaultdict(set)

    for req in requests:
        frame, mid, token, code, uri = req
        method = "POST" if code == "2" else "PUT"
        for resp_code in resp_by_token.get(token, []):
            resp_class = resp_code >> 5
            if resp_class >= 4:  # 4.xx or 5.xx = unsuccessful
                if method == "POST":
                    post_unsucc[uri].add(mid)
                else:
                    put_unsucc[uri].add(mid)

    # ── Display results ──
    all_resources = sorted(set(post_unsucc.keys()) | set(put_unsucc.keys()))
    print(f"\n{'Resource':<30} {'POST (X)':<12} {'PUT (Y)':<12} {'X=Y?'}")
    print("-" * 70)

    matching = []
    for uri in all_resources:
        x = len(post_unsucc.get(uri, set()))
        y = len(put_unsucc.get(uri, set()))
        match = "<<< YES" if (x == y and x > 0) else ""
        # Display uri with / separators instead of commas
        display_uri = "/" + uri.replace(",", "/")
        print(f"{display_uri:<30} {x:<12} {y:<12} {match}")
        if x == y and x > 0:
            matching.append((display_uri, x))

    print(f"\n{'='*70}")
    print(f"CQ2 ANSWER: {len(matching)} resource(s) with X=Y (X>0)")
    for uri, count in matching:
        print(f"  {uri}: X=Y={count}")


if __name__ == "__main__":
    main()

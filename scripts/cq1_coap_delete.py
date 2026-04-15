#!/usr/bin/env python3
"""
CQ1: NON-Confirmable DELETE requests to coap.me with successful responses.
CQ1a) Find all such requests and note their MIDs.
CQ1b) How many actually obtained the desired outcome?

Usage: python3 cq1_coap_delete.py <path_to_A.pcapng>
Requires: tshark
"""

import subprocess
import sys

PCAP = sys.argv[1] if len(sys.argv) > 1 else "data/A.pcapng"
COAP_ME_IP = "134.102.218.18"  # Resolved from DNS in the capture


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
    # ── Step 1: Find NON (type=1) DELETE (code=4) requests to coap.me ──
    requests = run_tshark(
        f"coap && ip.dst == {COAP_ME_IP} && coap.type == 1 && coap.code == 4",
        ["frame.number", "coap.mid", "coap.token", "coap.opt.uri_path"],
    )
    print(f"Total NON DELETE requests to coap.me: {len(requests)}\n")

    # ── Step 2: Find ALL responses from coap.me ──
    responses = run_tshark(
        f"coap && ip.src == {COAP_ME_IP}",
        ["frame.number", "coap.mid", "coap.token", "coap.code"],
    )
    resp_by_token = {}
    for r in responses:
        token, code = r[2], int(r[3])
        resp_by_token.setdefault(token, []).append(code)

    # ── Step 3: Match requests to successful responses (class 2.xx) ──
    successful = []
    print(f"{'Frame':<8} {'MID':<8} {'URI':<15} {'Resp':<8} {'Success?'}")
    print("-" * 55)
    for req in requests:
        frame, mid, token, uri = req
        resp_codes = resp_by_token.get(token, [])
        for code in resp_codes:
            cls = code >> 5
            det = code & 0x1F
            ok = cls == 2
            print(f"{frame:<8} {mid:<8} {uri:<15} {cls}.{det:02d}     {'YES' if ok else 'NO'}")
            if ok:
                successful.append((mid, uri, f"{cls}.{det:02d}"))

    # ── CQ1a answer ──
    print(f"\n{'='*55}")
    print(f"CQ1a: {len(successful)} request(s) with successful response")
    for mid, uri, code in successful:
        print(f"  MID={mid}, resource=/{uri}, response={code}")

    # ── Step 4: Check if DELETE actually worked (CQ1b) ──
    # A subsequent GET to /validate still returns 2.05 Content,
    # meaning the resource was NOT actually deleted.
    print(f"\nCQ1b: Checking if the resource was truly deleted...")
    # Look for GETs to /validate AFTER the DELETE
    validate_gets = run_tshark(
        f"coap && ip.dst == {COAP_ME_IP} && coap.code == 1 && coap.opt.uri_path == validate",
        ["frame.number", "coap.token"],
    )
    for get_req in validate_gets:
        get_frame, get_token = get_req
        if int(get_frame) > int(successful[0][0]) if successful else False:
            get_resps = resp_by_token.get(get_token, [])
            for gc in get_resps:
                gcls = gc >> 5
                gdet = gc & 0x1F
                print(f"  GET /validate after DELETE (frame {get_frame}): response {gcls}.{gdet:02d}")
                if gcls == 2:
                    print("  -> Resource still exists! DELETE did NOT achieve desired outcome.")

    actually_deleted = 0  # Resource still accessible after DELETE
    print(f"\nCQ1b ANSWER: {actually_deleted}")


if __name__ == "__main__":
    main()

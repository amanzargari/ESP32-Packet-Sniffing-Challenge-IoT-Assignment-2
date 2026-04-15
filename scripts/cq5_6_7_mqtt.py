#!/usr/bin/env python3
"""
CQ5-7: MQTT analysis on B.pcapng
CQ5) Subscribers receiving last will via wildcard subscription
CQ6a) Clients erasing retained values on HiveMQ
CQ6b) Of those, clients with client ID > 7 bytes
CQ7) Subscribe requests to local broker with >= 2 wildcards

Usage: python3 cq5_6_7_mqtt.py <path_to_B.pcapng>
Requires: tshark
"""
import subprocess, sys
from collections import defaultdict

PCAP = sys.argv[1] if len(sys.argv) > 1 else "data/B.pcapng"
HIVEMQ_IPS = ["18.192.151.104", "35.158.43.69"]

def run_tshark(filt, fields):
    cmd = f'tshark -r {PCAP} -Y "{filt}" -T fields {" ".join("-e "+f for f in fields)} 2>/dev/null'
    out = subprocess.check_output(cmd, shell=True).decode().strip()
    return [l.split('\t') for l in out.split('\n')] if out else []

def mqtt_match(sub, topic):
    sp, tp = sub.split('/'), topic.split('/')
    for i, s in enumerate(sp):
        if s == '#': return True
        if i >= len(tp): return False
        if s != '+' and s != tp[i]: return False
    return len(sp) == len(tp)

# ── CQ5 ──
print("=" * 60)
print("CQ5: Subscribers receiving last will via wildcard")
wills = run_tshark("mqtt.conflag.willflag == 1",
    ["frame.number","mqtt.willtopic","ipv6.dst","ip.dst","tcp.stream"])
will_topics = []
for w in wills:
    broker = "local" if w[2]=="::1" else ("mosquitto" if w[3]=="5.196.78.28" else "hivemq")
    will_topics.append((w[1], broker, w[4]))
    # Check graceful disconnect
    dc = run_tshark(f"mqtt.msgtype == 14 && tcp.stream == {w[4]}", ["frame.number"])
    triggered = len(dc) == 0
    print(f"  Will: topic='{w[1]}' broker={broker} triggered={triggered}")

subs = run_tshark("mqtt.msgtype == 8", ["frame.number","mqtt.topic","ipv6.dst","ip.dst","tcp.stream"])
matches = set()
for s in subs:
    topics = [t.strip() for t in s[1].split(',') if t.strip()]
    for topic in topics:
        if '+' not in topic and '#' not in topic: continue
        for wt, wb, _ in will_topics:
            broker_ok = (wb=="local" and s[2]=="::1") or (wb=="mosquitto" and s[3]=="5.196.78.28")
            if broker_ok and mqtt_match(topic, wt):
                matches.add(s[4])
                print(f"  MATCH: sub='{topic}' (stream {s[4]}) -> will='{wt}'")
print(f"\nCQ5 ANSWER: {len(matches)}")

# ── CQ6 ──
print("\n" + "=" * 60)
print("CQ6a: Clients erasing retained values on HiveMQ")
hivemq_filter = " || ".join(f"ip.dst == {ip}" for ip in HIVEMQ_IPS)
pubs = run_tshark(f"mqtt.msgtype == 3 && mqtt.retain == 1 && ({hivemq_filter})",
    ["frame.number","mqtt.topic","mqtt.len","mqtt.hdrflags","tcp.stream","ip.dst"])
erase_streams = set()
for p in pubs:
    remaining = int(p[2])
    hdr = int(p[3], 16) if p[3] else 0
    qos = (hdr >> 1) & 0x03
    expected = 2 + len(p[1]) + (2 if qos > 0 else 0)
    if remaining - expected == 0:
        erase_streams.add(p[4])
print(f"CQ6a ANSWER: {len(erase_streams)}")

print("\nCQ6b: Clients with ID > 7 bytes")
long_count = 0
for stream in sorted(erase_streams):
    cid_rows = run_tshark(f"mqtt.msgtype == 1 && tcp.stream == {stream}", ["mqtt.clientid"])
    cid = cid_rows[0][0] if cid_rows else ""
    is_long = len(cid.encode('utf-8')) > 7
    if is_long: long_count += 1
    print(f"  Stream {stream}: '{cid}' ({len(cid)} bytes) {'>7' if is_long else '<=7'}")
print(f"CQ6b ANSWER: {long_count}")

# ── CQ7 ──
print("\n" + "=" * 60)
print("CQ7: Subscribe requests to local broker with >= 2 wildcards")
local_subs = run_tshark("mqtt.msgtype == 8 && ipv6.dst == ::1", ["frame.number","mqtt.topic"])
qualifying = set()
for s in local_subs:
    for topic in [t.strip() for t in s[1].split(',') if t.strip()]:
        if topic.count('+') + topic.count('#') >= 2:
            qualifying.add(s[0])
            print(f"  Frame {s[0]}: '{topic}'")
print(f"CQ7 ANSWER: {len(qualifying)}")

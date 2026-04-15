# IoT Challenge #2 — Packet Sniffing

**Course:** Internet of Things — Politecnico di Milano (2025–2026)  
**Authors:** SeyedAman Zargari (11109586), Amirhossein Dibaj (11109540)

## Overview

Analysis of two packet capture files (A.pcapng and B.pcapng) containing CoAP, MQTT, and MQTT-SN traffic, plus a theoretical energy comparison between CoAP and MQTT for a smart building IoT system.

## Repository Structure

```
iot-challenge-2/
├── README.md
├── scripts/
│   ├── cq1_coap_delete.py          # CQ1: NON DELETE requests to coap.me
│   ├── cq2_coap_post_put.py        # CQ2: Unsuccessful CON POST/PUT matching
│   ├── cq3_observe.py              # CQ3: Observe notifications analysis
│   ├── cq4_mqttsn.py               # CQ4: MQTT-SN broker on port 1885
│   ├── cq5_6_7_mqtt.py             # CQ5-7: MQTT last will, retain, wildcards
│   └── cq8_topic_layers.py         # CQ8: Topic depth histogram (both files)
├── figures/
│   └── cq8_histogram.png           # Generated histogram for CQ8
├── data/
│   ├── A.pcapng                    # Capture file A (not included, see below)
│   └── B.pcapng                    # Capture file B (not included, see below)
└── report/
    ├── Challenge.pdf               # Part 1 report (CQ1–CQ8)
    └── Exercise.pdf                # Part 2 report (EQ1–EQ2)
```

> **Note:** The `.pcapng` files are not included in this repository. Place them in `data/` to run the scripts.

## Requirements

- **tshark** (Wireshark CLI) — tested with v4.2.2
- **Python 3.10+**
- **matplotlib** (for CQ8 histogram)

```bash
# Ubuntu/Debian
sudo apt install tshark
pip install matplotlib
```

## Quick Start

```bash
# Run all scripts from the repo root
python3 scripts/cq1_coap_delete.py data/A.pcapng
python3 scripts/cq2_coap_post_put.py data/A.pcapng
python3 scripts/cq3_observe.py data/A.pcapng
python3 scripts/cq4_mqttsn.py data/A.pcapng
python3 scripts/cq5_6_7_mqtt.py data/B.pcapng
python3 scripts/cq8_topic_layers.py data/A.pcapng data/B.pcapng
```

## Answers Summary

### Part 1 — PCAP Analysis

| Question | Answer | Description |
|----------|--------|-------------|
| CQ1a | MID 30800 | 1 NON DELETE to coap.me with successful (2.02) response |
| CQ1b | 0 | Resource `/validate` still accessible after DELETE |
| CQ2 | 1 | `/dining_room` has X=Y=1 (POST 4.00, PUT 4.04) |
| CQ3a | 11 | Unique observe notifications (by MID) |
| CQ3b | 5 | Unacknowledged CON notifications (MIDs 54,62,74,87,90) |
| CQ4 | 0 | Broker on port 1885 not running (ICMP port unreachable) |
| CQ5 | 1 | `university/#` on stream 10 matches will topic |
| CQ6a | 3 | Streams 1, 22, 43 sent empty retained publishes to HiveMQ |
| CQ6b | 1 | `giuxfijwus` (10 bytes) > 7 |
| CQ7 | 9 | Subscribe requests with ≥2 wildcards to local broker |
| CQ8a | 439 | MQTT publishes to local broker in A.pcapng |
| CQ8b | 534 | MQTT publishes to local broker in B.pcapng |

### Part 2 — Energy Exercise

| Question | Answer |
|----------|--------|
| EQ1a (CoAP) | 2203.20 µJ |
| EQ1b (MQTT) | 5498.72 µJ |
| EQ2 | MQTT with `retain=1`, `clean_session=1`, QoS 1 |

## Key Findings

- **CQ1:** coap.me's `/validate` endpoint accepts DELETE (responds 2.02) but does not actually remove the resource — a subsequent GET still returns 2.05 Content.
- **CQ3:** The CoAP observe server continues sending CON notifications even after the client stops ACKing, violating RFC 7641 §4.5.
- **CQ4:** No MQTT-SN broker was running on port 1885; all 219 client messages received ICMP Port Unreachable.
- **CQ8:** B.pcapng shows broader topic depth distribution (layers 1–4) compared to A.pcapng (layers 2–4 only), with consistently higher message counts.
- **EQ2:** With a sleeping actuator (30-min wake cycle), MQTT is preferred over CoAP despite higher baseline energy cost, because CoAP fails 93% of messages due to retransmission timeouts while MQTT's retain flag guarantees the actuator always receives the latest reading.

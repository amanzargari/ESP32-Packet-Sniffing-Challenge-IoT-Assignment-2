# IoT Challenge 2 — Packet Sniffing

Solution to **Challenge #2** of the *Internet of Things* course at **Politecnico di Milano** (A.Y. 2025–2026, ANTLab). The challenge is split in two parts:

- **Part 1** — Analysis of two packet captures (`A.pcapng`, `B.pcapng`) with CoAP, MQTT and MQTT-SN traffic (questions CQ1–CQ8).
- **Part 2** — Energy-consumption exercise comparing CoAP and MQTT for a battery-powered sensor/actuator pair (questions EQ1, EQ2).

## Repository structure

```
.
├── Challenge2-Brief.pdf        # Original challenge text (questions CQ1–CQ8, EQ1, EQ2)
├── Challenge.pdf         # Part 1 solution — PCAP analysis (CQ1–CQ8)
├── Exercise.pdf          # Part 2 solution — energy exercise (EQ1, EQ2)
├── data/
│   ├── A.pcapng          # Capture used for CQ1–CQ4 and CQ8a
│   └── B.pcapng          # Capture used for CQ5–CQ7 and CQ8b
└── README.md
```

## Part 1 — PCAP analysis

All filters are standard Wireshark display filters. Counting across many packets was done with `tshark` piped into short Python snippets. Malformed packets are ignored throughout, as required by the challenge.

| # | Question (short) | Answer |
|---|------------------|--------|
| CQ1a | NON CoAP DELETE to `coap.me` with a successful response | MID **30800** (`/validate`) |
| CQ1b | Of those, how many actually deleted the resource | **0** |
| CQ2  | Resources with X = Y > 0 unique unsuccessful CON POST/PUT | **1** (`/dining_room`) |
| CQ3a | Separate observe notifications on `/dining_room/temperature` | **10** |
| CQ3b | Of those, how many are wasted (no client ACK) | **5** |
| CQ4  | MQTT-SN messages received by clients from local broker on port 1885 | **0** |
| CQ5  | Subscribers that received a Will via a wildcard subscription | **1** |
| CQ6a | Clients erasing a retained value on HiveMQ | **5** |
| CQ6b | Of those, how many have a client-ID strictly longer than 7 B | **2** |
| CQ7  | SUBSCRIBE to local broker with ≥ 2 wildcards | **9** |
| CQ8a | Total PUBLISH to local broker in A.pcapng | **439** |
| CQ8b | Total PUBLISH to local broker in B.pcapng | **534** |

All filters, token-matching tables and justifications are in `Challenge.pdf`. The CQ8 plotting script (`cq8_plot.py` — `tshark` + `matplotlib`) is embedded in the report.

## Part 2 — Energy exercise

Battery-powered temperature sensor (publishes every 2 min) and battery-powered fan actuator, communicating either directly via CoAP (CON) or via a mains-powered MQTT gateway (QoS 1). Energy per bit: E_TX = 50 nJ/bit, E_RX = 58 nJ/bit.

### EQ1 — Hourly communication energy (sensor + actuator)

| Protocol | Sensor/h | Actuator/h | **Total/h** |
|----------|----------|------------|-------------|
| CoAP (direct, CON) | 1048.80 µJ | 1154.40 µJ | **2203.20 µJ** |
| MQTT (via gateway, QoS 1) | 1643.20 µJ | 1742.72 µJ | **3385.92 µJ** |

CoAP is ≈ 1.54× cheaper because it avoids the MQTT connection/subscription overhead and uses a 15 B piggybacked ACK instead of a 50 B PUBACK.

### EQ2 — Actuator wakes up every 30 min

**Chosen protocol: MQTT** with `retain = 1`, `QoS = 1`, `cleanSession = false`. Direct CoAP CON would fail every sensor cycle while the actuator sleeps (RTO retransmits ⇒ wasted sensor energy, no delivery). With retained messages + persistent session the actuator wakes every 30 min, skips re-subscribing, and receives the latest value plus any queued updates. Metric optimised: actuator-side energy per hour and delivery reliability.

Full derivations in `Exercise.pdf`.

## Tools used

- **Wireshark / tshark 4.x** — display filters, MQTT-SN dissector enabled on UDP port 1885 (*Edit → Preferences → Protocols → MQTT-SN*).
- **Python 3** with `matplotlib` and `subprocess` — CQ8 histogram and ancillary token-matching.

## Reproducing the results

1. Open `data/A.pcapng` or `data/B.pcapng` in Wireshark.
2. Apply the display filters listed in `Challenge.pdf` for each CQ.
3. For CQ4, register the MQTT-SN dissector on UDP port 1885 before filtering.
4. For CQ8, run the embedded `cq8_plot.py` script from the repository root:
   ```bash
   python3 cq8_plot.py        # expects A.pcapng and B.pcapng in the working dir
   ```

## Course

*Internet of Things* — Politecnico di Milano, ANTLab, A.Y. 2025–2026.
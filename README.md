# Sentinel – Network Security Operations Platform

> Agentic AI-powered SOC automation with network traffic anomaly detection.

## Layer 1 – Ingestion (current scope)

```
PCAP → Zeek → conn/ssl/dns.log → Feature Extractor → Kafka (network-features)
                                                            ↓
                                                     Dashboard (live UI)
```

## Quick Start

### Prerequisites
- Docker ≥ 24 and Docker Compose v2
- (Optional) `scapy` to generate a sample PCAP: `pip install scapy`

### 1. Generate a sample PCAP (first time only)

```bash
cd /home/millie/Sentinel
.venv/bin/python3 capture/generate_sample.py
cp sample.pcap capture/pcap/
```

Or drop any real `.pcap` / `.pcapng` file into `capture/pcap/`.

### 2. Start the stack

```bash
docker compose up --build
```

Services:
| Service | Port | Purpose |
|---|---|---|
| Zookeeper | 2181 (internal) | Kafka coordination |
| Kafka | 9092 (internal) | Message bus |
| Kafka UI | [9000](http://localhost:9000) | Browse topics & messages |
| Zeek | – | Packet analysis |
| Feature Extractor | – | Log parsing → Kafka |
| Dashboard | [8080](http://localhost:8080) | Live visualization |

### 3. View results

| What | Where |
|---|---|
| **Live dashboard** | http://localhost:8080 |
| **Kafka topic browser** | http://localhost:9000 |
| **Zeek logs** | `capture/zeek/<pcap-name>/` |

### 4. Add more PCAPs at runtime

```bash
cp /path/to/traffic.pcap capture/pcap/
# Zeek automatically picks it up via inotifywait
```

---

## Architecture

### Feature Vectors (CESSNET-like)

Each connection in `conn.log` produces a JSON feature vector published to Kafka topic `network-features`:

```json
{
  "uid": "CKyrpe4JCbVRCPbNe8",
  "ts":  "1700000001.234",
  "src_ip": "192.168.1.12",  "src_port": 54321,
  "dst_ip": "10.0.0.1",      "dst_port": 443,
  "proto": "tcp",   "service": "ssl",
  "duration": 0.142,
  "orig_bytes": 2048, "resp_bytes": 8192,
  "orig_pkts":  12,   "resp_pkts": 18,
  "bytes_ratio": 0.25,
  "pkts_ratio":  0.67,
  "avg_pkt_size_orig": 170.7,
  "avg_pkt_size_resp": 455.1,
  "missed_bytes": 0,
  "conn_state_SF": 1,
  "ssl_version": "TLSv12", "ssl_cipher": "TLS_AES_256_GCM_SHA384",
  "is_encrypted": 1,
  "is_dns": 0
}
```

### Directory structure

```
Sentinel/
├── capture/
│   ├── pcap/              ← drop PCAPs here
│   ├── zeek/              ← zeek logs written here (auto-created)
│   └── generate_sample.py
├── ingestion/
│   ├── Dockerfile
│   ├── main.py
│   ├── requirements.txt
│   ├── features/extractor.py   ← CESSNET feature extraction
│   ├── kafka/producer.py       ← publishes to network-features
│   ├── pipeline/watcher.py     ← watchdog on zeek log dir
│   └── zeek/
│       ├── Dockerfile          ← Ubuntu 22.04 + official Zeek repo
│       └── entrypoint.sh
├── dashboard/
│   ├── Dockerfile
│   ├── server.py          ← FastAPI + WebSocket
│   ├── index.html         ← Real-time UI
│   └── requirements.txt
└── docker-compose.yml
```

---

## Troubleshooting

**Zeek produces no logs** – verify the PCAP is valid: `file capture/pcap/<name>.pcap`

**Feature extractor keeps retrying Kafka** – Kafka takes ~25s to initialise; this is normal.

**Dashboard shows nothing** – check that `feature-extractor` is publishing:
```bash
docker compose logs -f feature-extractor
```

**Check raw Kafka messages:**
```bash
docker exec sentinel-kafka kafka-console-consumer \
  --bootstrap-server localhost:9092 \
  --topic network-features --from-beginning --max-messages 5
```

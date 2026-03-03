# Agentic IDS — Demo Guide

This guide walks through running a live demonstration of the IDS on a `virbr0` (libvirt)
network without requiring access to a corporate or production network.

All simulated events are injected as fake-but-realistic log records into the same pipeline
that processes real traffic. No actual packets are sent to any external destination.

---

## Prerequisites

The full IDS stack must be running before injecting demo events:

```bash
docker compose up -d
docker compose ps          # all services should show "healthy"
```

If this is a fresh start, wait ~2 minutes for:
- OUI manufacturer database to download (~32K entries)
- GeoIP database to download (~250K IPv4 ranges)
- Suricata rules to update via `suricata-update`

**Required Ollama model** (for chat UI and email alerts):
```bash
ollama pull qwen2.5:3b
```

**Required for Threat Intel RAG** (Phase 3d, if enabled):
```bash
ollama pull nomic-embed-text
```

---

## The Demo Script

```
scripts/demo_inject.py
```

Writes fake NDJSON event records directly into `/var/log/ids/vector/` (the same
staging directory Vector uses for real traffic). The `duckdb-mgr` service picks
them up within 10 seconds and processes them through the standard pipeline.

### Alert timing

| Step | What happens | Elapsed |
|------|-------------|---------|
| 0s | NDJSON files written to staging dir | — |
| ~10s | `duckdb-mgr` ingests files into DuckDB | 10s |
| ~50s | Device summaries + anomaly detection run | 60s |
| ~60s | `alert-agent` polls, LLM drafts email | 120s |
| **~2 min** | **Email arrives in inbox** | **120s total** |

Add `--fast` to skip the detection wait: anomaly records are injected directly into
`anomaly_events` via `docker exec`, so the email arrives in under 60 seconds.

---

## Usage

```bash
# Interactive menu (recommended for live demos)
sudo python3 scripts/demo_inject.py

# Inject all 4 scenarios at once
sudo python3 scripts/demo_inject.py --all

# Inject all + fast email (skips ~2 min detection wait)
sudo python3 scripts/demo_inject.py --all --fast

# Inject specific scenarios only
sudo python3 scripts/demo_inject.py -s 1 -s 4

# Clean up all injected demo data
sudo python3 scripts/demo_inject.py --clean

# Custom paths (if stack uses non-default dirs)
sudo python3 scripts/demo_inject.py --all --vector-dir /custom/path --container my-duckdb-mgr
```

> **Note:** The script needs write access to `/var/log/ids/vector/`. Run with `sudo`
> or as a user in the `docker` group.

---

## Scenarios

### Scenario 1 — New IoT Device

**What it simulates:** A previously-unseen device with MAC address `de:ad:be:ef:ca:fe`
joins the network at `192.168.122.200`. The device performs a DHCP handshake, DNS
lookups, and then makes several HTTPS connections (typical of a new smart device
"phoning home").

| Field | Value |
|-------|-------|
| Device IP | `192.168.122.200` |
| Device MAC | `de:ad:be:ef:ca:fe` |
| Manufacturer | Unknown (OUI `DE:AD:BE` is not a registered vendor) |
| Events injected | 8 Zeek conn.log records (DHCP + DNS + HTTPS) |
| Anomaly type | `new_device` |
| Severity | medium |

**Detection logic:** `duckdb-mgr` compares the `devices` materialized table against
`_known_devices`. Any IP not previously seen triggers the anomaly.

**To ensure it fires:** The script automatically removes `192.168.122.200` from
`_known_devices` before injecting, so the detection fires even if you ran the demo
before.

**Where to see it:**
- Grafana → **Network Nodes** — new row with MAC `de:ad:be:ef:ca:fe`
- Chat UI: *"What new devices appeared on the network today?"*
- Email alert subject: *"New device de:ad:be:ef:ca:fe (Unknown) appeared on 192.168.122.200"*

---

### Scenario 2 — DPRK C2 Beacon (North Korea)

**What it simulates:** An IP camera at `192.168.122.100` has been compromised and is
periodically beaconing to a North Korean IP (`175.45.176.3`, AS131279 — Korean Computer
Center, Pyongyang). The pattern includes 6 periodic HTTPS check-ins (~every 45 seconds,
jittered to look organic) followed by a large data exfiltration burst (~10 MB upload).

| Field | Value |
|-------|-------|
| Source device | `192.168.122.100` (IP Camera) |
| Source MAC | `de:ad:be:ef:00:01` |
| Destination IP | `175.45.176.3` (DPRK — AS131279) |
| Ports | 443 (HTTPS), 8080 |
| Beacon payload | 380–980 bytes per checkin |
| Exfil burst | 8–18 MB outbound upload |
| Events injected | 7 Zeek conn.log records |
| Anomaly type | `suspicious_country` |
| Severity | high |

**Detection logic:** `duckdb-mgr` joins `external_ips` with the GeoIP database. IPs in
the `SUSPICIOUS_COUNTRIES` watchlist (`CN,RU,KP,IR,BY` by default) trigger the anomaly.

> **GeoIP dependency:** This scenario requires the DB-IP GeoIP database to map
> `175.45.176.3` to `KP`. The DB-IP database includes the DPRK range `175.45.176.0/22`.
> If you are demoing on a freshly started stack (GeoIP not yet downloaded), use `--fast`
> to inject the anomaly directly.

**Where to see it:**
- Grafana → **External Access & GeoIP** — North Korea (KP) appears in country breakdown
- Grafana → **Connection Map** — `192.168.122.100` ↔ `175.45.176.3` edge
- Chat UI: *"Are we communicating with any suspicious countries?"*
- Email alert subject: *"Traffic to suspicious country: 175.45.176.3 (KP) — 7 connections"*

---

### Scenario 3 — IoT Traffic Spike (Botnet Port Scan)

**What it simulates:** A smart thermostat at `192.168.122.101` suddenly generates 2000
rejected TCP connections within 4 minutes — the hallmark pattern of a botnet-infected IoT
device performing a port scan. The connections target sequential IPs across multiple `10.x.x.x`
subnets, hitting ports 22, 23, 80, 443, 3389, and 5900 (common scan targets).

| Field | Value |
|-------|-------|
| Source device | `192.168.122.101` (Smart Thermostat) |
| Source MAC | `de:ad:be:ef:00:02` |
| Destination | Sequential IPs across `10.0.0.0/8` |
| Ports scanned | 22, 23, 80, 443, 3389, 5900 |
| Connection state | `REJ` (rejected — destination not listening) |
| Events injected | 2000 Zeek conn.log records |
| Anomaly type | `traffic_spike` |
| Severity | high |

**Detection logic:** The spike detector compares connections in the last 5 minutes against
the hourly rolling average (hourly count ÷ 12). Fires when: count ≥ 1000 AND ratio > 5×.
With 2000 injected records and minimal existing traffic, the ratio is approximately 12×.

**Where to see it:**
- Grafana → **Network Nodes** — `192.168.122.101` becomes the noisiest device
- Grafana → **Network Traffic** — spike visible in the connection timeline
- Chat UI: *"Which device is generating the most traffic?"*
- Chat UI: *"Run an nmap scan on 192.168.122.101"*
- Email alert subject: *"Traffic spike: 2000 connections in 5 min (12.0× above average)"*

---

### Scenario 4 — Malware Detected (Cobalt Strike + Nmap Scan)

**What it simulates:** A laptop at `192.168.122.102` triggers two Suricata signatures:

1. **ET MALWARE Cobalt Strike/Meterpreter Beacon** (severity 1 = critical) — 5 hits,
   each a small outbound TCP connection to `203.0.113.55:4444` (the classic Meterpreter
   listener port). Cobalt Strike beacons at regular intervals to maintain C2 connectivity.

2. **ET SCAN Nmap SYN Scan** (severity 2 = high) — the infected laptop is also
   actively scanning the local network, likely for lateral movement.

| Field | Value |
|-------|-------|
| Source device | `192.168.122.102` (Laptop-Demo) |
| Source MAC | `de:ad:be:ef:00:03` |
| C2 destination | `203.0.113.55:4444` |
| Suricata signatures | ET MALWARE Cobalt Strike Beacon (sev 1), ET SCAN Nmap SYN Scan (sev 2) |
| Events injected | 6 Suricata EVE JSON alert records |
| Anomaly types | `suricata_alert` × 2 |
| Severity | critical (sev 1) + high (sev 2) |

**Detection logic:** The Suricata alert detector queries events with `event_type = 'alert'`
and `severity ≤ 2` in the last 5 minutes. Each unique signature fires a separate anomaly
with 30-minute dedup cooldown.

> **If Phase 3d (Threat Intel RAG) is enabled:** The alert-agent will automatically
> look up the matched Suricata rule text and inject it as context before the LLM drafts
> the email, producing a more detailed and accurate alert with CVSS-style risk assessment.

**Where to see it:**
- Grafana → **Alerts** — both signatures appear with hit count and category
- Grafana → **Threats & Correlation** — community-id cross-references Suricata + Zeek
- Chat UI: *"Show me recent Suricata alerts and explain what they mean."*
- Chat UI: *"What is 203.0.113.55 and should I be worried?"*
- Email alert subject: *"Suricata alert: ET MALWARE Possible C&C Beacon (Cobalt Strike/Meterpreter Variant) — CRITICAL"*

---

## Watching the Demo in Real Time

Open these in separate browser tabs / terminal windows:

```bash
# 1. Watch duckdb-mgr ingest events and detect anomalies
docker compose logs duckdb-mgr --follow

# 2. Watch alert-agent send emails
docker compose logs alert-agent --follow

# 3. Check anomaly_events table directly
docker exec ids-duckdb-mgr python3 -c "
import duckdb
db = duckdb.connect('/var/log/ids/duckdb/ids.duckdb', read_only=True)
print(db.sql(\"SELECT id, anomaly_type, severity, summary, detected_at FROM anomaly_events ORDER BY detected_at DESC LIMIT 10\").df().to_string())
"
```

**Grafana dashboards** — http://localhost:3000 (admin / admin)
| Dashboard | What to show |
|-----------|-------------|
| Overview | KPI cards: event counts, device count, alert count |
| Network Nodes | New device row, noisiest device (Thermostat) |
| Alerts | Suricata signature breakdown |
| External Access & GeoIP | North Korea in country map |
| Connection Map | Node graph showing `.100` ↔ DPRK edge |
| Device Detail | Select `192.168.122.101` — connection spike visible |

**Streamlit chat UI** — http://localhost:8501

Suggested demo conversation flow:
```
1. "Give me a security summary of the last hour."
2. "What new devices appeared on the network today?"
3. "Are we talking to any suspicious countries? Show me details."
4. "Which device is behaving most abnormally right now?"
5. "Show me the Suricata alerts and explain what Cobalt Strike is."
6. "Run an nmap scan on 192.168.122.102 and tell me what you find."
```

---

## Cleanup

After the demo, remove all injected fake data:

```bash
sudo python3 scripts/demo_inject.py --clean
```

This:
1. Deletes the 4 demo NDJSON files from the Vector staging directory
2. Removes their corresponding events from DuckDB (via `docker exec`)
3. Removes any `[DEMO]` anomaly events injected in fast mode

Any remaining data will expire automatically via the 72-hour TTL.

---

## Troubleshooting

**Email alert not arriving after 3+ minutes:**
```bash
docker compose logs alert-agent --tail 30
# Check: is GMAIL_USER and GMAIL_APP_PASSWORD set in .env?
# Check: did anomaly_events get populated?
docker exec ids-duckdb-mgr python3 -c "
import duckdb
db = duckdb.connect('/var/log/ids/duckdb/ids.duckdb', read_only=True)
print(db.sql('SELECT count(*) FROM anomaly_events').fetchone())
"
```

**Scenario 2 (DPRK) not triggering suspicious_country alert:**
- GeoIP database may not be downloaded yet (takes ~2 min on first start)
- Re-run with `--fast` flag: `sudo python3 scripts/demo_inject.py -s 2 --fast`
- Check if GeoIP loaded: `docker compose logs duckdb-mgr | grep -i geoip`

**Scenario 3 (IoT Spike) not triggering — existing traffic too high:**
- virbr0 may have high baseline traffic from running VMs
- The spike needs to be 5× the hourly average AND ≥ 1000 connections
- Use `--fast` to inject directly: `sudo python3 scripts/demo_inject.py -s 3 --fast`

**Grafana shows no data:**
```bash
docker compose logs grafana --tail 20
# Ensure DuckDB snapshot exists:
ls -lh /var/log/ids/duckdb/ids_readonly.duckdb
```

**duckdb-mgr not picking up NDJSON files:**
```bash
ls -la /var/log/ids/vector/zeek/conn/demo-*.ndjson
ls -la /var/log/ids/vector/suricata/eve/demo-*.ndjson
docker compose logs duckdb-mgr --tail 20
```

---

## Architecture Note

The demo injector writes to the **same staging directory** that Vector uses for real traffic.
This means:
- All 9 Grafana dashboards reflect the injected data
- The Streamlit chat UI can query it with natural language
- The alert-agent LLM analyzes it and drafts real emails
- Cleanup is clean — file deletion + DuckDB `DELETE WHERE source_file = ?`

The injected NDJSON files use a `demo-` prefix for easy identification and cleanup.
They are treated identically to real Vector-produced files by the ingestion pipeline.

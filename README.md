# Agentic IDS

A fully local, AI-powered Intrusion Detection System. Captures live network traffic with Suricata and Zeek, stores enriched logs in DuckDB, visualizes everything in Grafana, and lets you interrogate your network in plain English through an LLM-powered chat interface. When anomalies are detected, an autonomous agent drafts and emails context-rich alerts — no cloud services, no subscriptions, everything runs on your hardware.

```
                              YOUR NETWORK
                                   |
                    [ one or more network interfaces ]
                   /         |         |         \
              suricata   suricata-  suricata-   zeek
                         wifi       virbr       zeek-wifi
                                                zeek-virbr
                   \         |         |         /
                   /var/log/ids/suricata*/eve.json
                   /var/log/ids/zeek*/*.log
                                  |
                           +-----------+
                           |  Vector   |   (wildcard globs all interface dirs)
                           | Normalize |
                           +-----------+
                                  |
                        /var/log/ids/vector/**/*.ndjson
                                  |
                   ┌──────────────┴──────────────────┐
                   | IPWatcher thread (1s poll)       |
                   | tails raw log files directly     |
                   | new private IP? → fast_alerts.db │
                   └──────────────┬──────────────────┘
                                  |
                           +-----------+
                           | DuckDB    |    OUI (IEEE)
                           | Manager   |<-- GeoIP (DB-IP)
                           |  + nmap   |    7 Anomaly Detectors
                           +-----------+    Scheduled nmap scans
                                  |
               ┌──────────────────┼──────────────────┐
               |                  |                   |
        +-----------+      +-----------+       +-----------+
        |  Grafana  |      | Streamlit |       |  Alert    |
        | Dashboards|      |  Chat UI  |       |  Agent    |
        +-----------+      |  + nmap   |       +-----------+
         :3000             +-----------+    FAST: fast_alerts.db (2s)
                            :8501         RICH: Ollama LLM + Gmail
                           Ollama
                         (qwen2.5:3b)

        All 7 services have Docker healthchecks (auto-restart on failure)
```

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Components](#components)
  - [Suricata — Signature-Based IDS](#1-suricata--signature-based-ids)
  - [Zeek — Network Metadata Analyzer](#2-zeek--network-metadata-analyzer)
  - [Vector — Log Pipeline](#3-vector--log-pipeline)
  - [DuckDB Manager — Storage & Enrichment](#4-duckdb-manager--storage--enrichment)
  - [Grafana — Dashboards](#5-grafana--dashboards)
  - [Streamlit — Chat with your Network](#6-streamlit--chat-with-your-network)
  - [Alert Agent — Autonomous Email Alerts](#7-alert-agent--autonomous-email-alerts)
  - [Ollama — Local LLM Engine](#8-ollama--local-llm-engine)
- [Data Flow](#data-flow)
- [Database Schema](#database-schema)
- [Component Reference](#component-reference)
- [Network Interfaces](#network-interfaces)
- [Design Patterns](#design-patterns)
- [Container & Persistence Model](#container--persistence-model)
- [Open Source Modules](#open-source-modules)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Configuration Reference](#configuration-reference)
- [Management & Operations](#management--operations)
- [Grafana Dashboards](#grafana-dashboards)
- [Anomaly Detection](#anomaly-detection)
- [Nmap Active Scanning](#nmap-active-scanning)
- [Email Alerts Setup](#email-alerts-setup)
- [Dual Interface Mode](#dual-interface-mode)
- [Testing](#testing)
- [Generating Test Traffic](#generating-test-traffic)
- [Troubleshooting](#troubleshooting)
- [Project Status](#project-status)

---

## Architecture Overview

The system is organized into six layers:

| Layer | Components | Purpose |
|-------|-----------|---------|
| **Data Acquisition** | Suricata, Zeek | Capture packets from physical network interfaces, produce structured JSON logs |
| **Active Scanning** | Nmap (in Streamlit + DuckDB Manager) | On-demand port scanning via chat, scheduled weekly subnet scans |
| **Data Pipeline** | Vector, DuckDB Manager | Normalize, enrich (OUI/GeoIP), store in DuckDB with automatic TTL purge |
| **Analytics** | Grafana (9 dashboards) | Visual monitoring — traffic, devices, alerts, DNS, geo, threats, connection map |
| **Agentic Intelligence** | Streamlit + Ollama, Alert Agent | Natural language querying, autonomous anomaly detection and email alerting |
| **Operations** | Docker healthchecks, rule auto-update | All 7 services monitored; Suricata rules updated daily |

All components run as Docker containers orchestrated by Docker Compose. The only host-installed dependency is Ollama (the local LLM runtime). No data ever leaves the machine.

---

## Components

### 1. Suricata — Signature-Based IDS

| | |
|---|---|
| **Image** | `jasonish/suricata:7.0.8` |
| **Container** | `ids-suricata` |
| **Network** | `host` mode (direct interface access) |
| **Capabilities** | `NET_ADMIN`, `NET_RAW`, `SYS_NICE` |
| **Output** | `/var/log/ids/suricata/eve.json` |

Suricata is a high-performance, signature-based intrusion detection engine. It inspects every packet against thousands of rules (ET Open ruleset, updated at build time) and produces a single EVE JSON log file with multiple event types.

**What it captures:**
- **Alerts** — rule-triggered detections (malware, exploits, policy violations)
- **DNS** — all DNS queries and responses with full detail
- **TLS** — certificate info, SNI, JA3/JA4 fingerprints
- **HTTP** — requests, headers, URIs, user agents
- **Anomalies** — protocol decode errors, malformed packets
- **SMTP/Files** — email metadata, file extraction with MD5/SHA256 hashes

**Key configuration** (`suricata/suricata.yaml`):
- `community-id: true` — generates a standardized flow hash that correlates events with Zeek
- `af-packet` with `use-mmap: yes` and `tpacket-v3: yes` for high-performance capture
- App-layer protocol detection enabled for HTTP, TLS, DNS, SSH, SMTP, FTP, DHCP, SMB, NFS, and more
- `interface: default` — actual interface substituted at runtime from `$NETWORK_INTERFACE`

**Background watchdogs** (`suricata/entrypoint.sh`):

| Watchdog | Function | Interval | Signal |
|----------|----------|----------|--------|
| `eve_rotate_watchdog` | Rotates `eve.json` when it exceeds `MAX_EVE_SIZE_MB` (default 200MB) | 5 min | HUP (log reopen) |
| `rule_update_watchdog` | Runs `suricata-update --no-test` for fresh ET Open rules | `RULE_UPDATE_INTERVAL_HOURS` (default 24h) | USR2 (zero-downtime rule reload) |

The rule update watchdog waits 120 seconds for Suricata to fully start, then runs `suricata-update` at the configured interval. After a successful update, it sends `SIGUSR2` to reload rules without restarting the engine.

---

### 2. Zeek — Network Metadata Analyzer

| | |
|---|---|
| **Image** | `zeek/zeek:7.0.4` |
| **Container** | `ids-zeek` |
| **Network** | `host` mode (direct interface access) |
| **Capabilities** | `NET_ADMIN`, `NET_RAW` |
| **Output** | `/var/log/ids/zeek/*.log` (JSON, hourly rotation) |

Zeek (formerly Bro) is a network analysis framework. Unlike Suricata (which matches signatures), Zeek creates structured metadata logs for every connection and protocol it observes — think of it as a flight recorder for your network.

**Log types produced:**
| Log File | Content |
|----------|---------|
| `conn.log` | Every TCP/UDP/ICMP connection: IPs, ports, bytes, duration, protocol, service |
| `dns.log` | DNS queries: domain, type (A/AAAA/MX/PTR), response codes |
| `http.log` | HTTP requests: method, URI, host, user agent, status |
| `ssl.log` | TLS handshakes: SNI, certificate details, version |
| `dhcp.log` | DHCP leases: MAC → IP assignments, hostnames |
| `files.log` | Transferred files: MIME types, sizes, hashes |
| `ssh.log` | SSH connections: version, auth attempts |
| `weird.log` | Protocol anomalies |

**Key configuration** (`zeek/local.zeek`):
- `LogAscii::use_json = T` — all logs in JSON format (not Zeek's default tab-separated)
- `policy/protocols/conn/community-id-logging` — same community-id as Suricata for cross-correlation
- `policy/protocols/conn/mac-logging` — adds MAC addresses (`orig_l2_addr`, `resp_l2_addr`) to conn.log, enabling device identification
- `policy/frameworks/files/hash-all-files` — MD5/SHA256 for transferred files
- SSH brute-force and SQL injection detection policies loaded
- Hourly log rotation (`Log::default_rotation_interval = 1hr`)

**Why both Suricata and Zeek?** They serve complementary purposes. Suricata excels at signature-based detection (known threats). Zeek excels at metadata extraction (full connection records, protocol details). Both can capture on the same interface simultaneously — Linux delivers packet copies to each socket independently. The `community-id` flow hash lets you correlate a Suricata alert with the full Zeek connection record.

---

### 3. Vector — Log Pipeline

| | |
|---|---|
| **Image** | `timberio/vector:0.53.0-alpine` |
| **Container** | `ids-vector` |
| **Network** | Default (bridge) |
| **Config** | `vector/vector.yaml` |
| **Output** | `/var/log/ids/vector/**/*.ndjson` |

Vector.dev is a lightweight, high-performance log pipeline written in Rust. It tails the raw log files from Suricata and Zeek, normalizes them into a consistent schema, and writes hourly-partitioned NDJSON (newline-delimited JSON) files for DuckDB to ingest.

**Pipeline stages** (`vector/vector.yaml`):

```
Sources                         Transforms               Sinks
──────────────────────────────  ──────────────────────   ──────────────────────────
suricata_eve                    parse_suricata            ndjson_suricata
  /var/log/ids/suricata*/         Parse JSON               /vector/suricata/eve/
  eve.json (glob)                 Add source_tool=           YYYY-MM-DD-HH.ndjson
  covers: suricata/               "suricata", log_type=
          suricata-wifi/          "eve"
          suricata-virbr/

zeek_logs                       parse_zeek                ndjson_zeek
  /var/log/ids/zeek*/*.log        Parse JSON               /vector/zeek/{log_type}/
  (glob, excl. reporter,          Add source_tool=           YYYY-MM-DD-HH.ndjson
   packet_filter)                 "zeek"
  covers: zeek/                   Derive log_type from
          zeek-wifi/              filename (strips zeek
          zeek-virbr/             dir + timestamp suffix)
                                  Convert epoch→ISO8601
```

**Why Vector and not direct ingestion?**
- Suricata and Zeek output different formats; Vector normalizes them with consistent `source_tool`, `log_type`, and `timestamp` fields
- Hourly file partitioning means past-hour files are immutable — safe for bulk ingestion without deduplication concerns
- Vector handles log rotation, file discovery, and backpressure automatically
- Keeps the DuckDB manager simple: it just reads completed NDJSON files

---

### 4. DuckDB Manager — Storage & Enrichment

| | |
|---|---|
| **Image** | `python:3.12-slim` + `duckdb==1.4.4` + `nmap` |
| **Container** | `ids-duckdb-mgr` |
| **Network** | `host` mode (to reach Ollama on localhost for RAG indexing) |
| **Database** | `/var/log/ids/duckdb/ids.duckdb` |

The DuckDB Manager is the central data service. It runs a 10-second main loop plus a continuously running background thread (IPWatcher) for near-real-time new-device detection.

**Background threads:**

| Thread | Trigger | Purpose |
|--------|---------|---------|
| **IPWatcher** (always running, 1s poll) | New bytes in any `zeek*/conn*.log` or `suricata*/eve.json` | Detects new RFC1918 IPs within ~1s and writes to `fast_alerts.db` — email sent within ~2s, no ingest cycle wait |
| **RAG Indexer** (on-demand, `RAG_AUTO_INDEX=true` only) | Rules file mtime change | Embeds all Suricata rules via `nomic-embed-text` into `rag.duckdb` for semantic threat intel search; ~90min on CPU-only hardware; disabled by default |

**Main loop (every 10 seconds):**

```
┌─────────────────────────────────────────────────────────┐
│  0. FAST-PATH DRAIN                                     │
│     Drain IPWatcher fast_alerts.db → _known_devices     │
│       + anomaly_events (via duckdb_drained flag)        │
│                                                         │
│  1. INGEST                                              │
│     Scan /var/log/ids/vector/ for new/modified NDJSON   │
│     Bulk-load via read_json_objects() into events table  │
│     Track ingested files by path + mtime                │
│                                                         │
│  2. FAST NEW DEVICE CHECK                               │
│     Query events table for new private IPs (last 2 min) │
│     Fallback for IPs that slipped past IPWatcher        │
│     Insert into _known_devices + anomaly_events         │
│                                                         │
│  3. PURGE                                               │
│     Delete events older than TTL_HOURS (default 24h)    │
│     Run CHECKPOINT to finalize deletions                │
│                                                         │
│  4. ENRICHMENT + SUMMARIES (every 5 cycles / ~50s)      │
│     Rebuild devices table (internal IPs + MACs)         │
│       - Join with OUI lookup → manufacturer name        │
│       - Join with DHCP logs → hostname                  │
│     Rebuild external_ips table                          │
│       - Join with GeoIP lookup → country code           │
│     Update per-device behavioral baselines (EMA)        │
│     Detect anomalies (7 detectors) → anomaly_events     │
│                                                         │
│  5. NMAP                                                │
│     Sync on-demand scan results from SQLite → DuckDB    │
│     Run scheduled subnet scan (weekly by default)       │
│                                                         │
│  6. VACUUM + AUTO-COMPACT (every 10 cycles / ~100s)     │
│     VACUUM: reclaim space from deleted rows             │
│     AUTO-COMPACT: if DB > 80% of MAX_DB_SIZE_MB AND    │
│       file is >3x estimated live data size →            │
│       export to parquet, recreate DB, reimport          │
│       (DuckDB VACUUM alone cannot shrink the file)      │
│                                                         │
│  7. CLEANUP                                             │
│     Remove old NDJSON staging files                     │
│     Remove rotated Zeek logs (all zeek* dirs)           │
│     Enforce disk size caps                              │
│                                                         │
│  8. SNAPSHOT                                            │
│     Copy ids.duckdb → ids_readonly.duckdb (Grafana)     │
│     Copy ids.duckdb → ids_streamlit.duckdb (Chat UI)    │
│     Copy ids.duckdb → ids_alert.duckdb (Alert Agent)    │
└─────────────────────────────────────────────────────────┘
```

**Enrichment databases** (downloaded automatically, no API keys needed):
- **OUI (IEEE)** — Maps MAC address prefixes to hardware manufacturers (e.g., `AA:BB:CC` → "Apple, Inc."). Source: `standards-oui.ieee.org`, ~32K entries, refreshed weekly.
- **GeoIP (DB-IP)** — Maps IPv4 addresses to countries (e.g., `8.8.8.8` → "US"). Source: `download.db-ip.com` free tier, ~250K IPv4 ranges, refreshed monthly.

**Snapshot architecture:**
DuckDB has a single-writer lock. Multiple containers (Grafana, Streamlit, Alert Agent) need to read the database simultaneously, but Docker's PID namespace isolation causes lock conflicts even for read-only connections. Solution: each consumer gets its own atomic copy of the database, updated after every ingestion cycle:

| Snapshot File | Consumer | Purpose |
|--------------|----------|---------|
| `ids.duckdb` | DuckDB Manager | Primary read-write database |
| `ids_readonly.duckdb` | Grafana | Dashboard queries |
| `ids_streamlit.duckdb` | Streamlit | Chat tool queries |
| `ids_alert.duckdb` | Alert Agent | Anomaly context queries |

---

### 5. Grafana — Dashboards

| | |
|---|---|
| **Image** | `grafana/grafana:11.6.0-ubuntu` + DuckDB plugin |
| **Container** | `ids-grafana` |
| **Port** | `GRAFANA_PORT` (default `3000`) — set in `.env` |
| **Credentials** | `admin` / `admin` |

Grafana provides 9 auto-provisioned dashboards that query DuckDB directly via the `motherduck-duckdb-datasource` plugin (v0.4.0). All dashboards and the datasource are provisioned from files — no manual setup needed on first boot.

**Dashboards:**

| Dashboard | What it shows |
|-----------|--------------|
| **Overview** (home) | KPI stats (total events, alerts, unique IPs), event timeline, event type & protocol breakdowns, device table, external IP table |
| **Suricata Alerts** | Alert timeline, severity distribution, top signatures, alert detail table |
| **Network Traffic** | Traffic volume over time, protocol distribution, top talkers (source/dest), bytes by protocol |
| **DNS Analysis** | Query timeline, top domains, NXDOMAIN failures, query types |
| **Threats & Correlation** | Anomaly events, TLS issues, community-id cross-correlation between Suricata and Zeek |
| **Network Nodes** | Device inventory with manufacturer, connection count, noisiest devices |
| **Device Detail** | Drill-down per device (dropdown selector): connection history, protocols, services, external IPs contacted |
| **External Access & GeoIP** | External IPs by country, country breakdown pie chart, inbound connections, top services/ports |
| **Connection Map** | Node graph of device-to-device connections with manufacturer/country enrichment; top connection pairs table |

---

### 6. Streamlit — Chat with your Network

| | |
|---|---|
| **Image** | `python:3.12-slim` + `streamlit`, `ollama`, `duckdb`, `nmap`, `curl` |
| **Container** | `ids-streamlit` |
| **Network** | `host` mode (to reach Ollama on localhost) |
| **Port** | `8501` (http://localhost:8501) |

Streamlit provides a natural language chat interface powered by a local LLM (Qwen2.5-3B via Ollama). You ask questions in plain English and the LLM translates them into SQL queries and tool calls against your IDS database.

**Example prompts:**
- "List all devices on my network"
- "Show me DNS queries to suspicious domains in the last hour"
- "What external IPs from Russia have contacted my network?"
- "Are there any Suricata alerts?"
- "What protocols is 192.168.2.1 using?"
- "Scan 192.168.2.1 for open ports"
- "Do a service detection scan on 192.168.2.0/24"
- "Show me previous scan results for 192.168.2.1"

**How it works:**
1. User types a question
2. Streamlit sends it to Ollama with the system prompt (which teaches the LLM your database schema) and 12 available tool definitions
3. The LLM decides which tool(s) to call — it may chain multiple calls (e.g., query events, then look up a device, then check the whitelist)
4. Each tool result is fed back to the LLM
5. The LLM synthesizes a final answer in plain English with markdown tables

**Available tools:**

| Tool | What it does |
|------|-------------|
| `query_events` | Execute arbitrary read-only SQL against DuckDB (SELECT only, 50-row cap) |
| `get_devices` | List all known internal devices with manufacturer, hostname, traffic stats |
| `get_alerts` | Get recent Suricata IDS alerts (signature, severity, source/dest IPs) |
| `get_external_connections` | External IPs with GeoIP country data, optional country filter |
| `get_dns_top_domains` | Most queried DNS domains |
| `get_traffic_by_protocol` | Connection counts and bytes by protocol (TCP, UDP, ICMP) |
| `get_event_stats` | Event counts grouped by source tool and log type |
| `check_whitelist` | Manage IP whitelist (list/check/add/remove) via SQLite |
| `send_notification` | Send notifications via Apprise (Slack, email, Discord, etc.) |
| `send_email` | Send email via Gmail SMTP (App Password, TLS encrypted) |
| `nmap_scan` | Active port scan — RFC1918 targets only, quick/full/service modes, 300s timeout |
| `get_scan_history` | Retrieve past nmap scan results, optional IP filter |

**Safety:** DuckDB is opened read-only. Only SELECT queries are allowed. Results are capped at 50 rows. Nmap scans are restricted to RFC1918 private addresses only — external targets are rejected. No NSE scripts are used.

---

### 7. Alert Agent — Autonomous Email Alerts

| | |
|---|---|
| **Image** | `python:3.12-slim` + `ollama`, `duckdb` |
| **Container** | `ids-alert-agent` |
| **Network** | `host` mode (to reach Ollama on localhost) |
| **Secrets** | Gmail credentials via Docker Secrets |

The Alert Agent has two independent alerting paths running simultaneously:

**Fast path — `fast_alert_loop` daemon thread (polls every 2s):**
- Reads `fast_alerts.db` SQLite (written by duckdb-mgr's IPWatcher thread)
- Sends an immediate, template-based email within ~2s of a new device appearing
- Subject: `[IDS FAST ALERT] New Device: {ip}`
- No LLM involved — zero inference latency
- Uses independent `alert_emailed` flag so it never conflicts with the main LLM path

**Rich path — main loop (polls every 10s):**
- Reads `anomaly_events` from DuckDB snapshot (`ids_alert.duckdb`)
- For each unprocessed anomaly, hands it to the LLM (Qwen2.5 via Ollama) which:
  1. Reads the anomaly details
  2. Optionally queries the DB for additional context (e.g., "what other connections did this IP make?")
  3. Drafts a professional email with severity analysis and recommended actions
  4. Calls `send_email` tool
- Covers all 7 anomaly types (new device, traffic spike, Suricata alert, suspicious country, massive volume, device behavior, dest fan-out)

**Why two paths?** The fast path delivers instant notification while the LLM is still processing. A new-device event generates two emails: an immediate bare-facts alert within seconds, followed by a richer LLM-analyzed email with context.

**Tools available to the Alert Agent (rich path):**

| Tool | Purpose |
|------|---------|
| `query_events` | Read-only SQL against DuckDB for context gathering |
| `send_email` | Send email via Gmail SMTP (App Password, TLS encrypted) |
| `rag_search_threat_intel` | Semantic search over Suricata rule embeddings in `rag.duckdb` (pre-injected automatically for `suricata_alert` anomalies) |

**State tracking:** Uses a separate SQLite database (`alert_state.db`) to track which `anomaly_events` IDs have been processed by the LLM path, avoiding the DuckDB single-writer lock entirely.

**Credential security:** Gmail App Password stored as Docker Secrets (mounted read-only at `/run/secrets/` inside the container, never in environment variables, never in Docker image layers, never visible in `docker inspect`).

---

### 8. Ollama — Local LLM Engine

| | |
|---|---|
| **Installed on** | Host machine (not in Docker) |
| **Port** | `11434` (localhost only) |
| **Model** | `qwen3.5:2b` (default) |
| **GPU** | Radeon 780M via Vulkan (`OLLAMA_VULKAN=1`) — ~18 tok/s decode |

Ollama is the local LLM runtime. It serves the Qwen3.5 model that powers both the Streamlit chat and the Alert Agent.

**Why host-installed?** Ollama needs direct GPU/CPU access for inference. Running it inside Docker adds complexity (GPU passthrough) with no benefit. Both Streamlit and Alert Agent containers use `network_mode: host` to reach it on `localhost:11434`.

**Model choice:**
- `qwen3.5:2b` — Default. ~18 tok/s on Radeon 780M GPU (~12s for 200-token response), 2.7GB RAM, 262K context, better than qwen2.5:3b. Fits on Raspberry Pi 5 (CPU-only there).
- `qwen2.5:3b` — Fallback. ~10 tok/s CPU-only, 2GB RAM.

**GPU acceleration (Radeon 780M):**
Ollama uses the integrated Radeon 780M via Vulkan (enabled with `OLLAMA_VULKAN=1` in the systemd service override). No ROCm installation needed — Mesa RADV provides the Vulkan driver. Confirmed working on Ubuntu 24.04 with `ollama ps` showing `100% GPU`.

Systemd override at `/etc/systemd/system/ollama.service.d/override.conf`:
```ini
[Service]
CPUQuota=600%
Environment="OLLAMA_VULKAN=1"
```

To verify GPU is active: `ollama ps` — look for `100% GPU` in the PROCESSOR column.

Ollama's native tool/function calling is used (no separate MCP server). The LLM receives tool schemas and decides when to call them.

---

## Data Flow

Here is the complete path of a single network packet through the system:

```
1. CAPTURE          Packet arrives on network interface
                    ├── Suricata: checks against ~30K ET Open rules
                    │   → writes to /var/log/ids/$LOG_SUBDIR/eve.json
                    │     (suricata/, suricata-wifi/, suricata-virbr/)
                    └── Zeek: extracts connection metadata
                        → writes to /var/log/ids/$LOG_SUBDIR/*.log
                          (zeek/, zeek-wifi/, zeek-virbr/)

1b. FAST DETECT     IPWatcher thread in duckdb-mgr (every 1s)
                    ├── Tails all zeek*/conn*.log + suricata*/eve.json (byte-level)
                    ├── New RFC1918 IP seen? → write to fast_alerts.db immediately
                    └── Alert Agent fast_alert_loop picks it up within 2s
                        └── Email sent: [IDS FAST ALERT] New Device: {ip}

2. NORMALIZE        Vector tails all interface subdirs via wildcard globs
                    ├── suricata*/eve.json → parse + tag source_tool="suricata"
                    ├── zeek*/*.log        → parse + tag source_tool="zeek"
                    │   (derive log_type from filename, convert epoch→ISO8601)
                    └── Writes to /var/log/ids/vector/{tool}/{type}/YYYY-MM-DD-HH.ndjson

3. INGEST           DuckDB Manager (every 10s)
                    ├── Scans for new/modified NDJSON files
                    ├── Bulk loads via read_json_objects() into events table
                    └── Tracks ingested files by path + mtime to prevent duplicates

3b. FAST CHECK      DuckDB Manager — fast_new_device_check (every 10s)
                    ├── Queries events table for new IPs seen in last 2 min
                    └── Fallback for IPs that IPWatcher may have missed

4. ENRICH           DuckDB Manager (every ~50s / 5 cycles)
                    ├── Drains fast_alerts.db → _known_devices + anomaly_events
                    ├── Rebuilds devices table (internal IPs)
                    │   ├── MAC → manufacturer via OUI lookup (IEEE database)
                    │   └── IP → hostname via DHCP log correlation
                    ├── Rebuilds external_ips table
                    │   └── IP → country via GeoIP lookup (DB-IP database)
                    ├── Updates per-device behavioral baselines (EMA)
                    └── Runs 7 anomaly detectors → anomaly_events table

4b. NMAP            DuckDB Manager (each cycle + weekly scheduled)
                    ├── Syncs on-demand scan results from SQLite → DuckDB
                    └── Runs scheduled subnet scan (weekly, configurable)

5. SNAPSHOT         DuckDB Manager (after each data change)
                    └── Atomic copy to 3 read-only snapshots for consumers

6. VISUALIZE        Grafana reads ids_readonly.duckdb → 9 dashboards
                    Streamlit reads ids_streamlit.duckdb → chat tool queries
                    Alert Agent reads ids_alert.duckdb → anomaly context queries

7. ALERT (RICH)     Alert Agent polls anomaly_events every 10s
                    ├── Hands anomaly to LLM (Qwen2.5 via Ollama)
                    ├── LLM may query DB for more context (up to 5 tool rounds)
                    ├── suricata_alert anomalies: pre-enriched with RAG context
                    │   (semantic search over rag.duckdb threat intel index)
                    ├── LLM drafts email and calls send_email tool
                    └── Email sent via Gmail SMTP (App Password)

8. RAG INDEX        duckdb-mgr background thread (only if RAG_AUTO_INDEX=true)
                    ├── Triggered when suricata.rules mtime changes
                    ├── Parses all ~49K rules → enriched chunk text
                    ├── Embeds via Ollama nomic-embed-text (batch 50, ~90min)
                    └── Atomic rename staging → rag.duckdb on completion
```

---

## Database Schema

All data lives in DuckDB (`/var/log/ids/duckdb/ids.duckdb`). Here are the tables:

### Core Tables

**`events`** — All log events from Suricata and Zeek (the primary table)
```sql
timestamp    TIMESTAMPTZ   -- When the event occurred
source_tool  VARCHAR       -- 'suricata' or 'zeek'
log_type     VARCHAR       -- 'eve', 'conn', 'dns', 'ssl', 'http', etc.
source_file  VARCHAR       -- Path to the NDJSON file it was loaded from
raw          JSON          -- Complete original event JSON
```
Fields within `raw` are queried via `json_extract_string(raw, '$.field')`. Zeek's dotted keys need quoting: `json_extract_string(raw, '$."id.orig_h"')`.

### Enrichment Tables

**`oui_lookup`** — IEEE MAC manufacturer database (~32K entries)
```sql
oui_prefix    VARCHAR(6) PK   -- First 6 hex chars of MAC (e.g., "A4C3F0")
manufacturer  VARCHAR         -- "Apple, Inc.", "Intel Corporate", etc.
```

**`geoip_lookup`** — DB-IP country ranges (~250K IPv4 ranges)
```sql
ip_start  UINTEGER    -- Range start as uint32
ip_end    UINTEGER    -- Range end as uint32
country   VARCHAR(2)  -- ISO 3166-1 alpha-2 code ("US", "DE", "CN")
```

### Materialized Summary Tables (rebuilt every 5 min)

**`devices`** — Internal network device inventory
```sql
ip           VARCHAR PK     -- Internal IP address
mac          VARCHAR        -- MAC address (from Zeek conn.log)
manufacturer VARCHAR        -- Resolved via OUI lookup
hostname     VARCHAR        -- From DHCP log correlation
first_seen   TIMESTAMPTZ    -- Earliest event timestamp
last_seen    TIMESTAMPTZ    -- Latest event timestamp
total_conns  BIGINT         -- Total connection count
total_bytes  BIGINT         -- Total bytes transferred (orig + resp)
protocols    VARCHAR        -- Comma-separated (e.g., "tcp,udp")
services     VARCHAR        -- Comma-separated (e.g., "dns,http,ssl")
```

**`external_ips`** — External IP addresses your network communicated with
```sql
ip            VARCHAR PK     -- External IP address
country       VARCHAR(2)     -- Resolved via GeoIP lookup
total_conns   BIGINT         -- Total connections to this IP
total_bytes   BIGINT         -- Total bytes transferred
contacted_by  VARCHAR        -- Comma-separated internal IPs that contacted it
top_service   VARCHAR        -- Most common service (e.g., "dns", "ssl")
top_dest_port INTEGER        -- Most common destination port
```

### Anomaly Detection Tables

**`anomaly_events`** — Detected anomalies (consumed by Alert Agent)
```sql
id           INTEGER PK              -- Auto-incrementing via anomaly_id_seq
detected_at  TIMESTAMPTZ DEFAULT now()
anomaly_type VARCHAR                 -- 'new_device', 'traffic_spike', 'suricata_alert',
                                     -- 'suspicious_country', 'massive_volume',
                                     -- 'device_behavior', 'dest_fanout'
severity     VARCHAR                 -- 'medium', 'high', 'critical'
summary      VARCHAR                 -- Human-readable one-liner
details      JSON                    -- Structured data for LLM context
```

**`_known_devices`** — Tracks baseline devices for new-device detection
```sql
ip              VARCHAR PK
first_detected  TIMESTAMPTZ DEFAULT now()
```

**`device_baselines`** — Per-device behavioral baselines (rolling EMA averages)
```sql
ip              VARCHAR PK
manufacturer    VARCHAR
avg_bytes_5min  DOUBLE DEFAULT 0     -- EMA of bytes per 5-min window
avg_conns_5min  DOUBLE DEFAULT 0     -- EMA of connections per 5-min window
avg_dest_ips    DOUBLE DEFAULT 0     -- EMA of unique destination IPs per 5-min window
samples         INTEGER DEFAULT 0    -- Number of EMA samples (min 3 before alerting)
updated_at      TIMESTAMPTZ
```

### Nmap Scan Results

**`nmap_scans`** — Stored results from on-demand and scheduled nmap scans
```sql
id          INTEGER PK               -- Auto-incrementing via nmap_scan_id_seq
scanned_at  TIMESTAMPTZ DEFAULT now()
target      VARCHAR                  -- IP or CIDR that was scanned
scan_type   VARCHAR                  -- 'quick', 'full', 'service', 'scheduled_service'
results     JSON                     -- Full scan results (hosts, ports, services)
```

### SQLite Databases (separate from DuckDB)

| File | Writer | Readers | Purpose |
|------|--------|---------|---------|
| `fast_alerts.db` | IPWatcher thread (duckdb-mgr) | Alert Agent (fast path), duckdb-mgr (drain path) | Near-real-time new device fast alerts; two independent flags (`alert_emailed`, `duckdb_drained`) prevent race conditions |
| `whitelist.db` | Streamlit | Streamlit | IP whitelist (add/remove/check via chat) |
| `nmap_results.db` | Streamlit | DuckDB Manager | On-demand nmap results (synced to DuckDB by duckdb-mgr) |
| `alert_state.db` | Alert Agent | Alert Agent | Tracks which anomaly IDs have been processed by the LLM path |

### Utility

**`ip_to_uint(ip)`** — SQL macro to convert IPv4 string to uint32 for GeoIP range lookups.

---

## Component Reference

### Runtime Summary

| Component | Container | Network Mode | Runtime | Base Image | Technology |
|-----------|-----------|-------------|---------|------------|------------|
| Suricata | `ids-suricata` | host | C daemon | `jasonish/suricata:7.0.8` | af-packet capture, signature matching, EVE JSON |
| Zeek | `ids-zeek` | host | C++ daemon | `zeek/zeek:7.0.4` | libpcap capture, protocol analysis, JSON logs |
| Vector | `ids-vector` | bridge | Rust daemon | `timberio/vector:0.53.0-alpine` | VRL transforms, file tailing, NDJSON staging |
| DuckDB Manager | `ids-duckdb-mgr` | host | Python 3.12 | `python:3.12-slim` + nmap | DuckDB ingestion, enrichment, anomaly detection, scheduled nmap |
| Grafana | `ids-grafana` | bridge | Go daemon | `grafana/grafana:11.6.0-ubuntu` | DuckDB plugin, 9 provisioned dashboards |
| Streamlit | `ids-streamlit` | host | Python 3.12 | `python:3.12-slim` + nmap + curl | Ollama tool-calling, 12 LLM tools, on-demand nmap |
| Alert Agent | `ids-alert-agent` | host | Python 3.12 | `python:3.12-slim` | Ollama tool-calling, anomaly polling, Gmail SMTP |
| Ollama | _(host process)_ | host | Go daemon | _(native install)_ | Qwen2.5-3B/7B inference, tool/function calling |

### Interfaces & Ports

| Component | Inbound | Outbound | Exposed Ports |
|-----------|---------|----------|---------------|
| Suricata | Physical NIC via af-packet | `/var/log/ids/suricata/eve.json` | None |
| Zeek | Physical NIC via libpcap | `/var/log/ids/zeek/*.log` | None |
| Vector | Reads Suricata EVE + Zeek logs | `/var/log/ids/vector/**/*.ndjson` | None |
| DuckDB Manager | Reads NDJSON + SQLite `nmap_results.db` | `ids.duckdb` + 3 readonly snapshots | None |
| Grafana | Reads `ids_readonly.duckdb` | HTTP to browser | `3000` |
| Streamlit | HTTP from browser, Ollama API | `ids_streamlit.duckdb` (read), `whitelist.db` + `nmap_results.db` (write), Ollama, Gmail, Apprise | `8501` |
| Alert Agent | Reads `ids_alert.duckdb`, Ollama API | `alert_state.db` (write), Gmail SMTP | None |
| Ollama | HTTP API from Streamlit + Alert Agent | GPU/CPU inference | `11434` |

### Storage Files

| File | Format | Writer | Readers | Purpose |
|------|--------|--------|---------|---------|
| `/var/log/ids/suricata*/eve.json` | JSON (append) | Suricata (per interface) | Vector, IPWatcher | EVE alert/metadata log |
| `/var/log/ids/zeek*/*.log` | JSON (per-protocol) | Zeek (per interface) | Vector, IPWatcher | conn, dns, ssl, http, dhcp, files, ssh, weird |
| `/var/log/ids/vector/**/*.ndjson` | NDJSON (hourly) | Vector | DuckDB Manager | Normalized staging files |
| `/var/log/ids/duckdb/ids.duckdb` | DuckDB | DuckDB Manager | _(exclusive)_ | Primary database |
| `/var/log/ids/duckdb/ids_readonly.duckdb` | DuckDB (copy) | DuckDB Manager | Grafana | Dashboard snapshot |
| `/var/log/ids/duckdb/ids_streamlit.duckdb` | DuckDB (copy) | DuckDB Manager | Streamlit | Chat query snapshot |
| `/var/log/ids/duckdb/ids_alert.duckdb` | DuckDB (copy) | DuckDB Manager | Alert Agent | Alert analysis snapshot |
| `/var/log/ids/duckdb/fast_alerts.db` | SQLite | IPWatcher (duckdb-mgr thread) | Alert Agent + duckdb-mgr | Near-real-time new device fast alerts |
| `/var/log/ids/duckdb/whitelist.db` | SQLite | Streamlit | Streamlit | IP whitelist CRUD |
| `/var/log/ids/duckdb/nmap_results.db` | SQLite | Streamlit | DuckDB Manager | On-demand nmap results (synced to DuckDB) |
| `/var/log/ids/duckdb/alert_state.db` | SQLite | Alert Agent | Alert Agent | Processed anomaly ID tracking (LLM path) |
| `/var/log/ids/duckdb/oui.csv` | CSV | DuckDB Manager | DuckDB Manager | IEEE OUI manufacturer database |
| `/var/log/ids/duckdb/geoip.csv.gz` | Gzip CSV | DuckDB Manager | DuckDB Manager | DB-IP country lookup |
| `/var/log/ids/duckdb/rag.duckdb` | DuckDB | DuckDB Manager (indexer thread) | Streamlit, Alert Agent | Threat intel embeddings — Suricata rules indexed via `nomic-embed-text`; only updated when `RAG_AUTO_INDEX=true` |

### DuckDB Tables Summary

| Table | Category | Purpose |
|-------|----------|---------|
| `events` | Core | All Suricata + Zeek log events (timestamp, source_tool, log_type, raw JSON) |
| `_ingested_files` | Internal | NDJSON file dedup tracking (filepath + mtime) |
| `oui_lookup` | Enrichment | MAC prefix → manufacturer (IEEE, ~32K entries) |
| `geoip_lookup` | Enrichment | IPv4 range → country code (DB-IP, ~250K ranges) |
| `devices` | Materialized | Internal device inventory (IP, MAC, manufacturer, hostname, traffic) |
| `external_ips` | Materialized | External IP summary (IP, country, connections, contacted_by) |
| `anomaly_events` | Alerting | Detected anomalies (7 types, severity, details JSON) |
| `_known_devices` | Alerting | Baseline device IPs for new-device detection |
| `device_baselines` | Alerting | Per-device EMA behavioral baselines |
| `nmap_scans` | Scanning | Nmap scan results (target, type, results JSON) |
| `rag_threat_intel` | Threat Intel | Suricata rule embeddings (sid, msg, classtype, chunk_text, embedding float[]) — stored in `rag.duckdb` |
| `rag_index_meta` | Threat Intel | Indexer state (rules file mtime, rule count) — stored in `rag.duckdb` |

---

## Network Interfaces

The system captures traffic from physical network interfaces. Both Suricata and Zeek run with `network_mode: host` in Docker, giving them direct access to the host's interfaces.

| Interface | Type | Default Role | Notes |
|-----------|------|-------------|-------|
| `enp1s0f0` | Wired Ethernet | Primary (`NETWORK_INTERFACE`) | Full promiscuous mode, sees all LAN traffic |
| `wlp2s0` | Wireless (WiFi) | Secondary (`NETWORK_INTERFACE_2`) | Managed mode only — sees traffic to/from this machine, not full LAN |
| `virbr0` | Virtual Bridge (KVM/libvirt) | Primary or tertiary (`NETWORK_INTERFACE` or `NETWORK_INTERFACE_3`) | Monitors VM traffic on libvirt's default bridge; `192.168.0.0/16` HOME_NET covers `192.168.122.0/24` |

Set `NETWORK_INTERFACE=virbr0` in `.env` to use the virtual bridge as the primary capture interface (useful for demo environments or VM-only monitoring). The `HOME_NET=192.168.0.0/16` default already covers libvirt's default `192.168.122.0/24` subnet — no Suricata config change required.

**Important:** Wireless interfaces in managed mode cannot do true promiscuous capture. You'll only see traffic involving the machine running the IDS, not other devices' traffic. For full network visibility, use a wired connection to a mirror/span port on your switch, or use a network tap.

Both Suricata and Zeek can capture on the same interface simultaneously without conflict. Linux delivers independent packet copies to each capture socket.

**Dual-interface mode:** Activate with `docker compose --profile dual up -d` to monitor both wired and wireless simultaneously (starts `ids-suricata-wifi` and `ids-zeek-wifi` containers).

---

## Design Patterns

### Single-Table Events Store
All log types (Suricata alerts, Zeek connections, DNS queries, etc.) are stored in one `events` table with the full JSON in a `raw` column. This keeps the schema simple and lets the LLM query any field dynamically via `json_extract_string()`.

### Community-ID Cross-Correlation
Both Suricata and Zeek generate a standardized `community_id` flow hash for every connection. This allows correlating a Suricata alert with its full Zeek connection record — you can go from "Suricata flagged this" to "here's every byte count, protocol, and service Zeek observed for that same flow."

### Snapshot-per-Consumer
DuckDB allows only one writer. Instead of complex locking, the DuckDB Manager owns the write lock and atomically copies the database to separate snapshot files for each read-only consumer (Grafana, Streamlit, Alert Agent). Each snapshot is written via temp file + rename for crash safety.

### Hourly File Partitioning
Vector writes NDJSON files partitioned by hour (`YYYY-MM-DD-HH.ndjson`). Past-hour files are immutable (never appended to), making them safe for bulk ingestion. The DuckDB Manager skips the current hour's file to avoid re-ingestion churn.

### Agentic Tool Calling
Both the Streamlit chat and Alert Agent use Ollama's native function/tool calling. The LLM receives tool schemas, decides which to call, receives results, and iterates until it has enough information to answer. This is the same pattern as OpenAI function calling — no MCP server process needed.

### Docker Secrets for Credentials
Gmail credentials are stored in `secrets/*.txt` files (gitignored), referenced in `docker-compose.yml`'s top-level `secrets:` block, and mounted read-only at `/run/secrets/` inside the alert-agent container. They never appear in environment variables, image layers, or `docker inspect` output.

### State Separation
The Alert Agent tracks processed anomalies in a separate SQLite database (`alert_state.db`), not in DuckDB. This avoids write contention with the DuckDB Manager entirely.

---

## Container & Persistence Model

A common question: *do Suricata, Zeek, and DuckDB lose all their data when containers restart?* The short answer is **no** — because the containers don't own the data. The host filesystem does.

### The bind-mount pattern

Every service in this stack maps the same host directory into the container:

```yaml
volumes:
  - ${LOG_DIR:-/var/log/ids}:/var/log/ids   # same host dir, all containers
```

This means writes to `/var/log/ids` *inside* a container physically land on the host at `/var/log/ids`. Containers are just process wrappers around executables. Killing a container is equivalent to killing a process — the files it wrote remain on disk.

```
Host filesystem                           Docker containers (ephemeral)
─────────────────────────────────         ──────────────────────────────
/var/log/ids/suricata/eve.json    ◄────── ids-suricata  (Suricata daemon)
/var/log/ids/zeek/conn.log etc.   ◄────── ids-zeek      (Zeek daemon)
/var/log/ids/vector/*.ndjson      ◄────── ids-vector    (Vector pipeline)
/var/log/ids/duckdb/ids.duckdb    ◄────►  ids-duckdb-mgr (Python + DuckDB)
/var/log/ids/duckdb/alert_state.db        ids-alert-agent (Python)
/var/log/ids/duckdb/fast_alerts.db
```

### What each container actually is

| Container | What runs inside | State model |
|-----------|----------------|-------------|
| `ids-suricata` | `suricata` binary, C daemon | Stateless — reads packets from NIC, appends to `eve.json` on host. No memory of past sessions needed. |
| `ids-zeek` | `zeek` binary, C++ daemon | Stateless — reads packets from NIC, appends to `*.log` files on host. |
| `ids-vector` | `vector` binary, Rust daemon | Stateless — tails files, writes files, all on host. |
| `ids-duckdb-mgr` | Python process | **DuckDB file on host is the state.** Opened fresh every cycle, closed during sleep. |
| `ids-grafana` | Grafana binary, Go daemon | Has a named Docker volume (`grafana-data`) for its internal settings. DuckDB accessed via bind mount. |
| `ids-streamlit` | Python process | Reads DuckDB read-only snapshot. Writes `whitelist.db` and `nmap_results.db` to host. |
| `ids-alert-agent` | Python process | `alert_state.db` and `fast_alerts.db` on host track state across restarts. |
| Ollama | **Host process** (not Docker) | Not in Docker at all — runs natively for GPU access. |

### What survives a container restart

| Data | Survived? | Why |
|------|-----------|-----|
| Suricata `eve.json` | ✅ Yes | Written to bind-mounted host directory |
| Zeek `conn.log`, `dns.log`, etc. | ✅ Yes | Written to bind-mounted host directory |
| DuckDB `ids.duckdb` (all events, devices, baselines, anomalies) | ✅ Yes | On host at `/var/log/ids/duckdb/` |
| `_known_devices` table | ✅ Yes | Part of DuckDB, persists on host |
| `alert_state.db` (processed anomaly IDs) | ✅ Yes | SQLite on host |
| `fast_alerts.db` (fast alert queue) | ✅ Yes | SQLite on host |
| `known_ips` in-memory set (duckdb-mgr) | ❌ Lost | Re-seeded from `_known_devices` table at startup (~1ms) |
| IPWatcher file positions | ❌ Lost | Re-initializes by seeking all existing files to EOF (won't replay old data as "new devices") |
| Grafana dashboards / datasource config | ✅ Yes | Auto-provisioned from `grafana/provisioning/` on every startup — always correct |
| Grafana user data (annotations, etc.) | ✅ Yes | `grafana-data` named Docker volume |

The only in-memory state that gets lost is the `known_ips` set in duckdb-mgr. It's rebuilt in a single DuckDB query at startup:

```python
for (ip,) in db.execute("SELECT ip FROM _known_devices").fetchall():
    known_ips.add(ip)
log.info("Seeded %d known IPs from _known_devices", len(known_ips))
```

### Why `network_mode: host` for Suricata, Zeek, Streamlit, and Alert Agent

Docker's default **bridge networking** puts containers on a virtual `docker0` LAN — they only see inter-container traffic, not the physical network. With `network_mode: host`, the container shares the host's network stack directly:

- **Suricata / Zeek** — need raw socket access to physical interfaces (`virbr0`, `enp1s0f0`) for packet capture. Bridge networking would only show them Docker's internal traffic.
- **Streamlit / Alert Agent** — need to reach Ollama at `localhost:11434` on the host. With bridge networking, `localhost` inside the container refers to the container itself, not the host. `host` mode makes them share the host's loopback.

Both Suricata and Zeek can capture the same physical interface simultaneously — Linux delivers independent packet copies to each capture socket, so there is no conflict.

### DuckDB single-writer lock

DuckDB allows only one writer at a time. When duckdb-mgr exits (container stop, crash), the write lock is released immediately — the next startup opens the file cleanly with no manual intervention. The lock is a file advisory lock, not embedded in the database file itself.

---

## Open Source Modules

| Module | Version | Language | Role |
|--------|---------|----------|------|
| [Suricata](https://suricata.io/) | 7.0.8 | C | Signature-based IDS, protocol analysis, EVE JSON output |
| [Zeek](https://zeek.org/) | 7.0.4 | C++ | Network metadata extraction, connection logging |
| [Vector](https://vector.dev/) | 0.53.0 | Rust | Log ingestion, parsing, transformation, routing |
| [DuckDB](https://duckdb.org/) | 1.4.4 | C++ | Embedded OLAP database, JSON support, SQL analytics |
| [Grafana](https://grafana.com/) | 11.6.0 | Go | Dashboard visualization, auto-provisioned panels |
| [DuckDB Grafana Plugin](https://github.com/motherduckdb/grafana-duckdb-datasource) | 0.4.0 | Go | Grafana datasource for DuckDB files |
| [Ollama](https://ollama.com/) | 0.14+ | Go | Local LLM inference runtime |
| [Qwen2.5](https://huggingface.co/Qwen/Qwen2.5-3B) | 3B/7B | — | LLM model with tool-calling support |
| [Streamlit](https://streamlit.io/) | 1.40+ | Python | Chat UI framework |
| [Apprise](https://github.com/caronc/apprise) | 1.8+ | Python | Multi-platform notification library (Slack, email, Discord) |
| [DB-IP](https://db-ip.com/db/lite.php) | Monthly | — | Free GeoIP country database (IPv4 → country) |
| [IEEE OUI](https://standards-oui.ieee.org/) | Weekly | — | MAC address manufacturer database |

---

## Prerequisites

### 1. Docker Engine + Compose

```bash
docker --version          # need 24.0+
docker compose version    # need v2.20+

# Install on Ubuntu/Debian if needed:
sudo apt update
sudo apt install -y docker.io docker-compose-v2
sudo usermod -aG docker $USER
# Log out and back in for group change
```

### 2. Ollama (for Phase 3 chat + alerts)

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen3.5:2b
ollama pull nomic-embed-text   # for RAG threat intel (optional)
```

**Enable GPU acceleration (Radeon 780M on Ubuntu 24.04):**
```bash
sudo mkdir -p /etc/systemd/system/ollama.service.d
sudo tee /etc/systemd/system/ollama.service.d/override.conf << 'EOF'
[Service]
CPUQuota=600%
Environment="OLLAMA_VULKAN=1"
EOF
sudo systemctl daemon-reload && sudo systemctl restart ollama
```
Verify with `ollama ps` after running a query — should show `100% GPU`.

### 3. Identify your network interface

```bash
ip -br link show | grep -v lo
```

Look for the interface showing `UP`:
```
enp1s0f0   DOWN   ...      <-- wired (cable not plugged in)
wlp2s0     UP     ...      <-- wireless (active)
```

---

## Quick Start

### 1. Clone and configure

```bash
cd ~/claude_ids
cp .env.example .env
nano .env   # set NETWORK_INTERFACE to your active interface
```

### 2. Create the log directory

```bash
sudo mkdir -p /var/log/ids
sudo chmod 777 /var/log/ids
```

### 3. Set up Gmail alerts (optional)

```bash
mkdir -p secrets
echo "your-email@gmail.com" > secrets/gmail_user.txt
echo "xxxx-xxxx-xxxx-xxxx" > secrets/gmail_app_password.txt
echo "recipient@example.com" > secrets/alert_recipient.txt
```

See [Email Alerts Setup](#email-alerts-setup) for details on generating a Gmail App Password.

### 4. Build and start

```bash
docker compose build
docker compose up -d
```

First run pulls ~500MB of images and builds custom images. Takes 3-5 minutes.

### 5. Verify

```bash
docker compose ps                    # All containers should be "Up"
bash scripts/verify.sh               # Phase 1: Suricata + Zeek
bash scripts/verify_phase2.sh        # Phase 2: Vector + DuckDB
bash scripts/verify_phase2_5.sh      # Phase 2.5: Grafana dashboards
bash scripts/verify_phase3.sh        # Phase 3: Ollama + Streamlit
```

### 6. Access the UIs

| Service | URL | Credentials |
|---------|-----|-------------|
| Grafana Dashboards | `http://localhost:${GRAFANA_PORT}` (default: 3000) | admin / admin |
| Streamlit Chat | `http://localhost:${STREAMLIT_PORT}` (default: 8501) | — |

Both ports are configurable in `.env` via `GRAFANA_PORT` and `STREAMLIT_PORT`.

---

## Configuration Reference

All runtime settings live in `.env` (never hardcode):

| Variable | Default | Description |
|----------|---------|-------------|
| `NETWORK_INTERFACE` | `enp1s0f0` | Primary capture interface |
| `NETWORK_INTERFACE_2` | `wlp2s0` | Secondary interface (dual mode) |
| `LOG_DIR` | `/var/log/ids` | Host path for all logs and databases |
| `HOME_NET` | `192.168.0.0/16` | Your LAN CIDR (Suricata alerting context) |
| `SURICATA_TAG` | `7.0.8` | Suricata Docker image tag |
| `ZEEK_TAG` | `7.0.4` | Zeek Docker image tag |
| `VECTOR_TAG` | `0.53.0-alpine` | Vector Docker image tag |
| `GRAFANA_TAG` | `11.6.0-ubuntu` | Grafana Docker image tag |
| `DUCKDB_TTL_HOURS` | `24` | Hours to retain events before purging |
| `STAGING_RETENTION_HOURS` | `6` | Hours to keep NDJSON staging files |
| `MAX_DB_SIZE_MB` | `4000` | DuckDB max size — ingestion pauses if exceeded |
| `MAX_EVE_SIZE_MB` | `200` | Suricata eve.json rotation threshold |
| `GRAFANA_PORT` | `3000` | Grafana web UI port |
| `OLLAMA_MODEL` | `qwen2.5:3b` | LLM model for chat and alerts |
| `STREAMLIT_PORT` | `8501` | Streamlit chat UI port |
| `APPRISE_URLS` | (empty) | Apprise notification URLs (comma-separated) |
| `NMAP_SUBNET` | `192.168.2.0/24` | Subnet for scheduled nmap scans (RFC1918 only) |
| `NMAP_SCAN_INTERVAL_HOURS` | `168` | Hours between scheduled scans (168 = weekly) |
| `RULE_UPDATE_INTERVAL_HOURS` | `24` | Hours between Suricata rule auto-updates |
| `SPIKE_RATIO` | `5.0` | Traffic spike: fire when 5-min conns > N x hourly avg |
| `SPIKE_MIN_CONNS` | `1000` | Traffic spike: minimum absolute connections to trigger |
| `SPIKE_COOLDOWN_MIN` | `60` | Minutes between traffic spike alerts |
| `VOLUME_THRESHOLD_MB` | `500` | Massive volume: MB in 5 min per device to trigger |
| `SUSPICIOUS_COUNTRIES` | `CN,RU,KP,IR,BY` | ISO country codes for suspicious traffic alerts |
| `BEHAVIOR_RATIO` | `10.0` | Device behavior: alert when N x above EMA baseline |
| `BEHAVIOR_MIN_SAMPLES` | `3` | EMA samples needed before behavioral alerting |
| `BASELINE_EMA_ALPHA` | `0.3` | EMA smoothing factor (higher = adapts faster) |
| `FANOUT_RATIO` | `5.0` | Destination fan-out: alert when unique dest IPs > N x baseline |
| `FANOUT_MIN_IPS` | `10` | Minimum unique dest IPs to trigger fan-out alert |
| `RAG_AUTO_INDEX` | `false` | Enable automatic Suricata rule re-embedding on rule updates (CPU-intensive ~90min run on CPU-only hardware; set `true` to enable) |
| `EMBED_MODEL` | `nomic-embed-text` | Ollama embedding model used for RAG indexing |

---

## Management & Operations

### Container management

```bash
docker compose ps                     # Status of all containers
docker compose logs <service> -f      # Follow logs for a service
docker compose up -d                  # Start/recreate all services
docker compose down                   # Stop all containers (data persists)
docker compose build && docker compose up -d   # Rebuild after code changes
```

### Docker health checks

All 7 services have Docker-native healthchecks. View status:

```bash
docker compose ps                     # Shows health status for each container
```

| Service | Check Method | Start Period |
|---------|-------------|-------------|
| Suricata | `pidof suricata` | 60s |
| Zeek | `pidof zeek` | 60s |
| Vector | `pgrep -x vector` | 30s |
| DuckDB Manager | `ids.duckdb` file exists | 30s |
| Grafana | `curl /api/health` | 30s |
| Streamlit | `curl /_stcore/health` | 30s |
| Alert Agent | `alert_state.db` file exists | 30s |

All: interval 30s, timeout 10s, retries 3. Docker marks containers as `unhealthy` after 3 consecutive failures and `restart: unless-stopped` ensures automatic recovery.

### Verification scripts

```bash
bash scripts/verify.sh                # Phase 1: capture layer
bash scripts/verify_phase2.sh         # Phase 2: data pipeline
bash scripts/verify_phase2_5.sh       # Phase 2.5: Grafana
bash scripts/verify_phase3.sh         # Phase 3: LLM chat
bash scripts/verify_phase3b.sh        # Phase 3b: alert agent
bash tests/test_sanity.sh             # Full-stack sanity (84 tests)
```

### Query DuckDB manually

```bash
docker exec ids-duckdb-mgr python3 -c "
import duckdb
db = duckdb.connect('/var/log/ids/duckdb/ids.duckdb', read_only=True)
print(db.sql('SELECT source_tool, log_type, count(*) FROM events GROUP BY ALL').fetchall())
db.close()
"
```

### End-to-end alert test

```bash
bash scripts/test_alert.sh
```

Injects a fake device into the database, waits for the Alert Agent to detect it, verifies the LLM drafts and sends an email, then cleans up all test data.

---

## Grafana Dashboards

All 9 dashboards are auto-provisioned — no manual import needed.

### Overview (Home Dashboard)
![overview] 4 KPI stat panels (total events, Suricata alerts, unique source IPs, unique dest IPs), stacked timeseries of events over time, three pie charts (event types, protocol distribution, source tool split), and two tables (internal devices with drill-down links, external IPs with country).

### Suricata Alerts
Timeline of alerts, severity breakdown, top alert signatures, detailed alert table with source/dest IPs and ports.

### Network Traffic
Traffic volume over time, protocol distribution, top source and destination IPs by connection count and bytes.

### DNS Analysis
DNS query timeline, top queried domains, NXDOMAIN failure tracking, query type breakdown (A, AAAA, PTR, MX).

### Threats & Correlation
Anomaly events from the detection pipeline, TLS certificate issues, community-id based cross-correlation between Suricata alerts and Zeek connection metadata.

### Network Nodes
Device inventory table with manufacturer, MAC, hostname. Noisiest devices ranked by connection count. Manufacturer distribution.

### Device Detail
Dropdown selector for any known device IP. Shows per-device stats: protocols used, services accessed, first/last seen, recent connections, external IPs contacted.

### External Access & GeoIP
External IPs grouped by country, country breakdown pie chart, top external services and ports, which internal devices are contacting which countries.

### Connection Map
Node graph visualization of device-to-device connections. Nodes represent IPs (enriched with manufacturer/country), edges show connection count and bytes transferred. Configurable minimum connection threshold to reduce clutter. Includes top connection pairs table with service info.

---

## Anomaly Detection

Seven detectors run every ~50s inside the DuckDB Manager. New-device detection additionally has a fast path via the IPWatcher thread (within ~2s). Each uses configurable thresholds and cooldown periods to avoid alert fatigue.

| # | Detector | Type Key | Trigger | Cooldown | Severity |
|---|----------|----------|---------|----------|----------|
| 1 | **New Device** | `new_device` | New RFC1918 IP seen (fast: IPWatcher ~2s; fallback: events table 10s; full: devices table ~50s) | Once per IP | medium |
| 2 | **Traffic Spike** | `traffic_spike` | 5-min conns > `SPIKE_RATIO`x hourly avg AND >= `SPIKE_MIN_CONNS` | `SPIKE_COOLDOWN_MIN` | high |
| 3 | **Suricata Alert** | `suricata_alert` | Severity 1-2 alert in last 5 min | 30 min per signature | critical/high |
| 4 | **Suspicious Country** | `suspicious_country` | Traffic to `SUSPICIOUS_COUNTRIES` watchlist | `COUNTRY_COOLDOWN_MIN` per IP | high |
| 5 | **Massive Volume** | `massive_volume` | Device > `VOLUME_THRESHOLD_MB` in 5 min | `VOLUME_COOLDOWN_MIN` | high |
| 6 | **Device Behavior** | `device_behavior` | Bytes or conns > `BEHAVIOR_RATIO`x EMA baseline (needs `BEHAVIOR_MIN_SAMPLES` first) | 60 min per IP | high |
| 7 | **Destination Fan-out** | `dest_fanout` | Unique dest IPs > `FANOUT_RATIO`x baseline AND >= `FANOUT_MIN_IPS` | 60 min per IP | high |

### Per-Device Behavioral Baselines

Detectors 6 and 7 use exponential moving averages (EMA) to learn each device's normal behavior:

- **Metrics tracked:** bytes/5min, connections/5min, unique destination IPs/5min
- **EMA formula:** `new_avg = alpha * current + (1 - alpha) * old_avg` where `alpha = BASELINE_EMA_ALPHA` (default 0.3)
- **Minimum samples:** At least `BEHAVIOR_MIN_SAMPLES` (default 3) observations before alerting — prevents false positives on first appearance
- Baselines adapt over time: a device that gradually increases usage won't trigger, but a sudden 10x spike will

---

## Nmap Active Scanning

The IDS is primarily passive (observing traffic), but nmap provides active scanning capabilities for deeper investigation.

### On-Demand Scanning (via Chat)

Ask the LLM in Streamlit to scan any RFC1918 target:

```
"Scan 192.168.2.1 for open ports"           → quick scan (top 100 ports)
"Do a full port scan on 192.168.2.0/24"     → full scan (top 1000 ports)
"Detect services on 192.168.2.100"          → service scan (-sV version detection)
"Show previous scans for 192.168.2.1"       → retrieves scan history
```

Results are saved to SQLite (`nmap_results.db`) and synced to the DuckDB `nmap_scans` table by duckdb-mgr on the next cycle.

### Scheduled Scanning

The DuckDB Manager runs a weekly `-sV` subnet scan automatically:

| Setting | Default | Description |
|---------|---------|-------------|
| `NMAP_SUBNET` | `192.168.2.0/24` | Subnet to scan (CIDR, RFC1918 only) |
| `NMAP_SCAN_INTERVAL_HOURS` | `168` | Hours between scans (168 = weekly) |

Results are stored directly in the DuckDB `nmap_scans` table.

### Safety Constraints

- **RFC1918 only** — targets outside `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` are rejected
- **300-second timeout** — prevents hung scans
- **No NSE scripts** — `--script` is not used
- **Subprocess isolation** — nmap runs via `subprocess.run()` with captured output

### Testing Nmap

```bash
# Verify nmap is installed in containers
docker exec ids-streamlit nmap --version
docker exec ids-duckdb-mgr nmap --version

# Test a scan directly
docker exec ids-streamlit nmap --top-ports 100 -T4 192.168.2.1

# Test via Python tool
docker exec ids-streamlit python3 -c "
import sys; sys.path.insert(0, '/app')
from tools import nmap_scan
print(nmap_scan('192.168.2.1', 'quick'))
"
```

---

## Email Alerts Setup

The Alert Agent sends emails via Gmail SMTP using an App Password (not your regular password).

### 1. Enable 2-Step Verification on your Google account
- Go to https://myaccount.google.com/security
- Enable 2-Step Verification (required for App Passwords)

### 2. Generate an App Password
- Go to https://myaccount.google.com/apppasswords
- Select "Other" and name it "IDS Alerts"
- Copy the 16-character password (format: `xxxx xxxx xxxx xxxx`)

### 3. Store credentials as Docker Secrets

```bash
mkdir -p secrets
echo "your-email@gmail.com" > secrets/gmail_user.txt
echo "xxxxxxxxxxxxxxxx" > secrets/gmail_app_password.txt    # no spaces
echo "recipient@example.com" > secrets/alert_recipient.txt
```

These files are gitignored and mounted read-only into the alert-agent container at `/run/secrets/`.

### 4. Restart the alert-agent

```bash
docker compose up -d alert-agent
```

### 5. Test it

```bash
bash scripts/test_alert.sh
```

---

## Dual Interface Mode

To monitor both wired and wireless simultaneously:

```bash
docker compose --profile dual up -d
```

This starts two additional containers:
- `ids-suricata-wifi` — Suricata on `$NETWORK_INTERFACE_2`, writes to `/var/log/ids/suricata-wifi/`
- `ids-zeek-wifi` — Zeek on `$NETWORK_INTERFACE_2`, writes to `/var/log/ids/zeek-wifi/`

Each interface gets its own log subdirectory (`LOG_SUBDIR` env var), preventing log file conflicts. Vector picks up all subdirs via wildcard globs (`suricata*/eve.json`, `zeek*/*.log`), and all events flow into the same DuckDB database. IPWatcher also tails all `suricata*/` and `zeek*/` dirs.

## Virtual Interface Mode (virbr0)

There are two ways to monitor KVM/libvirt VM traffic on `virbr0`:

**Option A — Primary interface (recommended for VM-only monitoring):**

Set `virbr0` as the main capture interface in `.env`:

```env
NETWORK_INTERFACE=virbr0
```

The main `ids-suricata` and `ids-zeek` containers will then capture on `virbr0`. This is the simplest setup when VMs are the only traffic you want to monitor.

**Option B — Additional interface alongside a physical NIC:**

```bash
docker compose --profile virbr up -d
```

This starts two extra containers alongside the main stack:
- `ids-suricata-virbr` — Suricata on `$NETWORK_INTERFACE_3` (default `virbr0`), writes to `/var/log/ids/suricata-virbr/`
- `ids-zeek-virbr` — Zeek on `$NETWORK_INTERFACE_3`, writes to `/var/log/ids/zeek-virbr/`

Vector's wildcard globs (`suricata*/eve.json`, `zeek*/*.log`) and IPWatcher automatically pick up all interface subdirs — no additional config needed.

The default `HOME_NET=192.168.0.0/16` covers libvirt's default `192.168.122.0/24` subnet in both options.

---

## Testing

### Full-Stack Sanity Test

A single script validates every layer of the system end-to-end:

```bash
bash tests/test_sanity.sh                # All tests (static + runtime)
bash tests/test_sanity.sh --static-only  # Config validation only (no containers needed)
bash tests/test_sanity.sh --runtime-only # Runtime checks only (containers must be up)
```

**Static tests (41):** Docker Compose parsing, network modes, capabilities, image pinning, Suricata/Zeek configs, healthcheck definitions, DuckDB schema completeness, rule update watchdog, nmap tool definitions, Python syntax validation.

**Runtime tests (43):** All containers running, Docker health status, Suricata/Zeek log output, Vector NDJSON staging, DuckDB tables and data, TTL compliance, community-id presence, OUI/GeoIP enrichment, device summaries, Grafana health/datasource/dashboards, Ollama API/model, Streamlit health/DB/Ollama connectivity, nmap binary/RFC1918 validation/scan execution/SQLite storage/history retrieval/external rejection, alert agent tables/state.

### Test Suite Overview

| Script | Scope | Tests |
|--------|-------|-------|
| `tests/test_sanity.sh` | Full-stack (all phases) | 41 static + 43 runtime |
| `tests/test_phase1.sh` | Suricata + Zeek | 16 static + 15 runtime |
| `tests/test_phase2.sh` | Vector + DuckDB | 4 static + 6 runtime |
| `scripts/verify.sh` | Phase 1 quick check | 8 runtime |
| `scripts/verify_phase2.sh` | Phase 2 quick check | 6 runtime |
| `scripts/verify_phase2_5.sh` | Grafana dashboards | 5 runtime |
| `scripts/verify_phase3.sh` | Ollama + Streamlit | 6 runtime |
| `scripts/verify_phase3b.sh` | Alert agent | 6 runtime |

---

## Generating Test Traffic

On a quiet interface, generate traffic for testing:

```bash
curl -s https://example.com > /dev/null
curl -s http://testphp.vulnweb.com > /dev/null
ping -c 3 8.8.8.8
nslookup example.com

# Wait ~2 minutes for the pipeline to process, then verify:
bash scripts/verify_phase2.sh
```

---

## Troubleshooting

| Problem | Diagnosis | Fix |
|---------|-----------|-----|
| Container keeps restarting | `docker compose logs <service> --tail=30` | Check error message — usually config syntax or missing file |
| 0 events in DuckDB | `ls /var/log/ids/vector/` | If empty, Vector hasn't processed logs yet. Wait 2 min. If populated, check duckdb-mgr logs |
| New device not showing in Grafana | Device summaries rebuild every ~50s (5 cycles × 10s); Grafana reads a snapshot that updates after each data change | Wait up to ~60s after first traffic from the device |
| DuckDB lock error | PID namespace isolation between containers | Each consumer uses its own snapshot — restart the affected container |
| Grafana dashboards empty | DuckDB snapshot may be stale or bloated | Restart duckdb-mgr, then Grafana: `docker compose restart duckdb-mgr grafana` |
| Streamlit shows "Done" with no answer | LLM hit max tool call rounds (5 default) without producing text | Fixed: `MAX_TOOL_ROUNDS=10` in `app.py`. Also check for `pytz` in container: `docker exec ids-streamlit python3 -c "import pytz"` |
| Chat `get_devices` returns pytz error | `pytz` missing from Streamlit container | Rebuild: `docker compose build streamlit && docker compose up -d streamlit` |
| Ollama shows `100% CPU` not GPU | Vulkan not enabled or model not yet loaded | Check `/etc/systemd/system/ollama.service.d/override.conf` has `OLLAMA_VULKAN=1`; run a query first then `ollama ps` |
| Alert email not sent | Check `docker compose logs alert-agent --tail=30` | Verify Gmail App Password in `secrets/`, ensure 2FA is enabled |
| No Zeek traffic logs | Only `packet_filter.log` and `reporter.log` exist | No network traffic detected. Generate some (see above) |
| Permission denied on `/var/log/ids` | Directory permissions | `sudo chmod 777 /var/log/ids` |
| OUI/GeoIP download fails | IEEE/DB-IP servers may rate-limit | Will retry next cycle (weekly/monthly). Non-blocking — ingestion continues |
| Fast alert email not sent | `docker compose logs alert-agent --tail=30` — look for `fast_alert_loop` lines | Verify Gmail App Password secrets; fast_alerts.db must exist at `/var/log/ids/duckdb/fast_alerts.db` |
| Dual/virbr interface logs missing | `ls /var/log/ids/suricata-wifi/` etc. | Run with correct profile: `docker compose --profile dual up -d`; check `NETWORK_INTERFACE_2/3` in `.env` |

---

## Project Status

- [x] **Phase 1** — Suricata + Zeek capturing live traffic to JSON
- [x] **Phase 2** — Vector normalization + DuckDB storage with TTL purge
- [x] **Phase 2.5** — Grafana dashboards (9 dashboards) with OUI/GeoIP enrichment
- [x] **Phase 3** — Ollama/Qwen2.5 LLM chat UI (Streamlit) with 12 tools
- [x] **Phase 3b** — Agentic alerts: 7 anomaly detectors + LLM-drafted email notifications + per-device EMA baselines
- [x] **Phase 3c** — Nmap active scanning (on-demand + scheduled), Docker healthchecks (all 7 services), Suricata rule auto-update
- [x] **Phase 3d** — Near-real-time new device detection: IPWatcher thread (1s), fast_alerts.db fast path, dual-path alerts (instant template + rich LLM), multi-interface log subdirs, virbr0 as primary interface; Threat Intel RAG (semantic search over Suricata rules via `nomic-embed-text`, `RAG_AUTO_INDEX=false` by default to avoid CPU load on rule updates)
- [ ] **Phase 4** — Authelia (2FA/TOTP) + Cloudflare Tunnel for secure remote access

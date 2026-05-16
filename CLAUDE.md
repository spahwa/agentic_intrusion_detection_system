# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Agentic IDS** — A local, AI-powered Intrusion Detection System with:
- 24-hour rolling memory window for log retention
- Agentic LLM querying via Qwen3.5 (natural language "Chat with your Network")
- Secure 2FA remote access via Cloudflare Tunnels + Authelia

## Target Platforms

- **Primary (current)**: Laptop — x86_64, 8 CPU cores, 32GB RAM, Ubuntu 24.04
- **Future migration**: Raspberry Pi 5 — ARM64, 4 cores, 4-8GB RAM
- All Docker images must support both `linux/amd64` and `linux/arm64` architectures
- Pin image tags in `.env` (never use `latest`) for reproducible builds

## Environment

- Docker 29.2.0, Docker Compose v5.0.2
- Ollama 0.17.7 (installed on host)
- Network interfaces: `enp1s0f0` (wired), `wlp2s0` (wireless) — configurable via `.env`
- Hostname: `ethereal`
- GPU: AMD Radeon 780M iGPU (RDNA3/gfx1103) — Vulkan inference via Mesa RADV, ~27.7 tok/s decode (short prompts), ~27.5 tok/s (long prompts); BIOS UMA Frame Buffer = 4 GB → model runs 100% GPU
- Ollama systemd override: `CPUQuota=600%` + `Environment="OLLAMA_VULKAN=1"` in `/etc/systemd/system/ollama.service.d/override.conf`

## Tech Stack

| Layer | Tools |
|-------|-------|
| IDS/Metadata | Suricata, Zeek, Nmap (active scanning) |
| Data Pipeline | Vector.dev (TTL management) |
| Storage | DuckDB (logs), SQLite (settings/whitelists) |
| AI Engine | Ollama (Qwen3.5-2B), MCP (Model Context Protocol) |
| Frontend | Streamlit (chat UI), Grafana (dashboards) |
| Security | Cloudflare Tunnels, Authelia (2FA/TOTP) |

## Project Structure

```
claude_ids/
├── .env                          # Runtime config (NETWORK_INTERFACE, LOG_DIR, image tags, HOME_NET)
├── .env.example                  # Documented template for version control
├── docker-compose.yml            # Service orchestration
├── suricata/
│   ├── Dockerfile                # Thin layer over jasonish/suricata
│   ├── suricata.yaml             # EVE JSON output, af-packet, community-id
│   ├── rules/custom.rules        # Project-specific Suricata rules
│   └── entrypoint.sh             # Interface substitution + suricata-update + rule auto-update watchdog
├── zeek/
│   ├── Dockerfile                # Thin layer over zeek/zeek
│   ├── local.zeek                # JSON output, protocol analyzers, community-id
│   ├── node.cfg                  # Standalone mode config
│   └── entrypoint.sh             # Interface substitution + foreground zeek
├── vector/
│   └── vector.yaml               # Vector pipeline: sources, transforms, file sink
├── duckdb-mgr/
│   ├── Dockerfile                # Python 3.12-slim + duckdb + nmap
│   ├── main.py                   # Ingest NDJSON → DuckDB + TTL purge + OUI/GeoIP + device summaries + scheduled nmap
│   ├── schema.sql                # DuckDB table DDL (events, oui_lookup, geoip_lookup, devices, external_ips, nmap_scans)
│   └── requirements.txt          # duckdb pinned version
├── grafana/
│   ├── Dockerfile                # Grafana + DuckDB plugin (Ubuntu-based)
│   ├── provisioning/
│   │   ├── datasources/duckdb.yml  # DuckDB datasource auto-config
│   │   └── dashboards/provider.yml # Dashboard file provider
│   └── dashboards/               # Provisioned dashboard JSONs
│       ├── overview.json          # KPI stats, event timeline, breakdowns
│       ├── alerts.json            # Suricata alerts analysis
│       ├── network-traffic.json   # Traffic volume, protocols, top talkers
│       ├── dns.json               # DNS queries, domains, NXDOMAIN
│       ├── threats.json           # Anomalies, TLS, community-id correlation
│       ├── nodes.json             # Device inventory, manufacturer, noisiest devices
│       ├── device-detail.json     # Per-device drill-down (selectable via dropdown)
│       ├── external-geoip.json   # External IPs, country breakdown, inbound connections
│       └── connection-map.json   # Device connection map (node graph + top pairs)
├── streamlit/
│   ├── Dockerfile                # Python 3.12-slim + Streamlit + Ollama client + nmap + curl
│   ├── app.py                    # Chat UI + Ollama tool-calling loop
│   ├── tools.py                  # Tool definitions + implementations (DuckDB, whitelist, Apprise, nmap)
│   ├── system_prompt.py          # Schema-aware system prompt for LLM
│   └── requirements.txt          # ollama, streamlit, duckdb, apprise
├── alert-agent/
│   ├── Dockerfile                # Python 3.12-slim + Ollama + DuckDB
│   ├── main.py                   # Poll anomaly_events, LLM analysis, email alerts
│   ├── tools.py                  # query_events + send_email tool implementations
│   ├── system_prompt.py          # Alert analyst system prompt for LLM
│   └── requirements.txt          # ollama, duckdb
├── scripts/
│   ├── verify.sh                 # Phase 1 health check
│   ├── verify_phase2.sh          # Phase 2 health check
│   ├── verify_phase2_5.sh        # Phase 2.5 health check
│   └── verify_phase3.sh          # Phase 3 health check
├── tests/
│   └── test_phase2.sh            # Phase 2 regression tests
└── CLAUDE.md
```

## Docker Images

| Service | Image | Tag | AMD64 | ARM64 |
|---------|-------|-----|-------|-------|
| Suricata | `jasonish/suricata` | `7.0.8` | Yes | Yes |
| Zeek | `zeek/zeek` | `7.0.4` | Yes | Yes |
| Vector | `timberio/vector` | `0.53.0-alpine` | Yes | Yes |
| DuckDB mgr | `python` (base) | `3.12-slim` | Yes | Yes |
| Grafana | `grafana/grafana` | `11.6.0-ubuntu` | Yes | Yes |
| Streamlit | `python` (base) | `3.12-slim` | Yes | Yes |
| Alert Agent | `python` (base) | `3.12-slim` | Yes | Yes |

Fallback images: `oisf/suricata` (Suricata), `blacktop/zeek` (Zeek, good ARM64 support).

## Key Architecture Decisions

- **community-id**: Both Suricata and Zeek emit `community_id` flow hashes for cross-tool event correlation
- **af-packet**: Suricata uses af-packet for high-performance Linux packet capture
- **JSON output**: Suricata outputs EVE JSON; Zeek uses `LogAscii::use_json = T`
- **network_mode: host**: Both containers need direct physical interface access for packet capture (bridge networking only sees inter-container traffic)
- **Bind-mount shared volume**: Named Docker volume with `driver_opts` binding to `${LOG_DIR:-/var/log/ids}` on host; both containers mount at `/var/log/ids` and write to tool-specific subdirectories (`suricata/`, `zeek/`)
- **Capabilities**: Both services require `NET_ADMIN` and `NET_RAW`; Suricata also gets `SYS_NICE` for thread affinity
- **Vector → NDJSON → DuckDB**: No native DuckDB sink in Vector; Vector normalizes and stages NDJSON files, Python `duckdb-mgr` bulk-loads via `read_json_auto()`. This keeps Vector stateless and gives Python full control over schema/TTL.
- **Single events table**: All log types stored in one `events` table with `raw JSON` column. Simple, flexible, and lets Phase 3 MCP query any field dynamically.
- **Enrichment tables**: `oui_lookup` (IEEE OUI→manufacturer), `geoip_lookup` (DB-IP IPv4→country), `devices` (materialized internal IP summary), `external_ips` (materialized external IP summary with country). Rebuilt every 5 minutes from events data. No new pip dependencies — uses Python stdlib (`csv`, `gzip`, `urllib.request`, `struct`, `socket`).
- **Direct tool calling**: Ollama 0.14+ supports OpenAI-compatible tool/function calling. Qwen3.5-2B tools are defined as Python functions in Streamlit app — no separate MCP server process needed. If MCP is needed later (multi-client), tool functions can be wrapped in FastMCP trivially.
- **Streamlit reads readonly snapshot**: Uses `ids_readonly.duckdb` (same as Grafana) to avoid DuckDB single-writer conflicts. SQLite `whitelist.db` for IP whitelist CRUD.
- **Agentic alerts**: `duckdb-mgr` detects anomalies (new device, traffic spike, high-severity Suricata alert) and writes to `anomaly_events` table. `alert-agent` polls anomalies, feeds each to the LLM which queries for additional context and drafts a rich email alert via Gmail SMTP. Alert state tracked in SQLite (`alert_state.db`) to avoid DuckDB write contention.
- **Nmap integration**: Active scanning installed in Streamlit (on-demand via chat) and duckdb-mgr (scheduled weekly). On-demand results go to SQLite (`nmap_results.db`) since Streamlit reads DuckDB read-only; duckdb-mgr syncs SQLite → DuckDB `nmap_scans` table each cycle. RFC1918-only enforcement prevents scanning external targets.
- **Docker healthchecks**: All 7 services have healthchecks (pidof/pgrep for daemons, curl for HTTP services, file-exists for background workers). Docker auto-detects hung processes and marks containers unhealthy.
- **Suricata rule auto-update**: Background watchdog in entrypoint.sh runs `suricata-update` at configurable interval (default 24h), then sends USR2 for zero-downtime rule reload.

## .env Configuration

All runtime settings live in `.env` (never hardcode):

```env
NETWORK_INTERFACE=enp1s0f0    # Physical interface to monitor
LOG_DIR=/var/log/ids           # Host path for shared log volume
SURICATA_TAG=7.0.8             # Suricata Docker image tag
ZEEK_TAG=7.0.4                 # Zeek Docker image tag
HOME_NET=192.168.0.0/16        # Suricata HOME_NET CIDR
VECTOR_TAG=0.53.0-alpine       # Vector Docker image tag
DUCKDB_TTL_HOURS=24            # Log retention window in hours
STAGING_RETENTION_HOURS=6      # Hours to keep NDJSON staging + rotated Zeek logs
MAX_DB_SIZE_MB=4000            # DuckDB max file size before pausing ingestion
MAX_EVE_SIZE_MB=200            # Suricata eve.json rotation threshold in MB
GRAFANA_TAG=11.6.0-ubuntu      # Grafana Docker image tag (Ubuntu for DuckDB plugin)
GRAFANA_PORT=3000              # Grafana web UI port
OLLAMA_MODEL=qwen3.5-ids:2b    # Custom model: qwen3.5:2b base + num_ctx=32768 (see Modelfile)
STREAMLIT_PORT=8501            # Streamlit chat UI port
APPRISE_URLS=                  # Apprise notification URLs (comma-separated)
GMAIL_USER=your-email@gmail.com  # Gmail for alert-agent email notifications
GMAIL_APP_PASSWORD=xxxx-xxxx-xxxx-xxxx  # Gmail App Password
ALERT_RECIPIENT=your-email@gmail.com    # Recipient for IDS alert emails
NMAP_SUBNET=192.168.2.0/24      # Subnet for scheduled nmap scans (RFC1918 only)
NMAP_SCAN_INTERVAL_HOURS=168     # Hours between scheduled nmap scans (168 = weekly)
RULE_UPDATE_INTERVAL_HOURS=24    # Hours between Suricata rule auto-updates
```

## Commands

```bash
# Build images
docker compose build

# Start stack
docker compose up -d

# Check status
docker compose ps

# View logs
docker compose logs suricata | tail -20
docker compose logs zeek | tail -20
docker compose logs vector | tail -20
docker compose logs duckdb-mgr | tail -20
docker compose logs grafana | tail -20
docker compose logs streamlit | tail -20
docker compose logs alert-agent | tail -20

# Verify deployment (Phase 1)
bash scripts/verify.sh

# Verify deployment (Phase 2)
bash scripts/verify_phase2.sh

# Verify deployment (Phase 2.5)
bash scripts/verify_phase2_5.sh

# Verify deployment (Phase 3)
bash scripts/verify_phase3.sh

# Verify deployment (Phase 3b - Agentic Alerts)
bash scripts/verify_phase3b.sh

# Run Phase 2 regression tests
bash tests/test_phase2.sh

# Stop stack
docker compose down

# Query DuckDB manually
docker exec ids-duckdb-mgr python3 -c "
import duckdb
db = duckdb.connect('/var/log/ids/duckdb/ids.duckdb', read_only=True)
print(db.sql('SELECT source_tool, log_type, count(*) FROM events GROUP BY ALL').fetchall())
"
```

Prerequisites before first `docker compose up`:
```bash
sudo mkdir -p /var/log/ids
sudo chmod 777 /var/log/ids
```

## Phased Implementation

### Phase 1: Data Acquisition Layer (complete)

**Goal**: Suricata + Zeek docker-compose stack producing JSON logs.

- `docker-compose.yml` with both services using `network_mode: host`
- Suricata: EVE JSON to `/var/log/ids/suricata/eve.json` with community-id enabled
- Zeek: JSON logs (conn, dns, http, ssl, etc.) to `/var/log/ids/zeek/`
- Configurable interface via `NETWORK_INTERFACE` in `.env`
- `scripts/verify.sh` confirms containers running and JSON logs populating
- **Success metric**: `.json` logs populating in `/var/log/ids/`

### Phase 2: Storage & Retention (24hr Window) (complete)

**Goal**: Vector.dev pipeline with DuckDB storage and automatic TTL purge.

- Vector.dev ingests Suricata EVE + Zeek JSON, normalizes via VRL transforms, stages as NDJSON
- Python `duckdb-mgr` service ingests NDJSON into DuckDB `events` table (single table, full JSON in `raw` column)
- 24-hour TTL: purge loop deletes records older than `DUCKDB_TTL_HOURS`, cleans up staging files
- DuckDB stored at `/var/log/ids/duckdb/ids.duckdb`; queryable via `json_extract_string(raw, '$.field')` JSON extraction
- **Success metric**: Querying DuckDB shows 0 records with timestamps >24 hours old

### Phase 2.5: Grafana IDS Dashboards (complete)

**Goal**: Industry-grade Grafana dashboards querying DuckDB for IDS analytics.

- Grafana 11.6.0-ubuntu with `motherduck-duckdb-datasource` plugin (v0.4.0, DuckDB 1.4.1)
- Reads DuckDB file read-only via bind mount (coexists with duckdb-mgr write lock)
- 9 provisioned dashboards: Overview, Alerts, Network Traffic, DNS, Threats & Correlation, Network Nodes, Device Detail, External Access & GeoIP, Connection Map
- OUI manufacturer lookup (IEEE CSV, ~32K entries, refreshed weekly) + GeoIP country lookup (DB-IP CSV, ~250K IPv4 ranges, refreshed monthly)
- `devices` and `external_ips` summary tables rebuilt every 5 minutes by duckdb-mgr
- Datasource and dashboards auto-provisioned on startup (no manual setup needed)
- Access at `http://localhost:3000` (admin/admin)
- `scripts/verify_phase2_5.sh` confirms Grafana health, datasource, and dashboard provisioning
- **Success metric**: All 9 dashboards load and display live DuckDB data with device/geo enrichment

### Phase 3: Agentic Intelligence (complete)

**Goal**: Natural language "Chat with your Network" via Ollama + Streamlit.

- Ollama (host-installed) running Qwen3.5-2B with native tool/function calling
- Streamlit chat UI with 12 tools: `query_events` (arbitrary SQL), `get_devices`, `get_alerts`, `get_external_connections`, `get_dns_top_domains`, `get_traffic_by_protocol`, `get_event_stats`, `check_whitelist` (SQLite CRUD), `send_notification` (Apprise), `send_email`, `nmap_scan` (active port scanning), `get_scan_history`
- Schema-aware system prompt teaches LLM full DuckDB schema + JSON field paths + example queries
- Tool-calling loop: Ollama → tool calls → execute → feed results back → repeat until text response
- Safety: DuckDB opened read-only, SELECT-only validation, 50-row result cap
- SQLite whitelist at `/var/log/ids/duckdb/whitelist.db` for IP allow-listing
- Access at `http://localhost:8501`
- `scripts/verify_phase3.sh` confirms Ollama, model, Streamlit health, DuckDB connectivity
- **Success metric**: LLM accurately reports a specific network event from logs via chat UI

### Phase 3b: Agentic Alert System (complete)

**Goal**: Anomaly detection + LLM-drafted email notifications.

- `duckdb-mgr` detects 7 anomaly types every 5 min: new device, traffic spike, high-severity Suricata alerts, suspicious country traffic, massive volume, per-device behavior anomaly, destination fan-out
- Anomalies stored in `anomaly_events` DuckDB table with type, severity, summary, and structured details JSON
- `alert-agent` service polls anomalies every 60s, feeds each to Ollama LLM with tools
- LLM analyzes anomaly, optionally queries DB for additional context, drafts and sends email via `send_email` tool
- Gmail SMTP with App Passwords (zero external dependencies beyond `smtplib`)
- Alert state tracked in SQLite (`alert_state.db`) to avoid DuckDB write contention
- `_known_devices` table tracks previously seen devices for new-device detection
- `scripts/verify_phase3b.sh` confirms alert-agent running, tables exist, Ollama connectivity
- **Success metric**: LLM-drafted email sent within 60s of anomaly detection

### Phase 3c: Active Scanning, Health Checks, Rule Updates (complete)

**Goal**: Nmap active scanning, Docker healthchecks, Suricata rule auto-update.

- Nmap installed in Streamlit (on-demand via chat LLM) and duckdb-mgr (scheduled weekly subnet scan)
- On-demand scan results stored in SQLite (`nmap_results.db`), synced to DuckDB `nmap_scans` table by duckdb-mgr
- RFC1918-only target validation prevents scanning external addresses; 300s subprocess timeout; no NSE scripts
- All 7 services have Docker healthchecks (interval 30s, retries 3, start_period 30-60s)
- Suricata rules auto-update via background watchdog: `suricata-update --no-test` + USR2 signal for zero-downtime reload
- **Success metric**: `docker compose ps` shows all services "healthy"; nmap scan via chat returns port results; `docker logs ids-suricata | grep rule-update` shows successful updates

### Phase 4: Exposure, UI, & Hardening

**Goal**: Secure remote access with 2FA and role-based dashboards.

- Grafana dashboards for visual LAN/WiFi monitoring
- Authelia with TOTP (2FA) for authentication
- Cloudflare Tunnel (`cloudflared`) to expose Streamlit and Grafana ports
- RBAC: non-root users get read-only dashboard access, no LLM config access
- **Success metric**: External login requires 2FA; guest users see restricted view only

## Component Reference

### Component Overview

| Component | Container | Network Mode | Runtime | Base Image | Function |
|-----------|-----------|-------------|---------|------------|----------|
| Suricata | `ids-suricata` | host | C (daemon) | `jasonish/suricata:7.0.8` | Signature-based IDS — inspects packets via af-packet, generates EVE JSON alerts/metadata |
| Zeek | `ids-zeek` | host | C++ (daemon) | `zeek/zeek:7.0.4` | Protocol analyzer — deep packet inspection, generates structured JSON logs per protocol |
| Vector | `ids-vector` | bridge | Rust (daemon) | `timberio/vector:0.53.0-alpine` | Log pipeline — reads Suricata EVE + Zeek JSON, normalizes via VRL, stages as hourly NDJSON |
| DuckDB Manager | `ids-duckdb-mgr` | bridge | Python 3.12 | `python:3.12-slim` + nmap | Data engine — ingests NDJSON into DuckDB, TTL purge, enrichment, anomaly detection, scheduled nmap |
| Grafana | `ids-grafana` | bridge | Go (daemon) | `grafana/grafana:11.6.0-ubuntu` | Dashboard UI — 9 provisioned IDS dashboards querying DuckDB read-only snapshot |
| Streamlit | `ids-streamlit` | host | Python 3.12 | `python:3.12-slim` + nmap + curl | Chat UI — natural language queries via Ollama tool-calling, on-demand nmap scanning |
| Alert Agent | `ids-alert-agent` | host | Python 3.12 | `python:3.12-slim` | Alert processor — polls anomalies, LLM analysis, drafts and sends email alerts via Gmail |
| Ollama | _(host process)_ | host | Go (daemon) | _(native install)_ | LLM inference server — serves Qwen3.5-2B with native tool/function calling |

### Component Interfaces

| Component | Inbound Interfaces | Outbound Interfaces | Exposed Ports |
|-----------|--------------------|---------------------|---------------|
| Suricata | Physical NIC (`enp1s0f0`) via af-packet | Writes `/var/log/ids/suricata/eve.json` | None |
| Zeek | Physical NIC (`enp1s0f0`) via libpcap | Writes `/var/log/ids/zeek/*.log` (hourly rotation) | None |
| Vector | Reads `/var/log/ids/suricata/eve.json`, `/var/log/ids/zeek/*.log` | Writes `/var/log/ids/vector/{suricata,zeek}/<type>/YYYY-MM-DD-HH.ndjson` | None |
| DuckDB Manager | Reads `/var/log/ids/vector/**/*.ndjson`, SQLite `nmap_results.db` | Writes `ids.duckdb` (primary), copies to `ids_readonly.duckdb`, `ids_streamlit.duckdb`, `ids_alert.duckdb` | None |
| Grafana | Reads `ids_readonly.duckdb` via DuckDB plugin | HTTP responses to browser | `3000` (HTTP UI) |
| Streamlit | HTTP from browser, Ollama API (`localhost:11434`) | Reads `ids_streamlit.duckdb` (read-only), writes `whitelist.db` + `nmap_results.db` (SQLite), Ollama API, Gmail SMTP, Apprise | `8501` (HTTP UI) |
| Alert Agent | Reads `ids_alert.duckdb` (read-only), Ollama API | Writes `alert_state.db` (SQLite), Gmail SMTP (`smtp.gmail.com:465`) | None |
| Ollama | HTTP API from Streamlit + Alert Agent | GPU/CPU inference | `11434` (HTTP API) |

### Data Flow

```
Physical NIC (enp1s0f0)
    │
    ├──► Suricata ──► /var/log/ids/suricata/eve.json ──► Vector ──► /var/log/ids/vector/suricata/eve/*.ndjson ──┐
    │                                                                                                           │
    └──► Zeek ──► /var/log/ids/zeek/{conn,dns,ssl,...}.log ──► Vector ──► /var/log/ids/vector/zeek/*/*.ndjson ──┤
                                                                                                                │
                                                                                                                ▼
                                                                                                         DuckDB Manager
                                                                                                                │
                                                    ┌───────────────────────────────────────────────────────────┤
                                                    │                       │                                   │
                                                    ▼                       ▼                                   ▼
                                          ids_readonly.duckdb      ids_streamlit.duckdb              ids_alert.duckdb
                                                    │                       │                                   │
                                                    ▼                       ▼                                   ▼
                                                 Grafana               Streamlit                          Alert Agent
                                              (dashboards)            (chat UI)                        (email alerts)
                                                                          │                                   │
                                                                          ▼                                   ▼
                                                                    Ollama (LLM)                        Ollama (LLM)
```

### Storage Files

| File | Type | Writer | Readers | Purpose |
|------|------|--------|---------|---------|
| `/var/log/ids/suricata/eve.json` | JSON (append) | Suricata | Vector | EVE alert/metadata log |
| `/var/log/ids/zeek/*.log` | JSON (per-protocol) | Zeek | Vector | Protocol-specific logs (conn, dns, ssl, http, dhcp, etc.) |
| `/var/log/ids/vector/**/*.ndjson` | NDJSON (hourly partitioned) | Vector | DuckDB Manager | Normalized staging files |
| `/var/log/ids/duckdb/ids.duckdb` | DuckDB | DuckDB Manager | _(exclusive writer)_ | Primary database — single-writer lock |
| `/var/log/ids/duckdb/ids_readonly.duckdb` | DuckDB (snapshot) | DuckDB Manager (copy) | Grafana | Read-only snapshot for dashboards |
| `/var/log/ids/duckdb/ids_streamlit.duckdb` | DuckDB (snapshot) | DuckDB Manager (copy) | Streamlit | Read-only snapshot for chat queries |
| `/var/log/ids/duckdb/ids_alert.duckdb` | DuckDB (snapshot) | DuckDB Manager (copy) | Alert Agent | Read-only snapshot for alert analysis |
| `/var/log/ids/duckdb/whitelist.db` | SQLite | Streamlit | Streamlit | IP whitelist CRUD |
| `/var/log/ids/duckdb/nmap_results.db` | SQLite | Streamlit | DuckDB Manager | On-demand nmap scan results (synced to DuckDB) |
| `/var/log/ids/duckdb/alert_state.db` | SQLite | Alert Agent | Alert Agent | Tracks processed anomalies by `(anomaly_id, detected_at)` composite key — survives DuckDB sequence resets |
| `/var/log/ids/duckdb/oui.csv` | CSV | DuckDB Manager (download) | DuckDB Manager | IEEE OUI manufacturer database (~32K entries) |
| `/var/log/ids/duckdb/geoip.csv.gz` | Gzip CSV | DuckDB Manager (download) | DuckDB Manager | DB-IP country lookup (~250K IPv4 ranges) |

### DuckDB Tables

| Table | Type | Purpose |
|-------|------|---------|
| `events` | Core | All Suricata + Zeek log events (timestamp, source_tool, log_type, raw JSON) |
| `_ingested_files` | Internal | Tracks NDJSON files already ingested (filepath + mtime for dedup) |
| `oui_lookup` | Enrichment | IEEE OUI prefix → manufacturer name (6-char hex prefix) |
| `geoip_lookup` | Enrichment | IPv4 range → 2-letter country code (uint32 start/end) |
| `devices` | Materialized | Internal device summary (IP, MAC, manufacturer, hostname, traffic stats) |
| `external_ips` | Materialized | External IP summary (IP, country, connection count, contacted_by) |
| `anomaly_events` | Alerting | Detected anomalies (type, severity, summary, details JSON) |
| `_known_devices` | Alerting | Previously seen device IPs (for new-device detection) |
| `device_baselines` | Alerting | Per-device EMA behavioral baselines (bytes, conns, dest IPs) |
| `nmap_scans` | Scanning | Nmap scan results (target, scan_type, results JSON) |

### Streamlit LLM Tools

| Tool | Function | Data Source | Write Target |
|------|----------|-------------|--------------|
| `query_events` | Arbitrary SELECT query against DuckDB | `ids_streamlit.duckdb` | _(read-only)_ |
| `get_devices` | List internal devices with manufacturer/traffic | `devices` table | _(read-only)_ |
| `get_alerts` | Recent Suricata alerts by severity | `events` table (filtered) | _(read-only)_ |
| `get_external_connections` | External IPs with GeoIP, optional country filter | `external_ips` table | _(read-only)_ |
| `get_dns_top_domains` | Most queried DNS domains | `events` table (zeek/dns) | _(read-only)_ |
| `get_traffic_by_protocol` | Connection/byte breakdown by protocol | `events` table (zeek/conn) | _(read-only)_ |
| `get_event_stats` | Event counts by source_tool and log_type | `events` table | _(read-only)_ |
| `check_whitelist` | List/check/add/remove IP whitelist entries | `whitelist.db` (SQLite) | `whitelist.db` |
| `send_notification` | Send alert via Apprise (Slack, email, etc.) | _(none)_ | External service |
| `send_email` | Send email via Gmail SMTP | _(none)_ | `smtp.gmail.com:465` |
| `nmap_scan` | Active port scan (RFC1918 only, 300s timeout) | nmap subprocess | `nmap_results.db` (SQLite) |
| `get_scan_history` | Retrieve past nmap scan results | `nmap_results.db` (SQLite) | _(read-only)_ |

### Anomaly Detectors (duckdb-mgr)

| Detector | Type | Trigger Condition | Cooldown | Severity |
|----------|------|-------------------|----------|----------|
| New Device | `new_device` | IP in `devices` not in `_known_devices` | None (once per IP) | medium |
| Traffic Spike | `traffic_spike` | 5-min conns > `SPIKE_RATIO`x hourly avg AND >= `SPIKE_MIN_CONNS` | `SPIKE_COOLDOWN_MIN` | high |
| Suricata Alert | `suricata_alert` | Severity 1-2 alert in last 5 min | 30 min per signature | critical/high |
| Suspicious Country | `suspicious_country` | Traffic to `SUSPICIOUS_COUNTRIES` watchlist | `COUNTRY_COOLDOWN_MIN` per IP | high |
| Massive Volume | `massive_volume` | Device > `VOLUME_THRESHOLD_MB` in 5 min | `VOLUME_COOLDOWN_MIN` | high |
| Device Behavior | `device_behavior` | Bytes or conns > `BEHAVIOR_RATIO`x EMA baseline | 60 min per IP | high |
| Destination Fan-out | `dest_fanout` | Unique dest IPs > `FANOUT_RATIO`x baseline AND >= `FANOUT_MIN_IPS` | 60 min per IP | high |

### Health Checks

| Service | Check Method | Command | Interval | Timeout | Retries | Start Period |
|---------|-------------|---------|----------|---------|---------|-------------|
| Suricata | Process alive | `pidof suricata` | 30s | 10s | 3 | 60s |
| Zeek | Process alive | `pidof zeek` | 30s | 10s | 3 | 60s |
| Vector | Process alive | `pgrep -x vector` | 30s | 10s | 3 | 30s |
| DuckDB Manager | DB file exists | `test -f /var/log/ids/duckdb/ids.duckdb` | 30s | 10s | 3 | 30s |
| Grafana | HTTP health API | `curl -sf http://localhost:3000/api/health` | 30s | 10s | 3 | 30s |
| Streamlit | HTTP health API | `curl -sf http://localhost:8501/_stcore/health` | 30s | 10s | 3 | 30s |
| Alert Agent | State file exists | `test -f /var/log/ids/duckdb/alert_state.db` | 30s | 10s | 3 | 30s |

### Background Watchdogs (Suricata entrypoint.sh)

| Watchdog | Function | Interval | Signal |
|----------|----------|----------|--------|
| `eve_rotate_watchdog` | Rotates `eve.json` when it exceeds `MAX_EVE_SIZE_MB` | 5 min check | HUP (log reopen) |
| `rule_update_watchdog` | Runs `suricata-update --no-test` for fresh rules | `RULE_UPDATE_INTERVAL_HOURS` (default 24h) | USR2 (rule reload) |

### Test Suite

| Script | Type | Scope | Tests |
|--------|------|-------|-------|
| `tests/test_sanity.sh` | Full-stack sanity | All phases, all components | 41 static + 43 runtime |
| `tests/test_phase1.sh` | Regression | Suricata + Zeek config + runtime | 16 static + 15 runtime |
| `tests/test_phase2.sh` | Regression | Vector + DuckDB pipeline | 4 static + 6 runtime |
| `scripts/verify.sh` | Deployment | Phase 1 quick check | 8 runtime |
| `scripts/verify_phase2.sh` | Deployment | Phase 2 quick check | 6 runtime |
| `scripts/verify_phase2_5.sh` | Deployment | Grafana dashboards | 5 runtime |
| `scripts/verify_phase3.sh` | Deployment | Ollama + Streamlit | 6 runtime |
| `scripts/verify_phase3b.sh` | Deployment | Alert agent | 6 runtime |

## Important Notes

- Wireless interfaces (`wlp2s0`) don't support true promiscuous mode in managed mode — use wired (`enp1s0f0`) for full network visibility
- Both Suricata and Zeek can capture on the same interface simultaneously without conflict (Linux delivers packet copies to each socket independently)
- Suricata EVE JSON does not auto-rotate; Phase 2 handles retention. Zeek rotates hourly by default.
- Host directory `/var/log/ids` must exist before `docker compose up` (bind-mount won't auto-create it)
- On RPI5 migration: verify ARM64 manifests with `docker manifest inspect`, rebuild with `--no-cache`, adjust `NETWORK_INTERFACE` to match RPI5 interface name (likely `eth0` or `end0`), and consider reducing Zeek file extraction to save resources

## Ollama Performance Notes

### CPU Allocation

Ollama runs as a host systemd service. CPU allocation is controlled via a systemd drop-in:

```ini
# /etc/systemd/system/ollama.service.d/override.conf
[Service]
CPUQuota=600%
Environment="OLLAMA_VULKAN=1"
```

`CPUQuota=600%` = 6 full cores out of 16 threads (leaves headroom for other apps). After changing:
```bash
sudo systemctl daemon-reload && sudo systemctl restart ollama
```

**`OLLAMA_NUM_THREADS` is ignored** — Ollama uses its own thread-count heuristic derived from CPUQuota. Setting `CPUQuota=600%` results in 8 threads automatically (not 6). Do not set `OLLAMA_NUM_THREADS`.

### GPU Acceleration (AMD Radeon 780M)

The Radeon 780M (gfx1103 / RDNA3) is not in AMD's official ROCm support matrix, but Vulkan inference works via Mesa RADV on Ubuntu 24.04:

```bash
# Install Mesa Vulkan driver (usually already present)
sudo apt install mesa-vulkan-drivers

# Verify Vulkan device is visible
vulkaninfo --summary 2>/dev/null | grep -A2 "GPU id"

# After setting OLLAMA_VULKAN=1 and restarting, verify GPU is active:
ollama ps
# Should show: 100% GPU (not 100% CPU)
```

**Performance reference (qwen3.5:2b on this machine)**:
| Config | Tokens/s |
|--------|----------|
| CPUQuota=400%, CPU-only | ~1.1 tok/s |
| CPUQuota=600%, CPU-only | ~10.3 tok/s |
| CPUQuota=600% + OLLAMA_VULKAN=1 | ~18.0 tok/s |

If `ollama ps` shows `100% CPU` after enabling Vulkan, the model doesn't fully fit in VRAM — this is expected for the iGPU (shared RAM); Ollama still offloads as many layers as possible.

### Custom Model: qwen3.5-ids:2b (Context Window)

The default `qwen3.5:2b` Ollama model uses a 4096-token context window. For IDS chat sessions with multiple tool calls, the system prompt + tool results can exceed 4096 tokens mid-investigation, causing the model to forget earlier results. A custom model with 32768 context is used instead.

**Creating the custom model** (already done — `Modelfile` checked into repo root):
```bash
ollama create qwen3.5-ids:2b -f Modelfile
```

**Modelfile** (`/home/popoye/claude_ids/Modelfile`):
```
FROM qwen3.5:2b
PARAMETER num_ctx 32768
PARAMETER presence_penalty 1.5
PARAMETER temperature 1
PARAMETER top_k 20
PARAMETER top_p 0.95
```

**Benchmark results** (updated 2026-05-15, Radeon 780M + Vulkan + 4 GB BIOS VRAM):
| Metric | 1 GB VRAM (GTT spill) | **4 GB VRAM (100% GPU)** | Delta |
|--------|----------------------|--------------------------|-------|
| Generate rate — short prompt | ~25.5 tok/s | **27.7 tok/s** | +2.2 (+9%) |
| Generate rate — long prompt (~700 tok) | ~24.2 tok/s | **27.5 tok/s** | +3.3 (+14%) |
| Prompt ingestion — warm KV cache | n/a | **~2200 tok/s** | — |
| `ollama ps` PROCESSOR | partial GPU+GTT | **100% GPU** | ✓ |
| Model size in memory | ~4 GB GTT | **4.8 GB on-chip** | — |

**Key findings:**
- 32768 ctx costs ~1.5 tok/s (~6%) on short prompts; zero difference above ~1500 prompt tokens
- Overhead is KV cache allocation at load time, not per-token generation cost
- Moving from 1 GB → 4 GB BIOS UMA Frame Buffer gained ~9–14% generate throughput
- Prompt ingestion runs at ~2200 tok/s (warm KV cache) — IDS system prompt (~700 tokens) ingests in <1s
- `think=False` must be set per-request — without it, qwen3.5 thinking tokens consume the entire output budget before producing an answer

**VRAM / GTT memory impact (Radeon 780M iGPU):**
- Dedicated VRAM (BIOS-allocated): **4 GB** (UMA Frame Buffer raised from 1 GB → 4 GB)
- Model footprint: **4.8 GB** — fits on-chip (`ollama ps` shows `100% GPU`, no GTT spill)
- At full 32768-token context: KV cache headroom remains within GTT if needed; typical sessions fit in 4 GB
- `mem_info_vram_total=4096 MB`, 258 MB used at idle (verified 2026-05-15)

## DuckDB Compaction Notes

### VACUUM Does Not Shrink Files

`VACUUM` in DuckDB 1.4.x reclaims internal free-list pages but does **not** shrink the file on disk. After heavy TTL-based DELETEs the file can grow to GBs while holding only MBs of live data.

### Auto-Compaction in duckdb-mgr

`compact_db()` in `duckdb-mgr/main.py` triggers automatically when:
- DB file exceeds **80% of `MAX_DB_SIZE_MB`** (default 3200 MB), AND
- File size is **>3× the estimated live data size** (bloat ratio)

It uses a safe Parquet export → delete → recreate → reimport pattern. After compaction, `_sync_anomaly_seq()` is called to advance the anomaly sequence past any previously processed IDs.

**Manual trigger** (if needed):
```python
docker exec ids-duckdb-mgr python3 -c "
import duckdb, main
db = duckdb.connect('/var/log/ids/duckdb/ids.duckdb')
main.compact_db(db)
"
```

## Streamlit Chat Notes

- `pytz` **must** be in `streamlit/requirements.txt` — DuckDB TIMESTAMPTZ columns require it at read time. Missing `pytz` causes `get_devices` to crash silently, consuming tool rounds with no answer.
- `MAX_TOOL_ROUNDS = 10` in `streamlit/app.py` — raised from 5. A value of 5 was too low when fallback SQL retries occurred, leaving no round for the final text answer.

## Grafana Operational Notes

### DuckDB Version Must Be Pinned to Match the Plugin

The `motherduck-duckdb-datasource` plugin (v0.4.0) embeds DuckDB **1.4.1** as a Go C library. All Python services (`duckdb-mgr`, `streamlit`, `alert-agent`) **must** pin `duckdb==1.4.1` in their `requirements.txt`. A version mismatch causes the plugin to silently return 0 rows for all data queries (schema/`SHOW TABLES` still works, but no row data is returned). The `test_sanity.sh` S31 test enforces this.

If the DB was written with a mismatched version, delete all `.duckdb` files and restart `ids-duckdb-mgr` to recreate them:
```bash
docker exec ids-duckdb-mgr rm -f /var/log/ids/duckdb/ids.duckdb /var/log/ids/duckdb/ids_readonly.duckdb \
  /var/log/ids/duckdb/ids_streamlit.duckdb /var/log/ids/duckdb/ids_alert.duckdb
docker restart ids-duckdb-mgr
```

### Grafana Plugin Connection Caching

The Grafana DuckDB Go plugin caches its database connection. When `ids-duckdb-mgr` atomically replaces `ids_readonly.duckdb` (via `shutil.copy2` + `os.rename`), the plugin may continue reading the old inode. If Grafana shows 0 rows but `SHOW TABLES` works, restart the container: `docker restart ids-grafana`.

### Dashboard Variable SQL Pattern

Grafana dashboard variables with text values like `Hidden`/`Visible` must **not** be used as SQL string literals. DuckDB treats `HIDDEN` as a reserved keyword, causing a `Parser Error: syntax error at or near "Hidden"` when the Grafana plugin interpolates the variable.

**Broken pattern** (do not use):
```sql
CASE WHEN '${show_manufacturer}' = 'Visible' THEN ...
```

**Correct pattern** (use integer values `0`/`1`):
```json
{ "text": "Hidden", "value": "0" }, { "text": "Visible", "value": "1" }
```
```sql
CASE WHEN ${show_manufacturer} = 1 THEN ...
```
The `test_sanity.sh` S32 test catches any dashboard that regresses to the broken string-comparison pattern.

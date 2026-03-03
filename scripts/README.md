# IDS Management Script

`ids.sh` is the single entry point for managing the Agentic IDS stack.

## Quick Start

```bash
# First-time setup
bash scripts/ids.sh start

# Check everything is working
bash scripts/ids.sh status

# Stop the stack
bash scripts/ids.sh stop
```

## Commands

| Command | Description |
|---------|-------------|
| `start` | Build images, create log directory, ensure secret files exist, and start all services |
| `stop` | Stop all services gracefully. Data is preserved. |
| `restart` | Stop and start all services |
| `status` | Show container status and run health checks on all 8 components |
| `logs [service]` | Tail logs. Omit service name for all, or specify one (e.g., `logs suricata`) |
| `verify` | Run all phase verification scripts (Phase 1 through 3b) |
| `rebuild` | Rebuild all Docker images from scratch (`--no-cache`) and restart |
| `destroy` | Stop services and remove Docker volumes. **Grafana config will be lost.** Log data in `/var/log/ids/` is not affected. |

## Services

| Service | Description | Access |
|---------|-------------|--------|
| `suricata` | Signature-based IDS (Suricata 7.0.8) | — |
| `zeek` | Network metadata analyzer (Zeek 7.0.4) | — |
| `vector` | Log pipeline (Vector 0.53.0) | — |
| `duckdb-mgr` | Storage, TTL, enrichment, anomaly detection | — |
| `grafana` | Dashboards | http://localhost:3000 |
| `streamlit` | Chat UI ("Chat with your Network") | http://localhost:8501 |
| `alert-agent` | LLM-drafted email alerts | — |
| Ollama | LLM inference (host-installed, not a container) | http://localhost:11434 |

## Prerequisites

- Docker and Docker Compose installed
- Ollama installed and running on the host (`ollama serve`)
- LLM model pulled (`ollama pull qwen2.5:3b`)

## Examples

```bash
# View only Suricata logs
bash scripts/ids.sh logs suricata

# Check health after a change
bash scripts/ids.sh status

# Code change in alert-agent? Rebuild just that service:
docker compose build alert-agent && docker compose up -d alert-agent

# Full rebuild (all images from scratch)
bash scripts/ids.sh rebuild
```

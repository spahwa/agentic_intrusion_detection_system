#!/usr/bin/env bash
# ids.sh — Manage the Agentic IDS stack
set -euo pipefail

COMPOSE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$COMPOSE_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

usage() {
    echo "Usage: $(basename "$0") <command> [options]"
    echo
    echo "Commands:"
    echo "  start        Build and start all services"
    echo "  stop         Stop all services (preserves data)"
    echo "  restart      Restart all services"
    echo "  status       Show container status and health checks"
    echo "  logs [svc]   Tail logs (all services, or specify one)"
    echo "  verify       Run all phase verification scripts"
    echo "  rebuild      Rebuild images and restart (use after code changes)"
    echo "  destroy      Stop all services and remove volumes (DELETES DATA)"
    echo
    echo "Services: suricata, zeek, vector, duckdb-mgr, grafana, streamlit, alert-agent"
    exit 1
}

ensure_log_dir() {
    local log_dir
    log_dir=$(grep -E '^LOG_DIR=' .env 2>/dev/null | cut -d= -f2 || echo "/var/log/ids")
    log_dir="${log_dir:-/var/log/ids}"
    if [ ! -d "$log_dir" ]; then
        echo -e "${YELLOW}Creating log directory $log_dir ...${NC}"
        sudo mkdir -p "$log_dir"
        sudo chmod 777 "$log_dir"
    fi
}

ensure_secrets() {
    local missing=0
    for f in secrets/gmail_user.txt secrets/gmail_app_password.txt secrets/alert_recipient.txt; do
        if [ ! -f "$f" ]; then
            missing=1
        fi
    done
    if [ "$missing" -eq 1 ]; then
        echo -e "${YELLOW}Secret files missing. Creating empty placeholders...${NC}"
        mkdir -p secrets
        touch secrets/gmail_user.txt secrets/gmail_app_password.txt secrets/alert_recipient.txt
        chmod 600 secrets/*.txt
        echo -e "${YELLOW}Configure secrets for email alerts: see secrets/README.md${NC}"
    fi
}

cmd_start() {
    echo -e "${CYAN}Starting Agentic IDS stack...${NC}"
    ensure_log_dir
    ensure_secrets
    docker compose build
    docker compose up -d
    echo -e "${GREEN}All services started.${NC}"
    echo
    cmd_status
}

_stop_ordered() {
    # Stop services in dependency order, then remove containers and networks.
    # Volumes are never touched.
    #
    # Order rationale:
    #   1. alert-agent, streamlit  — LLM consumers; frees Ollama, closes SQLite writers
    #                                (alert_state.db, nmap_results.db, whitelist.db)
    #   2. grafana                 — snapshot reader only; safe any time
    #   3. duckdb-mgr              — sole DuckDB writer; 60s timeout covers compaction
    #                                (Parquet export/reimport must complete atomically)
    #   4. vector                  — log pipeline; stops NDJSON staging
    #   5. suricata, zeek          — packet capturers last; data already staged by vector
    #
    # Each step uses || true so a service that is already stopped does not abort the script.

    echo -e "  ${CYAN}[1/5] LLM consumers   : alert-agent, streamlit${NC}"
    docker compose stop --timeout 15 alert-agent streamlit 2>/dev/null || true

    echo -e "  ${CYAN}[2/5] Dashboard       : grafana${NC}"
    docker compose stop --timeout 10 grafana 2>/dev/null || true

    echo -e "  ${CYAN}[3/5] DB writer       : duckdb-mgr${NC}"
    docker compose stop --timeout 60 duckdb-mgr 2>/dev/null || true

    echo -e "  ${CYAN}[4/5] Log pipeline    : vector${NC}"
    docker compose stop --timeout 10 vector 2>/dev/null || true

    echo -e "  ${CYAN}[5/5] Packet capturers: suricata, zeek${NC}"
    docker compose stop --timeout 15 suricata zeek 2>/dev/null || true
}

cmd_stop() {
    echo -e "${CYAN}Stopping Agentic IDS stack (safe sequence)...${NC}"
    _stop_ordered
    # Remove stopped containers and networks; volumes preserved (no -v)
    docker compose down 2>/dev/null || true
    echo -e "${GREEN}All services stopped safely. Data preserved in log directory.${NC}"
}

cmd_restart() {
    echo -e "${CYAN}Restarting Agentic IDS stack...${NC}"
    ensure_secrets
    _stop_ordered
    docker compose down 2>/dev/null || true
    docker compose up -d
    echo -e "${GREEN}All services restarted.${NC}"
    echo
    cmd_status
}

cmd_status() {
    echo -e "${CYAN}=== Container Status ===${NC}"
    docker compose ps --format 'table {{.Name}}\t{{.Status}}'
    echo

    echo -e "${CYAN}=== Health Checks ===${NC}"
    local pass=0 fail=0

    # Suricata
    if docker ps --format '{{.Names}}' | grep -q '^ids-suricata$'; then
        echo -e "  ${GREEN}✓${NC} Suricata — running"
        pass=$((pass+1))
    else
        echo -e "  ${RED}✗${NC} Suricata — not running"
        fail=$((fail+1))
    fi

    # Zeek
    if docker ps --format '{{.Names}}' | grep -q '^ids-zeek$'; then
        echo -e "  ${GREEN}✓${NC} Zeek — running"
        pass=$((pass+1))
    else
        echo -e "  ${RED}✗${NC} Zeek — not running"
        fail=$((fail+1))
    fi

    # Vector
    if docker ps --format '{{.Names}}' | grep -q '^ids-vector$'; then
        echo -e "  ${GREEN}✓${NC} Vector — running"
        pass=$((pass+1))
    else
        echo -e "  ${RED}✗${NC} Vector — not running"
        fail=$((fail+1))
    fi

    # DuckDB Manager
    if docker ps --format '{{.Names}}' | grep -q '^ids-duckdb-mgr$'; then
        echo -e "  ${GREEN}✓${NC} DuckDB Manager — running"
        pass=$((pass+1))
    else
        echo -e "  ${RED}✗${NC} DuckDB Manager — not running"
        fail=$((fail+1))
    fi

    # Grafana
    if curl -sf http://localhost:3000/api/health > /dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} Grafana — healthy (http://localhost:3000)"
        pass=$((pass+1))
    else
        echo -e "  ${RED}✗${NC} Grafana — not reachable"
        fail=$((fail+1))
    fi

    # Streamlit
    if curl -sf http://localhost:8501/_stcore/health > /dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} Streamlit — healthy (http://localhost:8501)"
        pass=$((pass+1))
    else
        echo -e "  ${RED}✗${NC} Streamlit — not reachable"
        fail=$((fail+1))
    fi

    # Ollama (host service)
    if curl -sf http://localhost:11434/api/tags > /dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} Ollama — running (host)"
        pass=$((pass+1))
    else
        echo -e "  ${RED}✗${NC} Ollama — not reachable (start with: ollama serve)"
        fail=$((fail+1))
    fi

    # Alert Agent
    if docker ps --format '{{.Names}}' | grep -q '^ids-alert-agent$'; then
        echo -e "  ${GREEN}✓${NC} Alert Agent — running"
        pass=$((pass+1))
    else
        echo -e "  ${RED}✗${NC} Alert Agent — not running"
        fail=$((fail+1))
    fi

    echo
    if [ "$fail" -eq 0 ]; then
        echo -e "${GREEN}All $pass components healthy.${NC}"
    else
        echo -e "${YELLOW}$pass healthy, $fail unhealthy.${NC}"
    fi
}

cmd_logs() {
    local service="${1:-}"
    if [ -n "$service" ]; then
        docker compose logs -f "$service"
    else
        docker compose logs -f
    fi
}

cmd_verify() {
    echo -e "${CYAN}Running all verification scripts...${NC}"
    echo
    for script in scripts/verify.sh scripts/verify_phase2.sh scripts/verify_phase2_5.sh scripts/verify_phase3.sh scripts/verify_phase3b.sh; do
        if [ -f "$script" ]; then
            echo -e "${CYAN}--- $(basename "$script") ---${NC}"
            bash "$script" || true
            echo
        fi
    done
}

cmd_rebuild() {
    echo -e "${CYAN}Rebuilding images and restarting...${NC}"
    ensure_secrets
    docker compose build --no-cache
    docker compose up -d
    echo -e "${GREEN}Rebuild complete.${NC}"
    echo
    cmd_status
}

cmd_destroy() {
    echo -e "${RED}WARNING: This will stop all services and remove Docker volumes.${NC}"
    echo -e "${RED}Log data in /var/log/ids/ will NOT be deleted (only Docker volumes like grafana-data).${NC}"
    read -rp "Are you sure? (y/N): " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        docker compose down -v
        echo -e "${GREEN}All services stopped and volumes removed.${NC}"
    else
        echo "Cancelled."
    fi
}

# --- Main ---
[ $# -lt 1 ] && usage

case "$1" in
    start)    cmd_start ;;
    stop)     cmd_stop ;;
    restart)  cmd_restart ;;
    status)   cmd_status ;;
    logs)     cmd_logs "${2:-}" ;;
    verify)   cmd_verify ;;
    rebuild)  cmd_rebuild ;;
    destroy)  cmd_destroy ;;
    *)        usage ;;
esac

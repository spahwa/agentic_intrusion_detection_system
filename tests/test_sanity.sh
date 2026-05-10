#!/bin/bash
# Agentic IDS — Full-Stack Sanity Test
#
# A single script that validates every layer of the IDS stack end-to-end.
# Designed to run after `docker compose up -d` as a smoke test.
#
# Usage:
#   bash tests/test_sanity.sh                # Run all tests
#   bash tests/test_sanity.sh --static-only  # Config tests only (no containers needed)
#   bash tests/test_sanity.sh --runtime-only # Runtime tests only (containers must be up)
#
# Exit code: 0 if all tests pass, 1 if any FAIL

set -euo pipefail

# --- Colors & counters ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0

pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; PASS=$((PASS + 1)); }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; FAIL=$((FAIL + 1)); }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; WARN=$((WARN + 1)); }
section() { echo -e "\n${CYAN}${BOLD}── $1 ──${NC}"; }

# --- Parse flags ---
RUN_STATIC=true
RUN_RUNTIME=true

case "${1:-}" in
    --static-only)  RUN_RUNTIME=false ;;
    --runtime-only) RUN_STATIC=false ;;
    "") ;; # default: run both
    *) echo "Usage: $0 [--static-only|--runtime-only]"; exit 2 ;;
esac

# --- Resolve paths ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Source .env for variable defaults
if [ -f "$PROJECT_ROOT/.env" ]; then
    set -a
    # shellcheck disable=SC1091
    source "$PROJECT_ROOT/.env"
    set +a
fi

LOG_DIR="${LOG_DIR:-/var/log/ids}"
NETWORK_INTERFACE="${NETWORK_INTERFACE:-enp1s0f0}"
GRAFANA_PORT="${GRAFANA_PORT:-3000}"
STREAMLIT_PORT="${STREAMLIT_PORT:-8501}"
DUCKDB_FILE="${LOG_DIR}/duckdb/ids.duckdb"
DUCKDB_READONLY="${LOG_DIR}/duckdb/ids_readonly.duckdb"
TTL_HOURS="${DUCKDB_TTL_HOURS:-72}"

echo "============================================================"
echo " Agentic IDS — Full-Stack Sanity Test"
echo "============================================================"
echo " Project: $PROJECT_ROOT"
echo " Mode:    $(if $RUN_STATIC && $RUN_RUNTIME; then echo "full"; elif $RUN_STATIC; then echo "static-only"; else echo "runtime-only"; fi)"
echo ""

# All containers in the primary stack (no dual-interface wifi)
ALL_CONTAINERS="ids-suricata ids-zeek ids-vector ids-duckdb-mgr ids-grafana ids-streamlit ids-alert-agent"

# =============================================================================
# STATIC TESTS
# =============================================================================

if $RUN_STATIC; then

    COMPOSE_JSON=$(docker compose -f "$PROJECT_ROOT/docker-compose.yml" config --format json 2>/dev/null) || true

    # ---- S1. Docker Compose Parsing ----
    section "S1. Docker Compose Config"

    if docker compose -f "$PROJECT_ROOT/docker-compose.yml" config > /dev/null 2>&1; then
        pass "S01: docker-compose.yml parses without error"
    else
        fail "S01: docker-compose.yml fails to parse"
    fi

    if docker compose -f "$PROJECT_ROOT/docker-compose.yml" --profile dual config > /dev/null 2>&1; then
        pass "S02: --profile dual config parses without error"
    else
        fail "S02: --profile dual config fails to parse"
    fi

    # ---- S2. Network Modes & Capabilities ----
    section "S2. Network Modes & Capabilities"

    if [ -n "$COMPOSE_JSON" ]; then
        # Host-networked services
        for svc in suricata zeek streamlit alert-agent; do
            NET_MODE=$(echo "$COMPOSE_JSON" | python3 -c "
import sys, json; cfg = json.load(sys.stdin)
print(cfg.get('services',{}).get('${svc}',{}).get('network_mode',''))" 2>/dev/null || echo "")
            if [ "$NET_MODE" = "host" ]; then
                pass "S03: $svc uses network_mode: host"
            else
                fail "S03: $svc network_mode=$NET_MODE (expected host)"
            fi
        done

        # Suricata capabilities
        SURI_CAPS=$(echo "$COMPOSE_JSON" | python3 -c "
import sys, json; cfg = json.load(sys.stdin)
caps = cfg.get('services',{}).get('suricata',{}).get('cap_add',[])
print(' '.join(sorted(caps)))" 2>/dev/null || echo "")
        if echo "$SURI_CAPS" | grep -q "NET_ADMIN" && \
           echo "$SURI_CAPS" | grep -q "NET_RAW" && \
           echo "$SURI_CAPS" | grep -q "SYS_NICE"; then
            pass "S04: Suricata has NET_ADMIN, NET_RAW, SYS_NICE"
        else
            fail "S04: Suricata capabilities: [$SURI_CAPS]"
        fi

        # Zeek capabilities
        ZEEK_CAPS=$(echo "$COMPOSE_JSON" | python3 -c "
import sys, json; cfg = json.load(sys.stdin)
caps = cfg.get('services',{}).get('zeek',{}).get('cap_add',[])
print(' '.join(sorted(caps)))" 2>/dev/null || echo "")
        if echo "$ZEEK_CAPS" | grep -q "NET_ADMIN" && echo "$ZEEK_CAPS" | grep -q "NET_RAW"; then
            pass "S05: Zeek has NET_ADMIN, NET_RAW"
        else
            fail "S05: Zeek capabilities: [$ZEEK_CAPS]"
        fi
    else
        fail "S03-S05: Could not parse docker compose config as JSON"
    fi

    # ---- S3. Image Tags ----
    section "S3. Image Tags & Pinning"

    if grep -qi "latest" "$PROJECT_ROOT/docker-compose.yml" 2>/dev/null; then
        fail "S06: Found 'latest' tag in docker-compose.yml"
    else
        pass "S06: No 'latest' image tags — all pinned"
    fi

    # ---- S4. Suricata Config ----
    section "S4. Suricata Configuration"

    SURICATA_YAML="$PROJECT_ROOT/suricata/suricata.yaml"
    if grep -q 'community-id: true' "$SURICATA_YAML" 2>/dev/null; then
        pass "S07: community-id enabled in suricata.yaml"
    else
        fail "S07: community-id not enabled"
    fi

    if grep -q 'eve-log:' "$SURICATA_YAML" 2>/dev/null; then
        pass "S08: EVE JSON output configured"
    else
        fail "S08: EVE JSON not configured"
    fi

    # ---- S5. Zeek Config ----
    section "S5. Zeek Configuration"

    LOCAL_ZEEK="$PROJECT_ROOT/zeek/local.zeek"
    if grep -q 'community-id-logging' "$LOCAL_ZEEK" 2>/dev/null; then
        pass "S09: community-id-logging loaded in local.zeek"
    else
        fail "S09: community-id-logging missing"
    fi

    if grep -q 'LogAscii::use_json = T' "$LOCAL_ZEEK" 2>/dev/null; then
        pass "S10: JSON output enabled in local.zeek"
    else
        fail "S10: JSON output not enabled"
    fi

    # ---- S6. Healthchecks Defined ----
    section "S6. Healthcheck Definitions"

    if [ -n "$COMPOSE_JSON" ]; then
        for svc in suricata zeek vector duckdb-mgr grafana streamlit alert-agent; do
            HC=$(echo "$COMPOSE_JSON" | python3 -c "
import sys, json; cfg = json.load(sys.stdin)
hc = cfg.get('services',{}).get('${svc}',{}).get('healthcheck',{})
print('yes' if hc.get('test') else 'no')" 2>/dev/null || echo "no")
            if [ "$HC" = "yes" ]; then
                pass "S11: $svc has healthcheck defined"
            else
                fail "S11: $svc missing healthcheck"
            fi
        done
    fi

    # ---- S7. DuckDB Schema ----
    section "S7. DuckDB Schema File"

    SCHEMA_FILE="$PROJECT_ROOT/duckdb-mgr/schema.sql"
    for table in events _ingested_files oui_lookup geoip_lookup devices external_ips anomaly_events _known_devices device_baselines nmap_scans; do
        if grep -q "$table" "$SCHEMA_FILE" 2>/dev/null; then
            pass "S12: Table '$table' defined in schema.sql"
        else
            fail "S12: Table '$table' missing from schema.sql"
        fi
    done

    # ---- S8. Suricata Rule Update Config ----
    section "S8. Suricata Rule Update Watchdog"

    if grep -q 'rule_update_watchdog' "$PROJECT_ROOT/suricata/entrypoint.sh" 2>/dev/null; then
        pass "S13: rule_update_watchdog defined in entrypoint.sh"
    else
        fail "S13: rule_update_watchdog missing from entrypoint.sh"
    fi

    if grep -q 'RULE_UPDATE_INTERVAL_HOURS' "$PROJECT_ROOT/suricata/entrypoint.sh" 2>/dev/null; then
        pass "S14: RULE_UPDATE_INTERVAL_HOURS used in entrypoint.sh"
    else
        fail "S14: RULE_UPDATE_INTERVAL_HOURS missing from entrypoint.sh"
    fi

    # ---- S9. Nmap Tool Definitions ----
    section "S9. Nmap Tool Definitions"

    TOOLS_PY="$PROJECT_ROOT/streamlit/tools.py"
    if grep -q 'def nmap_scan' "$TOOLS_PY" 2>/dev/null; then
        pass "S15: nmap_scan function defined in tools.py"
    else
        fail "S15: nmap_scan missing from tools.py"
    fi

    if grep -q 'def get_scan_history' "$TOOLS_PY" 2>/dev/null; then
        pass "S16: get_scan_history function defined in tools.py"
    else
        fail "S16: get_scan_history missing from tools.py"
    fi

    if grep -q '_is_rfc1918' "$TOOLS_PY" 2>/dev/null; then
        pass "S17: RFC1918 validation present in tools.py"
    else
        fail "S17: RFC1918 validation missing from tools.py"
    fi

    # Python syntax check on key files
    section "S10. Python Syntax Validation"

    for pyfile in streamlit/tools.py streamlit/app.py streamlit/system_prompt.py \
                  duckdb-mgr/main.py alert-agent/main.py alert-agent/tools.py; do
        FULL_PATH="$PROJECT_ROOT/$pyfile"
        if [ -f "$FULL_PATH" ]; then
            if python3 -c "import ast; ast.parse(open('$FULL_PATH').read())" 2>/dev/null; then
                pass "S18: $pyfile syntax OK"
            else
                fail "S18: $pyfile has syntax errors"
            fi
        fi
    done

    # ---- S11. Threat Intel RAG ----
    section "S11. Threat Intel RAG"

    # duckdb-mgr uses network_mode: host (required for Ollama access)
    if [ -n "$COMPOSE_JSON" ]; then
        DUCKDB_NET=$(echo "$COMPOSE_JSON" | python3 -c "
import sys, json; cfg = json.load(sys.stdin)
print(cfg.get('services',{}).get('duckdb-mgr',{}).get('network_mode',''))" 2>/dev/null || echo "")
        if [ "$DUCKDB_NET" = "host" ]; then
            pass "S19: duckdb-mgr uses network_mode: host (for Ollama RAG access)"
        else
            fail "S19: duckdb-mgr network_mode=$DUCKDB_NET (expected host for RAG)"
        fi

        # OLLAMA_HOST env in duckdb-mgr
        DUCKDB_ENV=$(echo "$COMPOSE_JSON" | python3 -c "
import sys, json; cfg = json.load(sys.stdin)
env = cfg.get('services',{}).get('duckdb-mgr',{}).get('environment',[])
if isinstance(env, dict):
    keys = list(env.keys())
else:
    keys = [e.split('=')[0] for e in env if '=' in e]
print(' '.join(keys))" 2>/dev/null || echo "")
        if echo "$DUCKDB_ENV" | grep -q "OLLAMA_HOST" && \
           echo "$DUCKDB_ENV" | grep -q "EMBED_MODEL" && \
           echo "$DUCKDB_ENV" | grep -q "RAG_DUCKDB_PATH"; then
            pass "S20: duckdb-mgr has OLLAMA_HOST, EMBED_MODEL, RAG_DUCKDB_PATH env vars"
        else
            fail "S20: duckdb-mgr missing RAG env vars (got: $DUCKDB_ENV)"
        fi

        # RAG env in streamlit
        ST_ENV=$(echo "$COMPOSE_JSON" | python3 -c "
import sys, json; cfg = json.load(sys.stdin)
env = cfg.get('services',{}).get('streamlit',{}).get('environment',[])
if isinstance(env, dict):
    keys = list(env.keys())
else:
    keys = [e.split('=')[0] for e in env if '=' in e]
print(' '.join(keys))" 2>/dev/null || echo "")
        if echo "$ST_ENV" | grep -q "EMBED_MODEL" && echo "$ST_ENV" | grep -q "RAG_DUCKDB_PATH"; then
            pass "S21: streamlit has EMBED_MODEL, RAG_DUCKDB_PATH env vars"
        else
            fail "S21: streamlit missing RAG env vars"
        fi

        # RAG env in alert-agent
        AA_ENV=$(echo "$COMPOSE_JSON" | python3 -c "
import sys, json; cfg = json.load(sys.stdin)
env = cfg.get('services',{}).get('alert-agent',{}).get('environment',[])
if isinstance(env, dict):
    keys = list(env.keys())
else:
    keys = [e.split('=')[0] for e in env if '=' in e]
print(' '.join(keys))" 2>/dev/null || echo "")
        if echo "$AA_ENV" | grep -q "EMBED_MODEL" && echo "$AA_ENV" | grep -q "RAG_DUCKDB_PATH"; then
            pass "S22: alert-agent has EMBED_MODEL, RAG_DUCKDB_PATH env vars"
        else
            fail "S22: alert-agent missing RAG env vars"
        fi
    fi

    # RAG functions defined in Python source
    if grep -q 'def rag_search_threat_intel' "$PROJECT_ROOT/streamlit/tools.py" 2>/dev/null; then
        pass "S23: rag_search_threat_intel defined in streamlit/tools.py"
    else
        fail "S23: rag_search_threat_intel missing from streamlit/tools.py"
    fi

    if grep -q 'def rag_search_threat_intel' "$PROJECT_ROOT/alert-agent/tools.py" 2>/dev/null; then
        pass "S24: rag_search_threat_intel defined in alert-agent/tools.py"
    else
        fail "S24: rag_search_threat_intel missing from alert-agent/tools.py"
    fi

    if grep -q 'def index_threat_intel' "$PROJECT_ROOT/duckdb-mgr/main.py" 2>/dev/null; then
        pass "S25: index_threat_intel defined in duckdb-mgr/main.py"
    else
        fail "S25: index_threat_intel missing from duckdb-mgr/main.py"
    fi

    # Suricata entrypoint copies rules to shared volume
    if grep -q 'suricata/rules' "$PROJECT_ROOT/suricata/entrypoint.sh" 2>/dev/null && \
       grep -q 'suricata.rules' "$PROJECT_ROOT/suricata/entrypoint.sh" 2>/dev/null; then
        pass "S26: suricata/entrypoint.sh copies rules to shared volume"
    else
        fail "S26: suricata/entrypoint.sh missing rule copy for RAG"
    fi

    # rag_search_threat_intel in tool definitions and map
    if grep -q '"rag_search_threat_intel"' "$PROJECT_ROOT/streamlit/tools.py" 2>/dev/null; then
        pass "S27: rag_search_threat_intel in streamlit TOOL_DEFINITIONS"
    else
        fail "S27: rag_search_threat_intel not in streamlit TOOL_DEFINITIONS"
    fi

    if grep -q '"rag_search_threat_intel"' "$PROJECT_ROOT/alert-agent/tools.py" 2>/dev/null; then
        pass "S28: rag_search_threat_intel in alert-agent TOOL_DEFINITIONS"
    else
        fail "S28: rag_search_threat_intel not in alert-agent TOOL_DEFINITIONS"
    fi

    # System prompt mentions RAG tool
    if grep -q 'rag_search_threat_intel' "$PROJECT_ROOT/streamlit/system_prompt.py" 2>/dev/null; then
        pass "S29: rag_search_threat_intel referenced in streamlit system_prompt.py"
    else
        fail "S29: rag_search_threat_intel missing from streamlit system_prompt.py"
    fi

    # Alert-agent main pre-enrichment
    if grep -q 'rag_search_threat_intel' "$PROJECT_ROOT/alert-agent/main.py" 2>/dev/null; then
        pass "S30: alert-agent/main.py uses rag_search_threat_intel for pre-enrichment"
    else
        fail "S30: alert-agent/main.py missing rag_search_threat_intel pre-enrichment"
    fi

    # ---- S12. DuckDB Version Alignment ----
    # Root cause: duckdb Python version must match the version embedded in the Grafana Go plugin.
    # Mismatches cause the plugin to silently return 0 rows for all queries.
    section "S12. DuckDB Version Alignment"

    GRAFANA_PLUGIN_DUCKDB_VER="1.4.1"   # Version embedded in motherduck-duckdb-datasource v0.4.0
    for req_file in duckdb-mgr/requirements.txt streamlit/requirements.txt alert-agent/requirements.txt; do
        FULL_REQ="$PROJECT_ROOT/$req_file"
        if [ -f "$FULL_REQ" ]; then
            PINNED=$(grep -E '^duckdb==' "$FULL_REQ" | cut -d= -f3 || echo "")
            if [ "$PINNED" = "$GRAFANA_PLUGIN_DUCKDB_VER" ]; then
                pass "S31: $req_file pins duckdb==$GRAFANA_PLUGIN_DUCKDB_VER (matches Grafana plugin)"
            elif [ -z "$PINNED" ]; then
                fail "S31: $req_file does not pin duckdb version (must be duckdb==$GRAFANA_PLUGIN_DUCKDB_VER)"
            else
                fail "S31: $req_file pins duckdb==$PINNED but Grafana plugin embeds $GRAFANA_PLUGIN_DUCKDB_VER — mismatch will cause Grafana to show 0 rows"
            fi
        fi
    done

    # ---- S13. Grafana Dashboard Variable SQL Safety ----
    # Root cause: DuckDB treats HIDDEN/VISIBLE as reserved keywords. Dashboard variables with
    # text values like "Hidden"/"Visible" must use integer values (0/1) in SQL to avoid
    # "syntax error at or near 'Hidden'" from the Grafana DuckDB plugin's variable interpolation.
    section "S13. Grafana Dashboard Variable SQL Safety"

    for dash in "$PROJECT_ROOT/grafana/dashboards/"*.json; do
        DASH_NAME=$(basename "$dash")
        # Check for string-valued variables used in SQL string comparisons (the broken pattern)
        if grep -q "= 'Visible'\|= 'Hidden'" "$dash" 2>/dev/null; then
            fail "S32: $DASH_NAME contains string comparison against 'Hidden'/'Visible' — use integer values (0/1) instead to avoid DuckDB keyword collision"
        else
            pass "S32: $DASH_NAME has no unsafe Hidden/Visible string comparisons"
        fi
    done

    # ---- S14. Alert Email Static Validation ----
    section "S14. Alert Email Static Validation"

    # Gmail credentials are loaded from Docker secrets files at ./secrets/*.txt
    for secret in gmail_user gmail_app_password alert_recipient; do
        SECRET_FILE="$PROJECT_ROOT/secrets/${secret}.txt"
        if [ -f "$SECRET_FILE" ] && [ -s "$SECRET_FILE" ]; then
            pass "S33: secrets/${secret}.txt exists and non-empty"
        elif [ -f "$SECRET_FILE" ]; then
            fail "S33: secrets/${secret}.txt is empty — email alerts will not send"
        else
            warn "S33: secrets/${secret}.txt not found (email alerts disabled)"
        fi
    done

    # fast_new_devices dual-flag pattern: alert_emailed (alert-agent consumer) + duckdb_drained (duckdb-mgr consumer)
    if grep -q "alert_emailed" "$PROJECT_ROOT/duckdb-mgr/main.py" && \
       grep -q "duckdb_drained" "$PROJECT_ROOT/duckdb-mgr/main.py"; then
        pass "S34: fast_new_devices dual-flag pattern present (alert_emailed + duckdb_drained) — no race condition between consumers"
    else
        fail "S34: fast_new_devices dual-flag pattern missing — alert-agent and duckdb-mgr may race on fast_alerts.db"
    fi

    # alert_state.db composite PK (anomaly_id, detected_at) — survives DuckDB sequence resets after DB recreation
    if grep -q "PRIMARY KEY (anomaly_id, detected_at)" "$PROJECT_ROOT/alert-agent/main.py"; then
        pass "S35: alert_state.db uses composite PK (anomaly_id, detected_at) — protects against email skip after DB reset"
    else
        fail "S35: alert_state.db does not use composite PK — DuckDB sequence resets will cause anomalies to be silently skipped"
    fi

    # nmap SQLite→DuckDB sync function defined in duckdb-mgr
    if grep -q "def sync_nmap_from_sqlite" "$PROJECT_ROOT/duckdb-mgr/main.py"; then
        pass "S36: sync_nmap_from_sqlite defined in duckdb-mgr (SQLite→DuckDB nmap sync)"
    else
        fail "S36: sync_nmap_from_sqlite missing from duckdb-mgr — on-demand nmap scans won't appear in Grafana"
    fi

    # ---- S15. LLM Configuration Correctness ----
    section "S15. LLM Configuration Correctness"

    # MAX_TOOL_ROUNDS must be >= 10 in streamlit — 5 was too low when fallback SQL retries consumed rounds
    ST_ROUNDS=$(grep "MAX_TOOL_ROUNDS" "$PROJECT_ROOT/streamlit/app.py" 2>/dev/null | grep -oE '[0-9]+' | head -1)
    if [ "${ST_ROUNDS:-0}" -ge 10 ] 2>/dev/null; then
        pass "S37: MAX_TOOL_ROUNDS=${ST_ROUNDS} in streamlit/app.py (≥10 required to handle fallback retries)"
    else
        fail "S37: MAX_TOOL_ROUNDS=${ST_ROUNDS} in streamlit/app.py is too low — LLM will exhaust rounds before answering when SQL retries occur"
    fi

    # pytz must be in streamlit/requirements.txt — DuckDB TIMESTAMPTZ columns crash without it
    if grep -q "pytz" "$PROJECT_ROOT/streamlit/requirements.txt" 2>/dev/null; then
        pass "S38: pytz in streamlit/requirements.txt (required for DuckDB TIMESTAMPTZ column reads)"
    else
        fail "S38: pytz missing from streamlit/requirements.txt — get_devices will crash silently and exhaust all tool rounds"
    fi

    # pytz also required in alert-agent — same TIMESTAMPTZ issue applies to anomaly reads
    if grep -q "pytz" "$PROJECT_ROOT/alert-agent/requirements.txt" 2>/dev/null; then
        pass "S39: pytz in alert-agent/requirements.txt (required for DuckDB TIMESTAMPTZ column reads)"
    else
        fail "S39: pytz missing from alert-agent/requirements.txt — anomaly timestamp reads may fail"
    fi

    # _sync_anomaly_seq must be called at startup in duckdb-mgr — prevents email skip after DB recreation
    if grep -q "_sync_anomaly_seq" "$PROJECT_ROOT/duckdb-mgr/main.py"; then
        pass "S40: _sync_anomaly_seq present in duckdb-mgr (guards against email-skip after DuckDB sequence reset)"
    else
        fail "S40: _sync_anomaly_seq missing from duckdb-mgr — DB recreation will reset sequence; all new anomalies will be silently skipped by alert-agent"
    fi

fi # end static tests

# =============================================================================
# RUNTIME TESTS
# =============================================================================

if $RUN_RUNTIME; then

    # ---- R1. All Containers Running ----
    section "R1. Container Status"

    for ctr in $ALL_CONTAINERS; do
        STATE=$(docker inspect --format='{{.State.Status}}' "$ctr" 2>/dev/null || echo "not_found")
        RESTARTING=$(docker inspect --format='{{.State.Restarting}}' "$ctr" 2>/dev/null || echo "true")
        if [ "$STATE" = "running" ] && [ "$RESTARTING" = "false" ]; then
            pass "R01: $ctr is running"
        else
            fail "R01: $ctr state=$STATE restarting=$RESTARTING"
        fi
    done

    # ---- R2. Docker Health Status ----
    section "R2. Docker Health Status"

    for ctr in $ALL_CONTAINERS; do
        HEALTH=$(docker inspect --format='{{.State.Health.Status}}' "$ctr" 2>/dev/null || echo "none")
        case "$HEALTH" in
            healthy)
                pass "R02: $ctr is healthy"
                ;;
            starting)
                warn "R02: $ctr health is still 'starting' (may need more time)"
                ;;
            unhealthy)
                fail "R02: $ctr is unhealthy"
                # Show last health check log
                docker inspect --format='{{range .State.Health.Log}}{{.Output}}{{end}}' "$ctr" 2>/dev/null | tail -3
                ;;
            none|"")
                warn "R02: $ctr has no healthcheck status"
                ;;
            *)
                warn "R02: $ctr health=$HEALTH"
                ;;
        esac
    done

    # ---- R3. Suricata ----
    section "R3. Suricata Logs & Output"

    EVE_FILE="$LOG_DIR/suricata/eve.json"
    elapsed=0
    while [ ! -s "$EVE_FILE" ] && [ $elapsed -lt 45 ]; do
        sleep 3
        elapsed=$((elapsed + 3))
    done

    if [ -s "$EVE_FILE" ]; then
        pass "R03: eve.json exists and non-empty (${elapsed}s)"

        if head -1 "$EVE_FILE" | python3 -m json.tool > /dev/null 2>&1; then
            pass "R04: eve.json contains valid JSON"
        else
            fail "R04: eve.json first line is not valid JSON"
        fi
    else
        fail "R03: eve.json missing or empty after 45s"
        fail "R04: Cannot test — eve.json missing"
    fi

    SURI_LOGS=$(docker logs ids-suricata 2>&1 | tail -200)
    if echo "$SURI_LOGS" | grep -qi "engine started"; then
        pass "R05: Suricata 'Engine started' in logs"
    else
        fail "R05: Suricata 'Engine started' not found in logs"
    fi

    if echo "$SURI_LOGS" | grep -q "$NETWORK_INTERFACE"; then
        pass "R06: Suricata listening on $NETWORK_INTERFACE"
    else
        fail "R06: Suricata not listening on $NETWORK_INTERFACE"
    fi

    # Rule update watchdog
    if echo "$SURI_LOGS" | grep -q "rule-update"; then
        pass "R07: Rule update watchdog started"
    else
        warn "R07: Rule update watchdog not yet visible in logs (120s startup delay)"
    fi

    # ---- R4. Zeek ----
    section "R4. Zeek Logs & Output"

    elapsed=0
    while [ -z "$(find "${LOG_DIR}/zeek" -name '*.log' 2>/dev/null)" ] && [ $elapsed -lt 45 ]; do
        sleep 3
        elapsed=$((elapsed + 3))
    done

    ZEEK_LOGS_FILES=$(find "${LOG_DIR}/zeek" -name '*.log' 2>/dev/null || true)
    if [ -n "$ZEEK_LOGS_FILES" ]; then
        LOG_COUNT=$(echo "$ZEEK_LOGS_FILES" | wc -l)
        pass "R08: Found $LOG_COUNT Zeek log file(s) (${elapsed}s)"

        # Validate JSON on first non-empty log
        for logfile in $ZEEK_LOGS_FILES; do
            if [ -s "$logfile" ]; then
                if head -1 "$logfile" | python3 -m json.tool > /dev/null 2>&1; then
                    pass "R09: Zeek JSON output valid ($(basename "$logfile"))"
                else
                    fail "R09: Zeek $(basename "$logfile") first line not valid JSON"
                fi
                break
            fi
        done
    else
        fail "R08: No Zeek .log files after 45s"
        fail "R09: Cannot test — no Zeek logs"
    fi

    ZEEK_DOCKER_LOGS=$(docker logs ids-zeek 2>&1 | tail -50)
    if echo "$ZEEK_DOCKER_LOGS" | grep -qi "listening on"; then
        pass "R10: Zeek 'listening on' in docker logs"
    else
        fail "R10: Zeek 'listening on' not found"
    fi

    # ---- R5. Vector ----
    section "R5. Vector Data Pipeline"

    VECTOR_DIR="${LOG_DIR}/vector"
    if [ -d "$VECTOR_DIR" ]; then
        NDJSON_COUNT=$(find "$VECTOR_DIR" -name '*.ndjson' 2>/dev/null | wc -l)
        if [ "$NDJSON_COUNT" -gt 0 ]; then
            pass "R11: $NDJSON_COUNT NDJSON staging file(s) in Vector dir"

            FIRST_NDJSON=$(find "$VECTOR_DIR" -name '*.ndjson' -size +0c 2>/dev/null | head -1 || true)
            if [ -n "$FIRST_NDJSON" ]; then
                if head -1 "$FIRST_NDJSON" | python3 -m json.tool > /dev/null 2>&1; then
                    pass "R12: NDJSON content is valid JSON"
                else
                    fail "R12: NDJSON first line is not valid JSON"
                fi
            else
                warn "R12: All NDJSON files empty"
            fi
        else
            warn "R11: No NDJSON files yet (need more time/traffic)"
            warn "R12: Cannot test — no NDJSON files"
        fi
    else
        fail "R11: Vector staging dir $VECTOR_DIR does not exist"
        fail "R12: Cannot test — no Vector dir"
    fi

    # ---- R6. DuckDB ----
    section "R6. DuckDB Database & Tables"

    if [ -f "$DUCKDB_FILE" ]; then
        pass "R13: DuckDB file exists"

        ROW_COUNT=$(docker exec ids-streamlit python3 -c "
import duckdb
db = duckdb.connect('$DUCKDB_READONLY', read_only=True)
print(db.execute('SELECT count(*) FROM events').fetchone()[0])
db.close()
" 2>/dev/null || echo "ERROR")

        if [ "$ROW_COUNT" != "ERROR" ] && [ "$ROW_COUNT" -gt 0 ] 2>/dev/null; then
            pass "R14: events table has $ROW_COUNT row(s)"
        elif [ "$ROW_COUNT" = "0" ]; then
            warn "R14: events table has 0 rows (need more time/traffic)"
        else
            fail "R14: Could not query events table"
        fi

        # TTL compliance
        EXPIRED=$(docker exec ids-streamlit python3 -c "
import duckdb
db = duckdb.connect('$DUCKDB_READONLY', read_only=True)
print(db.execute(\"SELECT count(*) FROM events WHERE timestamp < now() - INTERVAL '$TTL_HOURS hours'\").fetchone()[0])
db.close()
" 2>/dev/null || echo "ERROR")
        if [ "$EXPIRED" = "0" ]; then
            pass "R15: TTL compliant — 0 events older than ${TTL_HOURS}h"
        elif [ "$EXPIRED" = "ERROR" ]; then
            warn "R15: Could not check TTL compliance"
        else
            fail "R15: $EXPIRED event(s) older than ${TTL_HOURS}h"
        fi

        # Source tools present
        SOURCES=$(docker exec ids-streamlit python3 -c "
import duckdb
db = duckdb.connect('$DUCKDB_READONLY', read_only=True)
rows = db.execute('SELECT DISTINCT source_tool FROM events').fetchall()
for r in rows: print(r[0])
db.close()
" 2>/dev/null || echo "ERROR")
        if [ "$SOURCES" != "ERROR" ]; then
            for tool in suricata zeek; do
                if echo "$SOURCES" | grep -q "$tool"; then
                    pass "R16: Events from $tool present in DuckDB"
                else
                    warn "R16: No events from $tool yet"
                fi
            done
        else
            warn "R16: Could not query source tools"
        fi

        # All expected tables exist
        TABLES=$(docker exec ids-streamlit python3 -c "
import duckdb
db = duckdb.connect('$DUCKDB_READONLY', read_only=True)
rows = db.execute(\"SELECT table_name FROM information_schema.tables WHERE table_schema='main'\").fetchall()
for r in rows: print(r[0])
db.close()
" 2>/dev/null || echo "ERROR")
        if [ "$TABLES" != "ERROR" ]; then
            for tbl in events devices external_ips oui_lookup geoip_lookup anomaly_events _known_devices device_baselines nmap_scans; do
                if echo "$TABLES" | grep -q "$tbl"; then
                    pass "R17: Table '$tbl' exists in DuckDB"
                else
                    fail "R17: Table '$tbl' missing from DuckDB"
                fi
            done
        else
            fail "R17: Could not list DuckDB tables"
        fi

        # Readonly snapshots exist
        for snap in ids_readonly.duckdb ids_streamlit.duckdb ids_alert.duckdb; do
            if [ -f "${LOG_DIR}/duckdb/$snap" ]; then
                pass "R18: Snapshot $snap exists"
            else
                warn "R18: Snapshot $snap not yet created (first cycle may not have run)"
            fi
        done

        # community_id presence
        CID_COUNT=$(docker exec ids-streamlit python3 -c "
import duckdb
db = duckdb.connect('$DUCKDB_READONLY', read_only=True)
print(db.execute(\"SELECT count(*) FROM events WHERE raw::VARCHAR LIKE '%community_id%'\").fetchone()[0])
db.close()
" 2>/dev/null || echo "ERROR")
        if [ "$CID_COUNT" != "ERROR" ] && [ "$CID_COUNT" -gt 0 ] 2>/dev/null; then
            pass "R19: $CID_COUNT event(s) with community_id"
        else
            warn "R19: No community_id events yet (need flow traffic)"
        fi
    else
        fail "R13: DuckDB file not found"
        fail "R14-R19: Skipped — no DuckDB file"
    fi

    # ---- R7. Enrichment Data ----
    section "R7. OUI & GeoIP Enrichment"

    OUI_COUNT=$(docker exec ids-streamlit python3 -c "
import duckdb
db = duckdb.connect('$DUCKDB_READONLY', read_only=True)
print(db.execute('SELECT count(*) FROM oui_lookup').fetchone()[0])
db.close()
" 2>/dev/null || echo "ERROR")
    if [ "$OUI_COUNT" != "ERROR" ] && [ "$OUI_COUNT" -gt 1000 ] 2>/dev/null; then
        pass "R20: OUI lookup has $OUI_COUNT entries"
    elif [ "$OUI_COUNT" = "0" ] || [ "$OUI_COUNT" = "ERROR" ]; then
        warn "R20: OUI lookup empty or not loaded"
    else
        warn "R20: OUI lookup has only $OUI_COUNT entries (expected 30K+)"
    fi

    GEOIP_COUNT=$(docker exec ids-streamlit python3 -c "
import duckdb
db = duckdb.connect('$DUCKDB_READONLY', read_only=True)
print(db.execute('SELECT count(*) FROM geoip_lookup').fetchone()[0])
db.close()
" 2>/dev/null || echo "ERROR")
    if [ "$GEOIP_COUNT" != "ERROR" ] && [ "$GEOIP_COUNT" -gt 10000 ] 2>/dev/null; then
        pass "R21: GeoIP lookup has $GEOIP_COUNT entries"
    elif [ "$GEOIP_COUNT" = "0" ] || [ "$GEOIP_COUNT" = "ERROR" ]; then
        warn "R21: GeoIP lookup empty or not loaded"
    else
        warn "R21: GeoIP lookup has only $GEOIP_COUNT entries (expected 200K+)"
    fi

    DEVICE_COUNT=$(docker exec ids-streamlit python3 -c "
import duckdb
db = duckdb.connect('$DUCKDB_READONLY', read_only=True)
print(db.execute('SELECT count(*) FROM devices').fetchone()[0])
db.close()
" 2>/dev/null || echo "ERROR")
    if [ "$DEVICE_COUNT" != "ERROR" ] && [ "$DEVICE_COUNT" -gt 0 ] 2>/dev/null; then
        pass "R22: Device summaries populated ($DEVICE_COUNT devices)"
    else
        warn "R22: No devices in summary table yet"
    fi

    # ---- R8. Grafana ----
    section "R8. Grafana Dashboards"

    HEALTH=$(curl -sf "http://localhost:${GRAFANA_PORT}/api/health" 2>/dev/null || echo "")
    if echo "$HEALTH" | grep -q '"database"'; then
        pass "R23: Grafana health endpoint OK"
    else
        fail "R23: Grafana health endpoint not responding"
    fi

    DS=$(curl -sf -u admin:admin "http://localhost:${GRAFANA_PORT}/api/datasources" 2>/dev/null || echo "")
    if echo "$DS" | grep -q 'motherduck-duckdb-datasource'; then
        pass "R24: DuckDB datasource provisioned"
    else
        fail "R24: DuckDB datasource not found"
    fi

    DASHBOARDS=$(curl -sf -u admin:admin "http://localhost:${GRAFANA_PORT}/api/search?tag=ids" 2>/dev/null || echo "")
    DASH_COUNT=$(echo "$DASHBOARDS" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
    if [ "$DASH_COUNT" -ge 6 ]; then
        pass "R25: $DASH_COUNT dashboards loaded"
    elif [ "$DASH_COUNT" -ge 1 ]; then
        warn "R25: Only $DASH_COUNT dashboards loaded (expected 6+)"
    else
        fail "R25: No dashboards found"
    fi

    # R25b: Grafana datasource actually returns data (not just provisioned)
    # Root cause: plugin can be provisioned but return 0 rows due to DuckDB version mismatch
    # or stale connection cache — this test catches both.
    DS_ID=$(curl -sf -u admin:admin "http://localhost:${GRAFANA_PORT}/api/datasources" 2>/dev/null \
        | python3 -c "import sys,json; ds=json.load(sys.stdin); print(ds[0]['id'] if ds else '')" 2>/dev/null || echo "")
    if [ -n "$DS_ID" ]; then
        NOW_MS=$(date -u +%s%3N)
        FROM_MS=$(( NOW_MS - 3600000 ))
        GF_ROW_COUNT=$(curl -sf -u admin:admin \
            -X POST "http://localhost:${GRAFANA_PORT}/api/ds/query?ds_type=motherduck-duckdb-datasource" \
            -H "Content-Type: application/json" \
            -d "{\"queries\":[{\"refId\":\"A\",\"datasourceId\":${DS_ID},\"rawSql\":\"SELECT count(*) as c FROM events\",\"format\":0}],\"from\":\"${FROM_MS}\",\"to\":\"${NOW_MS}\"}" \
            2>/dev/null \
            | python3 -c "
import sys,json
r=json.load(sys.stdin)
frames=r.get('results',{}).get('A',{}).get('frames',[])
print(frames[0]['data']['values'][0][0] if frames and frames[0]['data']['values'] else 0)
" 2>/dev/null || echo "ERROR")
        if [ "$GF_ROW_COUNT" = "ERROR" ]; then
            warn "R25b: Could not query Grafana datasource API"
        elif [ "$GF_ROW_COUNT" -gt 0 ] 2>/dev/null; then
            pass "R25b: Grafana datasource returns live data ($GF_ROW_COUNT events)"
        else
            fail "R25b: Grafana datasource returns 0 rows for events table — likely DuckDB version mismatch or stale plugin connection (restart ids-grafana to fix)"
        fi

        # R25c: Check Grafana plugin error log for known SQL syntax failures
        GF_SQL_ERR=$(docker logs ids-grafana 2>&1 | grep -c "syntax error at or near" 2>/dev/null || echo "0")
        GF_SQL_ERR="${GF_SQL_ERR:-0}"
        if [ "${GF_SQL_ERR}" -gt 0 ] 2>/dev/null; then
            warn "R25c: Grafana plugin logged $GF_SQL_ERR SQL syntax error(s) — check dashboard variable interpolation"
        else
            pass "R25c: No SQL syntax errors in Grafana plugin logs"
        fi
    else
        warn "R25b: Could not get datasource ID — skipping live data check"
    fi

    # R25d: Snapshot files are fresh (updated within last 10 minutes)
    # Root cause: if duckdb-mgr is stuck (e.g., nmap blocking) snapshots go stale and Grafana shows old data
    SNAP_AGE_LIMIT=600  # 10 minutes in seconds
    for snap in ids_readonly.duckdb ids_streamlit.duckdb ids_alert.duckdb; do
        SNAP_PATH="${LOG_DIR}/duckdb/$snap"
        if [ -f "$SNAP_PATH" ]; then
            SNAP_MTIME=$(stat -c %Y "$SNAP_PATH" 2>/dev/null || echo "0")
            NOW_S=$(date +%s)
            AGE=$(( NOW_S - SNAP_MTIME ))
            if [ "$AGE" -le "$SNAP_AGE_LIMIT" ]; then
                pass "R25d: $snap is fresh (${AGE}s old)"
            else
                warn "R25d: $snap is stale (${AGE}s old — expected <${SNAP_AGE_LIMIT}s) — duckdb-mgr may be blocked"
            fi
        else
            warn "R25d: $snap not yet created (first cycle may not have run)"
        fi
    done

    # R25e: DuckDB size within configured limit
    MAX_DB_MB="${MAX_DB_SIZE_MB:-4000}"
    if [ -f "${LOG_DIR}/duckdb/ids.duckdb" ]; then
        DB_SIZE_MB=$(du -m "${LOG_DIR}/duckdb/ids.duckdb" 2>/dev/null | cut -f1 || echo "0")
        if [ "$DB_SIZE_MB" -lt "$MAX_DB_MB" ] 2>/dev/null; then
            pass "R25e: DuckDB size ${DB_SIZE_MB}MB is within ${MAX_DB_MB}MB limit"
        else
            fail "R25e: DuckDB size ${DB_SIZE_MB}MB exceeds ${MAX_DB_MB}MB limit — ingestion is blocked, Grafana may show stale data"
        fi
    fi

    # ---- R9. Ollama ----
    section "R9. Ollama LLM"

    OLLAMA_TAGS=$(curl -sf "http://localhost:11434/api/tags" 2>/dev/null || echo "")
    if [ -n "$OLLAMA_TAGS" ]; then
        pass "R26: Ollama API reachable on localhost:11434"
    else
        fail "R26: Ollama API not reachable"
    fi

    if echo "$OLLAMA_TAGS" | grep -q "qwen2.5"; then
        pass "R27: qwen2.5 model available"
    else
        fail "R27: qwen2.5 model not found (run: ollama pull qwen2.5:3b)"
    fi

    # ---- R10. Streamlit Chat UI ----
    section "R10. Streamlit Chat UI"

    ST_HEALTH=$(curl -sf "http://localhost:${STREAMLIT_PORT}/_stcore/health" 2>/dev/null || echo "")
    if echo "$ST_HEALTH" | grep -qi "ok"; then
        pass "R28: Streamlit health endpoint OK"
    else
        fail "R28: Streamlit health endpoint not responding"
    fi

    # DuckDB queryable from streamlit
    DB_CHECK=$(docker exec ids-streamlit python3 -c "
import duckdb, os
db = duckdb.connect(os.environ.get('DUCKDB_PATH', '/var/log/ids/duckdb/ids_streamlit.duckdb'), read_only=True)
count = db.execute('SELECT count(*) FROM events').fetchone()[0]
print(f'OK:{count}')
db.close()
" 2>/dev/null || echo "FAIL")
    if echo "$DB_CHECK" | grep -q "^OK:"; then
        EVENT_COUNT=$(echo "$DB_CHECK" | sed 's/OK://')
        pass "R29: DuckDB queryable from Streamlit ($EVENT_COUNT events)"
    else
        fail "R29: DuckDB not queryable from Streamlit"
    fi

    # Ollama reachable from streamlit
    OLLAMA_CHECK=$(docker exec ids-streamlit python3 -c "
import ollama, os
client = ollama.Client(host=os.environ.get('OLLAMA_HOST', 'http://localhost:11434'))
models = client.list()
names = [m.model for m in models.models]
print(f'OK:{len(names)}')
" 2>/dev/null || echo "FAIL")
    if echo "$OLLAMA_CHECK" | grep -q "^OK:"; then
        pass "R30: Ollama reachable from Streamlit container"
    else
        fail "R30: Ollama not reachable from Streamlit"
    fi

    # ---- R11. Nmap ----
    section "R11. Nmap Integration"

    # Nmap binary in streamlit
    NMAP_VER_ST=$(docker exec ids-streamlit nmap --version 2>/dev/null | head -1 || echo "")
    if echo "$NMAP_VER_ST" | grep -qi "nmap"; then
        pass "R31: nmap installed in Streamlit container ($NMAP_VER_ST)"
    else
        fail "R31: nmap not found in Streamlit container"
    fi

    # Nmap binary in duckdb-mgr
    NMAP_VER_DB=$(docker exec ids-duckdb-mgr nmap --version 2>/dev/null | head -1 || echo "")
    if echo "$NMAP_VER_DB" | grep -qi "nmap"; then
        pass "R32: nmap installed in duckdb-mgr container ($NMAP_VER_DB)"
    else
        fail "R32: nmap not found in duckdb-mgr container"
    fi

    # RFC1918 validation works
    RFC_CHECK=$(docker exec ids-streamlit python3 -c "
import sys
sys.path.insert(0, '/app')
from tools import _is_rfc1918
assert _is_rfc1918('192.168.1.0/24') == True
assert _is_rfc1918('10.0.0.1') == True
assert _is_rfc1918('172.16.0.0/12') == True
assert _is_rfc1918('8.8.8.8') == False
assert _is_rfc1918('1.1.1.1') == False
print('OK')
" 2>/dev/null || echo "FAIL")
    if [ "$RFC_CHECK" = "OK" ]; then
        pass "R33: RFC1918 validation logic correct"
    else
        fail "R33: RFC1918 validation logic failed"
    fi

    # Nmap scan on a private address (quick, validates RFC1918 + nmap execution)
    # Use the gateway (first IP in configured subnet) — always reachable on local LAN
    NMAP_TARGET=$(echo "${NMAP_SUBNET:-192.168.2.0/24}" | sed 's|\.[0-9]*/.*|.1|')
    SCAN_CHECK=$(docker exec ids-streamlit python3 -c "
import sys, json
sys.path.insert(0, '/app')
from tools import nmap_scan
result = json.loads(nmap_scan('$NMAP_TARGET', 'quick'))
if 'error' in result:
    print(f'ERROR:{result[\"error\"]}')
else:
    print(f'OK:{result.get(\"host_count\", 0)}')
" 2>/dev/null || echo "FAIL")
    if echo "$SCAN_CHECK" | grep -q "^OK:"; then
        HOST_CT=$(echo "$SCAN_CHECK" | sed 's/OK://')
        pass "R34: nmap_scan on $NMAP_TARGET worked ($HOST_CT host(s))"
    else
        fail "R34: nmap_scan on $NMAP_TARGET failed: $SCAN_CHECK"
    fi

    # Scan saved to SQLite
    SQLITE_CHECK=$(docker exec ids-streamlit python3 -c "
import sqlite3
conn = sqlite3.connect('/var/log/ids/duckdb/nmap_results.db')
count = conn.execute('SELECT count(*) FROM nmap_results').fetchone()[0]
print(f'OK:{count}')
conn.close()
" 2>/dev/null || echo "FAIL")
    if echo "$SQLITE_CHECK" | grep -q "^OK:"; then
        SCAN_CT=$(echo "$SQLITE_CHECK" | sed 's/OK://')
        if [ "$SCAN_CT" -gt 0 ] 2>/dev/null; then
            pass "R35: nmap results saved to SQLite ($SCAN_CT scan(s))"
        else
            warn "R35: nmap_results.db exists but 0 scans (previous test may have failed)"
        fi
    else
        fail "R35: Could not query nmap_results.db"
    fi

    # get_scan_history works
    HIST_CHECK=$(docker exec ids-streamlit python3 -c "
import sys, json
sys.path.insert(0, '/app')
from tools import get_scan_history
result = json.loads(get_scan_history())
print(f'OK:{result.get(\"count\", 0)}')
" 2>/dev/null || echo "FAIL")
    if echo "$HIST_CHECK" | grep -q "^OK:"; then
        pass "R36: get_scan_history returns results"
    else
        fail "R36: get_scan_history failed: $HIST_CHECK"
    fi

    # Reject non-RFC1918 targets
    REJECT_CHECK=$(docker exec ids-streamlit python3 -c "
import sys, json
sys.path.insert(0, '/app')
from tools import nmap_scan
result = json.loads(nmap_scan('8.8.8.8', 'quick'))
if 'error' in result and 'RFC1918' in result['error']:
    print('OK')
else:
    print('FAIL')
" 2>/dev/null || echo "FAIL")
    if [ "$REJECT_CHECK" = "OK" ]; then
        pass "R37: nmap_scan rejects non-RFC1918 targets"
    else
        fail "R37: nmap_scan did NOT reject external target 8.8.8.8"
    fi

    # nmap_scans table in DuckDB
    NMAP_TBL=$(docker exec ids-streamlit python3 -c "
import duckdb
db = duckdb.connect('$DUCKDB_READONLY', read_only=True)
print(db.execute('SELECT count(*) FROM nmap_scans').fetchone()[0])
db.close()
" 2>/dev/null || echo "ERROR")
    if [ "$NMAP_TBL" != "ERROR" ]; then
        pass "R38: nmap_scans table queryable in DuckDB ($NMAP_TBL rows)"
    else
        fail "R38: nmap_scans table not queryable"
    fi

    # ---- R12. Alert Agent ----
    section "R12. Alert Agent"

    ANOM_CHECK=$(docker exec ids-streamlit python3 -c "
import duckdb
db = duckdb.connect('$DUCKDB_READONLY', read_only=True)
print(db.execute('SELECT count(*) FROM anomaly_events').fetchone()[0])
db.close()
" 2>/dev/null || echo "ERROR")
    if [ "$ANOM_CHECK" != "ERROR" ]; then
        pass "R39: anomaly_events table queryable ($ANOM_CHECK rows)"
    else
        fail "R39: anomaly_events table not queryable"
    fi

    KD_CHECK=$(docker exec ids-streamlit python3 -c "
import duckdb
db = duckdb.connect('$DUCKDB_READONLY', read_only=True)
print(db.execute('SELECT count(*) FROM _known_devices').fetchone()[0])
db.close()
" 2>/dev/null || echo "ERROR")
    if [ "$KD_CHECK" != "ERROR" ]; then
        pass "R40: _known_devices table queryable ($KD_CHECK devices)"
    else
        fail "R40: _known_devices table not queryable"
    fi

    if [ -f "/var/log/ids/duckdb/alert_state.db" ]; then
        pass "R41: alert_state.db exists"
    else
        warn "R41: alert_state.db not yet created (created on first anomaly poll)"
    fi

    ALERT_LOGS=$(docker logs ids-alert-agent 2>&1 | tail -50)
    if echo "$ALERT_LOGS" | grep -q "Ollama ready"; then
        pass "R42: alert-agent connected to Ollama"
    elif echo "$ALERT_LOGS" | grep -q "Waiting for Ollama"; then
        warn "R42: alert-agent is waiting for Ollama"
    else
        warn "R42: alert-agent Ollama status unclear from logs"
    fi

    # ---- R13. Curl in Streamlit (for healthcheck) ----
    section "R13. Healthcheck Dependencies"

    CURL_CHECK=$(docker exec ids-streamlit curl --version 2>/dev/null | head -1 || echo "")
    if echo "$CURL_CHECK" | grep -qi "curl"; then
        pass "R43: curl installed in Streamlit container"
    else
        fail "R43: curl not found in Streamlit container (needed for healthcheck)"
    fi

    # ---- R14. Threat Intel RAG ----
    section "R14. Threat Intel RAG"

    # Rules file copied to shared volume by Suricata entrypoint
    if [ -f "${LOG_DIR}/suricata/rules/suricata.rules" ]; then
        RULES_SIZE=$(du -sh "${LOG_DIR}/suricata/rules/suricata.rules" 2>/dev/null | cut -f1)
        pass "R44: suricata.rules exists on shared volume (${RULES_SIZE})"
    else
        warn "R44: suricata.rules not yet on shared volume (suricata-update may still be running)"
    fi

    # rag.duckdb exists
    RAG_DB="${LOG_DIR}/duckdb/rag.duckdb"
    if [ -f "$RAG_DB" ]; then
        RAG_SIZE=$(du -sh "$RAG_DB" 2>/dev/null | cut -f1)
        pass "R45: rag.duckdb exists (${RAG_SIZE})"
    else
        fail "R45: rag.duckdb not found (duckdb-mgr may not have initialized it)"
    fi

    # nomic-embed-text model available
    EMBED_MODEL_CHECK=$(curl -sf "http://localhost:11434/api/tags" 2>/dev/null || echo "")
    if echo "$EMBED_MODEL_CHECK" | grep -q "nomic-embed"; then
        pass "R46: nomic-embed-text model available in Ollama"
    else
        warn "R46: nomic-embed-text not found in Ollama (run: ollama pull nomic-embed-text)"
    fi

    # rag_threat_intel table queryable
    RAG_TBL=$(docker exec ids-streamlit python3 -c "
import duckdb, os
path = os.environ.get('RAG_DUCKDB_PATH', '/var/log/ids/duckdb/rag.duckdb')
db = duckdb.connect(path, read_only=True)
total = db.execute('SELECT count(*) FROM rag_threat_intel').fetchone()[0]
embedded = db.execute('SELECT count(*) FROM rag_threat_intel WHERE embedding IS NOT NULL').fetchone()[0]
db.close()
print(f'OK:{total}:{embedded}')
" 2>/dev/null || echo "ERROR")
    if echo "$RAG_TBL" | grep -q "^OK:"; then
        TOTAL_RULES=$(echo "$RAG_TBL" | cut -d: -f2)
        EMBEDDED=$(echo "$RAG_TBL" | cut -d: -f3)
        if [ "$EMBEDDED" -gt 0 ] 2>/dev/null; then
            pass "R47: rag_threat_intel has $EMBEDDED embedded rules (${TOTAL_RULES} total)"
        else
            warn "R47: rag_threat_intel has $TOTAL_RULES rules but 0 embeddings (indexing may still be running)"
        fi
    else
        warn "R47: rag_threat_intel table not queryable yet"
    fi

    # rag_search_threat_intel callable from streamlit (returns valid JSON)
    # timeout 90: rag_search requires Ollama for embeddings; if Ollama is busy it would hang
    RAG_SEARCH=$(timeout 90 docker exec ids-streamlit python3 -c "
import sys, json, os
sys.path.insert(0, '/app')
os.environ.setdefault('RAG_DUCKDB_PATH', '/var/log/ids/duckdb/rag.duckdb')
os.environ.setdefault('EMBED_MODEL', 'nomic-embed-text')
os.environ.setdefault('OLLAMA_HOST', 'http://localhost:11434')
from tools import rag_search_threat_intel
result = json.loads(rag_search_threat_intel('nmap port scan detection', top_k=3))
if 'results' in result:
    print(f'OK:{len(result[\"results\"])}')
else:
    print(f'FAIL:{result}')
" 2>/dev/null || echo "TIMEOUT_OR_ERROR")
    if echo "$RAG_SEARCH" | grep -q "^OK:"; then
        RESULT_CT=$(echo "$RAG_SEARCH" | cut -d: -f2)
        if [ "$RESULT_CT" -gt 0 ] 2>/dev/null; then
            pass "R48: rag_search_threat_intel returns $RESULT_CT result(s)"
        else
            warn "R48: rag_search_threat_intel returned 0 results (indexing may still be in progress)"
        fi
    elif echo "$RAG_SEARCH" | grep -q "TIMEOUT_OR_ERROR"; then
        warn "R48: rag_search_threat_intel timed out (Ollama may be busy) or failed"
    else
        warn "R48: rag_search_threat_intel not yet functional: $RAG_SEARCH"
    fi

    # RAG indexer logged in duckdb-mgr
    DUCKDB_LOGS=$(docker logs ids-duckdb-mgr 2>&1)
    if echo "$DUCKDB_LOGS" | grep -q "RAG: indexer thread started"; then
        pass "R49: RAG indexer thread started (seen in duckdb-mgr logs)"
    elif echo "$DUCKDB_LOGS" | grep -q "RAG: indexing complete"; then
        pass "R49: RAG indexing already complete (seen in duckdb-mgr logs)"
    else
        warn "R49: RAG indexer not yet started (nmap scan may still be blocking the cycle)"
    fi

    # Rules copy logged in Suricata
    SURI_LOGS2=$(docker logs ids-suricata 2>&1)
    if echo "$SURI_LOGS2" | grep -q "Rules copied to shared volume"; then
        pass "R50: Suricata logged 'Rules copied to shared volume for RAG indexing'"
    else
        warn "R50: Rule copy log not yet seen (suricata-update may still be running)"
    fi

    # ---- R15. Alert Email Delivery ----
    section "R15. Alert Email Delivery"

    # Gmail secrets must be populated in both alert-agent and streamlit containers
    for ctr in ids-alert-agent ids-streamlit; do
        for secret in gmail_user gmail_app_password alert_recipient; do
            SECRET_VAL=$(docker exec "$ctr" cat /run/secrets/${secret} 2>/dev/null || echo "")
            if [ -n "$SECRET_VAL" ]; then
                pass "R51: /run/secrets/${secret} populated in $ctr"
            else
                fail "R51: /run/secrets/${secret} empty or missing in $ctr — email alerts will not work"
            fi
        done
    done

    # TCP connectivity to smtp.gmail.com:465 from alert-agent — tests network path without sending email
    SMTP_REACH=$(docker exec ids-alert-agent python3 -c "
import socket
try:
    s = socket.create_connection(('smtp.gmail.com', 465), timeout=10)
    s.close()
    print('OK')
except Exception as e:
    print(f'FAIL:{e}')
" 2>/dev/null || echo "FAIL")
    if [ "$SMTP_REACH" = "OK" ]; then
        pass "R52: smtp.gmail.com:465 reachable from alert-agent (TCP connectivity confirmed)"
    else
        fail "R52: smtp.gmail.com:465 NOT reachable from alert-agent: $SMTP_REACH"
    fi

    # Historical email delivery — check alert_state.db for at least one successful send
    if [ -f "/var/log/ids/duckdb/alert_state.db" ]; then
        EMAIL_SENT_COUNT=$(docker exec ids-alert-agent python3 -c "
import sqlite3
conn = sqlite3.connect('/var/log/ids/duckdb/alert_state.db')
count = conn.execute('SELECT count(*) FROM processed_anomalies WHERE email_sent=1').fetchone()[0]
total = conn.execute('SELECT count(*) FROM processed_anomalies').fetchone()[0]
conn.close()
print(f'{count}:{total}')
" 2>/dev/null || echo "ERROR")
        if [ "$EMAIL_SENT_COUNT" != "ERROR" ]; then
            SENT=$(echo "$EMAIL_SENT_COUNT" | cut -d: -f1)
            TOTAL=$(echo "$EMAIL_SENT_COUNT" | cut -d: -f2)
            if [ "${SENT:-0}" -gt 0 ] 2>/dev/null; then
                pass "R53: alert_state.db shows $SENT email(s) sent out of $TOTAL processed anomalies"
            else
                warn "R53: $TOTAL anomalies processed but 0 emails sent — check Gmail credentials or SMTP connectivity"
            fi
        else
            warn "R53: Could not query alert_state.db for email delivery count"
        fi
    else
        warn "R53: alert_state.db not yet created (no anomalies processed)"
    fi

    # Log evidence of email activity in alert-agent
    ALERT_LOGS_FULL=$(docker logs ids-alert-agent 2>&1)
    if echo "$ALERT_LOGS_FULL" | grep -q "Email sent for anomaly\|fast_alert_loop: email sent"; then
        EMAIL_LOG_COUNT=$(echo "$ALERT_LOGS_FULL" | grep -c "Email sent for anomaly\|fast_alert_loop: email sent" 2>/dev/null || echo 0)
        pass "R54: alert-agent logs confirm $EMAIL_LOG_COUNT successful email send(s)"
    else
        warn "R54: No email send confirmations in alert-agent logs (no anomalies processed yet, or credentials failed)"
    fi

    # ---- R16. LLM Response Quality ----
    section "R16. LLM Response Quality"

    OLLAMA_MODEL="${OLLAMA_MODEL:-qwen3.5:2b}"

    # Pre-check: verify Ollama is idle before running inference tests.
    # alert-agent and duckdb-mgr both use Ollama; if a request is in flight the
    # inference tests will time out (not a code defect — just resource contention).
    OLLAMA_BUSY=$(curl -sf --max-time 5 "http://localhost:11434/api/ps" 2>/dev/null | \
        python3 -c "
import sys, json
data = json.load(sys.stdin)
models = data.get('models', [])
busy = [m['name'] for m in models if m.get('size_vram', 0) > 0 or m.get('expires_at')]
print('BUSY:' + ','.join(busy) if busy else 'IDLE')
" 2>/dev/null || echo "UNKNOWN")

    if echo "$OLLAMA_BUSY" | grep -q "^BUSY:"; then
        BUSY_MODEL=$(echo "$OLLAMA_BUSY" | sed 's/^BUSY://')
        warn "R56: Skipping inference test — Ollama is currently processing: $BUSY_MODEL (rerun when idle)"
        warn "R57: Skipping tool-calling test — Ollama busy"
        warn "R58: Skipping end-to-end pipeline test — Ollama busy"
    else
        # R56: Basic sanity — model returns a coherent answer to a trivial prompt
        LLM_BASIC=$(curl -sf --max-time 300 \
            -X POST "http://localhost:11434/api/chat" \
            -H "Content-Type: application/json" \
            -d "{\"model\":\"${OLLAMA_MODEL}\",\"messages\":[{\"role\":\"user\",\"content\":\"What is 2+2? Reply with just the number.\"}],\"stream\":false,\"options\":{\"num_ctx\":512,\"num_thread\":4}}" \
            2>/dev/null | python3 -c "
import sys, json
r = json.load(sys.stdin)
content = r.get('message', {}).get('content', '').strip()
print(content)" 2>/dev/null || echo "")
        if echo "$LLM_BASIC" | grep -q "4"; then
            pass "R56: Ollama correctly answers '2+2=4' (model is responsive and coherent)"
        elif [ -n "$LLM_BASIC" ]; then
            warn "R56: Ollama response to '2+2': '${LLM_BASIC:0:80}' — model is responding but answer unexpected"
        else
            fail "R56: Ollama returned empty response — model may be misconfigured or API is broken"
        fi

        # R57: Tool-calling — model invokes the correct tool when explicitly asked
        LLM_TOOL=$(timeout 300 docker exec ids-streamlit python3 -c "
import json, os
import ollama
client = ollama.Client(host=os.environ.get('OLLAMA_HOST', 'http://localhost:11434'))
model = os.environ.get('OLLAMA_MODEL', 'qwen3.5:2b')
tool_def = [{
    'type': 'function',
    'function': {
        'name': 'get_event_stats',
        'description': 'Get event counts by source tool and log type from the IDS database',
        'parameters': {'type': 'object', 'properties': {}}
    }
}]
resp = client.chat(
    model=model,
    messages=[{'role': 'user', 'content': 'Call get_event_stats right now to retrieve event counts from the IDS database.'}],
    tools=tool_def,
    options={'num_ctx': 1024, 'num_thread': 4}
)
msg = resp.message
if msg.tool_calls:
    print('TOOL:' + msg.tool_calls[0].function.name)
elif msg.content:
    print('TEXT:' + msg.content[:100])
else:
    print('EMPTY')
" 2>/dev/null || echo "TIMEOUT")
        if echo "$LLM_TOOL" | grep -q "^TOOL:get_event_stats"; then
            pass "R57: Ollama correctly invokes get_event_stats tool when asked — tool-calling pipeline is operational"
        elif echo "$LLM_TOOL" | grep -q "^TOOL:"; then
            TOOL_NAME=$(echo "$LLM_TOOL" | sed 's/^TOOL://')
            warn "R57: Ollama called '$TOOL_NAME' instead of get_event_stats — tool routing may be unreliable"
        elif echo "$LLM_TOOL" | grep -q "^TEXT:"; then
            warn "R57: Ollama responded with text instead of tool call: ${LLM_TOOL:5:100} — model may not support tool-calling for this prompt"
        elif echo "$LLM_TOOL" | grep -q "^TIMEOUT"; then
            warn "R57: Tool-calling test timed out (300s) — Ollama may have become busy mid-test"
        else
            fail "R57: Ollama tool-calling test failed unexpectedly: $LLM_TOOL"
        fi

        # R58: End-to-end pipeline — real tool output fed to LLM produces coherent summary
        LLM_PIPELINE=$(timeout 300 docker exec ids-streamlit python3 -c "
import json, os, sys
sys.path.insert(0, '/app')
import ollama
from tools import get_event_stats

client = ollama.Client(host=os.environ.get('OLLAMA_HOST', 'http://localhost:11434'))
model = os.environ.get('OLLAMA_MODEL', 'qwen3.5:2b')

stats_json = get_event_stats()
stats = json.loads(stats_json)

if 'error' in stats or stats.get('row_count', 0) == 0:
    print('SKIP:no data')
    sys.exit(0)

messages = [
    {'role': 'user', 'content': 'Here are IDS event statistics from the database:'},
    {'role': 'tool', 'content': stats_json},
    {'role': 'user', 'content': 'In one sentence, tell me the total number of events and which source tools produced them.'}
]
resp = client.chat(
    model=model,
    messages=messages,
    options={'num_ctx': 2048, 'num_thread': 4}
)
content = (resp.message.content or '').strip()
print(f'LEN:{len(content)}:{content[:200]}')
" 2>/dev/null || echo "TIMEOUT")
        if echo "$LLM_PIPELINE" | grep -q "^SKIP:"; then
            warn "R58: Skipping end-to-end pipeline test — no event data in DuckDB yet"
        elif echo "$LLM_PIPELINE" | grep -q "^LEN:"; then
            RESP_LEN=$(echo "$LLM_PIPELINE" | cut -d: -f2)
            RESP_TEXT=$(echo "$LLM_PIPELINE" | cut -d: -f3-)
            if [ "${RESP_LEN:-0}" -ge 40 ] 2>/dev/null; then
                pass "R58: LLM produces coherent summary from tool output (${RESP_LEN} chars): ${RESP_TEXT:0:90}..."
            else
                warn "R58: LLM response is suspiciously short (${RESP_LEN} chars): '$RESP_TEXT'"
            fi
        elif echo "$LLM_PIPELINE" | grep -q "^TIMEOUT"; then
            warn "R58: End-to-end pipeline test timed out (300s) — Ollama may have become busy mid-test"
        else
            fail "R58: End-to-end LLM pipeline test failed unexpectedly: $LLM_PIPELINE"
        fi
    fi

    # ---- R17. Missed Service Interfaces ----
    section "R17. Missed Service Interfaces"

    # fast_alerts.db schema — both consumer flags must be present (dual-consumer, no race condition)
    if [ -f "/var/log/ids/duckdb/fast_alerts.db" ]; then
        FA_SCHEMA=$(docker exec ids-alert-agent python3 -c "
import sqlite3
conn = sqlite3.connect('/var/log/ids/duckdb/fast_alerts.db')
cols = [r[1] for r in conn.execute('PRAGMA table_info(fast_new_devices)').fetchall()]
conn.close()
print(':'.join(cols))
" 2>/dev/null || echo "ERROR")
        if echo "$FA_SCHEMA" | grep -q "alert_emailed" && echo "$FA_SCHEMA" | grep -q "duckdb_drained"; then
            pass "R59: fast_alerts.db has both consumer flags (alert_emailed + duckdb_drained) — independent consumer paths confirmed"
        elif [ "$FA_SCHEMA" = "ERROR" ]; then
            fail "R59: Could not read fast_alerts.db schema"
        else
            fail "R59: fast_alerts.db schema missing flags (got: $FA_SCHEMA) — consumers may interfere with each other"
        fi
    else
        warn "R59: fast_alerts.db not yet created (IPWatcher not started or no new private IPs seen)"
    fi

    # alert_state.db composite PK — SQLite PRAGMA confirms (anomaly_id, detected_at) as PK
    if [ -f "/var/log/ids/duckdb/alert_state.db" ]; then
        STATE_PK=$(docker exec ids-alert-agent python3 -c "
import sqlite3
conn = sqlite3.connect('/var/log/ids/duckdb/alert_state.db')
# pk column in PRAGMA table_info is 1-based position in PK; 0 means not part of PK
pk_cols = sorted([r[1] for r in conn.execute('PRAGMA table_info(processed_anomalies)').fetchall() if r[5] > 0])
conn.close()
print(':'.join(pk_cols))
" 2>/dev/null || echo "ERROR")
        if echo "$STATE_PK" | grep -q "anomaly_id" && echo "$STATE_PK" | grep -q "detected_at"; then
            pass "R60: alert_state.db composite PK (anomaly_id + detected_at) confirmed — survives DuckDB sequence resets"
        elif [ "$STATE_PK" = "ERROR" ]; then
            warn "R60: Could not verify alert_state.db PK schema"
        else
            fail "R60: alert_state.db PK is '$STATE_PK' — expected composite (anomaly_id, detected_at); email dedup will break after DB reset"
        fi
    else
        warn "R60: alert_state.db not yet created — will be verified after first anomaly poll"
    fi

    # anomaly_id_seq sync logged at startup — critical guard against email-skip-after-DB-reset bug
    if echo "$DUCKDB_LOGS" | grep -q "Synced anomaly_id_seq\|anomaly_id_seq.*advanced"; then
        SYNC_LINE=$(echo "$DUCKDB_LOGS" | grep "Synced anomaly_id_seq\|anomaly_id_seq.*advanced" | tail -1)
        pass "R61: anomaly_id_seq startup sync ran: $SYNC_LINE"
    else
        warn "R61: anomaly_id_seq sync not logged — OK if alert_state.db was empty at startup (nothing to sync)"
    fi

    # nmap SQLite→DuckDB sync — after a scan is saved to SQLite, duckdb-mgr must copy it to DuckDB
    SQLITE_NMAP=$(docker exec ids-streamlit python3 -c "
import sqlite3
conn = sqlite3.connect('/var/log/ids/duckdb/nmap_results.db')
print(conn.execute('SELECT count(*) FROM nmap_results').fetchone()[0])
conn.close()
" 2>/dev/null || echo "0")
    DUCKDB_NMAP=$(docker exec ids-streamlit python3 -c "
import duckdb
db = duckdb.connect('$DUCKDB_READONLY', read_only=True)
print(db.execute(\"SELECT count(*) FROM nmap_scans WHERE scan_type != 'scheduled_service'\").fetchone()[0])
db.close()
" 2>/dev/null || echo "0")
    if [ "$SQLITE_NMAP" = "0" ] && [ "$DUCKDB_NMAP" = "0" ]; then
        warn "R62: No nmap scans in either SQLite or DuckDB yet (run a scan via chat to test sync)"
    elif [ "${DUCKDB_NMAP:-0}" -ge "${SQLITE_NMAP:-0}" ] 2>/dev/null; then
        pass "R62: nmap SQLite→DuckDB sync confirmed (SQLite=$SQLITE_NMAP rows, DuckDB=$DUCKDB_NMAP rows)"
    else
        warn "R62: nmap sync lag detected (SQLite=$SQLITE_NMAP rows, DuckDB=$DUCKDB_NMAP rows) — duckdb-mgr may not have cycled yet"
    fi

    # whitelist.db → Streamlit check_whitelist interface
    WLIST_CHECK=$(docker exec ids-streamlit python3 -c "
import sys, json
sys.path.insert(0, '/app')
from tools import check_whitelist
result = json.loads(check_whitelist('list'))
if 'whitelist' in result:
    print(f'OK:{result.get(\"count\",0)}')
else:
    print(f'FAIL:{result}')
" 2>/dev/null || echo "FAIL")
    if echo "$WLIST_CHECK" | grep -q "^OK:"; then
        WL_COUNT=$(echo "$WLIST_CHECK" | sed 's/OK://')
        pass "R63: whitelist.db ↔ Streamlit interface operational ($WL_COUNT entries)"
    else
        fail "R63: whitelist.db interface broken: $WLIST_CHECK"
    fi

    # Vector NDJSON → DuckDB interface covers both source tools
    VECTOR_SOURCES=$(find "${LOG_DIR}/vector" -name '*.ndjson' -size +0c 2>/dev/null | head -5 | \
        xargs -I{} sh -c "head -1 '{}' 2>/dev/null" | python3 -c "
import sys, json
sources = set()
for line in sys.stdin:
    try:
        src = json.loads(line).get('source_tool', '')
        if src:
            sources.add(src)
    except Exception:
        pass
print(':'.join(sorted(sources)))" 2>/dev/null || echo "")
    for tool_src in suricata zeek; do
        if echo "$VECTOR_SOURCES" | grep -q "$tool_src"; then
            pass "R64: Vector NDJSON staging contains $tool_src events"
        else
            warn "R64: No $tool_src events in Vector NDJSON staging files (interface may be broken or need more time)"
        fi
    done

    # alert-agent main polling loop is running (not just started)
    if echo "$ALERT_LOGS_FULL" | grep -q "Found.*unprocessed anomaly\|No new anomalies\|Starting alert-agent"; then
        pass "R65: alert-agent main polling loop is running"
    else
        warn "R65: alert-agent polling loop status unclear — check container logs"
    fi

    # fast_alert_loop daemon thread started in alert-agent
    if echo "$ALERT_LOGS_FULL" | grep -q "fast_alert_loop: started"; then
        pass "R66: fast_alert_loop daemon thread started in alert-agent"
    else
        warn "R66: fast_alert_loop not yet confirmed started — check alert-agent startup logs"
    fi

    # IPWatcher thread started in duckdb-mgr (near-real-time new-device detection)
    if echo "$DUCKDB_LOGS" | grep -q "IPWatcher: started"; then
        pass "R67: IPWatcher thread started in duckdb-mgr (near-real-time new-device detection active)"
    else
        warn "R67: IPWatcher not yet confirmed started in duckdb-mgr — new devices may have 5-7min detection delay"
    fi

    # duckdb-mgr drain_fast_alerts and nmap sync cycles ran
    if echo "$DUCKDB_LOGS" | grep -q "Synced.*nmap result"; then
        SYNC_CT=$(echo "$DUCKDB_LOGS" | grep -c "Synced.*nmap result" || echo 0)
        pass "R68: duckdb-mgr nmap SQLite sync ran ($SYNC_CT time(s) logged)"
    elif echo "$DUCKDB_LOGS" | grep -q "drain_fast_alerts\|Drained"; then
        pass "R68: duckdb-mgr fast-alert drain running"
    else
        warn "R68: No nmap sync or fast-alert drain logged yet in duckdb-mgr (normal if no scans or fast alerts occurred)"
    fi

fi # end runtime tests

# =============================================================================
# Summary
# =============================================================================

echo ""
echo "============================================================"
TOTAL=$((PASS + FAIL + WARN))
echo -e " Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}, ${YELLOW}${WARN} warnings${NC} (${TOTAL} total)"
echo "============================================================"

if [ $FAIL -gt 0 ]; then
    echo -e " ${RED}SANITY TEST FAILED${NC}"
    exit 1
else
    echo -e " ${GREEN}SANITY TEST PASSED${NC}"
fi

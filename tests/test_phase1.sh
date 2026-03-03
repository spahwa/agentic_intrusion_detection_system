#!/bin/bash
# Agentic IDS — Phase 1 Automated Regression Tests
# Validates docker-compose config, Suricata/Zeek settings, and runtime health.
#
# Usage:
#   bash tests/test_phase1.sh              # Run all tests
#   bash tests/test_phase1.sh --static-only   # Config tests only (no containers needed)
#   bash tests/test_phase1.sh --runtime-only  # Runtime tests only (containers must be up)

set -euo pipefail

# --- Colors & counters (same pattern as scripts/verify.sh) ---
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

# --- Resolve project root (parent of tests/) ---
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

echo "========================================"
echo " Agentic IDS — Phase 1 Regression Tests"
echo "========================================"
echo " Project: $PROJECT_ROOT"
echo " Mode:    $(if $RUN_STATIC && $RUN_RUNTIME; then echo "full"; elif $RUN_STATIC; then echo "static-only"; else echo "runtime-only"; fi)"

# =============================================================================
# STATIC TESTS — validate configs without running containers
# =============================================================================

if $RUN_STATIC; then

    # Capture docker compose config once for reuse
    COMPOSE_JSON=$(docker compose -f "$PROJECT_ROOT/docker-compose.yml" config --format json 2>/dev/null) || true

    section "S1. Docker Compose Parsing"

    # S1: docker compose config parses without error
    if docker compose -f "$PROJECT_ROOT/docker-compose.yml" config > /dev/null 2>&1; then
        pass "S01: docker compose config parses without error"
    else
        fail "S01: docker compose config fails to parse"
    fi

    # S2: docker compose --profile dual config parses without error
    if docker compose -f "$PROJECT_ROOT/docker-compose.yml" --profile dual config > /dev/null 2>&1; then
        pass "S02: docker compose --profile dual config parses without error"
    else
        fail "S02: docker compose --profile dual config fails to parse"
    fi

    section "S2. Container Capabilities & Modes"

    # S3: Suricata has NET_ADMIN, NET_RAW, SYS_NICE
    if [ -n "$COMPOSE_JSON" ]; then
        SURI_CAPS=$(echo "$COMPOSE_JSON" | python3 -c "
import sys, json
cfg = json.load(sys.stdin)
caps = cfg.get('services',{}).get('suricata',{}).get('cap_add',[])
print(' '.join(sorted(caps)))
" 2>/dev/null || echo "")
        if echo "$SURI_CAPS" | grep -q "NET_ADMIN" && \
           echo "$SURI_CAPS" | grep -q "NET_RAW" && \
           echo "$SURI_CAPS" | grep -q "SYS_NICE"; then
            pass "S03: Suricata has NET_ADMIN, NET_RAW, SYS_NICE"
        else
            fail "S03: Suricata capabilities: got [$SURI_CAPS], expected NET_ADMIN NET_RAW SYS_NICE"
        fi

        # S4: Zeek has NET_ADMIN, NET_RAW but NOT SYS_NICE
        ZEEK_CAPS=$(echo "$COMPOSE_JSON" | python3 -c "
import sys, json
cfg = json.load(sys.stdin)
caps = cfg.get('services',{}).get('zeek',{}).get('cap_add',[])
print(' '.join(sorted(caps)))
" 2>/dev/null || echo "")
        if echo "$ZEEK_CAPS" | grep -q "NET_ADMIN" && \
           echo "$ZEEK_CAPS" | grep -q "NET_RAW" && \
           ! echo "$ZEEK_CAPS" | grep -q "SYS_NICE"; then
            pass "S04: Zeek has NET_ADMIN, NET_RAW (no SYS_NICE)"
        else
            fail "S04: Zeek capabilities: got [$ZEEK_CAPS], expected NET_ADMIN NET_RAW only"
        fi

        # S5: Both services use network_mode: host
        SURI_NET=$(echo "$COMPOSE_JSON" | python3 -c "
import sys, json; cfg = json.load(sys.stdin)
print(cfg.get('services',{}).get('suricata',{}).get('network_mode',''))" 2>/dev/null || echo "")
        ZEEK_NET=$(echo "$COMPOSE_JSON" | python3 -c "
import sys, json; cfg = json.load(sys.stdin)
print(cfg.get('services',{}).get('zeek',{}).get('network_mode',''))" 2>/dev/null || echo "")
        if [ "$SURI_NET" = "host" ] && [ "$ZEEK_NET" = "host" ]; then
            pass "S05: Both services use network_mode: host"
        else
            fail "S05: network_mode: suricata=$SURI_NET, zeek=$ZEEK_NET (expected host)"
        fi

        # S6: Both services use restart: unless-stopped
        SURI_RESTART=$(echo "$COMPOSE_JSON" | python3 -c "
import sys, json; cfg = json.load(sys.stdin)
print(cfg.get('services',{}).get('suricata',{}).get('restart',''))" 2>/dev/null || echo "")
        ZEEK_RESTART=$(echo "$COMPOSE_JSON" | python3 -c "
import sys, json; cfg = json.load(sys.stdin)
print(cfg.get('services',{}).get('zeek',{}).get('restart',''))" 2>/dev/null || echo "")
        if [ "$SURI_RESTART" = "unless-stopped" ] && [ "$ZEEK_RESTART" = "unless-stopped" ]; then
            pass "S06: Both services use restart: unless-stopped"
        else
            fail "S06: restart policy: suricata=$SURI_RESTART, zeek=$ZEEK_RESTART"
        fi

        section "S3. Image Tags & Environment Variables"

        # S7: Image tags are pinned (no :latest)
        IMAGES=$(echo "$COMPOSE_JSON" | python3 -c "
import sys, json; cfg = json.load(sys.stdin)
for name, svc in cfg.get('services',{}).items():
    img = svc.get('image','')
    if img:
        print(f'{name}={img}')
    build = svc.get('build',{})
    if isinstance(build, dict):
        for k, v in build.get('args',{}).items():
            if 'TAG' in k:
                print(f'{name}_build_arg={k}:{v}')
" 2>/dev/null || echo "")
        HAS_LATEST=false
        while IFS= read -r line; do
            if echo "$line" | grep -q ":latest"; then
                HAS_LATEST=true
            fi
        done <<< "$IMAGES"
        # Also check that build args have version tags, not "latest"
        if grep -qi "latest" "$PROJECT_ROOT/docker-compose.yml" 2>/dev/null; then
            HAS_LATEST=true
        fi
        if ! $HAS_LATEST; then
            pass "S07: No 'latest' image tags found — tags are pinned"
        else
            fail "S07: Found 'latest' image tag (must be pinned)"
        fi

        # S8: Suricata receives NETWORK_INTERFACE and HOME_NET env vars
        SURI_ENV=$(echo "$COMPOSE_JSON" | python3 -c "
import sys, json; cfg = json.load(sys.stdin)
env = cfg.get('services',{}).get('suricata',{}).get('environment',{})
if isinstance(env, dict):
    print(' '.join(sorted(env.keys())))
elif isinstance(env, list):
    print(' '.join(sorted([e.split('=')[0] for e in env])))
" 2>/dev/null || echo "")
        if echo "$SURI_ENV" | grep -q "NETWORK_INTERFACE" && echo "$SURI_ENV" | grep -q "HOME_NET"; then
            pass "S08: Suricata receives NETWORK_INTERFACE and HOME_NET"
        else
            fail "S08: Suricata env vars: got [$SURI_ENV]"
        fi

        # S9: Zeek receives NETWORK_INTERFACE (not HOME_NET)
        ZEEK_ENV=$(echo "$COMPOSE_JSON" | python3 -c "
import sys, json; cfg = json.load(sys.stdin)
env = cfg.get('services',{}).get('zeek',{}).get('environment',{})
if isinstance(env, dict):
    print(' '.join(sorted(env.keys())))
elif isinstance(env, list):
    print(' '.join(sorted([e.split('=')[0] for e in env])))
" 2>/dev/null || echo "")
        if echo "$ZEEK_ENV" | grep -q "NETWORK_INTERFACE" && ! echo "$ZEEK_ENV" | grep -q "HOME_NET"; then
            pass "S09: Zeek receives NETWORK_INTERFACE (no HOME_NET)"
        else
            fail "S09: Zeek env vars: got [$ZEEK_ENV]"
        fi

        section "S4. Dual-Interface (WiFi) Services"

        # Get full config with dual profile for wifi tests
        COMPOSE_DUAL_JSON=$(docker compose -f "$PROJECT_ROOT/docker-compose.yml" --profile dual config --format json 2>/dev/null) || true

        # S10: WiFi services use NETWORK_INTERFACE_2
        if [ -n "$COMPOSE_DUAL_JSON" ]; then
            SURI_WIFI_ENV=$(echo "$COMPOSE_DUAL_JSON" | python3 -c "
import sys, json; cfg = json.load(sys.stdin)
env = cfg.get('services',{}).get('suricata-wifi',{}).get('environment',{})
if isinstance(env, dict):
    vals = list(env.values())
elif isinstance(env, list):
    vals = [e.split('=',1)[1] if '=' in e else e for e in env]
else:
    vals = []
print(' '.join(vals))
" 2>/dev/null || echo "")
            ZEEK_WIFI_ENV=$(echo "$COMPOSE_DUAL_JSON" | python3 -c "
import sys, json; cfg = json.load(sys.stdin)
env = cfg.get('services',{}).get('zeek-wifi',{}).get('environment',{})
if isinstance(env, dict):
    vals = list(env.values())
elif isinstance(env, list):
    vals = [e.split('=',1)[1] if '=' in e else e for e in env]
else:
    vals = []
print(' '.join(vals))
" 2>/dev/null || echo "")
            # The wifi services should reference NETWORK_INTERFACE_2's value (wlp2s0)
            WIFI_IFACE="${NETWORK_INTERFACE_2:-wlp2s0}"
            if echo "$SURI_WIFI_ENV" | grep -q "$WIFI_IFACE" && \
               echo "$ZEEK_WIFI_ENV" | grep -q "$WIFI_IFACE"; then
                pass "S10: WiFi services use NETWORK_INTERFACE_2 ($WIFI_IFACE)"
            else
                fail "S10: WiFi services don't reference $WIFI_IFACE"
            fi

            # S11: WiFi services are under profiles: [dual]
            SURI_WIFI_PROFILES=$(echo "$COMPOSE_DUAL_JSON" | python3 -c "
import sys, json; cfg = json.load(sys.stdin)
profiles = cfg.get('services',{}).get('suricata-wifi',{}).get('profiles',[])
print(' '.join(profiles))
" 2>/dev/null || echo "")
            ZEEK_WIFI_PROFILES=$(echo "$COMPOSE_DUAL_JSON" | python3 -c "
import sys, json; cfg = json.load(sys.stdin)
profiles = cfg.get('services',{}).get('zeek-wifi',{}).get('profiles',[])
print(' '.join(profiles))
" 2>/dev/null || echo "")
            if echo "$SURI_WIFI_PROFILES" | grep -q "dual" && \
               echo "$ZEEK_WIFI_PROFILES" | grep -q "dual"; then
                pass "S11: WiFi services use profiles: [dual]"
            else
                fail "S11: WiFi profiles: suricata-wifi=[$SURI_WIFI_PROFILES], zeek-wifi=[$ZEEK_WIFI_PROFILES]"
            fi
        else
            fail "S10: Could not parse dual profile config"
            fail "S11: Could not parse dual profile config"
        fi
    else
        fail "S03–S11: Could not parse docker compose config as JSON"
    fi

    section "S5. Suricata Configuration (suricata.yaml)"

    SURICATA_YAML="$PROJECT_ROOT/suricata/suricata.yaml"

    # S12: community-id: true
    if grep -q 'community-id: true' "$SURICATA_YAML" 2>/dev/null; then
        pass "S12: suricata.yaml has community-id: true"
    else
        fail "S12: suricata.yaml missing community-id: true"
    fi

    # S13: eve-log: enabled: yes
    if grep -q 'eve-log:' "$SURICATA_YAML" && grep -q 'enabled: yes' "$SURICATA_YAML" 2>/dev/null; then
        pass "S13: suricata.yaml has eve-log enabled"
    else
        fail "S13: suricata.yaml eve-log not enabled"
    fi

    # S14: rule-files loads both suricata.rules and custom.rules
    if grep -q 'suricata.rules' "$SURICATA_YAML" && grep -q 'custom.rules' "$SURICATA_YAML" 2>/dev/null; then
        pass "S14: suricata.yaml loads suricata.rules and custom.rules"
    else
        fail "S14: suricata.yaml missing rule file references"
    fi

    section "S6. Zeek Configuration (local.zeek)"

    LOCAL_ZEEK="$PROJECT_ROOT/zeek/local.zeek"

    # S15: community-id-logging loaded
    if grep -q 'community-id-logging' "$LOCAL_ZEEK" 2>/dev/null; then
        pass "S15: local.zeek loads community-id-logging"
    else
        fail "S15: local.zeek missing community-id-logging"
    fi

    # S16: LogAscii::use_json = T
    if grep -q 'LogAscii::use_json = T' "$LOCAL_ZEEK" 2>/dev/null; then
        pass "S16: local.zeek sets LogAscii::use_json = T"
    else
        fail "S16: local.zeek missing JSON output config"
    fi

fi # end static tests

# =============================================================================
# RUNTIME TESTS — require running containers
# =============================================================================

if $RUN_RUNTIME; then

    section "R1. Container Status"

    # R1: Suricata container is running
    SURI_STATE=$(docker inspect --format='{{.State.Status}}' ids-suricata 2>/dev/null || echo "not_found")
    SURI_RESTARTING=$(docker inspect --format='{{.State.Restarting}}' ids-suricata 2>/dev/null || echo "true")
    if [ "$SURI_STATE" = "running" ] && [ "$SURI_RESTARTING" = "false" ]; then
        pass "R01: ids-suricata is running (not restarting)"
    else
        fail "R01: ids-suricata state=$SURI_STATE, restarting=$SURI_RESTARTING"
    fi

    # R2: Zeek container is running
    ZEEK_STATE=$(docker inspect --format='{{.State.Status}}' ids-zeek 2>/dev/null || echo "not_found")
    ZEEK_RESTARTING=$(docker inspect --format='{{.State.Restarting}}' ids-zeek 2>/dev/null || echo "true")
    if [ "$ZEEK_STATE" = "running" ] && [ "$ZEEK_RESTARTING" = "false" ]; then
        pass "R02: ids-zeek is running (not restarting)"
    else
        fail "R02: ids-zeek state=$ZEEK_STATE, restarting=$ZEEK_RESTARTING"
    fi

    section "R2. Log Directories & Permissions"

    # R3: Suricata log dir exists
    if [ -d "$LOG_DIR/suricata" ]; then
        pass "R03: $LOG_DIR/suricata/ exists"
    else
        fail "R03: $LOG_DIR/suricata/ does not exist"
    fi

    # R4: Zeek log dir exists
    if [ -d "$LOG_DIR/zeek" ]; then
        pass "R04: $LOG_DIR/zeek/ exists"
    else
        fail "R04: $LOG_DIR/zeek/ does not exist"
    fi

    # R5: Suricata log dir owned by uid 994
    if [ -d "$LOG_DIR/suricata" ]; then
        SURI_UID=$(stat -c '%u' "$LOG_DIR/suricata" 2>/dev/null || echo "unknown")
        if [ "$SURI_UID" = "994" ]; then
            pass "R05: $LOG_DIR/suricata/ owned by uid 994 (suricata)"
        else
            warn "R05: $LOG_DIR/suricata/ owned by uid $SURI_UID (expected 994)"
        fi
    else
        fail "R05: Cannot check ownership — directory missing"
    fi

    section "R3. Suricata EVE JSON Output"

    EVE_FILE="$LOG_DIR/suricata/eve.json"

    # R6: eve.json exists and is non-empty (wait up to 45s)
    elapsed=0
    while [ ! -s "$EVE_FILE" ] && [ $elapsed -lt 45 ]; do
        sleep 3
        elapsed=$((elapsed + 3))
    done

    if [ -s "$EVE_FILE" ]; then
        pass "R06: eve.json exists and is non-empty (found after ${elapsed}s)"
    else
        fail "R06: eve.json missing or empty after 45s"
    fi

    # R7: eve.json first line is valid JSON
    if [ -s "$EVE_FILE" ]; then
        if head -1 "$EVE_FILE" | python3 -m json.tool > /dev/null 2>&1; then
            pass "R07: eve.json first line is valid JSON"
        else
            fail "R07: eve.json first line is not valid JSON"
        fi

        # R8: eve.json contains community_id field
        if grep -q '"community_id"' "$EVE_FILE" 2>/dev/null; then
            pass "R08: eve.json contains community_id field"
        else
            warn "R08: community_id not yet found in eve.json (may need flow traffic)"
        fi

        # R9: eve.json contains event_type: stats
        if grep -q '"event_type":"stats"' "$EVE_FILE" 2>/dev/null || \
           grep -q '"event_type": "stats"' "$EVE_FILE" 2>/dev/null; then
            pass "R09: eve.json contains stats events"
        else
            warn "R09: No stats events yet (stats interval is 30s)"
        fi
    else
        fail "R07: Cannot test — eve.json missing"
        fail "R08: Cannot test — eve.json missing"
        fail "R09: Cannot test — eve.json missing"
    fi

    section "R4. Suricata Container Logs"

    SURI_LOGS=$(docker logs ids-suricata 2>&1 | tail -100)

    # R10: "Engine started" in logs
    if echo "$SURI_LOGS" | grep -qi "engine started"; then
        pass "R10: Suricata logs show 'Engine started'"
    else
        fail "R10: Suricata logs missing 'Engine started'"
    fi

    # R11: Correct interface name in logs
    if echo "$SURI_LOGS" | grep -q "$NETWORK_INTERFACE"; then
        pass "R11: Suricata logs show interface $NETWORK_INTERFACE"
    else
        fail "R11: Suricata logs don't mention interface $NETWORK_INTERFACE"
    fi

    # R12: Rules loaded (>0 rules)
    RULES_LINE=$(echo "$SURI_LOGS" | grep -i "rule" | grep -i "load\|process" | tail -1)
    if echo "$SURI_LOGS" | grep -qiE "[1-9][0-9]* rules? (loaded|processed|file)"; then
        pass "R12: Suricata rules loaded successfully"
    elif echo "$SURI_LOGS" | grep -qi "rules loaded"; then
        pass "R12: Suricata rules loaded"
    elif [ -n "$RULES_LINE" ]; then
        warn "R12: Found rules reference but can't confirm count: $RULES_LINE"
    else
        fail "R12: No evidence of rules being loaded"
    fi

    section "R5. Zeek Log Output"

    # R13: packet_filter.log exists with valid JSON
    # Zeek rotates logs with timestamps — check current file or most recent rotated file
    PF_LOG="$LOG_DIR/zeek/packet_filter.log"
    PF_ROTATED=$(ls -t "$LOG_DIR"/zeek/packet_filter.*.log 2>/dev/null | head -1)
    PF_FILE=""
    if [ -s "$PF_LOG" ]; then
        PF_FILE="$PF_LOG"
    elif [ -n "$PF_ROTATED" ] && [ -s "$PF_ROTATED" ]; then
        PF_FILE="$PF_ROTATED"
    else
        # Wait for it to appear
        elapsed=0
        while [ $elapsed -lt 30 ]; do
            if [ -s "$PF_LOG" ]; then PF_FILE="$PF_LOG"; break; fi
            PF_ROTATED=$(ls -t "$LOG_DIR"/zeek/packet_filter.*.log 2>/dev/null | head -1)
            if [ -n "$PF_ROTATED" ] && [ -s "$PF_ROTATED" ]; then PF_FILE="$PF_ROTATED"; break; fi
            sleep 3
            elapsed=$((elapsed + 3))
        done
    fi

    if [ -n "$PF_FILE" ]; then
        if head -1 "$PF_FILE" | python3 -m json.tool > /dev/null 2>&1; then
            pass "R13: packet_filter.log exists and contains valid JSON ($(basename "$PF_FILE"))"
        else
            fail "R13: $(basename "$PF_FILE") exists but first line is not valid JSON"
        fi

        # R14: packet_filter.log shows success:true
        if grep -q '"success":true' "$PF_FILE" 2>/dev/null || \
           grep -q '"success": true' "$PF_FILE" 2>/dev/null; then
            pass "R14: packet_filter.log shows success: true"
        else
            fail "R14: packet_filter.log does not show success: true"
        fi
    else
        fail "R13: packet_filter.log not found after 30s"
        fail "R14: Cannot test — packet_filter.log missing"
    fi

    # R15: Zeek logs show "listening on" correct interface
    ZEEK_LOGS=$(docker logs ids-zeek 2>&1 | tail -50)
    if echo "$ZEEK_LOGS" | grep -qi "listening on $NETWORK_INTERFACE"; then
        pass "R15: Zeek logs show listening on $NETWORK_INTERFACE"
    elif echo "$ZEEK_LOGS" | grep -qi "listening on"; then
        LISTEN_LINE=$(echo "$ZEEK_LOGS" | grep -i "listening on" | head -1)
        warn "R15: Zeek listening but on different interface: $LISTEN_LINE"
    else
        fail "R15: Zeek logs don't show 'listening on'"
    fi

fi # end runtime tests

# =============================================================================
# Summary
# =============================================================================

echo ""
echo "========================================"
TOTAL=$((PASS + FAIL + WARN))
echo -e " Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}, ${YELLOW}${WARN} warnings${NC} (${TOTAL} total)"
echo "========================================"

if [ $FAIL -gt 0 ]; then
    exit 1
fi

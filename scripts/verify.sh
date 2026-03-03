#!/bin/bash
# Agentic IDS — Phase 1 Deployment Verification
# Checks that Suricata and Zeek containers are running and producing JSON logs.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASS=0
FAIL=0
WARN=0

pass() { echo -e "  ${GREEN}[OK]${NC} $1"; PASS=$((PASS + 1)); }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; FAIL=$((FAIL + 1)); }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; WARN=$((WARN + 1)); }

LOG_DIR="${LOG_DIR:-/var/log/ids}"
TIMEOUT=60

echo "========================================"
echo " Agentic IDS — Phase 1 Verification"
echo "========================================"
echo ""

# --- 1. Container Status ---
echo "1. Container Status"

for svc in ids-suricata ids-zeek; do
    if docker inspect --format='{{.State.Running}}' "$svc" 2>/dev/null | grep -q true; then
        pass "$svc is running"
    else
        fail "$svc is NOT running"
        echo "     Check logs: docker logs $svc"
    fi
done

echo ""

# --- 2. Log Directories ---
echo "2. Log Directories"

for subdir in suricata zeek; do
    dir="${LOG_DIR}/${subdir}"
    if [ -d "$dir" ]; then
        pass "$dir exists"
    else
        fail "$dir does not exist"
    fi
done

echo ""

# --- 3. Suricata EVE JSON ---
echo "3. Suricata EVE JSON"

EVE_FILE="${LOG_DIR}/suricata/eve.json"
elapsed=0
while [ ! -f "$EVE_FILE" ] && [ $elapsed -lt $TIMEOUT ]; do
    sleep 2
    elapsed=$((elapsed + 2))
done

if [ -f "$EVE_FILE" ]; then
    pass "eve.json exists (found after ${elapsed}s)"

    if head -1 "$EVE_FILE" | python3 -m json.tool > /dev/null 2>&1; then
        pass "eve.json contains valid JSON"
    else
        fail "eve.json first line is not valid JSON"
    fi

    EVE_LINES=$(wc -l < "$EVE_FILE")
    echo "     Events: ${EVE_LINES} lines"
else
    fail "eve.json not found after ${TIMEOUT}s"
fi

echo ""

# --- 4. Zeek JSON Logs ---
echo "4. Zeek JSON Logs"

elapsed=0
while [ -z "$(find "${LOG_DIR}/zeek" -name '*.log' 2>/dev/null)" ] && [ $elapsed -lt $TIMEOUT ]; do
    sleep 2
    elapsed=$((elapsed + 2))
done

ZEEK_LOGS=$(find "${LOG_DIR}/zeek" -name '*.log' 2>/dev/null)
if [ -n "$ZEEK_LOGS" ]; then
    LOG_COUNT=$(echo "$ZEEK_LOGS" | wc -l)
    pass "Found ${LOG_COUNT} Zeek log file(s) (after ${elapsed}s)"

    # Validate JSON on the first non-empty log
    VALIDATED=false
    for logfile in $ZEEK_LOGS; do
        if [ -s "$logfile" ]; then
            if head -1 "$logfile" | python3 -m json.tool > /dev/null 2>&1; then
                pass "$(basename "$logfile") contains valid JSON"
                VALIDATED=true
                break
            else
                fail "$(basename "$logfile") first line is not valid JSON"
                VALIDATED=true
                break
            fi
        fi
    done
    if [ "$VALIDATED" = false ]; then
        warn "All Zeek log files are empty (may need more network traffic)"
    fi

    echo "     Log files:"
    for logfile in $ZEEK_LOGS; do
        SIZE=$(wc -l < "$logfile" 2>/dev/null || echo 0)
        echo "       $(basename "$logfile"): ${SIZE} lines"
    done
else
    fail "No Zeek .log files found in ${LOG_DIR}/zeek/ after ${TIMEOUT}s"
fi

echo ""

# --- Summary ---
echo "========================================"
echo " Summary: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}, ${YELLOW}${WARN} warnings${NC}"
echo "========================================"

if [ $FAIL -gt 0 ]; then
    exit 1
fi

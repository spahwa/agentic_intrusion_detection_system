#!/bin/bash
# Agentic IDS — Phase 2 Deployment Verification
# Checks that Vector and DuckDB manager are running and data is flowing.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0

pass() { echo -e "  ${GREEN}[OK]${NC} $1"; PASS=$((PASS + 1)); }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; FAIL=$((FAIL + 1)); }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; WARN=$((WARN + 1)); }

LOG_DIR="${LOG_DIR:-/var/log/ids}"
TTL_HOURS="${DUCKDB_TTL_HOURS:-72}"

echo "========================================"
echo " Agentic IDS — Phase 2 Verification"
echo "========================================"
echo ""

# --- 1. Container Status ---
echo "1. Container Status"

for svc in ids-vector ids-duckdb-mgr; do
    if docker inspect --format='{{.State.Running}}' "$svc" 2>/dev/null | grep -q true; then
        pass "$svc is running"
    else
        fail "$svc is NOT running"
        echo "     Check logs: docker logs $svc"
    fi
done

echo ""

# --- 2. Vector Staging Directory ---
echo "2. Vector NDJSON Staging"

VECTOR_DIR="${LOG_DIR}/vector"
if [ -d "$VECTOR_DIR" ]; then
    NDJSON_COUNT=$(find "$VECTOR_DIR" -name '*.ndjson' 2>/dev/null | wc -l)
    if [ "$NDJSON_COUNT" -gt 0 ]; then
        pass "Found $NDJSON_COUNT NDJSON staging file(s) in $VECTOR_DIR"
    else
        warn "Vector directory exists but no NDJSON files yet (may need more time or traffic)"
    fi
else
    fail "Vector staging directory $VECTOR_DIR does not exist"
fi

echo ""

# --- 3. DuckDB File ---
echo "3. DuckDB Database"

DUCKDB_FILE="${LOG_DIR}/duckdb/ids.duckdb"
if [ -f "$DUCKDB_FILE" ]; then
    pass "DuckDB file exists: $DUCKDB_FILE"

    # Query row count
    ROW_COUNT=$(docker exec ids-duckdb-mgr python3 -c "
import duckdb
db = duckdb.connect('$DUCKDB_FILE', read_only=True)
print(db.execute('SELECT count(*) FROM events').fetchone()[0])
" 2>/dev/null || echo "ERROR")

    if [ "$ROW_COUNT" = "ERROR" ]; then
        fail "Could not query DuckDB events table"
    elif [ "$ROW_COUNT" -gt 0 ] 2>/dev/null; then
        pass "DuckDB has $ROW_COUNT event(s)"
    else
        warn "DuckDB has 0 events (may need more time or network traffic)"
    fi

    # Check TTL compliance
    EXPIRED=$(docker exec ids-duckdb-mgr python3 -c "
import duckdb
db = duckdb.connect('$DUCKDB_FILE', read_only=True)
print(db.execute(\"SELECT count(*) FROM events WHERE timestamp < now() - INTERVAL '$TTL_HOURS hours'\").fetchone()[0])
" 2>/dev/null || echo "ERROR")

    if [ "$EXPIRED" = "ERROR" ]; then
        warn "Could not check TTL compliance"
    elif [ "$EXPIRED" = "0" ]; then
        pass "TTL compliant: 0 events older than ${TTL_HOURS}h"
    else
        fail "$EXPIRED event(s) older than ${TTL_HOURS}h (TTL purge may be delayed)"
    fi
else
    fail "DuckDB file not found: $DUCKDB_FILE"
fi

echo ""

# --- Summary ---
echo "========================================"
echo -e " Summary: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}, ${YELLOW}${WARN} warnings${NC}"
echo "========================================"

if [ $FAIL -gt 0 ]; then
    exit 1
fi

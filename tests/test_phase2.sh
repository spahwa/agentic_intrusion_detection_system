#!/bin/bash
# Agentic IDS — Phase 2 Regression Tests
# Static validation + runtime checks for Vector and DuckDB pipeline.

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
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "========================================"
echo " Agentic IDS — Phase 2 Regression Tests"
echo "========================================"
echo ""

# ==========================================
# STATIC TESTS
# ==========================================
echo "=== Static Tests ==="
echo ""

# --- 1. Vector config validation ---
echo "1. Vector Config Validation"

if docker exec ids-vector vector validate --config-yaml /etc/vector/vector.yaml 2>&1 | grep -qi "validated"; then
    pass "Vector config validates successfully"
else
    # Try alternate approach — just check exit code
    if docker exec ids-vector vector validate --config-yaml /etc/vector/vector.yaml > /dev/null 2>&1; then
        pass "Vector config validates successfully"
    else
        fail "Vector config validation failed"
        docker exec ids-vector vector validate --config-yaml /etc/vector/vector.yaml 2>&1 | tail -5
    fi
fi

echo ""

# --- 2. Docker Compose config includes Phase 2 services ---
echo "2. Docker Compose Config"

COMPOSE_CONFIG=$(docker compose -f "$PROJECT_DIR/docker-compose.yml" config 2>/dev/null)

for svc in vector duckdb-mgr; do
    if echo "$COMPOSE_CONFIG" | grep -q "$svc"; then
        pass "Service '$svc' found in docker-compose.yml"
    else
        fail "Service '$svc' NOT found in docker-compose.yml"
    fi
done

echo ""

# --- 3. Vector image tag is pinned (not 'latest') ---
echo "3. Image Tag Pinning"

VECTOR_IMAGE=$(docker inspect --format='{{.Config.Image}}' ids-vector 2>/dev/null || echo "unknown")
if echo "$VECTOR_IMAGE" | grep -qE ':[0-9]'; then
    pass "Vector image is pinned: $VECTOR_IMAGE"
elif echo "$VECTOR_IMAGE" | grep -q 'latest'; then
    fail "Vector image uses 'latest' tag: $VECTOR_IMAGE"
else
    warn "Could not determine Vector image tag: $VECTOR_IMAGE"
fi

echo ""

# --- 4. duckdb-mgr depends_on vector ---
echo "4. Service Dependencies"

if echo "$COMPOSE_CONFIG" | grep -A20 "duckdb-mgr" | grep -q "vector"; then
    pass "duckdb-mgr depends on vector"
else
    warn "Could not verify duckdb-mgr dependency on vector"
fi

echo ""

# ==========================================
# RUNTIME TESTS
# ==========================================
echo "=== Runtime Tests ==="
echo ""

# --- 5. Containers running ---
echo "5. Container Status"

for svc in ids-vector ids-duckdb-mgr; do
    if docker inspect --format='{{.State.Running}}' "$svc" 2>/dev/null | grep -q true; then
        pass "$svc is running"
    else
        fail "$svc is NOT running"
    fi
done

echo ""

# --- 6. NDJSON staging files ---
echo "6. NDJSON Staging Files"

VECTOR_DIR="${LOG_DIR}/vector"
if [ -d "$VECTOR_DIR" ]; then
    NDJSON_FILES=$(find "$VECTOR_DIR" -name '*.ndjson' 2>/dev/null)
    NDJSON_COUNT=$(echo "$NDJSON_FILES" | grep -c '.' 2>/dev/null || echo 0)
    if [ "$NDJSON_COUNT" -gt 0 ]; then
        pass "Found $NDJSON_COUNT NDJSON staging file(s)"

        # Validate JSON in first file
        FIRST_FILE=$(echo "$NDJSON_FILES" | head -1)
        if [ -n "$FIRST_FILE" ] && [ -f "$FIRST_FILE" ]; then
            if head -1 "$FIRST_FILE" | python3 -m json.tool > /dev/null 2>&1; then
                pass "NDJSON content is valid JSON"
            else
                fail "First NDJSON file has invalid JSON"
            fi
        fi
    else
        warn "No NDJSON files yet (may need more time or traffic)"
    fi
else
    fail "Vector staging directory does not exist"
fi

echo ""

# --- 7. DuckDB queryable ---
echo "7. DuckDB Database"

DUCKDB_FILE="${LOG_DIR}/duckdb/ids.duckdb"
if [ -f "$DUCKDB_FILE" ]; then
    pass "DuckDB file exists"

    # Check events table has records
    ROW_COUNT=$(docker exec ids-duckdb-mgr python3 -c "
import duckdb
db = duckdb.connect('$DUCKDB_FILE', read_only=True)
print(db.execute('SELECT count(*) FROM events').fetchone()[0])
" 2>/dev/null || echo "ERROR")

    if [ "$ROW_COUNT" != "ERROR" ] && [ "$ROW_COUNT" -gt 0 ] 2>/dev/null; then
        pass "events table has $ROW_COUNT row(s)"
    else
        warn "events table has 0 rows (may need more time or traffic)"
    fi
else
    fail "DuckDB file not found"
fi

echo ""

# --- 8. Both source_tools present ---
echo "8. Source Tool Coverage"

SOURCES=$(docker exec ids-duckdb-mgr python3 -c "
import duckdb
db = duckdb.connect('$DUCKDB_FILE', read_only=True)
rows = db.execute('SELECT DISTINCT source_tool FROM events').fetchall()
for r in rows:
    print(r[0])
" 2>/dev/null || echo "ERROR")

if [ "$SOURCES" = "ERROR" ]; then
    warn "Could not query source_tools"
else
    for tool in suricata zeek; do
        if echo "$SOURCES" | grep -q "$tool"; then
            pass "Found events from $tool"
        else
            warn "No events from $tool yet"
        fi
    done
fi

echo ""

# --- 9. TTL compliance ---
echo "9. TTL Compliance"

EXPIRED=$(docker exec ids-duckdb-mgr python3 -c "
import duckdb
db = duckdb.connect('$DUCKDB_FILE', read_only=True)
print(db.execute(\"SELECT count(*) FROM events WHERE timestamp < now() - INTERVAL '$TTL_HOURS hours'\").fetchone()[0])
" 2>/dev/null || echo "ERROR")

if [ "$EXPIRED" = "ERROR" ]; then
    warn "Could not check TTL compliance"
elif [ "$EXPIRED" = "0" ]; then
    pass "No events older than ${TTL_HOURS}h"
else
    fail "$EXPIRED event(s) older than ${TTL_HOURS}h"
fi

echo ""

# --- 10. community_id in records ---
echo "10. community_id Presence"

CID_COUNT=$(docker exec ids-duckdb-mgr python3 -c "
import duckdb
db = duckdb.connect('$DUCKDB_FILE', read_only=True)
count = db.execute(\"SELECT count(*) FROM events WHERE raw::VARCHAR LIKE '%community_id%'\").fetchone()[0]
print(count)
" 2>/dev/null || echo "ERROR")

if [ "$CID_COUNT" = "ERROR" ]; then
    warn "Could not check community_id presence"
elif [ "$CID_COUNT" -gt 0 ] 2>/dev/null; then
    pass "Found $CID_COUNT event(s) with community_id"
else
    warn "No events with community_id yet (need actual network traffic)"
fi

echo ""

# --- Summary ---
echo "========================================"
echo -e " Summary: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}, ${YELLOW}${WARN} warnings${NC}"
echo "========================================"

if [ $FAIL -gt 0 ]; then
    exit 1
fi

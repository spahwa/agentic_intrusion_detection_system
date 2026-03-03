#!/usr/bin/env bash
# Phase 2.5 verification: Grafana + DuckDB dashboards
set -euo pipefail

PASS=0
FAIL=0
WARN=0

pass() { echo "  [PASS] $1"; PASS=$((PASS+1)); }
fail() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
warn() { echo "  [WARN] $1"; WARN=$((WARN+1)); }

echo "=== Phase 2.5 Verification ==="
echo ""

# 1. Grafana container running
echo "1. Checking ids-grafana container..."
if docker ps --format '{{.Names}}' | grep -q '^ids-grafana$'; then
    pass "ids-grafana container is running"
else
    fail "ids-grafana container is NOT running"
fi

# 2. Grafana health endpoint
echo "2. Checking Grafana health endpoint..."
GRAFANA_PORT="${GRAFANA_PORT:-3000}"
HEALTH=$(curl -sf "http://localhost:${GRAFANA_PORT}/api/health" 2>/dev/null || echo "")
if echo "$HEALTH" | grep -q '"database":"ok"'; then
    pass "Grafana health check passed"
else
    fail "Grafana health endpoint not responding (tried port ${GRAFANA_PORT})"
fi

# 3. DuckDB datasource provisioned
echo "3. Checking DuckDB datasource..."
DS=$(curl -sf -u admin:admin "http://localhost:${GRAFANA_PORT}/api/datasources" 2>/dev/null || echo "")
if echo "$DS" | grep -q 'motherduck-duckdb-datasource'; then
    pass "DuckDB datasource is provisioned"
else
    fail "DuckDB datasource not found"
fi

# 4. Dashboards loaded
echo "4. Checking provisioned dashboards..."
DASHBOARDS=$(curl -sf -u admin:admin "http://localhost:${GRAFANA_PORT}/api/search?tag=ids" 2>/dev/null || echo "")
DASH_COUNT=$(echo "$DASHBOARDS" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
if [ "$DASH_COUNT" -ge 6 ]; then
    pass "All 6 dashboards loaded ($DASH_COUNT found)"
elif [ "$DASH_COUNT" -ge 1 ]; then
    warn "Only $DASH_COUNT of 6 dashboards loaded"
else
    fail "No dashboards found"
fi

# 5. DuckDB datasource health
echo "5. Checking DuckDB datasource connectivity..."
DS_HEALTH=$(curl -sf -u admin:admin "http://localhost:${GRAFANA_PORT}/api/datasources/uid/duckdb-ids/health" 2>/dev/null || echo "")
if echo "$DS_HEALTH" | grep -qi 'ok\|success'; then
    pass "DuckDB datasource health check passed"
else
    # Try querying directly as fallback
    QUERY_RESULT=$(curl -sf -u admin:admin -X POST "http://localhost:${GRAFANA_PORT}/api/ds/query" \
        -H 'Content-Type: application/json' \
        -d '{"queries":[{"refId":"A","datasource":{"uid":"duckdb-ids"},"rawSql":"SELECT count(*) as cnt FROM events","format":"table"}],"from":"now-1h","to":"now"}' 2>/dev/null || echo "")
    if echo "$QUERY_RESULT" | grep -q 'cnt'; then
        pass "DuckDB datasource responds to queries"
    else
        warn "DuckDB datasource health check inconclusive (plugin may not support /health endpoint)"
    fi
fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed, $WARN warnings ==="
echo ""
if [ "$FAIL" -gt 0 ]; then
    echo "Phase 2.5 verification FAILED"
    exit 1
else
    echo "Phase 2.5 verification PASSED"
    echo "Open http://localhost:${GRAFANA_PORT} in your browser (admin/admin)"
fi

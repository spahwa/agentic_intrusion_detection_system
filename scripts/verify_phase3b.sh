#!/usr/bin/env bash
# Phase 3b verification — Agentic Alert System
set -euo pipefail

PASS=0
FAIL=0
WARN=0

pass() { echo "  ✅ $1"; PASS=$((PASS+1)); }
fail() { echo "  ❌ $1"; FAIL=$((FAIL+1)); }
warn() { echo "  ⚠️  $1"; WARN=$((WARN+1)); }

echo "=== Phase 3b: Agentic Alert System ==="
echo

# 1. alert-agent container running
echo "1. alert-agent container"
if docker ps --format '{{.Names}}' | grep -q '^ids-alert-agent$'; then
    pass "ids-alert-agent container is running"
else
    fail "ids-alert-agent container is NOT running"
fi

# 2. anomaly_events table exists in DuckDB
echo "2. anomaly_events table"
ANOM_CHECK=$(docker exec ids-duckdb-mgr python3 -c "
import duckdb
db = duckdb.connect('/var/log/ids/duckdb/ids.duckdb', read_only=True)
print(db.execute(\"SELECT count(*) FROM anomaly_events\").fetchone()[0])
db.close()
" 2>/dev/null || echo "ERROR")
if [ "$ANOM_CHECK" != "ERROR" ]; then
    pass "anomaly_events table exists ($ANOM_CHECK rows)"
else
    fail "anomaly_events table not found"
fi

# 3. _known_devices table exists
echo "3. _known_devices table"
KD_CHECK=$(docker exec ids-duckdb-mgr python3 -c "
import duckdb
db = duckdb.connect('/var/log/ids/duckdb/ids.duckdb', read_only=True)
print(db.execute(\"SELECT count(*) FROM _known_devices\").fetchone()[0])
db.close()
" 2>/dev/null || echo "ERROR")
if [ "$KD_CHECK" != "ERROR" ]; then
    pass "_known_devices table exists ($KD_CHECK devices tracked)"
else
    fail "_known_devices table not found"
fi

# 4. alert_state.db exists (SQLite state tracking)
echo "4. alert state DB"
if [ -f "/var/log/ids/duckdb/alert_state.db" ]; then
    pass "alert_state.db exists"
else
    warn "alert_state.db not yet created (will be created on first anomaly)"
fi

# 5. Ollama reachable from alert-agent
echo "5. Ollama connectivity"
OLLAMA_CHECK=$(docker logs ids-alert-agent 2>&1 | grep -c "Ollama ready" || true)
if [ "$OLLAMA_CHECK" -ge 1 ]; then
    pass "alert-agent connected to Ollama"
else
    OLLAMA_WAIT=$(docker logs ids-alert-agent 2>&1 | grep -c "Waiting for Ollama" || true)
    if [ "$OLLAMA_WAIT" -ge 1 ]; then
        warn "alert-agent is waiting for Ollama (may still be starting)"
    else
        fail "alert-agent has no Ollama connectivity logs"
    fi
fi

# 6. Gmail credentials configured
echo "6. Gmail SMTP config"
GMAIL_USER="${GMAIL_USER:-}"
GMAIL_APP_PASSWORD="${GMAIL_APP_PASSWORD:-}"
ALERT_RECIPIENT="${ALERT_RECIPIENT:-}"
if [ -n "$GMAIL_USER" ] && [ -n "$GMAIL_APP_PASSWORD" ] && [ -n "$ALERT_RECIPIENT" ]; then
    pass "Gmail credentials configured (GMAIL_USER=$GMAIL_USER)"
else
    warn "Gmail credentials not configured — alert emails will not be sent"
fi

echo
echo "=== Results: $PASS passed, $FAIL failed, $WARN warnings ==="
[ "$FAIL" -eq 0 ] && echo "Phase 3b verification: PASS" || echo "Phase 3b verification: FAIL"
exit "$FAIL"

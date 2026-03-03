#!/usr/bin/env bash
# Phase 3 verification: Ollama + Streamlit chat UI
set -euo pipefail

PASS=0
FAIL=0
WARN=0

pass() { echo "  [PASS] $1"; PASS=$((PASS+1)); }
fail() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
warn() { echo "  [WARN] $1"; WARN=$((WARN+1)); }

echo "=== Phase 3 Verification ==="
echo ""

# 1. Ollama reachable on host
echo "1. Checking Ollama API..."
OLLAMA_TAGS=$(curl -sf "http://localhost:11434/api/tags" 2>/dev/null || echo "")
if [ -n "$OLLAMA_TAGS" ]; then
    pass "Ollama API reachable on localhost:11434"
else
    fail "Ollama API not reachable on localhost:11434"
fi

# 2. qwen2.5:7b model available
echo "2. Checking Ollama model..."
OLLAMA_MODEL="${OLLAMA_MODEL:-qwen2.5:7b}"
if echo "$OLLAMA_TAGS" | grep -q "qwen2.5"; then
    pass "qwen2.5 model found in Ollama"
else
    fail "qwen2.5 model not found in Ollama (run: ollama pull ${OLLAMA_MODEL})"
fi

# 3. Streamlit container running
echo "3. Checking ids-streamlit container..."
if docker ps --format '{{.Names}}' | grep -q '^ids-streamlit$'; then
    pass "ids-streamlit container is running"
else
    fail "ids-streamlit container is NOT running"
fi

# 4. Streamlit health endpoint
echo "4. Checking Streamlit health..."
STREAMLIT_PORT="${STREAMLIT_PORT:-8501}"
HEALTH=$(curl -sf "http://localhost:${STREAMLIT_PORT}/_stcore/health" 2>/dev/null || echo "")
if echo "$HEALTH" | grep -qi "ok"; then
    pass "Streamlit health check passed"
else
    fail "Streamlit health endpoint not responding (tried port ${STREAMLIT_PORT})"
fi

# 5. DuckDB queryable from streamlit container
echo "5. Checking DuckDB connectivity from streamlit..."
DB_CHECK=$(docker exec ids-streamlit python3 -c "
import duckdb, os
db = duckdb.connect(os.environ.get('DUCKDB_PATH', '/var/log/ids/duckdb/ids_readonly.duckdb'), read_only=True)
count = db.execute('SELECT count(*) FROM events').fetchone()[0]
print(f'OK:{count}')
db.close()
" 2>/dev/null || echo "FAIL")
if echo "$DB_CHECK" | grep -q "^OK:"; then
    EVENT_COUNT=$(echo "$DB_CHECK" | sed 's/OK://')
    pass "DuckDB queryable from streamlit (${EVENT_COUNT} events)"
else
    fail "DuckDB not queryable from streamlit container"
fi

# 6. Ollama reachable from streamlit container
echo "6. Checking Ollama connectivity from streamlit..."
OLLAMA_CHECK=$(docker exec ids-streamlit python3 -c "
import ollama, os
client = ollama.Client(host=os.environ.get('OLLAMA_HOST', 'http://localhost:11434'))
models = client.list()
names = [m.model for m in models.models]
print(f'OK:{len(names)} models')
" 2>/dev/null || echo "FAIL")
if echo "$OLLAMA_CHECK" | grep -q "^OK:"; then
    pass "Ollama reachable from streamlit container"
else
    fail "Ollama not reachable from streamlit container"
fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed, $WARN warnings ==="
echo ""
if [ "$FAIL" -gt 0 ]; then
    echo "Phase 3 verification FAILED"
    exit 1
else
    echo "Phase 3 verification PASSED"
    echo "Open http://localhost:${STREAMLIT_PORT} in your browser"
fi

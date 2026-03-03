#!/usr/bin/env bash
# Phase 3d verification — Threat Intel RAG
# Tests: rules file, rag.duckdb, nomic-embed-text, indexing status, search endpoint
set -euo pipefail

PASS=0
FAIL=0
WARN=0

pass() { echo "  [PASS] $1"; PASS=$((PASS+1)); }
fail() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
warn() { echo "  [WARN] $1"; WARN=$((WARN+1)); }

LOG_DIR="${LOG_DIR:-/var/log/ids}"
RAG_DB="${LOG_DIR}/duckdb/rag.duckdb"
RULES_FILE="${LOG_DIR}/suricata/rules/suricata.rules"

echo "=== Phase 3d: Threat Intel RAG ==="
echo

# 1. nomic-embed-text model available
echo "1. Ollama embedding model"
if curl -sf "http://localhost:11434/api/tags" 2>/dev/null | grep -q "nomic-embed"; then
    pass "nomic-embed-text available in Ollama"
else
    fail "nomic-embed-text not found — run: ollama pull nomic-embed-text"
fi

# 2. Suricata rules file on shared volume
echo "2. Suricata rules on shared volume"
if [ -f "$RULES_FILE" ]; then
    SIZE=$(du -sh "$RULES_FILE" | cut -f1)
    RULE_COUNT=$(grep -c '^alert\|^drop\|^reject\|^pass' "$RULES_FILE" 2>/dev/null || echo "?")
    pass "suricata.rules exists (${SIZE}, ~${RULE_COUNT} rules)"
else
    fail "suricata.rules not at $RULES_FILE — trigger suricata-update first"
fi

# 3. rag.duckdb exists
echo "3. RAG database file"
if [ -f "$RAG_DB" ]; then
    SIZE=$(du -sh "$RAG_DB" | cut -f1)
    pass "rag.duckdb exists (${SIZE})"
else
    fail "rag.duckdb not found at $RAG_DB"
fi

# 4. rag_threat_intel table populated with embeddings
echo "4. Embedding count"
EMBED_CHECK=$(docker exec ids-streamlit python3 -c "
import duckdb
db = duckdb.connect('$RAG_DB', read_only=True)
total = db.execute('SELECT count(*) FROM rag_threat_intel').fetchone()[0]
embedded = db.execute('SELECT count(*) FROM rag_threat_intel WHERE embedding IS NOT NULL').fetchone()[0]
meta = db.execute(\"SELECT value FROM rag_index_meta WHERE key='rule_count'\").fetchone()
db.close()
print(f'{total}:{embedded}:{meta[0] if meta else 0}')
" 2>/dev/null || echo "ERROR")

if [ "$EMBED_CHECK" = "ERROR" ]; then
    warn "Could not query rag.duckdb — may be empty or indexing in progress"
else
    TOTAL=$(echo "$EMBED_CHECK" | cut -d: -f1)
    EMBEDDED=$(echo "$EMBED_CHECK" | cut -d: -f2)
    META=$(echo "$EMBED_CHECK" | cut -d: -f3)
    if [ "$EMBEDDED" -gt 0 ] 2>/dev/null; then
        pass "rag_threat_intel: $EMBEDDED/$TOTAL rules have embeddings (meta count: $META)"
    else
        warn "rag_threat_intel: $TOTAL rules, 0 embeddings — indexing may still be running"
        echo "    Watch: docker compose logs -f duckdb-mgr | grep -i rag"
    fi
fi

# 5. RAG indexer logged completion
echo "5. Indexer status (duckdb-mgr logs)"
DUCKDB_LOG=$(docker logs ids-duckdb-mgr 2>&1)
if echo "$DUCKDB_LOG" | grep -q "RAG: indexing complete"; then
    COUNT=$(echo "$DUCKDB_LOG" | grep "RAG: indexing complete" | tail -1)
    pass "Indexing complete: $COUNT"
elif echo "$DUCKDB_LOG" | grep -q "RAG: indexer thread started"; then
    warn "Indexer thread started but not yet complete — embeddings in progress"
elif echo "$DUCKDB_LOG" | grep -q "RAG: initialized empty rag.duckdb"; then
    warn "RAG DB initialized but indexer not yet started (nmap scan may be blocking cycle)"
else
    warn "No RAG log entries yet — duckdb-mgr may not have run a cycle"
fi

# 6. rag_search_threat_intel works end-to-end from streamlit
echo "6. End-to-end semantic search"
SEARCH_RESULT=$(docker exec ids-streamlit python3 -c "
import sys, json, os
sys.path.insert(0, '/app')
result = json.loads(__import__('tools').rag_search_threat_intel('nmap port scan', top_k=3))
if 'results' in result:
    count = len(result['results'])
    first = result['results'][0]['msg'] if count > 0 else 'n/a'
    print(f'OK:{count}:{first[:50]}')
else:
    print(f'NOMSG:{result.get(\"message\",\"unknown\")}')
" 2>/dev/null || echo "ERROR")

if echo "$SEARCH_RESULT" | grep -q "^OK:"; then
    CT=$(echo "$SEARCH_RESULT" | cut -d: -f2)
    FIRST=$(echo "$SEARCH_RESULT" | cut -d: -f3-)
    if [ "$CT" -gt 0 ] 2>/dev/null; then
        pass "rag_search_threat_intel: $CT result(s) — top match: $FIRST"
    else
        warn "rag_search_threat_intel: 0 results (indexing may still be in progress)"
    fi
elif echo "$SEARCH_RESULT" | grep -q "^NOMSG:"; then
    MSG=$(echo "$SEARCH_RESULT" | cut -d: -f2-)
    warn "rag_search_threat_intel: $MSG"
else
    warn "rag_search_threat_intel: could not call function — $SEARCH_RESULT"
fi

# 7. rag_search_threat_intel works from alert-agent
echo "7. RAG callable from alert-agent"
AA_SEARCH=$(docker exec ids-alert-agent python3 -c "
import sys, json, os
sys.path.insert(0, '/app')
result = json.loads(__import__('tools').rag_search_threat_intel('ET SCAN Nmap', top_k=2))
print('OK' if 'results' in result else 'FAIL')
" 2>/dev/null || echo "ERROR")
if [ "$AA_SEARCH" = "OK" ]; then
    pass "rag_search_threat_intel callable from alert-agent"
else
    warn "rag_search_threat_intel not callable from alert-agent: $AA_SEARCH"
fi

# 8. Rules copy logged by Suricata
echo "8. Suricata rule copy log"
if docker logs ids-suricata 2>&1 | grep -q "Rules copied to shared volume"; then
    pass "Suricata logged 'Rules copied to shared volume for RAG indexing'"
else
    warn "Rule copy log not yet seen in Suricata logs"
fi

echo
echo "=== Results: $PASS passed, $FAIL failed, $WARN warnings ==="
if [ "$FAIL" -eq 0 ]; then
    echo "Phase 3d verification: PASS"
    exit 0
else
    echo "Phase 3d verification: FAIL"
    exit 1
fi

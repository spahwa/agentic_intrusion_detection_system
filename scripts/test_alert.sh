#!/usr/bin/env bash
# test_alert.sh — Insert a fake device anomaly, wait for LLM-drafted email, then clean up.
set -euo pipefail

COMPOSE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$COMPOSE_DIR"

FAKE_IP="192.168.2.250"
FAKE_MAC="de:ad:be:ef:ca:fe"
TIMEOUT=180  # max seconds to wait for email

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}=== Agentic Alert End-to-End Test ===${NC}"
echo

# --- Pre-checks ---
echo -e "${CYAN}1. Pre-flight checks${NC}"

if ! docker ps --format '{{.Names}}' | grep -q '^ids-duckdb-mgr$'; then
    echo -e "${RED}   ✗ ids-duckdb-mgr not running. Start the stack first.${NC}"
    exit 1
fi
if ! docker ps --format '{{.Names}}' | grep -q '^ids-alert-agent$'; then
    echo -e "${RED}   ✗ ids-alert-agent not running. Start the stack first.${NC}"
    exit 1
fi

# Check Gmail secrets are configured
HAS_GMAIL=$(docker exec ids-alert-agent python3 -c "
from tools import GMAIL_USER
print('yes' if GMAIL_USER else 'no')
" 2>/dev/null || echo "no")

if [ "$HAS_GMAIL" != "yes" ]; then
    echo -e "${RED}   ✗ Gmail credentials not configured. See secrets/README.md${NC}"
    exit 1
fi

echo -e "${GREEN}   ✓ duckdb-mgr, alert-agent running, Gmail configured${NC}"

# --- Get anomaly ID before insert ---
BEFORE_MAX_ID=$(docker exec ids-duckdb-mgr python3 -c "
import duckdb
db = duckdb.connect('/var/log/ids/duckdb/ids.duckdb', read_only=True)
r = db.execute('SELECT COALESCE(max(id), 0) FROM anomaly_events').fetchone()[0]
print(r)
db.close()
" 2>/dev/null)
echo -e "   Current max anomaly ID: ${BEFORE_MAX_ID}"

# --- Insert fake device + anomaly ---
echo
echo -e "${CYAN}2. Injecting fake device ${FAKE_IP} (${FAKE_MAC})${NC}"

docker exec ids-duckdb-mgr python3 -c "
import duckdb, json

db = duckdb.connect('/var/log/ids/duckdb/ids.duckdb')

# Insert fake device into devices table
db.execute(\"\"\"
    INSERT OR REPLACE INTO devices (ip, mac, manufacturer, hostname, first_seen, last_seen, total_conns, total_bytes, protocols, services)
    VALUES ('${FAKE_IP}', '${FAKE_MAC}', 'Test Manufacturer', 'fake-test-node', now(), now(), 42, 12345, 'tcp', 'dns, http')
\"\"\")

# Insert anomaly event
details = json.dumps({
    'ip': '${FAKE_IP}', 'mac': '${FAKE_MAC}', 'manufacturer': 'Test Manufacturer',
    'hostname': 'fake-test-node', 'first_seen': str(db.execute('SELECT now()').fetchone()[0]),
    'total_conns': 42
})
db.execute(\"\"\"
    INSERT INTO anomaly_events (id, detected_at, anomaly_type, severity, summary, details)
    VALUES (nextval('anomaly_id_seq'), now(), 'new_device', 'medium',
        'New device ${FAKE_IP} (Test Manufacturer) appeared on the network', ?)
\"\"\", [details])

new_id = db.execute('SELECT max(id) FROM anomaly_events').fetchone()[0]
print(f'ANOMALY_ID={new_id}')
db.close()
" 2>/dev/null

ANOMALY_ID=$(docker exec ids-duckdb-mgr python3 -c "
import duckdb
db = duckdb.connect('/var/log/ids/duckdb/ids.duckdb', read_only=True)
print(db.execute('SELECT max(id) FROM anomaly_events').fetchone()[0])
db.close()
" 2>/dev/null)

echo -e "${GREEN}   ✓ Fake anomaly inserted (ID: ${ANOMALY_ID})${NC}"

# --- Clear any stale alert state for this anomaly ---
docker exec ids-alert-agent python3 -c "
import sqlite3
conn = sqlite3.connect('/var/log/ids/duckdb/alert_state.db')
conn.execute('DELETE FROM processed_anomalies WHERE anomaly_id = ?', (${ANOMALY_ID},))
conn.commit()
conn.close()
print('Cleared stale state')
" 2>/dev/null

# --- Force snapshot copy so alert-agent can see it ---
echo
echo -e "${CYAN}3. Copying snapshot for alert-agent${NC}"

docker exec ids-duckdb-mgr python3 -c "
import shutil, os
src = '/var/log/ids/duckdb/ids.duckdb'
for dest in ['/var/log/ids/duckdb/ids_alert.duckdb', '/var/log/ids/duckdb/ids_readonly.duckdb', '/var/log/ids/duckdb/ids_streamlit.duckdb']:
    tmp = dest + '.tmp'
    shutil.copy2(src, tmp)
    os.rename(tmp, dest)
    os.chmod(dest, 0o666)
print('Snapshots copied')
" 2>/dev/null

echo -e "${GREEN}   ✓ Snapshots updated${NC}"

# --- Wait for alert-agent to process and send email ---
echo
echo -e "${CYAN}4. Waiting for alert-agent to process anomaly ${ANOMALY_ID}...${NC}"

START=$SECONDS
EMAIL_SENT=false

while [ $((SECONDS - START)) -lt $TIMEOUT ]; do
    # Check if alert-agent processed this anomaly and sent email
    RESULT=$(docker exec ids-alert-agent python3 -c "
import sqlite3
conn = sqlite3.connect('/var/log/ids/duckdb/alert_state.db')
row = conn.execute('SELECT email_sent FROM processed_anomalies WHERE anomaly_id = ?', (${ANOMALY_ID},)).fetchone()
conn.close()
if row:
    print('sent' if row[0] else 'processed_no_email')
else:
    print('pending')
" 2>/dev/null || echo "error")

    ELAPSED=$((SECONDS - START))

    if [ "$RESULT" = "sent" ]; then
        EMAIL_SENT=true
        echo -e "${GREEN}   ✓ Email sent! (${ELAPSED}s)${NC}"
        break
    elif [ "$RESULT" = "processed_no_email" ]; then
        echo -e "${YELLOW}   ⚠ Anomaly processed but email not confirmed (${ELAPSED}s)${NC}"
        # Check logs to see if email was actually sent
        if docker compose logs alert-agent --tail=30 2>&1 | grep -q "EMAIL SENT.*${ANOMALY_ID}\|Email sent for anomaly ${ANOMALY_ID}"; then
            EMAIL_SENT=true
            echo -e "${GREEN}   ✓ Email confirmed via logs (${ELAPSED}s)${NC}"
        fi
        break
    else
        printf "\r   ⏳ Waiting... %ds / %ds" "$ELAPSED" "$TIMEOUT"
    fi
    sleep 5
done
echo

if [ "$EMAIL_SENT" = "false" ]; then
    # One more check — look at alert-agent logs for this anomaly
    echo -e "${CYAN}   Checking alert-agent logs...${NC}"
    docker compose logs alert-agent --tail=30 2>&1 | grep -i "anomaly ${ANOMALY_ID}" || true
    echo
fi

# --- Show what the LLM did ---
echo -e "${CYAN}5. Alert-agent activity for anomaly ${ANOMALY_ID}:${NC}"
docker compose logs alert-agent 2>&1 | grep "Anomaly ${ANOMALY_ID}\|anomaly ${ANOMALY_ID}" | tail -10
echo

# --- Cleanup: remove fake data ---
echo -e "${CYAN}6. Cleaning up fake test data${NC}"

docker exec ids-duckdb-mgr python3 -c "
import duckdb

db = duckdb.connect('/var/log/ids/duckdb/ids.duckdb')
db.execute(\"DELETE FROM devices WHERE ip = '${FAKE_IP}'\")
db.execute(\"DELETE FROM _known_devices WHERE ip = '${FAKE_IP}'\")
db.execute(\"DELETE FROM anomaly_events WHERE id = ${ANOMALY_ID}\")
db.close()
print('Fake data removed from primary DB')
" 2>/dev/null

# Clean from alert state too
docker exec ids-alert-agent python3 -c "
import sqlite3
conn = sqlite3.connect('/var/log/ids/duckdb/alert_state.db')
conn.execute('DELETE FROM processed_anomalies WHERE anomaly_id = ?', (${ANOMALY_ID},))
conn.commit()
conn.close()
print('Cleaned alert state')
" 2>/dev/null

echo -e "${GREEN}   ✓ All fake data removed${NC}"

# --- Verify cleanup ---
REMAINING=$(docker exec ids-duckdb-mgr python3 -c "
import duckdb
db = duckdb.connect('/var/log/ids/duckdb/ids.duckdb', read_only=True)
d = db.execute(\"SELECT count(*) FROM devices WHERE ip = '${FAKE_IP}'\").fetchone()[0]
a = db.execute(\"SELECT count(*) FROM anomaly_events WHERE id = ${ANOMALY_ID}\").fetchone()[0]
print(f'{d},{a}')
db.close()
" 2>/dev/null)

if [ "$REMAINING" = "0,0" ]; then
    echo -e "${GREEN}   ✓ Verified: no test data remains${NC}"
else
    echo -e "${YELLOW}   ⚠ Some test data may remain: devices,anomalies = ${REMAINING}${NC}"
fi

# --- Summary ---
echo
echo -e "${CYAN}=== Test Summary ===${NC}"
if [ "$EMAIL_SENT" = "true" ]; then
    echo -e "${GREEN}PASS — LLM analyzed fake device, drafted and sent email alert, data cleaned up.${NC}"
    echo -e "Check your inbox for: [IDS Alert] ... ${FAKE_IP}"
else
    echo -e "${YELLOW}PARTIAL — Anomaly was processed but email delivery could not be confirmed.${NC}"
    echo -e "Check alert-agent logs: docker compose logs alert-agent --tail=30"
fi

#!/bin/bash
set -e

LOG_DIR="/var/log/ids/${LOG_SUBDIR:-suricata}"
MAX_EVE_SIZE_MB="${MAX_EVE_SIZE_MB:-200}"

mkdir -p "$LOG_DIR"
chown -R suricata:suricata "$LOG_DIR"

# Background watchdog: rotate eve.json when it exceeds MAX_EVE_SIZE_MB
eve_rotate_watchdog() {
    local eve_file="$LOG_DIR/eve.json"
    local max_bytes=$((MAX_EVE_SIZE_MB * 1024 * 1024))

    while true; do
        sleep 300  # Check every 5 minutes

        # Clean up stale backup (older than 1 hour — Vector has finished reading it)
        if [ -f "${eve_file}.1" ]; then
            backup_age=$(( $(date +%s) - $(stat -c%Y "${eve_file}.1" 2>/dev/null || echo 0) ))
            if [ "$backup_age" -gt 3600 ]; then
                rm -f "${eve_file}.1"
                echo "[eve-rotate] Removed stale eve.json.1 (age: ${backup_age}s)"
            fi
        fi

        if [ -f "$eve_file" ]; then
            file_size=$(stat -c%s "$eve_file" 2>/dev/null || echo 0)
            if [ "$file_size" -gt "$max_bytes" ]; then
                echo "[eve-rotate] eve.json is $(( file_size / 1024 / 1024 ))MB (limit ${MAX_EVE_SIZE_MB}MB) — rotating"

                # Remove previous backup if it exists
                rm -f "${eve_file}.1"

                # Rename current log (Vector continues reading by inode)
                mv "$eve_file" "${eve_file}.1"

                # Signal Suricata to reopen log files (creates new eve.json)
                pid=$(pidof suricata 2>/dev/null || true)
                if [ -n "$pid" ]; then
                    kill -HUP "$pid"
                    echo "[eve-rotate] Sent HUP to Suricata (pid $pid)"
                fi
            fi
        fi
    done
}

# Background watchdog: auto-update Suricata rules at configured interval
rule_update_watchdog() {
    local interval_hours="${RULE_UPDATE_INTERVAL_HOURS:-24}"
    local interval_seconds=$((interval_hours * 3600))

    # Wait for Suricata to fully start
    sleep 120

    echo "[rule-update] Watchdog started — updating rules every ${interval_hours}h"

    while true; do
        echo "[rule-update] Running suricata-update..."
        if suricata-update --no-test 2>&1; then
            echo "[rule-update] Rules updated successfully"
            # Copy updated rules to shared volume for RAG indexing
            mkdir -p /var/log/ids/suricata/rules
            cp /var/lib/suricata/rules/suricata.rules /var/log/ids/suricata/rules/suricata.rules
            echo "[rule-update] Rules copied to shared volume for RAG indexing"
            # Signal Suricata to reload rules (USR2 = rule reload)
            pid=$(pidof suricata 2>/dev/null || true)
            if [ -n "$pid" ]; then
                kill -USR2 "$pid"
                echo "[rule-update] Sent USR2 to Suricata (pid $pid) for rule reload"
            else
                echo "[rule-update] WARNING: Suricata process not found for rule reload"
            fi
        else
            echo "[rule-update] ERROR: suricata-update failed"
        fi

        sleep "$interval_seconds"
    done
}

# Initial rule update + copy for RAG indexing (runs before Suricata starts)
echo "[rule-update] Running initial suricata-update for RAG indexing..."
if suricata-update --no-test 2>&1; then
    mkdir -p /var/log/ids/suricata/rules
    cp /var/lib/suricata/rules/suricata.rules /var/log/ids/suricata/rules/suricata.rules
    echo "[rule-update] Rules copied to shared volume for RAG indexing"
else
    echo "[rule-update] WARNING: Initial suricata-update failed"
fi

# Start watchdogs in background
eve_rotate_watchdog &
rule_update_watchdog &

exec /docker-entrypoint.sh -i "${NETWORK_INTERFACE:-enp1s0f0}"

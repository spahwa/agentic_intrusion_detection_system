#!/usr/bin/env python3
"""Alert agent — polls anomaly_events, uses LLM to analyze and send email alerts."""

import json
import logging
import os
import sqlite3
import threading
import time

import duckdb
import ollama

from system_prompt import SYSTEM_PROMPT
from tools import TOOL_DEFINITIONS, TOOL_MAP, send_email, rag_search_threat_intel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("alert-agent")

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5:3b")
DUCKDB_PATH = os.environ.get("DUCKDB_PATH", "/var/log/ids/duckdb/ids_readonly.duckdb")
ALERT_STATE_PATH = os.environ.get("ALERT_STATE_PATH", "/var/log/ids/duckdb/alert_state.db")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "10"))
FAST_ALERTS_PATH = os.environ.get("FAST_ALERTS_PATH", "/var/log/ids/duckdb/fast_alerts.db")
FAST_POLL_INTERVAL = 2
MAX_TOOL_ROUNDS = 5
NUM_CTX = 4096


def init_state_db() -> sqlite3.Connection:
    """Initialize the SQLite state DB for tracking processed anomalies."""
    conn = sqlite3.connect(ALERT_STATE_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS processed_anomalies (
            anomaly_id INTEGER,
            detected_at TEXT,
            processed_at TEXT DEFAULT (datetime('now')),
            email_sent BOOLEAN DEFAULT FALSE,
            PRIMARY KEY (anomaly_id, detected_at)
        )
    """)
    # Migrate existing single-column PRIMARY KEY tables (add detected_at if missing)
    try:
        conn.execute("ALTER TABLE processed_anomalies ADD COLUMN detected_at TEXT")
        # Re-create with composite PK is not possible in SQLite via ALTER;
        # existing rows get detected_at=NULL which won't collide with real timestamps.
        conn.commit()
    except Exception:
        pass  # Column already exists — schema is up to date
    conn.commit()
    return conn


def get_unprocessed_anomalies(state_conn: sqlite3.Connection) -> list:
    """Read anomaly_events from DuckDB readonly snapshot, filter out already-processed ones."""
    for attempt in range(3):
        try:
            db = duckdb.connect(DUCKDB_PATH, read_only=True)
            try:
                rows = db.execute("""
                    SELECT id, detected_at, anomaly_type, severity, summary, details
                    FROM anomaly_events
                    ORDER BY detected_at ASC
                """).fetchall()
            finally:
                db.close()
            break
        except duckdb.IOException:
            log.warning("DuckDB locked (attempt %d/3), retrying...", attempt + 1)
            time.sleep(2)
        except Exception:
            log.exception("Failed to read anomaly_events from DuckDB")
            return []
    else:
        log.warning("DuckDB locked after 3 retries, skipping this cycle")
        return []

    # Dedup by (anomaly_id, detected_at) to survive DuckDB sequence resets after DB recreation.
    # Old rows have detected_at=NULL; new rows carry the real timestamp — so they never collide.
    processed_keys = set()
    for row in state_conn.execute(
        "SELECT anomaly_id, detected_at FROM processed_anomalies"
    ).fetchall():
        processed_keys.add((row[0], row[1]))

    unprocessed = []
    for row in rows:
        anomaly_id = row[0]
        detected_at = str(row[1])
        if (anomaly_id, detected_at) not in processed_keys:
            unprocessed.append({
                "id": anomaly_id,
                "detected_at": detected_at,
                "anomaly_type": row[2],
                "severity": row[3],
                "summary": row[4],
                "details": row[5],
            })

    return unprocessed


def process_anomaly(client: ollama.Client, anomaly: dict) -> bool:
    """Use LLM to analyze an anomaly and send an email alert. Returns True if successful."""
    # Build the user message with anomaly context
    details_str = anomaly["details"] if anomaly["details"] else "{}"
    try:
        details_parsed = json.loads(details_str) if isinstance(details_str, str) else details_str
        details_formatted = json.dumps(details_parsed, indent=2)
    except (json.JSONDecodeError, TypeError):
        details_formatted = str(details_str)

    # Auto-enrich suricata_alert anomalies with threat intel context from RAG
    threat_context_section = ""
    if anomaly["anomaly_type"] == "suricata_alert":
        try:
            details_obj = json.loads(anomaly.get("details") or "{}")
            signature = details_obj.get("signature", "") or anomaly.get("summary", "")
            if signature:
                rag_result = json.loads(rag_search_threat_intel(signature, top_k=3))
                if rag_result.get("results"):
                    lines = ["Threat Intel Context (from local Suricata rule database):"]
                    for r in rag_result["results"]:
                        lines.append(
                            f"  - {r['msg']} (SID {r['sid']}, category: {r['classtype']}): {r['context']}"
                        )
                    threat_context_section = "\n".join(lines) + "\n\n"
                    log.info("RAG pre-enrichment: %d rules found for signature '%s'", len(rag_result["results"]), signature[:60])
        except Exception:
            log.warning("RAG pre-enrichment failed", exc_info=True)

    user_message = (
        f"Anomaly detected: {anomaly['anomaly_type']} (severity: {anomaly['severity']})\n"
        f"Time: {anomaly['detected_at']}\n"
        f"Summary: {anomaly['summary']}\n"
        f"Details:\n{details_formatted}\n\n"
        f"{threat_context_section}"
        f"Analyze this anomaly. Query the database for additional context if needed, "
        f"then draft and send an email alert."
    )

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_message},
    ]

    email_sent = False

    for round_num in range(MAX_TOOL_ROUNDS):
        try:
            response = client.chat(
                model=OLLAMA_MODEL,
                messages=messages,
                tools=TOOL_DEFINITIONS,
                options={"num_ctx": NUM_CTX},
            )
        except Exception:
            log.exception("Ollama chat failed for anomaly %d", anomaly["id"])
            return False

        msg = response.message
        messages.append(msg)

        if not msg.tool_calls:
            # LLM finished without more tool calls
            if msg.content:
                log.info("LLM response for anomaly %d: %s", anomaly["id"], msg.content[:200])
            else:
                log.warning("LLM returned empty response for anomaly %d (round %d)", anomaly["id"], round_num)

            # If email hasn't been sent yet, nudge the LLM to call send_email
            if not email_sent and round_num < MAX_TOOL_ROUNDS - 1:
                messages.append({
                    "role": "user",
                    "content": "You must now call the send_email tool to send an alert email about this anomaly. Use the send_email function.",
                })
                continue
            break

        for tool_call in msg.tool_calls:
            fn_name = tool_call.function.name
            fn_args = tool_call.function.arguments
            log.info("Anomaly %d: calling %s(%s)", anomaly["id"], fn_name, json.dumps(fn_args)[:200])

            if fn_name in TOOL_MAP:
                result = TOOL_MAP[fn_name](fn_args)
            else:
                result = json.dumps({"error": f"Unknown tool: {fn_name}"})

            if fn_name == "send_email":
                try:
                    parsed = json.loads(result)
                    if parsed.get("success"):
                        email_sent = True
                        log.info("Email sent for anomaly %d: %s", anomaly["id"], parsed.get("subject", ""))
                    else:
                        log.warning("Email failed for anomaly %d: %s", anomaly["id"], parsed.get("error", ""))
                except (json.JSONDecodeError, TypeError):
                    pass

            messages.append({"role": "tool", "content": result})

    return email_sent


def mark_processed(state_conn: sqlite3.Connection, anomaly_id: int, email_sent: bool, detected_at: str = "") -> None:
    """Mark an anomaly as processed in the SQLite state DB."""
    state_conn.execute(
        "INSERT OR REPLACE INTO processed_anomalies (anomaly_id, detected_at, email_sent) VALUES (?, ?, ?)",
        (anomaly_id, detected_at, email_sent),
    )
    state_conn.commit()


def wait_for_ollama(client: ollama.Client) -> None:
    """Wait until Ollama is reachable and the model is available."""
    while True:
        try:
            models = client.list()
            model_names = [m.model for m in models.models]
            if any(OLLAMA_MODEL in name for name in model_names):
                log.info("Ollama ready with model %s", OLLAMA_MODEL)
                return
            log.warning("Model %s not found, available: %s", OLLAMA_MODEL, model_names)
        except Exception as e:
            log.warning("Waiting for Ollama: %s", e)
        time.sleep(10)


def wait_for_duckdb() -> None:
    """Wait until the DuckDB readonly snapshot exists."""
    while not os.path.exists(DUCKDB_PATH):
        log.info("Waiting for DuckDB snapshot at %s ...", DUCKDB_PATH)
        time.sleep(10)


def fast_alert_loop() -> None:
    """Daemon thread: poll fast_alerts.db every 2s and send immediate emails for new devices.

    Uses the 'alert_emailed' flag (independent of duckdb-mgr's 'duckdb_drained' flag)
    so both paths operate without race conditions.
    """
    log.info("fast_alert_loop: started (polling %s every %ds)", FAST_ALERTS_PATH, FAST_POLL_INTERVAL)
    while True:
        try:
            if os.path.exists(FAST_ALERTS_PATH):
                conn = sqlite3.connect(FAST_ALERTS_PATH, timeout=5)
                rows = conn.execute(
                    "SELECT id, detected_at, ip, mac FROM fast_new_devices WHERE alert_emailed = 0"
                ).fetchall()

                for row_id, detected_at, ip, mac in rows:
                    subject = f"[IDS FAST ALERT] New Device: {ip}"
                    body = (
                        f"New device detected on the network.\n\n"
                        f"IP Address:  {ip}\n"
                        f"MAC Address: {mac or 'unknown'}\n"
                        f"Detected At: {detected_at}\n\n"
                        f"This is an automated fast alert.\n"
                        f"A detailed LLM analysis email will follow shortly."
                    )
                    try:
                        result = json.loads(send_email(subject=subject, body=body))
                        if result.get("success"):
                            log.info("fast_alert_loop: email sent for new device %s", ip)
                        else:
                            log.warning(
                                "fast_alert_loop: email failed for %s: %s",
                                ip, result.get("error"),
                            )
                    except Exception:
                        log.exception("fast_alert_loop: send_email raised for %s", ip)

                    conn.execute(
                        "UPDATE fast_new_devices SET alert_emailed = 1 WHERE id = ?", (row_id,)
                    )
                    conn.commit()

                conn.close()
        except Exception:
            log.exception("fast_alert_loop: error")

        time.sleep(FAST_POLL_INTERVAL)


def main() -> None:
    log.info(
        "Starting alert-agent: model=%s duckdb=%s poll=%ds fast_poll=%ds",
        OLLAMA_MODEL, DUCKDB_PATH, POLL_INTERVAL, FAST_POLL_INTERVAL,
    )

    # Start fast-path email thread (runs independently, no Ollama needed)
    fast_thread = threading.Thread(target=fast_alert_loop, name="FastAlertLoop", daemon=True)
    fast_thread.start()

    # Wait for dependencies
    wait_for_duckdb()
    client = ollama.Client(host=OLLAMA_HOST)
    wait_for_ollama(client)

    state_conn = init_state_db()

    while True:
        try:
            anomalies = get_unprocessed_anomalies(state_conn)
            if anomalies:
                log.info("Found %d unprocessed anomaly/anomalies", len(anomalies))

            for anomaly in anomalies:
                log.info(
                    "Processing anomaly %d: %s (%s)",
                    anomaly["id"], anomaly["anomaly_type"], anomaly["severity"],
                )
                email_sent = process_anomaly(client, anomaly)
                mark_processed(state_conn, anomaly["id"], email_sent, anomaly["detected_at"])

        except Exception:
            log.exception("Error in alert-agent main loop")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()

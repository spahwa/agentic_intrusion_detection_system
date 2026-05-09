# Reactive Alert Agent — End-to-End Flow

How a network event traverses the stack from packet capture to LLM-drafted email alert.

## Pipeline Diagram

```
                            REACTIVE ALERT AGENT — END-TO-END FLOW

┌─────────────────────────────────────────────────────────────────────────────────────┐
│                          STAGE 0 — RAW DATA CAPTURE                                  │
│                                                                                      │
│   wlp2s0 (NIC)  ──┬──► Suricata ──► /var/log/ids/suricata/eve.json                  │
│                   │                                                                  │
│                   └──► Zeek     ──► /var/log/ids/zeek/{conn,dns,ssl,...}.log        │
└─────────────────────────────────────────────────────────────────────────────────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                       STAGE 1 — NORMALIZE & STAGE                                    │
│                                                                                      │
│   Vector  ──► /var/log/ids/vector/**/YYYY-MM-DD-HH.ndjson                            │
│             (hourly partitioned NDJSON, normalized via VRL transforms)               │
└─────────────────────────────────────────────────────────────────────────────────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│            STAGE 2 — INGEST + DETECT  (duckdb-mgr, every 10s cycle)                  │
│                                                                                      │
│   ┌─────────────────────────────────────────────────────────────────────────────┐   │
│   │ 1. read_json(*.ndjson) ──► INSERT INTO events (raw JSON)                    │   │
│   │ 2. TTL purge: DELETE events older than 24h                                  │   │
│   │ 3. Rebuild devices / external_ips (every 5 min)                             │   │
│   │ 4. RUN 7 ANOMALY DETECTORS:  ◄── THIS IS THE GATEKEEPER                     │   │
│   │                                                                             │   │
│   │      ┌──────────────────────┬────────────────────────────────────────┐     │   │
│   │      │ Detector             │ Trigger                                │     │   │
│   │      ├──────────────────────┼────────────────────────────────────────┤     │   │
│   │      │ new_device           │ IP not in _known_devices               │     │   │
│   │      │ traffic_spike        │ 5min conns > 5× hourly avg             │     │   │
│   │      │ suricata_alert       │ severity 1 or 2 in last 5 min          │     │   │
│   │      │ suspicious_country   │ traffic to watchlist country           │     │   │
│   │      │ massive_volume       │ device > VOLUME_THRESHOLD_MB / 5min    │     │   │
│   │      │ device_behavior      │ bytes/conns > BEHAVIOR_RATIO × EMA     │     │   │
│   │      │ dest_fanout          │ unique dest IPs > FANOUT_RATIO × EMA   │     │   │
│   │      └──────────────────────┴────────────────────────────────────────┘     │   │
│   │                                                                             │   │
│   │ 5. INSERT INTO anomaly_events (id, detected_at, type, severity, summary,   │   │
│   │                                 details JSON)                               │   │
│   └─────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                      │
│   ┌─────────────────────────────────────────────────────────────────────────────┐   │
│   │  FAST PATH (parallel, runs every 1s in IPWatcher thread)                    │   │
│   │  Tail Zeek conn.log  ──► new private IP?  ──► INSERT fast_alerts.db         │   │
│   │  (skips DuckDB entirely — pure SQLite, sub-2s latency)                      │   │
│   └─────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                      │
│   6. shutil.copy2 ids.duckdb ──► ids_readonly.duckdb  (atomic snapshot)              │
└─────────────────────────────────────────────────────────────────────────────────────┘
                    │                                              │
                    ▼                                              ▼
        ╔═══════════════════════╗                  ╔════════════════════════════╗
        ║  ids_readonly.duckdb  ║                  ║     fast_alerts.db         ║
        ║   ┌─────────────────┐ ║                  ║  ┌──────────────────────┐  ║
        ║   │ anomaly_events  │ ║                  ║  │ fast_new_devices     │  ║
        ║   │   id            │ ║                  ║  │   id                 │  ║
        ║   │   detected_at   │ ║                  ║  │   detected_at        │  ║
        ║   │   anomaly_type  │ ║                  ║  │   ip, mac            │  ║
        ║   │   severity      │ ║                  ║  │   alert_emailed flag │  ║
        ║   │   summary       │ ║                  ║  │   duckdb_drained flag│  ║
        ║   │   details JSON  │ ║                  ║  └──────────────────────┘  ║
        ║   └─────────────────┘ ║                  ╚════════════════════════════╝
        ╚═══════════════════════╝                              │
                    │                                          │ poll every 2s
                    │ poll every 10s                           │ (fast_alert_loop thread)
                    ▼                                          ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                       STAGE 3 — alert-agent CONSUMER                                 │
│                                                                                      │
│   ┌─────────────── LLM PATH (main loop) ──────────────┐  ┌──── FAST PATH ──────┐    │
│   │                                                    │  │                     │    │
│   │ get_unprocessed_anomalies()                        │  │ SELECT * FROM       │    │
│   │   SELECT * FROM anomaly_events                     │  │  fast_new_devices   │    │
│   │   MINUS rows in alert_state.db                     │  │  WHERE              │    │
│   │   (dedup key = (anomaly_id, detected_at))          │  │   alert_emailed=0   │    │
│   │                                                    │  │                     │    │
│   │ for each new anomaly:                              │  │ for each row:       │    │
│   │                                                    │  │   build template    │    │
│   │   ┌─ if anomaly_type == 'suricata_alert':          │  │   send_email()      │    │
│   │   │    rag_search_threat_intel(signature)          │  │   UPDATE            │    │
│   │   │    inject top-3 rules into prompt              │  │    alert_emailed=1  │    │
│   │   └─                                               │  │                     │    │
│   │                                                    │  │  (NO LLM —          │    │
│   │   build user_message {summary, details, context}   │  │   fixed template)   │    │
│   │                                                    │  └─────────────────────┘    │
│   │   ┌── TOOL-CALLING LOOP (max 5 rounds) ──┐         │                              │
│   │   │                                       │         │                              │
│   │   │  client.chat(model=qwen3.5:2b,        │         │                              │
│   │   │              tools=[query_events,     │         │                              │
│   │   │                     send_email,       │         │                              │
│   │   │                     rag_search...])   │         │                              │
│   │   │           │                           │         │                              │
│   │   │           ▼                           │         │                              │
│   │   │   LLM decides:                        │         │                              │
│   │   │    • call query_events for context?   │         │                              │
│   │   │    • call rag_search for related      │         │                              │
│   │   │      intel?                           │         │                              │
│   │   │    • call send_email with drafted     │         │                              │
│   │   │      subject + body?                  │         │                              │
│   │   │           │                           │         │                              │
│   │   │           ▼                           │         │                              │
│   │   │   tool result ──► append to messages  │         │                              │
│   │   │   ──► next round                      │         │                              │
│   │   │                                       │         │                              │
│   │   │   exit when: no more tool_calls       │         │                              │
│   │   │             OR email_sent == True     │         │                              │
│   │   └───────────────────────────────────────┘         │                              │
│   │                                                    │                              │
│   │   mark_processed() → INSERT alert_state.db          │                              │
│   │     (anomaly_id, detected_at, email_sent)           │                              │
│   └────────────────────────────────────────────────────┘                              │
└─────────────────────────────────────────────────────────────────────────────────────┘
                    │                                          │
                    └──────────────────┬───────────────────────┘
                                       ▼
                          ┌─────────────────────────┐
                          │   smtp.gmail.com:465    │
                          │   ──► alert recipient   │
                          └─────────────────────────┘
```

## Worked Example — `suricata_alert` severity-1 hit

1. Suricata writes alert JSON → `eve.json`
2. Vector tails the file, normalizes, writes line to `vector/suricata/eve/<hour>.ndjson`
3. duckdb-mgr ingests NDJSON → row appears in `events` table
4. Detector `suricata_alert` runs (next 10s cycle), sees severity ≤ 2 in last 5 min, no cooldown for this signature → `INSERT INTO anomaly_events`
5. Snapshot copy → `ids_readonly.duckdb`
6. alert-agent polls (10s), sees new `(anomaly_id, detected_at)` not in `alert_state.db`
7. Because `anomaly_type == 'suricata_alert'`, it runs `rag_search_threat_intel(signature)` → injects matching Suricata rules from `rag.duckdb` into the prompt
8. LLM gets the prompt + 3 tools (`query_events`, `send_email`, `rag_search_threat_intel`)
9. LLM may call `query_events` for related conn flows (community-id), then calls `send_email`
10. `send_email` returns `success: true` → `email_sent = True`
11. `mark_processed` inserts `(anomaly_id, detected_at, email_sent=True)` into `alert_state.db` — won't be re-processed

## Two Independent Paths

| Path | Trigger | Latency | LLM | Email Style |
|------|---------|---------|-----|-------------|
| **Fast** | New private IP in Zeek conn.log | ~2 s | No | Fixed template |
| **LLM** | Row in `anomaly_events` (any of 7 detectors) | ~10–60 s | Yes (qwen3.5:2b) | Drafted with investigation context |

Both run concurrently. The fast path uses the `alert_emailed` flag; duckdb-mgr's drain uses the independent `duckdb_drained` flag — neither consumer blocks the other.

## Key Design Decision — Where the Gate Lives

The alert-agent does **not** decide what's worth alerting on. The 7 detectors in `duckdb-mgr` are the deterministic gatekeepers. Anything that lands in `anomaly_events` is forwarded to the LLM. The LLM's job is to *investigate and explain* the anomaly, not to filter it.

## Related Files

- `duckdb-mgr/main.py` — anomaly detectors, snapshot copy
- `alert-agent/main.py` — consumer loop, fast-path thread, tool-calling loop
- `alert-agent/tools.py` — `send_email`, `query_events`, `rag_search_threat_intel`
- `alert-agent/system_prompt.py` — analyst persona for LLM

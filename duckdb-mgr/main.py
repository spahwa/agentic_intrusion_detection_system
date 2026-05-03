#!/usr/bin/env python3
"""DuckDB manager — ingests Vector NDJSON staging files into DuckDB and purges old records."""

import csv
import glob
import gzip
import json as _json
import logging
import os
import re
import shutil
import socket
import sqlite3
import struct
import subprocess
import threading
import time
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

import duckdb

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("duckdb-mgr")

DUCKDB_PATH = os.environ.get("DUCKDB_PATH", "/var/log/ids/duckdb/ids.duckdb")
DUCKDB_READONLY_PATH = DUCKDB_PATH.replace(".duckdb", "_readonly.duckdb")  # Grafana
DUCKDB_STREAMLIT_PATH = DUCKDB_PATH.replace(".duckdb", "_streamlit.duckdb")  # Streamlit
DUCKDB_ALERT_PATH = DUCKDB_PATH.replace(".duckdb", "_alert.duckdb")  # alert-agent
VECTOR_STAGING_DIR = os.environ.get("VECTOR_STAGING_DIR", "/var/log/ids/vector")
ZEEK_LOG_DIR = os.environ.get("ZEEK_LOG_DIR", "/var/log/ids/zeek")
TTL_HOURS = int(os.environ.get("TTL_HOURS", "72"))
STAGING_RETENTION_HOURS = int(os.environ.get("STAGING_RETENTION_HOURS", "6"))
INGEST_INTERVAL = int(os.environ.get("INGEST_INTERVAL_SECONDS", "10"))
MAX_DB_SIZE_MB = int(os.environ.get("MAX_DB_SIZE_MB", "4000"))
MAX_STAGING_SIZE_MB = int(os.environ.get("MAX_STAGING_SIZE_MB", "1024"))
MAX_ZEEK_LOGS_SIZE_MB = int(os.environ.get("MAX_ZEEK_LOGS_SIZE_MB", "1024"))
VACUUM_EVERY_N_CYCLES = 10  # VACUUM every 10 cycles (~10 minutes)
COMPACT_BLOAT_RATIO = 3.0   # Compact when file is this many times larger than estimated live data
SUMMARY_REBUILD_EVERY_N_CYCLES = 5  # Rebuild device/external_ips every 5 cycles (~5 min)

# Tables preserved during compaction (OUI/GeoIP are reloaded from cached CSV files)
TABLES_TO_PRESERVE = [
    "events", "_ingested_files", "anomaly_events",
    "_known_devices", "device_baselines", "nmap_scans",
]
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")

# --- Anomaly detection tunables ---
SPIKE_RATIO = float(os.environ.get("SPIKE_RATIO", "5.0"))         # Fire only when 5x above avg
SPIKE_MIN_CONNS = int(os.environ.get("SPIKE_MIN_CONNS", "1000"))  # Absolute minimum to trigger
SPIKE_COOLDOWN_MIN = int(os.environ.get("SPIKE_COOLDOWN_MIN", "60"))  # Minutes between spike alerts
VOLUME_THRESHOLD_MB = int(os.environ.get("VOLUME_THRESHOLD_MB", "500"))  # MB in 5 min per device
VOLUME_COOLDOWN_MIN = int(os.environ.get("VOLUME_COOLDOWN_MIN", "60"))
SUSPICIOUS_COUNTRIES = os.environ.get("SUSPICIOUS_COUNTRIES", "CN,RU,KP,IR,BY").split(",")
COUNTRY_COOLDOWN_MIN = int(os.environ.get("COUNTRY_COOLDOWN_MIN", "60"))
BEHAVIOR_RATIO = float(os.environ.get("BEHAVIOR_RATIO", "10.0"))   # Alert when device exceeds 10x its own baseline
BEHAVIOR_MIN_SAMPLES = int(os.environ.get("BEHAVIOR_MIN_SAMPLES", "3"))  # Need at least 3 samples before alerting
FANOUT_RATIO = float(os.environ.get("FANOUT_RATIO", "5.0"))        # Alert when unique dest IPs > 5x baseline
FANOUT_MIN_IPS = int(os.environ.get("FANOUT_MIN_IPS", "10"))       # Minimum unique dest IPs to trigger
BASELINE_EMA_ALPHA = float(os.environ.get("BASELINE_EMA_ALPHA", "0.3"))  # EMA smoothing factor (higher = faster adapt)

# --- Nmap scheduled scanning ---
NMAP_SUBNET = os.environ.get("NMAP_SUBNET", "192.168.2.0/24")
NMAP_SCAN_INTERVAL_HOURS = int(os.environ.get("NMAP_SCAN_INTERVAL_HOURS", "168"))  # Weekly
NMAP_TIMEOUT = 600  # seconds
NMAP_RESULTS_SQLITE = os.path.join(
    os.path.dirname(os.environ.get("DUCKDB_PATH", "/var/log/ids/duckdb/ids.duckdb")),
    "nmap_results.db",
)

# OUI + GeoIP data paths
DB_DIR = os.path.dirname(os.environ.get("DUCKDB_PATH", "/var/log/ids/duckdb/ids.duckdb"))
OUI_CSV_PATH = os.path.join(DB_DIR, "oui.csv")
OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"
OUI_REFRESH_SECONDS = 7 * 86400  # Refresh weekly

GEOIP_GZ_PATH = os.path.join(DB_DIR, "geoip.csv.gz")
GEOIP_REFRESH_SECONDS = 30 * 86400  # Refresh monthly

FAST_ALERTS_PATH = os.environ.get("FAST_ALERTS_PATH", os.path.join(DB_DIR, "fast_alerts.db"))
ALERT_STATE_PATH = os.environ.get("ALERT_STATE_PATH", os.path.join(DB_DIR, "alert_state.db"))

# Regex to extract hour partition from NDJSON filename: YYYY-MM-DD-HH.ndjson
HOUR_PATTERN = re.compile(r"(\d{4}-\d{2}-\d{2}-\d{2})\.ndjson$")

# --- Threat Intel RAG ---
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
RAG_AUTO_INDEX = os.environ.get("RAG_AUTO_INDEX", "false").lower() == "true"
RAG_DUCKDB_PATH = os.environ.get("RAG_DUCKDB_PATH", "/var/log/ids/duckdb/rag.duckdb")
RAG_STAGING_PATH = RAG_DUCKDB_PATH + ".staging"
RULES_PATH = "/var/log/ids/suricata/rules/suricata.rules"
EMBED_MODEL = os.environ.get("EMBED_MODEL", "nomic-embed-text")
EMBED_BATCH_SIZE = 50

CLASSTYPE_DESCRIPTIONS = {
    "trojan-activity": "A network trojan was detected — malware C2 or dropper activity",
    "attempted-admin": "Attempted administrator privilege gain — exploitation of admin services",
    "attempted-user": "Attempted user privilege gain — local or remote privilege escalation",
    "shellcode-detect": "Executable code was detected — shellcode injection or memory exploit",
    "successful-admin": "Successful administrator privilege gain",
    "successful-user": "Successful user privilege gain",
    "unsuccessful-user": "Unsuccessful user privilege gain attempt",
    "policy-violation": "Potential corporate privacy violation or policy breach",
    "network-scan": "Detection of a network scan — port scanning or host discovery",
    "denial-of-service": "Detection of a denial of service attack",
    "attempted-dos": "Attempted denial of service attack",
    "successful-dos": "Successful denial of service attack",
    "protocol-command-decode": "A suspicious protocol command was decoded",
    "web-application-attack": "Web application attack — SQL injection, XSS, or RCE attempt",
    "exploit-kit": "Exploit kit activity detected",
    "inappropriate-content": "Inappropriate content was detected",
    "misc-attack": "Miscellaneous attack detected",
    "misc-activity": "Miscellaneous activity detected",
    "bad-unknown": "Unknown traffic with bad characteristics",
    "not-suspicious": "Not a suspicious traffic pattern",
    "unknown": "Unknown traffic classification",
    "potential-vulnerability": "Traffic that could exploit a known vulnerability",
    "credential-theft": "Credential theft or credential harvesting activity",
    "targeted-activity": "Targeted malicious activity",
    "command-and-control": "Command and control (C2) communication detected",
}

# Regex patterns for Suricata rule parsing
_SID_RE = re.compile(r"\bsid:\s*(\d+)\s*;")
_MSG_RE = re.compile(r'\bmsg:\s*"([^"]+)"\s*;')
_CLASSTYPE_RE = re.compile(r"\bclasstype:\s*([^;]+?)\s*;")
_METADATA_RE = re.compile(r"\bmetadata:\s*([^;]+?)\s*;")

# Global state for background RAG indexer thread
_rag_thread: threading.Thread | None = None
_rag_last_mtime: float = 0.0


def init_db(db: duckdb.DuckDBPyConnection) -> None:
    """Run schema.sql to create tables and indexes if they don't exist."""
    # Check if schema already exists
    needs_full_init = False
    try:
        db.execute("SELECT 1 FROM _ingested_files LIMIT 0")
        db.execute("SELECT 1 FROM events LIMIT 0")
        # Both tables exist — check for source_file column migration
        cols = [r[0] for r in db.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_name = 'events'"
        ).fetchall()]
        if cols and "source_file" not in cols:
            log.info("Migrating: adding source_file column to events table")
            db.execute("DROP TABLE IF EXISTS events")
            db.execute("DELETE FROM _ingested_files")
            needs_full_init = True
    except Exception:
        needs_full_init = True  # Tables don't exist yet

    # Always run schema.sql — all statements are idempotent (CREATE IF NOT EXISTS)
    # This ensures new tables (oui_lookup, geoip_lookup, devices, external_ips) get created
    # even on existing databases that only have events + _ingested_files.
    schema_sql = Path(SCHEMA_PATH).read_text()
    for statement in schema_sql.split(";"):
        statement = statement.strip()
        if statement:
            db.execute(statement)
    if needs_full_init:
        log.info("Schema initialized")

    # Create ip_to_uint macro for GeoIP lookups (CREATE OR REPLACE is idempotent)
    db.execute("""
        CREATE OR REPLACE MACRO ip_to_uint(ip) AS (
            CAST(split_part(ip, '.', 1) AS UINTEGER) * 16777216 +
            CAST(split_part(ip, '.', 2) AS UINTEGER) * 65536 +
            CAST(split_part(ip, '.', 3) AS UINTEGER) * 256 +
            CAST(split_part(ip, '.', 4) AS UINTEGER)
        )
    """)

    # Load OUI + GeoIP data (idempotent, checks mtime)
    load_oui_database(db)
    load_geoip_database(db)


def _sync_anomaly_seq(db: duckdb.DuckDBPyConnection) -> None:
    """Advance anomaly_id_seq past the max ID in alert_state.db to prevent ID collisions.

    When DuckDB is recreated the sequence resets to 1, but alert_state.db retains
    processed anomaly IDs from the previous DB incarnation.  New anomalies then get
    IDs that collide with old processed IDs and are silently skipped by alert-agent.

    This function reads the max processed ID from alert_state.db and advances the
    DuckDB sequence past it (with a 100-ID buffer).  Safe to call on every startup
    and after DB recreation.
    """
    try:
        max_id = 0
        if os.path.exists(ALERT_STATE_PATH):
            conn = sqlite3.connect(ALERT_STATE_PATH, timeout=5)
            row = conn.execute(
                "SELECT COALESCE(max(anomaly_id), 0) FROM processed_anomalies"
            ).fetchone()
            max_id = row[0] if row else 0
            conn.close()

        if max_id == 0:
            return

        curr = db.execute("SELECT currval('anomaly_id_seq')").fetchone()[0]
        target = max_id + 100  # 100-ID safety buffer
        if curr < target:
            advance_by = target - curr
            db.execute(f"SELECT nextval('anomaly_id_seq') FROM range({advance_by})")
            new_curr = db.execute("SELECT currval('anomaly_id_seq')").fetchone()[0]
            log.info(
                "Synced anomaly_id_seq: advanced from %d to %d "
                "(max_processed=%d, next ID will be %d)",
                curr, new_curr, max_id, new_curr + 1,
            )
    except Exception:
        log.warning("Could not sync anomaly_id_seq with alert_state.db", exc_info=True)


def _download_if_stale(url: str, dest: str, max_age: float) -> bool:
    """Download url to dest if file is missing or older than max_age seconds. Returns True if downloaded."""
    if os.path.exists(dest):
        age = time.time() - os.path.getmtime(dest)
        if age < max_age:
            return False
    try:
        log.info("Downloading %s ...", url)
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (IDS-Manager)"})
        with urllib.request.urlopen(req, timeout=60) as resp, open(dest + ".tmp", "wb") as f:
            f.write(resp.read())
        os.rename(dest + ".tmp", dest)
        log.info("Saved %s (%.1f MB)", dest, os.path.getsize(dest) / 1048576)
        return True
    except Exception:
        log.exception("Failed to download %s", url)
        # Clean up partial download
        try:
            os.remove(dest + ".tmp")
        except OSError:
            pass
        return False


def load_oui_database(db: duckdb.DuckDBPyConnection) -> None:
    """Download IEEE OUI CSV and load into oui_lookup table."""
    existing = db.execute("SELECT count(*) FROM oui_lookup").fetchone()[0]
    downloaded = _download_if_stale(OUI_URL, OUI_CSV_PATH, OUI_REFRESH_SECONDS)
    # Only reload if: downloaded new file, or table is empty and file exists
    if not downloaded and existing > 0:
        return
    if not os.path.exists(OUI_CSV_PATH):
        log.warning("OUI database not available — skipping")
        return

    try:
        # IEEE OUI CSV has duplicate Assignment values (e.g., 080030 appears 3 times).
        # Use DISTINCT ON to keep only the first manufacturer per prefix.
        db.execute("DELETE FROM oui_lookup")
        db.execute("""
            INSERT INTO oui_lookup
            SELECT oui_prefix, FIRST(manufacturer) AS manufacturer
            FROM (
                SELECT UPPER("Assignment") AS oui_prefix, "Organization Name" AS manufacturer
                FROM read_csv(?, header=true, auto_detect=true, ignore_errors=true)
                WHERE length("Assignment") = 6 AND "Organization Name" IS NOT NULL
                  AND "Organization Name" != ''
            )
            GROUP BY oui_prefix
        """, [OUI_CSV_PATH])
        count = db.execute("SELECT count(*) FROM oui_lookup").fetchone()[0]
        log.info("Loaded %d OUI entries", count)
    except Exception:
        log.exception("Failed to load OUI database")


def load_geoip_database(db: duckdb.DuckDBPyConnection) -> None:
    """Download DB-IP Country Lite CSV and load into geoip_lookup table."""
    existing = db.execute("SELECT count(*) FROM geoip_lookup").fetchone()[0]

    # Build URL for current month
    now = datetime.now(timezone.utc)
    geoip_url = f"https://download.db-ip.com/free/dbip-country-lite-{now.year}-{now.month:02d}.csv.gz"

    downloaded = _download_if_stale(geoip_url, GEOIP_GZ_PATH, GEOIP_REFRESH_SECONDS)
    if not downloaded and existing > 0:
        return
    if not os.path.exists(GEOIP_GZ_PATH):
        log.warning("GeoIP database not available — skipping")
        return

    try:
        # Parse GeoIP CSV: convert IPv4 to uint32, skip IPv6, write temp CSV for DuckDB bulk load
        tmp_csv = os.path.join(DB_DIR, "geoip_parsed.csv")
        count = 0
        with gzip.open(GEOIP_GZ_PATH, "rt", encoding="utf-8") as fin, \
             open(tmp_csv + ".tmp", "w") as fout:
            reader = csv.reader(fin)
            for row in reader:
                if len(row) < 3:
                    continue
                ip_start_str, ip_end_str, country = row[0], row[1], row[2]
                if ":" in ip_start_str:
                    continue
                try:
                    start = struct.unpack("!I", socket.inet_aton(ip_start_str))[0]
                    end = struct.unpack("!I", socket.inet_aton(ip_end_str))[0]
                    fout.write(f"{start},{end},{country.upper()[:2]}\n")
                    count += 1
                except (OSError, struct.error):
                    continue
        os.rename(tmp_csv + ".tmp", tmp_csv)

        if count > 0:
            db.execute("DELETE FROM geoip_lookup")
            db.execute("""
                INSERT INTO geoip_lookup
                SELECT * FROM read_csv(?, header=false,
                    columns={'ip_start': 'UINTEGER', 'ip_end': 'UINTEGER', 'country': 'VARCHAR'})
            """, [tmp_csv])
            loaded = db.execute("SELECT count(*) FROM geoip_lookup").fetchone()[0]
            log.info("Loaded %d GeoIP entries", loaded)
        os.remove(tmp_csv)
    except Exception:
        log.exception("Failed to load GeoIP database")


def rebuild_device_summaries(db: duckdb.DuckDBPyConnection) -> None:
    """Rebuild the devices and external_ips summary tables from events data."""
    try:
        # -- Rebuild devices table (internal IPs) --
        db.execute("DELETE FROM devices")
        db.execute("""
            INSERT INTO devices (ip, mac, manufacturer, hostname, first_seen, last_seen, total_conns, total_bytes, protocols, services)
            WITH conn_stats AS (
                SELECT
                    json_extract_string(raw, '$."id.orig_h"') AS ip,
                    json_extract_string(raw, '$.orig_l2_addr') AS mac,
                    min(timestamp) AS first_seen,
                    max(timestamp) AS last_seen,
                    count(*) AS total_conns,
                    COALESCE(sum(TRY_CAST(json_extract(raw, '$.orig_bytes') AS BIGINT)), 0)
                      + COALESCE(sum(TRY_CAST(json_extract(raw, '$.resp_bytes') AS BIGINT)), 0) AS total_bytes,
                    string_agg(DISTINCT json_extract_string(raw, '$.proto'), ', ') AS protocols,
                    string_agg(DISTINCT json_extract_string(raw, '$.service'), ', ') AS services
                FROM events
                WHERE source_tool = 'zeek' AND log_type = 'conn'
                    AND json_extract_string(raw, '$."id.orig_h"') IS NOT NULL
                    AND (
                        json_extract_string(raw, '$."id.orig_h"') LIKE '192.168.%'
                        OR json_extract_string(raw, '$."id.orig_h"') LIKE '10.%'
                        OR json_extract_string(raw, '$."id.orig_h"') LIKE '172.16.%'
                        OR json_extract_string(raw, '$."id.orig_h"') LIKE '172.17.%'
                        OR json_extract_string(raw, '$."id.orig_h"') LIKE '172.18.%'
                        OR json_extract_string(raw, '$."id.orig_h"') LIKE '172.19.%'
                        OR json_extract_string(raw, '$."id.orig_h"') LIKE '172.2_.%'
                        OR json_extract_string(raw, '$."id.orig_h"') LIKE '172.30.%'
                        OR json_extract_string(raw, '$."id.orig_h"') LIKE '172.31.%'
                    )
                GROUP BY ip, mac
            ),
            -- Pick the most recent MAC per IP from conn.log
            conn_mac AS (
                SELECT ip, mac, ROW_NUMBER() OVER (PARTITION BY ip ORDER BY last_seen DESC) AS rn
                FROM conn_stats
                WHERE mac IS NOT NULL AND mac != ''
            ),
            -- DHCP info: MAC + hostname per IP
            dhcp_info AS (
                SELECT
                    json_extract_string(raw, '$.assigned_addr') AS ip,
                    json_extract_string(raw, '$.mac') AS mac,
                    json_extract_string(raw, '$.host_name') AS hostname,
                    ROW_NUMBER() OVER (
                        PARTITION BY json_extract_string(raw, '$.assigned_addr')
                        ORDER BY timestamp DESC
                    ) AS rn
                FROM events
                WHERE source_tool = 'zeek' AND log_type = 'dhcp'
                    AND json_extract_string(raw, '$.assigned_addr') IS NOT NULL
            ),
            -- Aggregate conn_stats per IP (may have multiple MAC entries)
            ip_agg AS (
                SELECT
                    ip,
                    min(first_seen) AS first_seen,
                    max(last_seen) AS last_seen,
                    sum(total_conns) AS total_conns,
                    sum(total_bytes) AS total_bytes,
                    string_agg(DISTINCT protocols, ', ') AS protocols,
                    string_agg(DISTINCT services, ', ') AS services
                FROM conn_stats
                GROUP BY ip
            )
            SELECT
                a.ip,
                COALESCE(cm.mac, dh.mac) AS mac,
                o.manufacturer,
                dh.hostname,
                a.first_seen,
                a.last_seen,
                a.total_conns,
                a.total_bytes,
                a.protocols,
                a.services
            FROM ip_agg a
            LEFT JOIN conn_mac cm ON cm.ip = a.ip AND cm.rn = 1
            LEFT JOIN dhcp_info dh ON dh.ip = a.ip AND dh.rn = 1
            LEFT JOIN oui_lookup o ON o.oui_prefix = UPPER(REPLACE(COALESCE(cm.mac, dh.mac, '')[1:8], ':', ''))
        """)
        device_count = db.execute("SELECT count(*) FROM devices").fetchone()[0]

        # -- Rebuild external_ips table --
        db.execute("DELETE FROM external_ips")
        db.execute("""
            INSERT INTO external_ips (ip, country, total_conns, total_bytes, contacted_by, top_service, top_dest_port)
            WITH ext AS (
                SELECT
                    json_extract_string(raw, '$."id.resp_h"') AS ip,
                    json_extract_string(raw, '$."id.orig_h"') AS orig_ip,
                    json_extract_string(raw, '$.service') AS service,
                    TRY_CAST(json_extract(raw, '$."id.resp_p"') AS INTEGER) AS dest_port,
                    COALESCE(TRY_CAST(json_extract(raw, '$.orig_bytes') AS BIGINT), 0)
                      + COALESCE(TRY_CAST(json_extract(raw, '$.resp_bytes') AS BIGINT), 0) AS bytes
                FROM events
                WHERE source_tool = 'zeek' AND log_type = 'conn'
                    AND json_extract_string(raw, '$."id.resp_h"') IS NOT NULL
                    AND json_extract_string(raw, '$."id.resp_h"') NOT LIKE '192.168.%'
                    AND json_extract_string(raw, '$."id.resp_h"') NOT LIKE '10.%'
                    AND json_extract_string(raw, '$."id.resp_h"') NOT LIKE '172.16.%'
                    AND json_extract_string(raw, '$."id.resp_h"') NOT LIKE '172.17.%'
                    AND json_extract_string(raw, '$."id.resp_h"') NOT LIKE '172.18.%'
                    AND json_extract_string(raw, '$."id.resp_h"') NOT LIKE '172.19.%'
                    AND json_extract_string(raw, '$."id.resp_h"') NOT LIKE '172.2_.%'
                    AND json_extract_string(raw, '$."id.resp_h"') NOT LIKE '172.30.%'
                    AND json_extract_string(raw, '$."id.resp_h"') NOT LIKE '172.31.%'
                    AND json_extract_string(raw, '$."id.resp_h"') NOT LIKE '%:%'
                    AND json_extract_string(raw, '$."id.resp_h"') != '255.255.255.255'
                    AND json_extract_string(raw, '$."id.resp_h"') NOT LIKE '224.%'
                    AND json_extract_string(raw, '$."id.resp_h"') NOT LIKE '239.%'
                    AND json_extract_string(raw, '$."id.resp_h"') != '0.0.0.0'
            ),
            agg AS (
                SELECT
                    ip,
                    count(*) AS total_conns,
                    sum(bytes) AS total_bytes,
                    string_agg(DISTINCT orig_ip, ', ') AS contacted_by,
                    mode(service) AS top_service,
                    mode(dest_port) AS top_dest_port
                FROM ext
                GROUP BY ip
            )
            SELECT
                a.ip,
                g.country,
                a.total_conns,
                a.total_bytes,
                a.contacted_by,
                a.top_service,
                a.top_dest_port
            FROM agg a
            LEFT JOIN geoip_lookup g
                ON ip_to_uint(a.ip) BETWEEN g.ip_start AND g.ip_end
        """)
        ext_count = db.execute("SELECT count(*) FROM external_ips").fetchone()[0]
        log.info("Rebuilt summaries: %d devices, %d external IPs", device_count, ext_count)
    except Exception:
        log.exception("Failed to rebuild device summaries")


def update_device_baselines(db: duckdb.DuckDBPyConnection) -> None:
    """Update per-device behavioral baselines using exponential moving average (EMA).

    Measures each device's last-5-min bytes, connections, and unique destination IPs,
    then blends into the rolling average using EMA: new_avg = alpha * current + (1 - alpha) * old_avg.
    """
    alpha = BASELINE_EMA_ALPHA

    # Get current 5-min stats per internal device
    current_stats = db.execute("""
        SELECT
            json_extract_string(raw, '$."id.orig_h"') AS ip,
            COALESCE(CAST(sum(
                COALESCE(TRY_CAST(json_extract_string(raw, '$."orig_bytes"') AS BIGINT), 0)
              + COALESCE(TRY_CAST(json_extract_string(raw, '$."resp_bytes"') AS BIGINT), 0)
            ) AS DOUBLE), 0) AS bytes_5min,
            CAST(count(*) AS DOUBLE) AS conns_5min,
            CAST(count(DISTINCT json_extract_string(raw, '$."id.resp_h"')) AS DOUBLE) AS dest_ips
        FROM events
        WHERE source_tool = 'zeek' AND log_type = 'conn'
          AND timestamp > now() - INTERVAL '5 minutes'
          AND json_extract_string(raw, '$."id.orig_h"') LIKE '192.168.%'
        GROUP BY ip
    """).fetchall()

    if not current_stats:
        return

    # Get manufacturer info from devices table
    manufacturers = {}
    for row in db.execute("SELECT ip, manufacturer FROM devices").fetchall():
        manufacturers[row[0]] = row[1]

    for ip, bytes_5min, conns_5min, dest_ips in current_stats:
        existing = db.execute(
            "SELECT avg_bytes_5min, avg_conns_5min, avg_dest_ips, samples FROM device_baselines WHERE ip = ?",
            [ip],
        ).fetchone()

        mfr = manufacturers.get(ip)

        if existing is None:
            # First observation — seed the baseline
            db.execute("""
                INSERT INTO device_baselines (ip, manufacturer, avg_bytes_5min, avg_conns_5min, avg_dest_ips, samples, updated_at)
                VALUES (?, ?, ?, ?, ?, 1, now())
            """, [ip, mfr, bytes_5min, conns_5min, dest_ips])
        else:
            old_bytes, old_conns, old_dests, samples = existing
            new_bytes = alpha * bytes_5min + (1 - alpha) * old_bytes
            new_conns = alpha * conns_5min + (1 - alpha) * old_conns
            new_dests = alpha * dest_ips + (1 - alpha) * old_dests
            db.execute("""
                UPDATE device_baselines
                SET avg_bytes_5min = ?, avg_conns_5min = ?, avg_dest_ips = ?,
                    samples = ?, manufacturer = ?, updated_at = now()
                WHERE ip = ?
            """, [new_bytes, new_conns, new_dests, samples + 1, mfr, ip])

    log.info("Updated baselines for %d devices", len(current_stats))


def _cooldown_ok(db: duckdb.DuckDBPyConnection, anomaly_type: str, cooldown_min: int, like_filter: str | None = None) -> bool:
    """Return True if no anomaly of this type was created within the cooldown window."""
    sql = f"""
        SELECT 1 FROM anomaly_events
        WHERE anomaly_type = ? AND detected_at > now() - INTERVAL '{cooldown_min} minutes'
    """
    params: list = [anomaly_type]
    if like_filter:
        sql += " AND details::VARCHAR LIKE ?"
        params.append(like_filter)
    sql += " LIMIT 1"
    return db.execute(sql, params).fetchone() is None


def detect_anomalies(db: duckdb.DuckDBPyConnection) -> int:
    """Detect network anomalies and insert into anomaly_events table.

    Five detectors:
    1. New device: IPs in devices not in _known_devices
    2. Traffic spike: 5-min conn count > SPIKE_RATIO x rolling 1-hour avg (with cooldown)
    3. Suricata high-severity alerts: severity 1-2 in last 5 min (deduped per 30 min)
    4. Suspicious country: traffic to watchlist countries (from external_ips)
    5. Massive byte volume: single device > VOLUME_THRESHOLD_MB in 5 min
    """
    inserted = 0

    try:
        # --- 1. New Device Detection ---
        new_devices = db.execute("""
            SELECT d.ip, d.mac, d.manufacturer, d.hostname, d.first_seen, d.total_conns
            FROM devices d
            LEFT JOIN _known_devices k ON d.ip = k.ip
            WHERE k.ip IS NULL
        """).fetchall()

        for row in new_devices:
            ip, mac, manufacturer, hostname, first_seen, total_conns = row
            summary = f"New device {ip} ({manufacturer or 'Unknown manufacturer'}) appeared on the network"
            details = _json.dumps({
                "ip": ip, "mac": mac, "manufacturer": manufacturer,
                "hostname": hostname, "first_seen": str(first_seen),
                "total_conns": total_conns,
            })
            db.execute("""
                INSERT INTO anomaly_events (id, detected_at, anomaly_type, severity, summary, details)
                VALUES (nextval('anomaly_id_seq'), now(), 'new_device', 'medium', ?, ?)
            """, [summary, details])
            inserted += 1

        # Upsert all current devices into _known_devices
        db.execute("""
            INSERT OR IGNORE INTO _known_devices (ip, first_detected)
            SELECT ip, now() FROM devices
        """)

        # --- 2. Traffic Spike Detection (with cooldown) ---
        if _cooldown_ok(db, "traffic_spike", SPIKE_COOLDOWN_MIN):
            spike = db.execute(f"""
                WITH recent AS (
                    SELECT count(*) AS cnt
                    FROM events
                    WHERE source_tool = 'zeek' AND log_type = 'conn'
                      AND timestamp > now() - INTERVAL '5 minutes'
                ),
                hourly AS (
                    SELECT count(*) / 12.0 AS avg_5min
                    FROM events
                    WHERE source_tool = 'zeek' AND log_type = 'conn'
                      AND timestamp > now() - INTERVAL '1 hour'
                )
                SELECT r.cnt, h.avg_5min, r.cnt / NULLIF(h.avg_5min, 0) AS ratio
                FROM recent r, hourly h
                WHERE r.cnt >= {SPIKE_MIN_CONNS}
                  AND h.avg_5min > 10
                  AND r.cnt > {SPIKE_RATIO} * h.avg_5min
            """).fetchone()

            if spike:
                cnt, avg_5min, ratio = spike
                top_talkers = db.execute("""
                    SELECT json_extract_string(raw, '$."id.orig_h"') AS ip, count(*) AS conns
                    FROM events
                    WHERE source_tool = 'zeek' AND log_type = 'conn'
                      AND timestamp > now() - INTERVAL '5 minutes'
                    GROUP BY ip ORDER BY conns DESC LIMIT 5
                """).fetchall()
                summary = f"Traffic spike: {int(cnt)} connections in 5 min ({ratio:.1f}x above average)"
                details = _json.dumps({
                    "current_5min_conns": int(cnt),
                    "hourly_avg_5min": round(float(avg_5min), 1),
                    "ratio": round(float(ratio), 1),
                    "top_talkers": [{"ip": r[0], "conns": r[1]} for r in top_talkers],
                })
                db.execute("""
                    INSERT INTO anomaly_events (id, detected_at, anomaly_type, severity, summary, details)
                    VALUES (nextval('anomaly_id_seq'), now(), 'traffic_spike', 'high', ?, ?)
                """, [summary, details])
                inserted += 1

        # --- 3. Suricata Alert Aggregation (severity 1-2) ---
        alerts = db.execute("""
            SELECT
                json_extract_string(raw, '$.alert.signature') AS signature,
                json_extract_string(raw, '$.alert.category') AS category,
                min(json_extract_string(raw, '$.alert.severity')) AS sev,
                json_extract_string(raw, '$.src_ip') AS src_ip,
                json_extract_string(raw, '$.dest_ip') AS dest_ip,
                count(*) AS cnt,
                min(timestamp) AS first_seen,
                max(timestamp) AS last_seen
            FROM events
            WHERE source_tool = 'suricata' AND log_type = 'eve'
              AND json_extract_string(raw, '$.event_type') = 'alert'
              AND TRY_CAST(json_extract_string(raw, '$.alert.severity') AS INTEGER) <= 2
              AND timestamp > now() - INTERVAL '5 minutes'
            GROUP BY signature, category, src_ip, dest_ip
        """).fetchall()

        for row in alerts:
            signature, category, sev, src_ip, dest_ip, cnt, first_seen, last_seen = row
            # Dedup: skip if same signature already anomaly'd in last 30 min
            if not _cooldown_ok(db, "suricata_alert", 30, f'%"signature": "{signature}"%'):
                continue

            severity = "critical" if str(sev) == "1" else "high"
            summary = f"Suricata alert: {signature} ({src_ip} → {dest_ip}, {cnt} hits)"
            details = _json.dumps({
                "signature": signature, "category": category,
                "src_ip": src_ip, "dest_ip": dest_ip, "count": cnt,
                "first_seen": str(first_seen), "last_seen": str(last_seen),
            })
            db.execute("""
                INSERT INTO anomaly_events (id, detected_at, anomaly_type, severity, summary, details)
                VALUES (nextval('anomaly_id_seq'), now(), 'suricata_alert', ?, ?, ?)
            """, [severity, summary, details])
            inserted += 1

        # --- 4. Suspicious Country Traffic ---
        if SUSPICIOUS_COUNTRIES and SUSPICIOUS_COUNTRIES != [""]:
            placeholders = ",".join(["?"] * len(SUSPICIOUS_COUNTRIES))
            suspect_ips = db.execute(f"""
                SELECT e.ip, e.country, e.total_conns, CAST(e.total_bytes AS BIGINT) AS total_bytes,
                       e.contacted_by, e.top_service
                FROM external_ips e
                WHERE e.country IN ({placeholders})
                  AND e.total_conns > 0
                ORDER BY e.total_conns DESC
                LIMIT 10
            """, SUSPICIOUS_COUNTRIES).fetchall()

            for row in suspect_ips:
                ip, country, conns, bytes_, contacted_by, svc = row
                # Cooldown per IP — don't re-alert for same external IP within window
                if not _cooldown_ok(db, "suspicious_country", COUNTRY_COOLDOWN_MIN, f'%"ip": "{ip}"%'):
                    continue
                summary = f"Traffic to suspicious country: {ip} ({country}) — {conns} connections"
                details = _json.dumps({
                    "ip": ip, "country": country, "total_conns": conns,
                    "total_bytes": bytes_, "contacted_by": contacted_by,
                    "top_service": svc,
                })
                db.execute("""
                    INSERT INTO anomaly_events (id, detected_at, anomaly_type, severity, summary, details)
                    VALUES (nextval('anomaly_id_seq'), now(), 'suspicious_country', 'high', ?, ?)
                """, [summary, details])
                inserted += 1

        # --- 5. Massive Byte Volume (per device, last 5 min) ---
        if _cooldown_ok(db, "massive_volume", VOLUME_COOLDOWN_MIN):
            threshold_bytes = VOLUME_THRESHOLD_MB * 1024 * 1024
            heavy = db.execute(f"""
                SELECT
                    json_extract_string(raw, '$."id.orig_h"') AS ip,
                    CAST(sum(COALESCE(TRY_CAST(json_extract_string(raw, '$."orig_bytes"') AS BIGINT), 0)
                           + COALESCE(TRY_CAST(json_extract_string(raw, '$."resp_bytes"') AS BIGINT), 0)) AS BIGINT) AS total_bytes,
                    count(*) AS conns
                FROM events
                WHERE source_tool = 'zeek' AND log_type = 'conn'
                  AND timestamp > now() - INTERVAL '5 minutes'
                GROUP BY ip
                HAVING total_bytes > {threshold_bytes}
                ORDER BY total_bytes DESC
                LIMIT 5
            """).fetchall()

            for row in heavy:
                ip, total_bytes, conns = row
                mb = round(total_bytes / (1024 * 1024), 1)
                summary = f"Massive data transfer: {ip} moved {mb} MB in 5 minutes ({conns} connections)"
                details = _json.dumps({
                    "ip": ip, "total_bytes": total_bytes, "total_mb": mb,
                    "connections": conns,
                })
                db.execute("""
                    INSERT INTO anomaly_events (id, detected_at, anomaly_type, severity, summary, details)
                    VALUES (nextval('anomaly_id_seq'), now(), 'massive_volume', 'high', ?, ?)
                """, [summary, details])
                inserted += 1

        # --- 6. Per-Device Behavior Anomaly (bytes or conns vs own baseline) ---
        baseline_devices = db.execute(f"""
            SELECT b.ip, b.manufacturer, b.avg_bytes_5min, b.avg_conns_5min, b.samples
            FROM device_baselines b
            WHERE b.samples >= {BEHAVIOR_MIN_SAMPLES}
              AND b.avg_bytes_5min > 0
        """).fetchall()

        for row in baseline_devices:
            bl_ip, bl_mfr, bl_avg_bytes, bl_avg_conns, bl_samples = row
            # Get this device's current 5-min stats
            current = db.execute("""
                SELECT
                    COALESCE(CAST(sum(
                        COALESCE(TRY_CAST(json_extract_string(raw, '$."orig_bytes"') AS BIGINT), 0)
                      + COALESCE(TRY_CAST(json_extract_string(raw, '$."resp_bytes"') AS BIGINT), 0)
                    ) AS DOUBLE), 0) AS bytes_5min,
                    CAST(count(*) AS DOUBLE) AS conns_5min
                FROM events
                WHERE source_tool = 'zeek' AND log_type = 'conn'
                  AND timestamp > now() - INTERVAL '5 minutes'
                  AND json_extract_string(raw, '$."id.orig_h"') = ?
            """, [bl_ip]).fetchone()

            if not current or current[0] == 0:
                continue

            cur_bytes, cur_conns = current
            bytes_ratio = cur_bytes / max(bl_avg_bytes, 1)
            conns_ratio = cur_conns / max(bl_avg_conns, 1)

            if bytes_ratio >= BEHAVIOR_RATIO or conns_ratio >= BEHAVIOR_RATIO:
                # Cooldown per device IP
                if not _cooldown_ok(db, "device_behavior", 60, f'%"ip": "{bl_ip}"%'):
                    continue
                cur_mb = round(cur_bytes / (1024 * 1024), 2)
                avg_mb = round(bl_avg_bytes / (1024 * 1024), 2)
                trigger = "bytes" if bytes_ratio >= conns_ratio else "connections"
                ratio = max(bytes_ratio, conns_ratio)
                summary = (
                    f"Unusual behavior from {bl_ip} ({bl_mfr or 'Unknown'}): "
                    f"{trigger} {ratio:.1f}x above baseline"
                )
                details = _json.dumps({
                    "ip": bl_ip, "manufacturer": bl_mfr,
                    "current_bytes_5min": int(cur_bytes), "current_mb": cur_mb,
                    "baseline_bytes_5min": round(bl_avg_bytes), "baseline_mb": avg_mb,
                    "bytes_ratio": round(bytes_ratio, 1),
                    "current_conns_5min": int(cur_conns),
                    "baseline_conns_5min": round(bl_avg_conns),
                    "conns_ratio": round(conns_ratio, 1),
                    "baseline_samples": bl_samples,
                })
                db.execute("""
                    INSERT INTO anomaly_events (id, detected_at, anomaly_type, severity, summary, details)
                    VALUES (nextval('anomaly_id_seq'), now(), 'device_behavior', 'high', ?, ?)
                """, [summary, details])
                inserted += 1

        # --- 7. Unusual Destination Fan-Out (device contacting many unique IPs) ---
        fanout_devices = db.execute(f"""
            SELECT b.ip, b.manufacturer, b.avg_dest_ips, b.samples
            FROM device_baselines b
            WHERE b.samples >= {BEHAVIOR_MIN_SAMPLES}
              AND b.avg_dest_ips > 0
        """).fetchall()

        for row in fanout_devices:
            fo_ip, fo_mfr, fo_avg_dests, fo_samples = row
            current_dests = db.execute("""
                SELECT count(DISTINCT json_extract_string(raw, '$."id.resp_h"')) AS dest_ips
                FROM events
                WHERE source_tool = 'zeek' AND log_type = 'conn'
                  AND timestamp > now() - INTERVAL '5 minutes'
                  AND json_extract_string(raw, '$."id.orig_h"') = ?
            """, [fo_ip]).fetchone()

            if not current_dests or current_dests[0] < FANOUT_MIN_IPS:
                continue

            dest_count = current_dests[0]
            fanout_ratio = dest_count / max(fo_avg_dests, 1)

            if fanout_ratio >= FANOUT_RATIO:
                if not _cooldown_ok(db, "dest_fanout", 60, f'%"ip": "{fo_ip}"%'):
                    continue
                summary = (
                    f"Unusual destination fan-out from {fo_ip} ({fo_mfr or 'Unknown'}): "
                    f"{dest_count} unique IPs ({fanout_ratio:.1f}x above baseline)"
                )
                details = _json.dumps({
                    "ip": fo_ip, "manufacturer": fo_mfr,
                    "current_dest_ips": dest_count,
                    "baseline_dest_ips": round(fo_avg_dests, 1),
                    "ratio": round(fanout_ratio, 1),
                    "baseline_samples": fo_samples,
                })
                db.execute("""
                    INSERT INTO anomaly_events (id, detected_at, anomaly_type, severity, summary, details)
                    VALUES (nextval('anomaly_id_seq'), now(), 'dest_fanout', 'high', ?, ?)
                """, [summary, details])
                inserted += 1

        if inserted:
            log.info("Detected %d anomaly/anomalies", inserted)

        # Purge old anomaly events (older than TTL)
        db.execute(f"DELETE FROM anomaly_events WHERE detected_at < now() - INTERVAL '{TTL_HOURS} hours'")

    except Exception:
        log.exception("Failed to detect anomalies")

    return inserted


def is_current_hour_file(filepath: str) -> bool:
    """Return True if the NDJSON file belongs to the current UTC hour (still being written)."""
    match = HOUR_PATTERN.search(filepath)
    if not match:
        return False
    file_hour = match.group(1)
    now_hour = datetime.now(timezone.utc).strftime("%Y-%m-%d-%H")
    return file_hour == now_hour


def db_size_mb() -> float:
    """Return the current DuckDB file size in MB."""
    try:
        return os.path.getsize(DUCKDB_PATH) / (1024 * 1024)
    except OSError:
        return 0.0


def ingest(db: duckdb.DuckDBPyConnection) -> int:
    """Ingest NDJSON files from Vector staging directory into DuckDB.

    Current-hour files (still being written by Vector) are also ingested.
    The delete+reinsert pattern (keyed on source_file) handles the fact that
    these files grow between cycles — mtime changes trigger re-ingestion.
    This reduces new-device detection latency from ~60min to ~7min.
    """
    # Check DB size before ingesting
    current_size = db_size_mb()
    if current_size > MAX_DB_SIZE_MB:
        log.warning(
            "DuckDB size %.0fMB exceeds limit %dMB — skipping ingestion (purge/vacuum will still run)",
            current_size, MAX_DB_SIZE_MB,
        )
        return 0

    pattern = os.path.join(VECTOR_STAGING_DIR, "**", "*.ndjson")
    files = glob.glob(pattern, recursive=True)
    ingested = 0

    for filepath in files:
        try:
            mtime = os.path.getmtime(filepath)
        except OSError:
            continue

        # Check if already ingested with same mtime
        row = db.execute(
            "SELECT mtime FROM _ingested_files WHERE filepath = ?", [filepath]
        ).fetchone()
        if row and row[0] == mtime:
            continue

        try:
            # Derive source_tool and log_type from path structure:
            # /var/log/ids/vector/suricata/eve/2026-02-07-03.ndjson
            # /var/log/ids/vector/zeek/conn/2026-02-07-03.ndjson
            rel = os.path.relpath(filepath, VECTOR_STAGING_DIR)
            parts = Path(rel).parts
            source_tool = parts[0] if len(parts) > 0 else "unknown"
            log_type = parts[1] if len(parts) > 1 else "unknown"

            # Delete existing events from this file (handles re-ingestion of modified files)
            db.execute("DELETE FROM events WHERE source_file = ?", [filepath])

            # Read NDJSON file — each line becomes a single JSON value
            # ignore_errors=true skips malformed lines; WHERE filters out resulting NULLs
            db.execute(
                """
                INSERT INTO events (timestamp, source_tool, log_type, source_file, raw)
                SELECT
                    COALESCE(
                        TRY_CAST(json->>'timestamp' AS TIMESTAMPTZ),
                        now()
                    ) AS timestamp,
                    ? AS source_tool,
                    ? AS log_type,
                    ? AS source_file,
                    json AS raw
                FROM read_json_objects(?, ignore_errors=true)
                WHERE json IS NOT NULL
                """,
                [source_tool, log_type, filepath, filepath],
            )

            # Track ingested file
            db.execute(
                """
                INSERT OR REPLACE INTO _ingested_files (filepath, mtime)
                VALUES (?, ?)
                """,
                [filepath, mtime],
            )
            ingested += 1
        except Exception:
            log.exception("Failed to ingest %s", filepath)

    return ingested


def purge(db: duckdb.DuckDBPyConnection) -> int:
    """Delete events older than TTL_HOURS and return count of deleted rows."""
    result = db.execute(
        f"DELETE FROM events WHERE timestamp < now() - INTERVAL '{TTL_HOURS} hours'"
    ).fetchone()
    deleted = result[0] if result else 0
    if deleted:
        db.execute("CHECKPOINT")
    return deleted


def vacuum(db: duckdb.DuckDBPyConnection) -> None:
    """Run VACUUM to reclaim space from deleted rows."""
    try:
        db.execute("VACUUM")
        log.info("VACUUM completed — DB size: %.0fMB", db_size_mb())
    except Exception:
        log.exception("VACUUM failed")


def compact_db(db: duckdb.DuckDBPyConnection) -> duckdb.DuckDBPyConnection:
    """Reclaim space by exporting live data to parquet, recreating the DB, and reimporting.

    DuckDB VACUUM does not shrink the file on disk. The only way to reclaim space from
    mass deletes is to recreate the file. Called automatically when the DB is bloated
    (file >> estimated live data size).
    """
    parquet_dir = DUCKDB_PATH + ".compact_tmp"
    os.makedirs(parquet_dir, exist_ok=True)
    size_before = db_size_mb()
    event_count = db.execute("SELECT count(*) FROM events").fetchone()[0]
    log.info("Compacting DB: %.0fMB with %d events — exporting tables...", size_before, event_count)

    try:
        for table in TABLES_TO_PRESERVE:
            pq_path = os.path.join(parquet_dir, f"{table}.parquet")
            try:
                db.execute(f"COPY {table} TO '{pq_path}' (FORMAT PARQUET)")
            except Exception:
                log.warning("compact_db: could not export %s — will be empty after compact", table)

        db.close()
        os.remove(DUCKDB_PATH)

        db = duckdb.connect(DUCKDB_PATH)
        init_db(db)  # recreates schema + reloads OUI/GeoIP from cached CSV

        for table in TABLES_TO_PRESERVE:
            pq_path = os.path.join(parquet_dir, f"{table}.parquet")
            if os.path.exists(pq_path):
                try:
                    db.execute(f"INSERT INTO {table} SELECT * FROM read_parquet('{pq_path}')")
                except Exception:
                    log.warning("compact_db: could not reimport %s", table)
                finally:
                    try:
                        os.remove(pq_path)
                    except OSError:
                        pass

        try:
            os.rmdir(parquet_dir)
        except OSError:
            pass

        _sync_anomaly_seq(db)
        size_after = db_size_mb()
        log.info("Compact complete: %.0fMB → %.0fMB (freed %.0fMB)",
                 size_before, size_after, size_before - size_after)
        return db

    except Exception:
        log.exception("compact_db failed")
        shutil.rmtree(parquet_dir, ignore_errors=True)
        if not os.path.exists(DUCKDB_PATH):
            db = duckdb.connect(DUCKDB_PATH)
            init_db(db)
        else:
            try:
                db = duckdb.connect(DUCKDB_PATH)
            except Exception:
                pass
        return db


def cleanup_staging() -> int:
    """Remove NDJSON staging files older than STAGING_RETENTION_HOURS.

    Also enforces MAX_STAGING_SIZE_MB cap — if total staging directory size exceeds
    the limit after age-based cleanup, deletes oldest files first until under the cap.
    """
    cutoff = time.time() - STAGING_RETENTION_HOURS * 3600
    pattern = os.path.join(VECTOR_STAGING_DIR, "**", "*.ndjson")
    files = glob.glob(pattern, recursive=True)
    removed = 0
    for filepath in files:
        try:
            if os.path.getmtime(filepath) < cutoff:
                os.remove(filepath)
                removed += 1
        except OSError:
            pass

    # Size cap safety valve
    if MAX_STAGING_SIZE_MB > 0:
        remaining = glob.glob(pattern, recursive=True)
        # Build list of (filepath, mtime, size)
        file_info = []
        total_size = 0
        for fp in remaining:
            try:
                st = os.stat(fp)
                file_info.append((fp, st.st_mtime, st.st_size))
                total_size += st.st_size
            except OSError:
                continue
        cap_bytes = MAX_STAGING_SIZE_MB * 1024 * 1024
        if total_size > cap_bytes:
            log.warning(
                "Staging dir %.0fMB exceeds cap %dMB — removing oldest files",
                total_size / (1024 * 1024), MAX_STAGING_SIZE_MB,
            )
            # Sort by mtime ascending (oldest first)
            file_info.sort(key=lambda x: x[1])
            for fp, _, sz in file_info:
                if total_size <= cap_bytes:
                    break
                try:
                    os.remove(fp)
                    total_size -= sz
                    removed += 1
                except OSError:
                    pass

    return removed


def cleanup_source_logs() -> int:
    """Remove old Zeek rotated log files older than STAGING_RETENTION_HOURS.

    Zeek rotated files have the pattern: <type>.<timestamp>.log
    e.g., conn.2026-02-08-05-00-00.log
    The current (active) log is just <type>.log (no timestamp).

    Also enforces MAX_ZEEK_LOGS_SIZE_MB cap — if total Zeek log directory size exceeds
    the limit after age-based cleanup, deletes oldest rotated files first until under
    the cap. Never deletes active log files.
    """
    cutoff = time.time() - STAGING_RETENTION_HOURS * 3600
    # Match rotated Zeek logs across all zeek* dirs (contain a timestamp in the name)
    zeek_base = os.path.dirname(ZEEK_LOG_DIR)  # /var/log/ids
    rotated_patterns = glob.glob(os.path.join(zeek_base, "zeek*", "*.*.log"))
    removed = 0
    for filepath in rotated_patterns:
        try:
            if os.path.getmtime(filepath) < cutoff:
                os.remove(filepath)
                removed += 1
        except OSError:
            pass

    # Size cap safety valve — count ALL files in all zeek* dirs but only delete rotated ones
    if MAX_ZEEK_LOGS_SIZE_MB > 0:
        all_files = glob.glob(os.path.join(zeek_base, "zeek*", "*"))
        total_size = 0
        for fp in all_files:
            try:
                if os.path.isfile(fp):
                    total_size += os.path.getsize(fp)
            except OSError:
                continue
        cap_bytes = MAX_ZEEK_LOGS_SIZE_MB * 1024 * 1024
        if total_size > cap_bytes:
            log.warning(
                "Zeek log dirs %.0fMB exceeds cap %dMB — removing oldest rotated logs",
                total_size / (1024 * 1024), MAX_ZEEK_LOGS_SIZE_MB,
            )
            # Only delete rotated files (*.*.log), never active logs
            rotated = glob.glob(os.path.join(zeek_base, "zeek*", "*.*.log"))
            file_info = []
            for fp in rotated:
                try:
                    st = os.stat(fp)
                    file_info.append((fp, st.st_mtime, st.st_size))
                except OSError:
                    continue
            file_info.sort(key=lambda x: x[1])
            for fp, _, sz in file_info:
                if total_size <= cap_bytes:
                    break
                try:
                    os.remove(fp)
                    total_size -= sz
                    removed += 1
                except OSError:
                    pass

    return removed


def _copy_snapshot(dest: str) -> None:
    """Atomically copy ids.duckdb to dest for read-only consumers."""
    tmp_path = dest + ".tmp"
    try:
        shutil.copy2(DUCKDB_PATH, tmp_path)
        os.rename(tmp_path, dest)
        os.chmod(dest, 0o666)
    except Exception:
        log.exception("Failed to create snapshot %s", dest)
        try:
            os.remove(tmp_path)
        except OSError:
            pass


def create_readonly_snapshot() -> None:
    """Copy ids.duckdb to readonly snapshots for Grafana and alert-agent.

    Each consumer gets its own copy to avoid DuckDB cross-container lock conflicts
    (PID namespace isolation makes locks appear as PID 0 across containers).
    """
    if not os.path.exists(DUCKDB_PATH):
        return
    _copy_snapshot(DUCKDB_READONLY_PATH)
    _copy_snapshot(DUCKDB_STREAMLIT_PATH)
    _copy_snapshot(DUCKDB_ALERT_PATH)


def _parse_nmap_xml(xml_str: str) -> list[dict]:
    """Parse nmap XML output into a list of host results."""
    hosts = []
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return hosts
    for host_elem in root.findall("host"):
        state_elem = host_elem.find("status")
        host_state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"
        addr_elem = host_elem.find("address")
        host_ip = addr_elem.get("addr", "unknown") if addr_elem is not None else "unknown"
        hostname = ""
        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            hn = hostnames_elem.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "")
        ports = []
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                port_info = {
                    "port": int(port_elem.get("portid", 0)),
                    "protocol": port_elem.get("protocol", ""),
                }
                state = port_elem.find("state")
                if state is not None:
                    port_info["state"] = state.get("state", "")
                service = port_elem.find("service")
                if service is not None:
                    port_info["service"] = service.get("name", "")
                    port_info["version"] = service.get("version", "")
                    port_info["product"] = service.get("product", "")
                ports.append(port_info)
        hosts.append({"ip": host_ip, "hostname": hostname, "state": host_state, "ports": ports})
    return hosts


def run_scheduled_nmap_scan(db: duckdb.DuckDBPyConnection) -> None:
    """Run a scheduled nmap scan of the configured subnet and store results in DuckDB."""
    if not NMAP_SUBNET:
        return
    try:
        cmd = ["nmap", "-sV", "-T4", "--top-ports", "100", "-oX", "-", NMAP_SUBNET]
        log.info("Running scheduled nmap scan: %s", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=NMAP_TIMEOUT)
        if result.returncode != 0:
            log.warning("Scheduled nmap scan failed: %s", result.stderr.strip())
            return
        hosts = _parse_nmap_xml(result.stdout)
        scan_result = _json.dumps({
            "target": NMAP_SUBNET,
            "scan_type": "scheduled_service",
            "host_count": len(hosts),
            "hosts": hosts,
        })
        db.execute("""
            INSERT INTO nmap_scans (id, scanned_at, target, scan_type, results)
            VALUES (nextval('nmap_scan_id_seq'), now(), ?, 'scheduled_service', ?)
        """, [NMAP_SUBNET, scan_result])
        log.info("Scheduled nmap scan complete: %d hosts found", len(hosts))
    except subprocess.TimeoutExpired:
        log.warning("Scheduled nmap scan timed out after %ds", NMAP_TIMEOUT)
    except FileNotFoundError:
        log.warning("nmap not installed — skipping scheduled scan")
    except Exception:
        log.exception("Failed to run scheduled nmap scan")


def sync_nmap_from_sqlite(db: duckdb.DuckDBPyConnection) -> int:
    """Copy new nmap results from Streamlit's SQLite to DuckDB nmap_scans table.

    Returns number of new results synced.
    """
    if not os.path.exists(NMAP_RESULTS_SQLITE):
        return 0
    try:
        # Get highest synced SQLite ID from DuckDB (use a tracking approach)
        # We track which SQLite IDs we've already synced via a simple max-id check
        max_synced = 0
        try:
            row = db.execute("""
                SELECT COALESCE(max(TRY_CAST(json_extract_string(results, '$.sqlite_id') AS INTEGER)), 0)
                FROM nmap_scans WHERE scan_type != 'scheduled_service'
            """).fetchone()
            if row:
                max_synced = row[0] or 0
        except Exception:
            pass

        sconn = sqlite3.connect(NMAP_RESULTS_SQLITE)
        sconn.row_factory = sqlite3.Row
        rows = sconn.execute(
            "SELECT id, scanned_at, target, scan_type, results FROM nmap_results WHERE id > ? ORDER BY id",
            (max_synced,),
        ).fetchall()
        sconn.close()

        synced = 0
        for r in rows:
            try:
                results_obj = _json.loads(r["results"])
            except (TypeError, _json.JSONDecodeError):
                results_obj = {"raw": r["results"]}
            results_obj["sqlite_id"] = r["id"]
            db.execute("""
                INSERT INTO nmap_scans (id, scanned_at, target, scan_type, results)
                VALUES (nextval('nmap_scan_id_seq'), ?::TIMESTAMPTZ, ?, ?, ?)
            """, [r["scanned_at"], r["target"], r["scan_type"], _json.dumps(results_obj)])
            synced += 1

        if synced:
            log.info("Synced %d nmap result(s) from Streamlit SQLite", synced)
        return synced
    except Exception:
        log.exception("Failed to sync nmap results from SQLite")
        return 0


def _is_private(ip: str) -> bool:
    """Return True if IP is in RFC1918 private address space (no IPv6)."""
    if not ip or ":" in ip:
        return False
    return (
        ip.startswith("10.")
        or ip.startswith("192.168.")
        or (
            ip.startswith("172.")
            and len(ip.split(".")) >= 2
            and ip.split(".")[1].isdigit()
            and 16 <= int(ip.split(".")[1]) <= 31
        )
    )


def init_fast_alerts_db() -> None:
    """Create fast_alerts.db SQLite table for IPWatcher → alert-agent communication."""
    conn = sqlite3.connect(FAST_ALERTS_PATH, timeout=10)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS fast_new_devices (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            detected_at    TEXT NOT NULL DEFAULT (datetime('now')),
            ip             TEXT NOT NULL,
            mac            TEXT,
            alert_emailed  INTEGER NOT NULL DEFAULT 0,
            duckdb_drained INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()


class IPWatcher:
    """Background thread: tail Zeek conn.log + Suricata eve.json for new private IPs.

    Detects new devices within ~1s by reading new bytes from log files directly,
    without waiting for the NDJSON ingest cycle. Writes fast alerts to SQLite so
    the alert-agent can send immediate emails.
    """

    def __init__(
        self,
        known_ips: set,
        known_ips_lock: threading.Lock,
        stop_event: threading.Event,
    ) -> None:
        self.known_ips = known_ips
        self.known_ips_lock = known_ips_lock
        self.stop_event = stop_event
        self._positions: dict[str, int] = {}  # filepath → last read byte position

    def _get_watched_files(self) -> list[str]:
        """Glob for all Zeek conn logs and Suricata eve.json files."""
        files: list[str] = []
        for pattern in [
            "/var/log/ids/zeek*/conn*.log",
            "/var/log/ids/zeek/conn*.log",
        ]:
            files.extend(glob.glob(pattern))
        for pattern in [
            "/var/log/ids/suricata*/eve.json",
            "/var/log/ids/suricata/eve.json",
        ]:
            files.extend(glob.glob(pattern))
        return list(set(files))

    def _extract_ip(self, line: str, is_zeek: bool) -> str | None:
        """Extract originating IP from a JSON log line."""
        try:
            data = _json.loads(line)
            if is_zeek:
                return data.get("id.orig_h")
            else:
                # Suricata: only interested in flow/conn/alert events
                if data.get("event_type") in ("flow", "conn", "alert", "dns", "tls", "http", "fileinfo"):
                    return data.get("src_ip")
        except (_json.JSONDecodeError, TypeError):
            pass
        return None

    def _write_fast_alert(self, ip: str) -> None:
        """Write a new-device fast alert to SQLite for alert-agent + drain consumption."""
        try:
            conn = sqlite3.connect(FAST_ALERTS_PATH, timeout=5)
            conn.execute(
                "INSERT INTO fast_new_devices (ip, alert_emailed, duckdb_drained) VALUES (?, 0, 0)",
                (ip,),
            )
            conn.commit()
            conn.close()
            log.info("IPWatcher: new private IP detected: %s → fast_alerts.db", ip)
        except Exception:
            log.exception("IPWatcher: failed to write fast alert for %s", ip)

    def _poll(self) -> None:
        """Read new log lines from all watched files and detect new IPs."""
        for filepath in self._get_watched_files():
            try:
                file_size = os.path.getsize(filepath)
            except OSError:
                self._positions.pop(filepath, None)
                continue

            last_pos = self._positions.get(filepath)

            if last_pos is None:
                # New file: seek to EOF to avoid replaying historical data
                self._positions[filepath] = file_size
                continue

            if file_size < last_pos:
                # File rotated/truncated — restart from beginning
                self._positions[filepath] = 0
                last_pos = 0

            if file_size == last_pos:
                continue  # No new data

            is_zeek = "zeek" in filepath
            try:
                with open(filepath, "rb") as f:
                    f.seek(last_pos)
                    new_bytes = f.read(file_size - last_pos)
                    self._positions[filepath] = f.tell()

                for line in new_bytes.decode("utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    ip = self._extract_ip(line, is_zeek)
                    if ip and _is_private(ip):
                        with self.known_ips_lock:
                            if ip not in self.known_ips:
                                self.known_ips.add(ip)
                                self._write_fast_alert(ip)
            except Exception:
                log.exception("IPWatcher: error reading %s", filepath)

    def run(self) -> None:
        """Main loop — polls every 1 second until stop_event is set."""
        log.info("IPWatcher: started")
        while not self.stop_event.is_set():
            try:
                self._poll()
            except Exception:
                log.exception("IPWatcher: unexpected error in poll")
            self.stop_event.wait(1.0)
        log.info("IPWatcher: stopped")


def drain_fast_alerts(db: duckdb.DuckDBPyConnection) -> int:
    """Drain undrained fast_alerts.db rows into DuckDB anomaly_events + _known_devices.

    Uses a separate 'duckdb_drained' flag so alert-agent's email path is independent.
    Returns number of alerts drained.
    """
    if not os.path.exists(FAST_ALERTS_PATH):
        return 0
    try:
        conn = sqlite3.connect(FAST_ALERTS_PATH, timeout=5)
        rows = conn.execute(
            "SELECT id, detected_at, ip, mac FROM fast_new_devices WHERE duckdb_drained = 0"
        ).fetchall()

        drained = 0
        for _row_id, detected_at, ip, mac in rows:
            # Register in _known_devices so the full anomaly detector won't re-detect
            db.execute(
                "INSERT OR IGNORE INTO _known_devices (ip, first_detected) VALUES (?, now())", [ip]
            )
            summary = f"New device {ip} detected (fast path)"
            details = _json.dumps({
                "ip": ip, "mac": mac, "detected_at": detected_at, "detection_path": "fast",
            })
            db.execute("""
                INSERT INTO anomaly_events (id, detected_at, anomaly_type, severity, summary, details)
                VALUES (nextval('anomaly_id_seq'), now(), 'new_device', 'medium', ?, ?)
            """, [summary, details])
            drained += 1

        if drained:
            conn.execute("UPDATE fast_new_devices SET duckdb_drained = 1 WHERE duckdb_drained = 0")
            conn.commit()
            log.info("Drained %d fast alert(s) into DuckDB", drained)

        conn.close()
        return drained
    except Exception:
        log.exception("Failed to drain fast_alerts.db")
        return 0


def fast_new_device_check(
    db: duckdb.DuckDBPyConnection,
    known_ips: set,
    known_ips_lock: threading.Lock,
) -> int:
    """Detect new private IPs from recent events without waiting for summary rebuild.

    Queries events table directly (data within last 2 min) instead of the devices
    summary table (rebuilt every 5 min). Runs every main cycle.

    Returns number of new devices detected.
    """
    try:
        rows = db.execute("""
            WITH recent_ips AS (
                SELECT
                    json_extract_string(raw, '$."id.orig_h"') AS ip,
                    FIRST(json_extract_string(raw, '$.orig_l2_addr')) AS mac
                FROM events
                WHERE source_tool = 'zeek' AND log_type = 'conn'
                  AND timestamp > now() - INTERVAL '2 minutes'
                  AND json_extract_string(raw, '$."id.orig_h"') IS NOT NULL
                  AND json_extract_string(raw, '$."id.orig_h"') NOT LIKE '%:%'
                GROUP BY 1
            )
            SELECT r.ip, r.mac FROM recent_ips r
            LEFT JOIN _known_devices k ON r.ip = k.ip
            WHERE k.ip IS NULL
        """).fetchall()
    except Exception:
        log.exception("fast_new_device_check: query failed")
        return 0

    detected = 0
    for ip, mac in rows:
        if not ip or not _is_private(ip):
            continue
        try:
            db.execute(
                "INSERT OR IGNORE INTO _known_devices (ip, first_detected) VALUES (?, now())", [ip]
            )
            summary = f"New device {ip} detected"
            details = _json.dumps({"ip": ip, "mac": mac, "detection_path": "events_table"})
            db.execute("""
                INSERT INTO anomaly_events (id, detected_at, anomaly_type, severity, summary, details)
                VALUES (nextval('anomaly_id_seq'), now(), 'new_device', 'medium', ?, ?)
            """, [summary, details])
            detected += 1
        except Exception:
            log.exception("fast_new_device_check: failed to insert anomaly for %s", ip)

        # Keep in-memory set in sync so IPWatcher won't duplicate this IP
        with known_ips_lock:
            known_ips.add(ip)

    if detected:
        log.info("fast_new_device_check: %d new device(s) detected", detected)
    return detected


def init_rag_db() -> None:
    """Create rag.duckdb with empty schema so readers don't fail before indexing completes."""
    if os.path.exists(RAG_DUCKDB_PATH):
        return
    try:
        db = duckdb.connect(RAG_DUCKDB_PATH)
        db.execute("""
            CREATE TABLE IF NOT EXISTS rag_threat_intel (
                sid INTEGER PRIMARY KEY,
                msg TEXT NOT NULL,
                classtype TEXT,
                chunk_text TEXT NOT NULL,
                embedding FLOAT[],
                indexed_at TIMESTAMP DEFAULT NOW()
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS rag_index_meta (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        db.close()
        log.info("RAG: initialized empty rag.duckdb")
    except Exception:
        log.exception("RAG: failed to initialize rag.duckdb")


def _ollama_embed(texts: list[str]) -> list[list[float]]:
    """Embed a batch of texts via Ollama /api/embed. No extra dependencies."""
    url = f"{OLLAMA_HOST}/api/embed"
    payload = _json.dumps({"model": EMBED_MODEL, "input": texts}).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = _json.loads(resp.read())
    return data["embeddings"]


def parse_suricata_rules(path: str) -> list[dict]:
    """Parse a Suricata rules file and return a list of rule dicts (sid, msg, classtype, chunk_text)."""
    rules = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                sid_m = _SID_RE.search(line)
                msg_m = _MSG_RE.search(line)
                if not sid_m or not msg_m:
                    continue

                sid = int(sid_m.group(1))
                msg = msg_m.group(1)

                classtype_m = _CLASSTYPE_RE.search(line)
                classtype = classtype_m.group(1).strip() if classtype_m else ""

                metadata_m = _METADATA_RE.search(line)
                metadata = metadata_m.group(1).strip() if metadata_m else ""

                # Build enriched chunk text for embedding
                classtype_desc = CLASSTYPE_DESCRIPTIONS.get(classtype, classtype)
                chunk_parts = [f"Suricata rule: {msg}"]
                if classtype:
                    chunk_parts.append(f"Category: {classtype_desc}")
                if metadata:
                    meta_clean = re.sub(r"\s+", " ", metadata).strip()[:200]
                    chunk_parts.append(f"Metadata: {meta_clean}")

                rules.append({
                    "sid": sid,
                    "msg": msg,
                    "classtype": classtype,
                    "chunk_text": ". ".join(chunk_parts) + ".",
                })
    except Exception:
        log.exception("RAG: failed to parse rules from %s", path)
    return rules


def index_threat_intel() -> None:
    """Index Suricata rules into rag.duckdb using Ollama embeddings.

    Checks rules file mtime against rag_index_meta; skips if unchanged.
    Writes to a staging DB then atomically renames to rag.duckdb.
    """
    if not os.path.exists(RULES_PATH):
        log.info("RAG: rules file not found at %s — skipping", RULES_PATH)
        return

    try:
        current_mtime = str(os.path.getmtime(RULES_PATH))
    except OSError:
        return

    # Check stored mtime — skip if rules haven't changed
    try:
        if os.path.exists(RAG_DUCKDB_PATH):
            _check_db = duckdb.connect(RAG_DUCKDB_PATH, read_only=True)
            stored = _check_db.execute(
                "SELECT value FROM rag_index_meta WHERE key = 'rules_mtime'"
            ).fetchone()
            _check_db.close()
            if stored and stored[0] == current_mtime:
                log.debug("RAG: rules unchanged (mtime %s) — skipping", current_mtime)
                return
    except Exception:
        pass  # rag.duckdb may be empty or not yet created; proceed

    log.info("RAG: indexing started (rules mtime: %s)", current_mtime)

    try:
        rules = parse_suricata_rules(RULES_PATH)
        if not rules:
            log.warning("RAG: no rules parsed from %s", RULES_PATH)
            return

        log.info("RAG: parsed %d rules, embedding in batches of %d", len(rules), EMBED_BATCH_SIZE)

        # Write to staging DB, then atomic rename to avoid readers seeing partial data
        staging_db = duckdb.connect(RAG_STAGING_PATH)
        staging_db.execute("""
            CREATE TABLE IF NOT EXISTS rag_threat_intel (
                sid INTEGER PRIMARY KEY,
                msg TEXT NOT NULL,
                classtype TEXT,
                chunk_text TEXT NOT NULL,
                embedding FLOAT[],
                indexed_at TIMESTAMP DEFAULT NOW()
            )
        """)
        staging_db.execute("""
            CREATE TABLE IF NOT EXISTS rag_index_meta (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        staging_db.execute("DELETE FROM rag_threat_intel")

        total_embedded = 0
        for i in range(0, len(rules), EMBED_BATCH_SIZE):
            batch = rules[i:i + EMBED_BATCH_SIZE]
            texts = [r["chunk_text"] for r in batch]
            try:
                embeddings = _ollama_embed(texts)
            except Exception:
                log.exception("RAG: embedding batch %d failed — skipping", i // EMBED_BATCH_SIZE)
                continue

            for rule, emb in zip(batch, embeddings):
                staging_db.execute(
                    """INSERT OR REPLACE INTO rag_threat_intel
                       (sid, msg, classtype, chunk_text, embedding, indexed_at)
                       VALUES (?, ?, ?, ?, ?, NOW())""",
                    [rule["sid"], rule["msg"], rule["classtype"], rule["chunk_text"], emb],
                )

            total_embedded += len(batch)
            if total_embedded % 5000 < EMBED_BATCH_SIZE:
                log.info("RAG: embedded %d/%d rules", total_embedded, len(rules))

        staging_db.execute(
            "INSERT OR REPLACE INTO rag_index_meta (key, value) VALUES ('rules_mtime', ?)",
            [current_mtime],
        )
        staging_db.execute(
            "INSERT OR REPLACE INTO rag_index_meta (key, value) VALUES ('rule_count', ?)",
            [str(total_embedded)],
        )
        staging_db.close()

        os.replace(RAG_STAGING_PATH, RAG_DUCKDB_PATH)
        log.info("RAG: indexing complete — %d rules indexed to %s", total_embedded, RAG_DUCKDB_PATH)

    except Exception:
        log.exception("RAG: indexing failed")
        try:
            if os.path.exists(RAG_STAGING_PATH):
                os.remove(RAG_STAGING_PATH)
        except OSError:
            pass


def maybe_start_rag_indexing() -> None:
    """Start a background RAG indexer thread if rules file has changed and no indexer is running."""
    global _rag_thread, _rag_last_mtime

    if not RAG_AUTO_INDEX:
        return

    if not os.path.exists(RULES_PATH):
        return
    try:
        current_mtime = os.path.getmtime(RULES_PATH)
    except OSError:
        return

    if current_mtime == _rag_last_mtime:
        return  # Rules unchanged since last check

    if _rag_thread is not None and _rag_thread.is_alive():
        return  # Indexer already running

    _rag_last_mtime = current_mtime
    _rag_thread = threading.Thread(target=index_threat_intel, name="RAGIndexer", daemon=True)
    _rag_thread.start()
    log.info("RAG: indexer thread started")


def main() -> None:
    # Ensure DuckDB directory exists with world-writable permissions
    # (Grafana runs as uid 472 and needs write access for DuckDB lock files)
    db_dir = os.path.dirname(DUCKDB_PATH)
    os.makedirs(db_dir, exist_ok=True)
    os.chmod(db_dir, 0o777)

    log.info(
        "Starting duckdb-mgr: db=%s staging=%s ttl=%dh staging_retention=%dh interval=%ds "
        "max_db=%dMB max_staging=%dMB max_zeek=%dMB",
        DUCKDB_PATH,
        VECTOR_STAGING_DIR,
        TTL_HOURS,
        STAGING_RETENTION_HOURS,
        INGEST_INTERVAL,
        MAX_DB_SIZE_MB,
        MAX_STAGING_SIZE_MB,
        MAX_ZEEK_LOGS_SIZE_MB,
    )

    # --- Fast-path setup: IPWatcher thread ---
    init_fast_alerts_db()

    # --- RAG: initialize empty DB so readers don't fail before first indexing ---
    init_rag_db()

    known_ips: set = set()
    known_ips_lock = threading.Lock()

    # Seed known_ips from _known_devices (if DB already exists)
    try:
        if os.path.exists(DUCKDB_PATH):
            _seed_db = duckdb.connect(DUCKDB_PATH, read_only=True)
            for (ip,) in _seed_db.execute("SELECT ip FROM _known_devices").fetchall():
                known_ips.add(ip)
            _seed_db.close()
            log.info("Seeded %d known IPs from _known_devices", len(known_ips))
    except Exception:
        log.warning("Could not seed known_ips from DB (first run or schema not yet created)")

    stop_event = threading.Event()
    watcher = IPWatcher(known_ips, known_ips_lock, stop_event)
    watcher_thread = threading.Thread(target=watcher.run, name="IPWatcher", daemon=True)
    watcher_thread.start()

    cycle = 0
    last_nmap_scan = 0.0  # epoch time of last scheduled nmap scan

    # On startup, sync the anomaly_id_seq past any IDs already in alert_state.db.
    # Guards against ID collisions when DuckDB was recreated but alert_state.db survived.
    try:
        if os.path.exists(DUCKDB_PATH):
            _sync_db = duckdb.connect(DUCKDB_PATH)
            _sync_anomaly_seq(_sync_db)
            _sync_db.close()
    except Exception:
        log.warning("Startup anomaly_id_seq sync failed", exc_info=True)

    while True:
        try:
            # Check if Suricata rules have changed and start RAG indexer if needed
            maybe_start_rag_indexing()

            # Open connection for this cycle only — release lock during sleep
            # so external tools (verify scripts, Grafana, Phase 3 MCP) can query
            db = duckdb.connect(DUCKDB_PATH)

            # Ensure schema exists (handles DB deletion / first run)
            init_db(db)

            data_changed = False

            # 1. Ingest NDJSON → events table
            ingested = ingest(db)
            if ingested:
                log.info("Ingested %d file(s)", ingested)
                data_changed = True

            # 2. Purge old events (TTL)
            deleted = purge(db)
            if deleted:
                log.info("Purged %d expired event(s)", deleted)
                data_changed = True

            # If DB is bloated but empty, recreate it to reclaim space
            # (DuckDB VACUUM doesn't shrink the file after mass deletes)
            event_count = db.execute("SELECT count(*) FROM events").fetchone()[0]
            if event_count == 0 and db_size_mb() > 500:
                log.info("DB is %.0fMB with 0 events — recreating to reclaim space", db_size_mb())
                db.close()
                os.remove(DUCKDB_PATH)
                db = duckdb.connect(DUCKDB_PATH)
                init_db(db)
                # Sync sequence past alert_state IDs to prevent collision after recreation
                _sync_anomaly_seq(db)
                data_changed = True
            elif db_size_mb() > MAX_DB_SIZE_MB * 0.8:
                # DB is 80%+ of the size limit — check for bloat relative to live data.
                # Estimate ~1500 bytes/event (typical Zeek/Suricata JSON).
                estimated_live_mb = max(event_count * 1500 / (1024 * 1024), 1.0)
                bloat_ratio = db_size_mb() / estimated_live_mb
                if bloat_ratio > COMPACT_BLOAT_RATIO:
                    log.info(
                        "DB bloat: %.0fMB for %d events (~%.0fMB live, %.0fx bloat) — compacting",
                        db_size_mb(), event_count, estimated_live_mb, bloat_ratio,
                    )
                    db = compact_db(db)
                    data_changed = True

            # 3. Drain IPWatcher fast alerts → _known_devices + anomaly_events
            drained = drain_fast_alerts(db)
            if drained:
                data_changed = True

            # 4. Fast new-device check directly from events table (every cycle)
            found = fast_new_device_check(db, known_ips, known_ips_lock)
            if found:
                data_changed = True

            # 5. Periodic device/external_ips summary rebuild + full anomaly detection
            cycle += 1
            if cycle == 1 or cycle % SUMMARY_REBUILD_EVERY_N_CYCLES == 0:
                rebuild_device_summaries(db)
                update_device_baselines(db)
                detect_anomalies(db)
                data_changed = True

            # 6. Periodic VACUUM to reclaim space from deleted rows
            if cycle % VACUUM_EVERY_N_CYCLES == 0:
                vacuum(db)
                data_changed = True

            # Sync on-demand nmap results from Streamlit SQLite → DuckDB
            nmap_synced = sync_nmap_from_sqlite(db)
            if nmap_synced:
                data_changed = True

            # Scheduled nmap subnet scan
            now_ts = time.time()
            if NMAP_SUBNET and (now_ts - last_nmap_scan) >= NMAP_SCAN_INTERVAL_HOURS * 3600:
                run_scheduled_nmap_scan(db)
                last_nmap_scan = now_ts
                data_changed = True

            removed_staging = cleanup_staging()
            if removed_staging:
                log.info("Cleaned up %d staging file(s)", removed_staging)

            removed_source = cleanup_source_logs()
            if removed_source:
                log.info("Cleaned up %d rotated Zeek log(s)", removed_source)

            total = db.execute("SELECT count(*) FROM events").fetchone()[0]
            log.info("Total events in DuckDB: %d (DB size: %.0fMB)", total, db_size_mb())

            db.close()

            # 7. Create read-only snapshots for Grafana/Streamlit/alert-agent
            # Only copy when data actually changed — avoids redundant copies on idle cycles
            if data_changed:
                create_readonly_snapshot()
        except Exception:
            log.exception("Error in main loop")
            try:
                db.close()
            except Exception:
                pass

        time.sleep(INGEST_INTERVAL)


if __name__ == "__main__":
    main()

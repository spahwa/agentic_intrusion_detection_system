CREATE TABLE IF NOT EXISTS events (
    timestamp    TIMESTAMPTZ NOT NULL,
    source_tool  VARCHAR NOT NULL,
    log_type     VARCHAR NOT NULL,
    source_file  VARCHAR NOT NULL,
    raw          JSON NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events (timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source ON events (source_tool, log_type);
CREATE INDEX IF NOT EXISTS idx_events_file ON events (source_file);

CREATE TABLE IF NOT EXISTS _ingested_files (
    filepath VARCHAR PRIMARY KEY,
    mtime    DOUBLE NOT NULL
);

-- OUI manufacturer lookup (loaded from IEEE CSV)
CREATE TABLE IF NOT EXISTS oui_lookup (
    oui_prefix VARCHAR(6) PRIMARY KEY,
    manufacturer VARCHAR
);

-- GeoIP country lookup (loaded from DB-IP CSV, IPv4 only)
CREATE TABLE IF NOT EXISTS geoip_lookup (
    ip_start UINTEGER NOT NULL,
    ip_end   UINTEGER NOT NULL,
    country  VARCHAR(2) NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_geoip_start ON geoip_lookup (ip_start);

-- Device summary (materialized, rebuilt periodically)
CREATE TABLE IF NOT EXISTS devices (
    ip           VARCHAR PRIMARY KEY,
    mac          VARCHAR,
    manufacturer VARCHAR,
    hostname     VARCHAR,
    first_seen   TIMESTAMPTZ,
    last_seen    TIMESTAMPTZ,
    total_conns  BIGINT,
    total_bytes  BIGINT,
    protocols    VARCHAR,
    services     VARCHAR
);

-- External IP summary (materialized, rebuilt periodically)
CREATE TABLE IF NOT EXISTS external_ips (
    ip            VARCHAR PRIMARY KEY,
    country       VARCHAR(2),
    total_conns   BIGINT,
    total_bytes   BIGINT,
    contacted_by  VARCHAR,
    top_service   VARCHAR,
    top_dest_port INTEGER
);

-- Anomaly events detected by duckdb-mgr, consumed by alert-agent
CREATE TABLE IF NOT EXISTS anomaly_events (
    id              INTEGER PRIMARY KEY,
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    anomaly_type    VARCHAR NOT NULL,
    severity        VARCHAR NOT NULL,
    summary         VARCHAR NOT NULL,
    details         JSON
);
CREATE SEQUENCE IF NOT EXISTS anomaly_id_seq;

-- Known devices tracking (for new device detection)
CREATE TABLE IF NOT EXISTS _known_devices (
    ip VARCHAR PRIMARY KEY,
    first_detected TIMESTAMPTZ DEFAULT now()
);

-- Nmap scan results (synced from Streamlit SQLite + scheduled scans)
CREATE TABLE IF NOT EXISTS nmap_scans (
    id          INTEGER PRIMARY KEY,
    scanned_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    target      VARCHAR NOT NULL,
    scan_type   VARCHAR NOT NULL,
    results     JSON NOT NULL
);
CREATE SEQUENCE IF NOT EXISTS nmap_scan_id_seq;

-- Per-device behavioral baselines (rolling averages for anomaly detection)
CREATE TABLE IF NOT EXISTS device_baselines (
    ip              VARCHAR PRIMARY KEY,
    manufacturer    VARCHAR,
    avg_bytes_5min  DOUBLE DEFAULT 0,       -- rolling average bytes per 5-min window
    avg_conns_5min  DOUBLE DEFAULT 0,       -- rolling average connections per 5-min window
    avg_dest_ips    DOUBLE DEFAULT 0,       -- rolling average unique destination IPs per 5-min window
    samples         INTEGER DEFAULT 0,      -- number of samples in the rolling average
    updated_at      TIMESTAMPTZ DEFAULT now()
);

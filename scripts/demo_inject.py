#!/usr/bin/env python3
"""
IDS Demo Event Injector
=======================
Simulates realistic network security incidents for demonstration purposes.
Writes fake-but-realistic event records into the Vector staging directory
so they flow through the same pipeline as real traffic.

Run on the HOST machine (not inside Docker):
  sudo python3 scripts/demo_inject.py            # interactive menu
  sudo python3 scripts/demo_inject.py --all      # inject all 4 scenarios
  sudo python3 scripts/demo_inject.py -s 1 -s 4  # specific scenarios
  sudo python3 scripts/demo_inject.py --all --fast   # immediate email (skips ~2min wait)
  sudo python3 scripts/demo_inject.py --clean    # remove all injected demo data

Pipeline timing (without --fast):
  0s    NDJSON written to /var/log/ids/vector/
  ~10s  duckdb-mgr ingests files (INGEST_INTERVAL=10s)
  ~50s  Anomaly detection + device summary rebuild fires
  ~60s  alert-agent picks up anomaly, LLM drafts email
  ~2min Email arrives

With --fast: anomaly_events also directly injected via docker exec → email in <60s.

Scenarios
---------
  1  New IoT Device      de:ad:be:ef:ca:fe appears on 192.168.122.200
  2  DPRK C2 Beacon     IP camera (192.168.122.100) beacons to North Korea (175.45.176.3)
  3  IoT Traffic Spike  Smart thermostat (192.168.122.101) fires 2000 connections in 5 min
  4  Malware Signature  Cobalt Strike C2 beacon caught by Suricata (severity 1)
"""

import argparse
import json
import os
import random
import string
import subprocess
import sys
import textwrap
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ─── Configuration ─────────────────────────────────────────────────────────────
VECTOR_DIR       = os.environ.get("VECTOR_DIR", "/var/log/ids/vector")
DUCKDB_CONTAINER = os.environ.get("DUCKDB_CONTAINER", "ids-duckdb-mgr")

# Demo device inventory (virbr0 / libvirt default: 192.168.122.0/24)
NEW_DEV_IP    = "192.168.122.200"
NEW_DEV_MAC   = "de:ad:be:ef:ca:fe"  # OUI DE:AD:BE → Unknown mfr (intentional)
CAM_IP        = "192.168.122.100"    # "IP Camera" — DPRK traffic source
CAM_MAC       = "de:ad:be:ef:00:01"
THERM_IP      = "192.168.122.101"    # "Smart Thermostat" — spike source
THERM_MAC     = "de:ad:be:ef:00:02"
LAPTOP_IP     = "192.168.122.102"    # "Laptop-Demo" — malware source
LAPTOP_MAC    = "de:ad:be:ef:00:03"
GW_MAC        = "52:54:00:12:35:01"  # libvirt gateway MAC

DPRK_IP       = "175.45.176.3"      # AS131279, Korean Computer Center (DPRK) — real DPRK range
C2_IP         = "203.0.113.55"      # RFC 5737 documentation range — fake C2 server
C2_PORT       = 4444                # Classic Meterpreter/Cobalt Strike port

# File paths for demo NDJSON (named with "demo-" prefix for easy cleanup)
DEMO_FILES = {
    "new_device":    "zeek/conn/demo-new-device.ndjson",
    "dprk_traffic":  "zeek/conn/demo-dprk-traffic.ndjson",
    "iot_spike":     "zeek/conn/demo-iot-spike.ndjson",
    "malware_alert": "suricata/eve/demo-malware-alert.ndjson",
}

# ─── ANSI colors ───────────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"


# ─── Utilities ─────────────────────────────────────────────────────────────────
def ago_iso(seconds: int) -> str:
    """ISO 8601 timestamp N seconds in the past."""
    t = datetime.now(timezone.utc) - timedelta(seconds=seconds)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def uid() -> str:
    """Generate a Zeek-style connection UID."""
    return "C" + "".join(random.choices(string.ascii_letters + string.digits, k=18))


def zeek_conn(
    orig_h: str, orig_mac: str, resp_h: str, resp_p: int,
    proto: str = "tcp", svc: str | None = None,
    orig_bytes: int | None = None, resp_bytes: int | None = None,
    state: str = "SF", ago_s: int = 0,
) -> dict:
    """Build a single Zeek conn.log JSON record."""
    return {
        "timestamp": ago_iso(ago_s),
        "ts": time.time() - ago_s,
        "uid": uid(),
        "id.orig_h": orig_h,
        "id.orig_p": random.randint(49152, 65535),
        "id.resp_h": resp_h,
        "id.resp_p": resp_p,
        "proto": proto,
        "service": svc,
        "duration": round(random.uniform(0.01, 3.0), 4),
        "orig_bytes": orig_bytes if orig_bytes is not None else random.randint(100, 3000),
        "resp_bytes": resp_bytes if resp_bytes is not None else random.randint(200, 10000),
        "conn_state": state,
        "orig_l2_addr": orig_mac,
        "resp_l2_addr": GW_MAC,
    }


def write_ndjson(rel_path: str, records: list[dict]) -> Path:
    """Write records as NDJSON to the Vector staging directory."""
    path = Path(VECTOR_DIR) / rel_path
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")
    print(f"  {GREEN}✓{RESET}  Wrote {len(records):>5} records → {DIM}{path}{RESET}")
    return path


def hdr(title: str, color: str = CYAN) -> None:
    line = "─" * 62
    print(f"\n{color}{BOLD}{line}{RESET}")
    print(f"{color}{BOLD}  {title}{RESET}")
    print(f"{color}{BOLD}{line}{RESET}")


def info(msg: str) -> None:
    print(f"  {BLUE}ℹ{RESET}  {msg}")


def warn(msg: str) -> None:
    print(f"  {YELLOW}⚠{RESET}  {msg}")


def ok(msg: str) -> None:
    print(f"  {GREEN}✓{RESET}  {msg}")


def timing_note(fast: bool) -> None:
    if fast:
        print(f"\n  {YELLOW}{BOLD}⏱  Anomaly injected directly — email alert expected in ~60s{RESET}")
    else:
        print(f"\n  {YELLOW}{BOLD}⏱  Events queued — email alert expected in ~2 min{RESET}")
        print(f"  {DIM}     (10s ingest + 50s detection + 60s alert-agent){RESET}")


# ─── Scenario 1: New IoT Device ────────────────────────────────────────────────
def build_new_device_records() -> list[dict]:
    """
    A previously-unseen device (MAC de:ad:be:ef:ca:fe) joins the network.
    Simulates initial DHCP/DNS handshake then HTTPS activity.
    Triggers: new_device anomaly (medium severity)
    """
    records = []
    # DHCP + initial DNS
    for i, (dest, port, proto, svc) in enumerate([
        ("192.168.122.1",  67,  "udp", "dhcp"),
        ("192.168.122.1",  53,  "udp", "dns"),
        ("192.168.122.1",  53,  "udp", "dns"),
    ]):
        records.append(zeek_conn(
            NEW_DEV_IP, NEW_DEV_MAC, dest, port,
            proto=proto, svc=svc,
            orig_bytes=random.randint(50, 300),
            resp_bytes=random.randint(100, 500),
            ago_s=270 - i * 15,
        ))
    # Calling home to cloud endpoints
    for i, (dest, port, svc) in enumerate([
        ("142.250.80.46",   443, "ssl"),    # Google
        ("54.239.28.85",    443, "ssl"),    # AWS
        ("151.101.193.140", 443, "ssl"),    # Fastly CDN
        ("192.168.122.1",   53,  "dns"),    # More DNS
        ("104.21.50.32",    80,  "http"),   # Cloudflare HTTP
    ]):
        records.append(zeek_conn(
            NEW_DEV_IP, NEW_DEV_MAC, dest, port,
            svc=svc,
            orig_bytes=random.randint(500, 8000),
            resp_bytes=random.randint(2000, 50000),
            ago_s=210 - i * 30,
        ))
    return records


def fast_anomaly_new_device() -> dict:
    return {
        "anomaly_type": "new_device",
        "severity": "medium",
        "summary": "[DEMO] New device de:ad:be:ef:ca:fe (Unknown) appeared on 192.168.122.200",
        "details": {
            "ip": NEW_DEV_IP, "mac": NEW_DEV_MAC,
            "manufacturer": None, "hostname": None,
            "first_seen": now_iso(), "total_conns": 8,
        },
    }


# ─── Scenario 2: DPRK C2 Beacon ────────────────────────────────────────────────
def build_dprk_records() -> list[dict]:
    """
    An IP camera (192.168.122.100) communicates with a North Korean IP
    (175.45.176.3, AS131279 Korean Computer Center).
    Simulates periodic C2 beacons + a data exfiltration burst.
    Triggers: suspicious_country anomaly (high severity, country=KP)
    Note: Requires GeoIP DB to have DPRK ranges (DB-IP does include 175.45.176.0/22).
          Use --fast as fallback if GeoIP lookup fails.
    """
    records = []
    # Periodic HTTPS C2 beacons (~every 5 min, jittered to look organic)
    beacon_intervals = [270, 220, 175, 130, 85, 40]
    for i, ago in enumerate(beacon_intervals):
        records.append(zeek_conn(
            CAM_IP, CAM_MAC, DPRK_IP,
            443 if i % 3 != 1 else 8080,
            svc="ssl" if i % 3 != 1 else None,
            orig_bytes=random.randint(380, 980),    # small C2 checkin
            resp_bytes=random.randint(200, 600),
            state="SF",
            ago_s=ago + random.randint(-8, 8),
        ))
    # Exfiltration burst (large upload to DPRK IP)
    records.append(zeek_conn(
        CAM_IP, CAM_MAC, DPRK_IP, 443,
        svc="ssl",
        orig_bytes=random.randint(8_000_000, 18_000_000),   # 8–18 MB upload
        resp_bytes=random.randint(15000, 45000),
        state="SF",
        ago_s=15,
    ))
    return records


def fast_anomaly_dprk() -> dict:
    return {
        "anomaly_type": "suspicious_country",
        "severity": "high",
        "summary": f"[DEMO] Traffic to suspicious country: {DPRK_IP} (KP) — 7 connections",
        "details": {
            "ip": DPRK_IP, "country": "KP",
            "total_conns": 7,
            "total_bytes": 10_485_760,
            "contacted_by": CAM_IP,
            "top_service": "ssl",
        },
    }


# ─── Scenario 3: IoT Traffic Spike ─────────────────────────────────────────────
def build_iot_spike_records(count: int = 2000) -> list[dict]:
    """
    A smart thermostat (192.168.122.101) suddenly generates thousands of
    rejected TCP connections — characteristic of botnet port-scan activity.
    Triggers: traffic_spike anomaly (high severity)
    Math: count=2000 ≥ SPIKE_MIN_CONNS(1000), ratio ≈ 12x ≥ SPIKE_RATIO(5.0)
    """
    records = []
    # All connections in last 4 minutes (within 5-min detection window)
    # REJ (rejected) state = port scan pattern
    # Scanning sequential IPs across multiple subnets
    for i in range(count):
        dest_third = (i // 254) % 256
        dest_fourth = (i % 254) + 1
        dest_ip = f"10.{random.randint(0, 3)}.{dest_third}.{dest_fourth}"
        records.append({
            "timestamp": ago_iso(random.randint(0, 230)),
            "ts": time.time() - random.randint(0, 230),
            "uid": uid(),
            "id.orig_h": THERM_IP,
            "id.orig_p": random.randint(49152, 65535),
            "id.resp_h": dest_ip,
            "id.resp_p": random.choice([22, 23, 80, 443, 8080, 8443, 3389, 5900]),
            "proto": "tcp",
            "service": None,
            "duration": round(random.uniform(0.0005, 0.05), 6),
            "orig_bytes": random.randint(40, 80),
            "resp_bytes": 0,
            "conn_state": "REJ",  # rejected — hallmark of port scan
            "orig_l2_addr": THERM_MAC,
            "resp_l2_addr": GW_MAC,
        })
    return records


def fast_anomaly_iot_spike(count: int = 2000) -> dict:
    return {
        "anomaly_type": "traffic_spike",
        "severity": "high",
        "summary": f"[DEMO] Traffic spike: {count} connections in 5 min (12.0x above average)",
        "details": {
            "current_5min_conns": count,
            "hourly_avg_5min": round(count / 12.0, 1),
            "ratio": 12.0,
            "top_talkers": [
                {"ip": THERM_IP, "conns": count},
            ],
        },
    }


# ─── Scenario 4: Malware / Cobalt Strike ───────────────────────────────────────
def build_malware_records() -> list[dict]:
    """
    A laptop (192.168.122.102) triggers two Suricata signatures:
      - ET MALWARE Cobalt Strike C2 beacon (severity 1 = critical)
      - ET SCAN Nmap SYN scan (severity 2 = high)
    Both will appear as separate anomaly_events.
    Triggers: suricata_alert anomaly (critical + high severity)
    """
    records = []

    # Cobalt Strike C2 beacon — severity 1 (critical), multiple hits
    for i in range(5):
        records.append({
            "timestamp": ago_iso(240 - i * 45),
            "event_type": "alert",
            "src_ip": LAPTOP_IP,
            "src_port": random.randint(49152, 65535),
            "dest_ip": C2_IP,
            "dest_port": C2_PORT,
            "proto": "TCP",
            "app_proto": "failed",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2027865,
                "rev": 1,
                "signature": "ET MALWARE Possible C&C Beacon (Cobalt Strike/Meterpreter Variant)",
                "category": "A Network Trojan was Detected",
                "severity": 1,
            },
            "flow": {
                "pkts_toserver": 3,
                "pkts_toclient": 2,
                "bytes_toserver": 680,
                "bytes_toclient": 420,
            },
            "community_id": f"1:{uid()[:22]}",
        })

    # Nmap SYN scan — severity 2 (high)
    records.append({
        "timestamp": ago_iso(55),
        "event_type": "alert",
        "src_ip": LAPTOP_IP,
        "src_port": random.randint(49152, 65535),
        "dest_ip": "192.168.122.1",
        "dest_port": 0,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2010937,
            "rev": 3,
            "signature": "ET SCAN Nmap SYN Scan",
            "category": "Network Scan",
            "severity": 2,
        },
        "community_id": f"1:{uid()[:22]}",
    })

    return records


def fast_anomaly_malware() -> list[dict]:
    return [
        {
            "anomaly_type": "suricata_alert",
            "severity": "critical",
            "summary": (
                f"[DEMO] Suricata alert: ET MALWARE Possible C&C Beacon "
                f"(Cobalt Strike/Meterpreter Variant) ({LAPTOP_IP} → {C2_IP}, 5 hits)"
            ),
            "details": {
                "signature": "ET MALWARE Possible C&C Beacon (Cobalt Strike/Meterpreter Variant)",
                "category": "A Network Trojan was Detected",
                "src_ip": LAPTOP_IP, "dest_ip": C2_IP,
                "count": 5,
                "first_seen": ago_iso(240), "last_seen": ago_iso(60),
            },
        },
        {
            "anomaly_type": "suricata_alert",
            "severity": "high",
            "summary": (
                f"[DEMO] Suricata alert: ET SCAN Nmap SYN Scan "
                f"({LAPTOP_IP} → 192.168.122.1, 1 hits)"
            ),
            "details": {
                "signature": "ET SCAN Nmap SYN Scan",
                "category": "Network Scan",
                "src_ip": LAPTOP_IP, "dest_ip": "192.168.122.1",
                "count": 1,
                "first_seen": ago_iso(55), "last_seen": ago_iso(55),
            },
        },
    ]


# ─── Direct DB Injection (--fast) ──────────────────────────────────────────────
_FAST_INJECT_PY = """\
import duckdb, json, sys, time
anomalies = json.loads(sys.argv[1])
for attempt in range(40):
    try:
        db = duckdb.connect('/var/log/ids/duckdb/ids.duckdb')
        for a in anomalies:
            db.execute(
                "INSERT INTO anomaly_events (id, detected_at, anomaly_type, severity, summary, details) "
                "VALUES (nextval('anomaly_id_seq'), now(), ?, ?, ?, ?)",
                [a['anomaly_type'], a['severity'], a['summary'], json.dumps(a['details'])]
            )
        count = len(anomalies)
        db.close()
        print(f"Injected {count} anomaly record(s) into anomaly_events")
        sys.exit(0)
    except Exception as e:
        if attempt < 39 and ('lock' in str(e).lower() or 'busy' in str(e).lower()):
            time.sleep(1)
        else:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)
"""


def docker_inject_anomalies(anomalies: list[dict]) -> bool:
    """Inject anomaly records directly via docker exec (bypasses detection cycle)."""
    payload = json.dumps(anomalies)
    try:
        result = subprocess.run(
            ["docker", "exec", DUCKDB_CONTAINER,
             "python3", "-c", _FAST_INJECT_PY, payload],
            capture_output=True, text=True, timeout=50,
        )
        if result.returncode == 0:
            ok(f"Fast inject: {result.stdout.strip()}")
            return True
        else:
            warn(f"Fast inject failed: {result.stderr.strip()}")
            return False
    except subprocess.TimeoutExpired:
        warn("Fast inject timed out (DuckDB lock held too long?)")
        return False
    except FileNotFoundError:
        warn("'docker' not found — skipping fast injection (normal 2-min path still active)")
        return False


def docker_remove_demo_ip(ip: str) -> None:
    """Remove a demo IP from _known_devices so new_device detection fires cleanly."""
    script = (
        f"import duckdb, time\n"
        f"for _ in range(30):\n"
        f"  try:\n"
        f"    db = duckdb.connect('/var/log/ids/duckdb/ids.duckdb')\n"
        f"    db.execute(\"DELETE FROM _known_devices WHERE ip = '{ip}'\")\n"
        f"    db.close(); break\n"
        f"  except: time.sleep(1)\n"
    )
    try:
        subprocess.run(
            ["docker", "exec", DUCKDB_CONTAINER, "python3", "-c", script],
            capture_output=True, timeout=35,
        )
    except Exception:
        pass


# ─── Cleanup ───────────────────────────────────────────────────────────────────
_CLEAN_PY = """\
import duckdb, time, sys
sources = sys.argv[1:]
for attempt in range(40):
    try:
        db = duckdb.connect('/var/log/ids/duckdb/ids.duckdb')
        for s in sources:
            db.execute('DELETE FROM events WHERE source_file = ?', [s])
            db.execute('DELETE FROM _ingested_files WHERE filepath = ?', [s])
        db.execute("DELETE FROM anomaly_events WHERE summary LIKE '%[DEMO]%'")
        db.close()
        print(f"Cleaned {len(sources)} source(s) + [DEMO] anomaly events")
        sys.exit(0)
    except Exception as e:
        if attempt < 39 and ('lock' in str(e).lower() or 'busy' in str(e).lower()):
            time.sleep(1)
        else:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)
"""


def do_clean() -> None:
    hdr("Cleaning Up Demo Data", RED)

    # Remove NDJSON files
    removed_files = []
    for rel in DEMO_FILES.values():
        path = Path(VECTOR_DIR) / rel
        if path.exists():
            path.unlink()
            print(f"  {GREEN}✓{RESET}  Removed {DIM}{path}{RESET}")
            removed_files.append(str(path))
        else:
            print(f"  {DIM}–   {path} (not found){RESET}")

    if not removed_files:
        info("No demo NDJSON files found — nothing to remove.")
        return

    # Remove events from DuckDB
    info("Removing demo events from DuckDB (via docker exec)...")
    try:
        result = subprocess.run(
            ["docker", "exec", DUCKDB_CONTAINER, "python3", "-c", _CLEAN_PY]
            + removed_files,
            capture_output=True, text=True, timeout=50,
        )
        if result.returncode == 0:
            ok(result.stdout.strip())
        else:
            warn(f"DB cleanup error: {result.stderr.strip()}")
            warn("Events will expire naturally via 72h TTL.")
    except Exception as e:
        warn(f"Could not clean DuckDB: {e}")
        warn("Events will expire naturally via 72h TTL.")

    print()
    ok("Demo data removed. Dashboards will refresh on next duckdb-mgr cycle (~10s).")


# ─── Scenario runners ──────────────────────────────────────────────────────────
def run_scenario_1(fast: bool) -> None:
    hdr("Scenario 1 — New IoT Device Detected", CYAN)
    info(f"Device:  {NEW_DEV_MAC}  →  {NEW_DEV_IP}")
    info("Events:  8 Zeek conn.log records (DHCP + DNS + HTTPS activity)")
    info("Trigger: new_device anomaly (medium severity)")
    info("Note:    OUI lookup returns 'Unknown' — DE:AD:BE is not a real OUI")
    print()

    # Ensure demo IP is not already "known" — otherwise detection won't fire
    docker_remove_demo_ip(NEW_DEV_IP)

    records = build_new_device_records()
    write_ndjson(DEMO_FILES["new_device"], records)

    if fast:
        docker_inject_anomalies([fast_anomaly_new_device()])

    timing_note(fast)
    print(f"\n  {DIM}Dashboard: Network Nodes → will show new device with MAC de:ad:be:ef:ca:fe{RESET}")
    print(f"  {DIM}Chat UI:   'Show me new devices in the last hour'{RESET}")


def run_scenario_2(fast: bool) -> None:
    hdr("Scenario 2 — DPRK C2 Beacon (North Korea)", RED)
    info(f"Device:  {CAM_IP}  (IP Camera, MAC {CAM_MAC})")
    info(f"Target:  {DPRK_IP}  (AS131279 — Korean Computer Center, Pyongyang, KP)")
    info("Events:  6 periodic HTTPS beacons + 1 exfiltration burst (~10 MB upload)")
    info("Trigger: suspicious_country anomaly (KP in watchlist, high severity)")
    print()
    warn(f"GeoIP note: Requires DB-IP to have {DPRK_IP} → KP mapping.")
    warn("Use --fast if you haven't downloaded GeoIP DB yet (demo started recently).")
    print()

    records = build_dprk_records()
    write_ndjson(DEMO_FILES["dprk_traffic"], records)

    if fast:
        docker_inject_anomalies([fast_anomaly_dprk()])

    timing_note(fast)
    print(f"\n  {DIM}Dashboard: External Access & GeoIP → North Korea should appear{RESET}")
    print(f"  {DIM}Dashboard: Connection Map → {CAM_IP} ↔ {DPRK_IP}{RESET}")
    print(f"  {DIM}Chat UI:   'What external countries are we talking to?'{RESET}")


def run_scenario_3(fast: bool) -> None:
    hdr("Scenario 3 — IoT Traffic Spike (Botnet Port Scan)", YELLOW)
    info(f"Device:  {THERM_IP}  (Smart Thermostat, MAC {THERM_MAC})")
    info("Events:  2000 Zeek conn.log records — all REJ (rejected) within 4 min")
    info("Pattern: Sequential IPs, ports 22/23/80/443/3389 — classic botnet scan")
    info("Trigger: traffic_spike anomaly (2000 conns ≥ 1000 min, ~12x above avg)")
    print()

    records = build_iot_spike_records(count=2000)
    write_ndjson(DEMO_FILES["iot_spike"], records)

    if fast:
        docker_inject_anomalies([fast_anomaly_iot_spike(count=2000)])

    timing_note(fast)
    print(f"\n  {DIM}Dashboard: Network Nodes → {THERM_IP} will be noisiest device{RESET}")
    print(f"  {DIM}Chat UI:   'Which device is generating the most traffic?'{RESET}")
    print(f"  {DIM}Chat UI:   'Run an nmap scan on 192.168.122.101'{RESET}")


def run_scenario_4(fast: bool) -> None:
    hdr("Scenario 4 — Malware Detected (Cobalt Strike + Nmap Scan)", RED)
    info(f"Device:  {LAPTOP_IP}  (Laptop-Demo, MAC {LAPTOP_MAC})")
    info(f"Alert 1: ET MALWARE Cobalt Strike C2 beacon → {C2_IP}:{C2_PORT}  [severity 1 = CRITICAL]")
    info("Alert 2: ET SCAN Nmap SYN Scan → 192.168.122.1                [severity 2 = HIGH]")
    info("Events:  5 C2 beacon hits + 1 scan signature in Suricata EVE format")
    info("Trigger: suricata_alert anomaly × 2 (critical + high)")
    print()

    records = build_malware_records()
    write_ndjson(DEMO_FILES["malware_alert"], records)

    if fast:
        docker_inject_anomalies(fast_anomaly_malware())

    timing_note(fast)
    print(f"\n  {DIM}Dashboard: Alerts → will show signature + category breakdown{RESET}")
    print(f"  {DIM}Dashboard: Threats & Correlation → community-id cross-reference{RESET}")
    print(f"  {DIM}Chat UI:   'Show me Suricata alerts in the last hour'{RESET}")
    print(f"  {DIM}Chat UI:   'What is 203.0.113.55 and should I be worried?'{RESET}")


# ─── Interactive menu ──────────────────────────────────────────────────────────
def interactive_menu() -> tuple[list[int], bool]:
    """Show a menu and return (selected_scenarios, fast_mode)."""
    print(f"""
{BOLD}{CYAN}╔══════════════════════════════════════════════════════════════╗
║           IDS Demo Event Injector                            ║
╚══════════════════════════════════════════════════════════════╝{RESET}

  Inject simulated network threats to trigger IDS alerts.
  No real traffic is sent — data is written to the log pipeline.

  {BOLD}Scenarios:{RESET}
    {GREEN}1{RESET}  New IoT Device       Unknown device joins 192.168.122.200
    {YELLOW}2{RESET}  DPRK C2 Beacon       IP camera beacons to North Korea
    {RED}3{RESET}  IoT Traffic Spike    Thermostat generates 2000 conn/5min
    {RED}4{RESET}  Malware Signature    Cobalt Strike beacon + Nmap scan

  {BOLD}Options:{RESET}
    a  All scenarios
    q  Quit

  {DIM}Email alert delay: ~2 min normally, ~60s with fast mode{RESET}
""")

    while True:
        raw = input(f"  {BOLD}Select scenarios (e.g. 1 2 4, or 'a'):{RESET} ").strip().lower()
        if raw in ("q", "quit", "exit"):
            print("  Bye.")
            sys.exit(0)
        if raw in ("a", "all"):
            chosen = [1, 2, 3, 4]
            break
        try:
            chosen = [int(x) for x in raw.replace(",", " ").split() if x]
            if all(1 <= s <= 4 for s in chosen) and chosen:
                break
            print(f"  {RED}Enter numbers 1–4 (e.g. '1 3'){RESET}")
        except ValueError:
            print(f"  {RED}Invalid input — enter numbers 1–4{RESET}")

    raw_fast = input(f"  {BOLD}Enable fast mode (inject anomaly directly, skip ~2min wait)? [y/N]:{RESET} ")
    fast = raw_fast.strip().lower() in ("y", "yes")

    return chosen, fast


# ─── Main ──────────────────────────────────────────────────────────────────────
def main() -> None:
    global VECTOR_DIR, DUCKDB_CONTAINER
    parser = argparse.ArgumentParser(
        description="IDS Demo Event Injector — simulate network threats for demonstration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              sudo python3 scripts/demo_inject.py              # interactive menu
              sudo python3 scripts/demo_inject.py --all        # all 4 scenarios
              sudo python3 scripts/demo_inject.py -s 1 -s 4   # scenario 1 + 4
              sudo python3 scripts/demo_inject.py --all --fast # immediate alerts
              sudo python3 scripts/demo_inject.py --clean      # remove demo data
        """),
    )
    parser.add_argument("--all", "-a", action="store_true", help="Run all 4 scenarios")
    parser.add_argument("--scenario", "-s", type=int, action="append", metavar="N",
                        help="Scenario to inject (1-4, repeatable)")
    parser.add_argument("--fast", "-f", action="store_true",
                        help="Also inject directly into anomaly_events (email in <60s)")
    parser.add_argument("--clean", action="store_true",
                        help="Remove all injected demo data and exit")
    parser.add_argument("--vector-dir", default=VECTOR_DIR,
                        help=f"Vector staging directory (default: {VECTOR_DIR})")
    parser.add_argument("--container", default=DUCKDB_CONTAINER,
                        help=f"duckdb-mgr container name (default: {DUCKDB_CONTAINER})")

    args = parser.parse_args()
    VECTOR_DIR = args.vector_dir
    DUCKDB_CONTAINER = args.container

    if args.clean:
        do_clean()
        return

    # Determine which scenarios to run

    if args.all:
        scenarios = [1, 2, 3, 4]
    elif args.scenario:
        scenarios = sorted(set(args.scenario))
    else:
        # Interactive mode
        scenarios, args.fast = interactive_menu()

    if not scenarios:
        parser.print_help()
        return

    # Validate vector dir exists
    if not os.path.isdir(VECTOR_DIR):
        print(f"\n{RED}ERROR: Vector staging directory not found: {VECTOR_DIR}{RESET}")
        print(f"  Is the IDS stack running? Try: docker compose up -d")
        sys.exit(1)

    print(f"\n{BOLD}Running {len(scenarios)} scenario(s): {scenarios}{RESET}")
    if args.fast:
        print(f"{YELLOW}Fast mode enabled — anomaly events injected directly{RESET}")

    runners = {
        1: run_scenario_1,
        2: run_scenario_2,
        3: run_scenario_3,
        4: run_scenario_4,
    }

    for s in scenarios:
        if s in runners:
            runners[s](fast=args.fast)

    # ── Summary ──────────────────────────────────────────────────────────────
    hdr("Demo Injection Complete", GREEN)
    print(f"\n  {BOLD}What happens next:{RESET}")
    print(f"  {DIM}1.{RESET} duckdb-mgr ingests NDJSON files           {DIM}(~10s){RESET}")
    print(f"  {DIM}2.{RESET} Device summaries + anomaly detection run   {DIM}(~50s){RESET}")
    print(f"  {DIM}3.{RESET} alert-agent drafts + sends email            {DIM}(~60s){RESET}")
    if args.fast:
        print(f"  {DIM}   Fast mode: steps 2+3 start immediately    ✓{RESET}")

    print(f"\n  {BOLD}Where to watch:{RESET}")
    print(f"  {BLUE}Grafana{RESET}    http://localhost:3000  →  Overview / Alerts / Network Nodes")
    print(f"  {BLUE}Chat UI{RESET}    http://localhost:8501  →  Ask: 'What threats did you find?'")
    print(f"  {BLUE}Alerts{RESET}     docker compose logs alert-agent --follow")
    print(f"  {BLUE}Pipeline{RESET}   docker compose logs duckdb-mgr --follow")

    print(f"\n  {BOLD}Suggested demo chat questions:{RESET}")
    print(f'  {DIM}•{RESET} "What new devices appeared on the network today?"')
    print(f'  {DIM}•{RESET} "Are we communicating with any suspicious countries?"')
    print(f'  {DIM}•{RESET} "Which device is generating the most traffic?"')
    print(f'  {DIM}•{RESET} "Show me recent Suricata alerts and explain them."')
    print(f'  {DIM}•{RESET} "Run an nmap scan on 192.168.122.102"')

    print(f"\n  {DIM}Cleanup: python3 scripts/demo_inject.py --clean{RESET}\n")


if __name__ == "__main__":
    main()

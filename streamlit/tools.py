"""Tool definitions and implementations for Ollama tool-calling."""

import ipaddress
import json
import os
import smtplib
import sqlite3
import subprocess
import traceback
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.mime.text import MIMEText

import apprise
import duckdb

DUCKDB_PATH = os.environ.get("DUCKDB_PATH", "/var/log/ids/duckdb/ids_readonly.duckdb")
WHITELIST_PATH = os.environ.get("WHITELIST_PATH", "/var/log/ids/duckdb/whitelist.db")
NMAP_RESULTS_PATH = os.environ.get("NMAP_RESULTS_PATH", "/var/log/ids/duckdb/nmap_results.db")
RAG_DUCKDB_PATH = os.environ.get("RAG_DUCKDB_PATH", "/var/log/ids/duckdb/rag.duckdb")
EMBED_MODEL = os.environ.get("EMBED_MODEL", "nomic-embed-text")
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
APPRISE_URLS = os.environ.get("APPRISE_URLS", "")
MAX_ROWS = 50
QUERY_TIMEOUT = 10  # seconds
NMAP_TIMEOUT = 300  # seconds


def _read_secret(name: str) -> str:
    """Read a Docker secret from /run/secrets/<name>. Returns empty string if not found."""
    path = f"/run/secrets/{name}"
    try:
        with open(path) as f:
            return f.read().strip()
    except FileNotFoundError:
        return ""


GMAIL_USER = _read_secret("gmail_user")
GMAIL_APP_PASSWORD = _read_secret("gmail_app_password")
ALERT_RECIPIENT = _read_secret("alert_recipient")


def _init_whitelist():
    """Create whitelist SQLite DB if it doesn't exist."""
    conn = sqlite3.connect(WHITELIST_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS whitelist (
            ip TEXT PRIMARY KEY,
            description TEXT,
            added_at TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.commit()
    conn.close()


def _init_nmap_db():
    """Create nmap results SQLite DB if it doesn't exist."""
    conn = sqlite3.connect(NMAP_RESULTS_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS nmap_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scanned_at TEXT NOT NULL,
            target TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            results TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


# Initialize on import
_init_whitelist()
_init_nmap_db()


# --- Tool implementations ---

def query_events(sql: str) -> str:
    """Execute a read-only SELECT query against DuckDB."""
    sql_stripped = sql.strip()
    if not sql_stripped.upper().startswith("SELECT"):
        return json.dumps({"error": "Only SELECT queries are allowed."})

    try:
        db = duckdb.connect(DUCKDB_PATH, read_only=True)
        try:
            # Inject LIMIT if not present
            if "LIMIT" not in sql_stripped.upper():
                sql_stripped = sql_stripped.rstrip(";") + f" LIMIT {MAX_ROWS}"

            result = db.execute(sql_stripped)
            columns = [desc[0] for desc in result.description]
            rows = result.fetchmany(MAX_ROWS)
            data = [dict(zip(columns, row)) for row in rows]

            # Convert non-serializable types to strings
            for row in data:
                for k, v in row.items():
                    if not isinstance(v, (str, int, float, bool, type(None))):
                        row[k] = str(v)

            return json.dumps({"columns": columns, "row_count": len(data), "data": data}, default=str)
        finally:
            db.close()
    except Exception as e:
        return json.dumps({"error": str(e), "traceback": traceback.format_exc()})


def get_devices(sort_by: str = "bytes", limit: int = 50) -> str:
    """List internal devices with manufacturer, hostname, traffic stats."""
    sort_col = {
        "bytes": "total_bytes",
        "conns": "total_conns",
        "last_seen": "last_seen",
    }.get(sort_by, "total_bytes")
    limit = max(1, min(int(limit), 50))
    return query_events(
        f"SELECT ip, mac, manufacturer, hostname, first_seen, last_seen, "
        f"total_conns, total_bytes, protocols, services "
        f"FROM devices ORDER BY {sort_col} DESC LIMIT {limit}"
    )


def get_alerts(hours: int = 24) -> str:
    """Get recent Suricata alerts from the last N hours."""
    return query_events(
        f"SELECT timestamp, json_extract_string(raw, '$.alert.signature') AS signature, "
        f"json_extract_string(raw, '$.alert.severity') AS severity, "
        f"json_extract_string(raw, '$.alert.category') AS category, "
        f"json_extract_string(raw, '$.src_ip') AS src_ip, "
        f"json_extract_string(raw, '$.dest_ip') AS dest_ip, "
        f"json_extract_string(raw, '$.src_port') AS src_port, "
        f"json_extract_string(raw, '$.dest_port') AS dest_port "
        f"FROM events WHERE source_tool='suricata' AND log_type='eve' "
        f"AND json_extract_string(raw, '$.event_type')='alert' "
        f"AND timestamp > now() - INTERVAL '{int(hours)} hours' "
        f"ORDER BY timestamp DESC LIMIT 50"
    )


def get_external_connections(country: str = "") -> str:
    """Get external IPs with optional country filter."""
    if country:
        country_clean = country.strip().upper()[:2]
        return query_events(
            f"SELECT ip, country, total_conns, total_bytes, contacted_by, top_service, top_dest_port "
            f"FROM external_ips WHERE country = '{country_clean}' "
            f"ORDER BY total_conns DESC LIMIT 50"
        )
    return query_events(
        "SELECT ip, country, total_conns, total_bytes, contacted_by, top_service, top_dest_port "
        "FROM external_ips ORDER BY total_conns DESC LIMIT 50"
    )


def get_dns_top_domains(hours: int = 24, limit: int = 10) -> str:
    """Get top DNS domains queried in the last N hours."""
    return query_events(
        f"SELECT json_extract_string(raw, '$.query') AS domain, count(*) AS queries "
        f"FROM events WHERE source_tool='zeek' AND log_type='dns' "
        f"AND timestamp > now() - INTERVAL '{int(hours)} hours' "
        f"GROUP BY domain ORDER BY queries DESC LIMIT {int(limit)}"
    )


def get_traffic_by_protocol(hours: int = 24) -> str:
    """Get connection count and bytes broken down by protocol."""
    return query_events(
        f"SELECT json_extract_string(raw, '$.proto') AS protocol, "
        f"count(*) AS connections, "
        f"CAST(sum(COALESCE(TRY_CAST(json_extract(raw, '$.orig_bytes') AS BIGINT),0) "
        f"+ COALESCE(TRY_CAST(json_extract(raw, '$.resp_bytes') AS BIGINT),0)) AS BIGINT) AS total_bytes "
        f"FROM events WHERE source_tool='zeek' AND log_type='conn' "
        f"AND timestamp > now() - INTERVAL '{int(hours)} hours' "
        f"GROUP BY protocol ORDER BY connections DESC LIMIT 20"
    )


def get_event_stats() -> str:
    """Get summary counts of events by source tool and log type."""
    return query_events(
        "SELECT source_tool, log_type, count(*) AS count "
        "FROM events GROUP BY source_tool, log_type ORDER BY count DESC"
    )


def check_whitelist(action: str = "list", ip: str = "", description: str = "") -> str:
    """Check, add, or remove IPs from the whitelist."""
    try:
        conn = sqlite3.connect(WHITELIST_PATH)
        conn.row_factory = sqlite3.Row

        if action == "check" and ip:
            row = conn.execute("SELECT * FROM whitelist WHERE ip = ?", (ip,)).fetchone()
            conn.close()
            if row:
                return json.dumps({"whitelisted": True, "ip": row["ip"],
                                   "description": row["description"], "added_at": row["added_at"]})
            return json.dumps({"whitelisted": False, "ip": ip})

        elif action == "add" and ip:
            conn.execute("INSERT OR REPLACE INTO whitelist (ip, description) VALUES (?, ?)",
                         (ip, description or "Added via chat"))
            conn.commit()
            conn.close()
            return json.dumps({"success": True, "action": "added", "ip": ip})

        elif action == "remove" and ip:
            conn.execute("DELETE FROM whitelist WHERE ip = ?", (ip,))
            conn.commit()
            conn.close()
            return json.dumps({"success": True, "action": "removed", "ip": ip})

        else:  # list
            rows = conn.execute("SELECT * FROM whitelist ORDER BY added_at DESC").fetchall()
            conn.close()
            data = [{"ip": r["ip"], "description": r["description"], "added_at": r["added_at"]} for r in rows]
            return json.dumps({"count": len(data), "whitelist": data})

    except Exception as e:
        return json.dumps({"error": str(e)})


def send_notification(title: str, body: str) -> str:
    """Send a notification via Apprise (email, Slack, etc.)."""
    if not APPRISE_URLS:
        return json.dumps({"error": "No APPRISE_URLS configured. Set the APPRISE_URLS environment variable."})
    try:
        apobj = apprise.Apprise()
        for url in APPRISE_URLS.split(","):
            url = url.strip()
            if url:
                apobj.add(url)
        result = apobj.notify(title=title, body=body)
        return json.dumps({"success": result, "title": title})
    except Exception as e:
        return json.dumps({"error": str(e)})


def send_email(subject: str, body: str, recipient: str = "") -> str:
    """Send an email via Gmail SMTP. Uses configured recipient if none provided."""
    to_addr = recipient or ALERT_RECIPIENT
    if not GMAIL_USER or not GMAIL_APP_PASSWORD or not to_addr:
        return json.dumps({
            "error": "Gmail credentials not configured. "
            "Ensure gmail_user, gmail_app_password, and alert_recipient Docker secrets are set."
        })
    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = GMAIL_USER
        msg["To"] = to_addr

        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=15) as server:
            server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
            server.send_message(msg)

        return json.dumps({"success": True, "subject": subject, "recipient": to_addr})
    except Exception as e:
        return json.dumps({"error": str(e), "traceback": traceback.format_exc()})


def _is_rfc1918(target: str) -> bool:
    """Check if a target IP or CIDR is within RFC1918 private address space."""
    try:
        net = ipaddress.ip_network(target, strict=False)
        private_ranges = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        ]
        return any(
            net.network_address >= r.network_address and net.broadcast_address <= r.broadcast_address
            for r in private_ranges
        )
    except ValueError:
        return False


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

        # Get hostname if available
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

        hosts.append({
            "ip": host_ip,
            "hostname": hostname,
            "state": host_state,
            "ports": ports,
        })
    return hosts


def nmap_scan(target: str, scan_type: str = "quick") -> str:
    """Run an nmap scan against a RFC1918 target. Results saved to SQLite for duckdb-mgr pickup."""
    if not _is_rfc1918(target):
        return json.dumps({"error": "Only RFC1918 private addresses are allowed (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)."})

    scan_args = {
        "quick": ["--top-ports", "100", "-T4"],
        "full": ["--top-ports", "1000", "-T4"],
        "service": ["-sV", "--top-ports", "100", "-T4"],
    }
    args = scan_args.get(scan_type, scan_args["quick"])
    cmd = ["nmap"] + args + ["-oX", "-", target]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=NMAP_TIMEOUT)
        if result.returncode != 0:
            return json.dumps({"error": f"nmap failed: {result.stderr.strip()}"})

        hosts = _parse_nmap_xml(result.stdout)
        scan_result = {
            "target": target,
            "scan_type": scan_type,
            "host_count": len(hosts),
            "hosts": hosts,
        }

        # Save to SQLite for duckdb-mgr to pick up
        try:
            conn = sqlite3.connect(NMAP_RESULTS_PATH)
            conn.execute(
                "INSERT INTO nmap_results (scanned_at, target, scan_type, results) VALUES (?, ?, ?, ?)",
                (datetime.now(timezone.utc).isoformat(), target, scan_type, json.dumps(scan_result)),
            )
            conn.commit()
            conn.close()
        except Exception:
            pass  # non-fatal — results still returned to user

        return json.dumps(scan_result, default=str)
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"nmap scan timed out after {NMAP_TIMEOUT}s"})
    except FileNotFoundError:
        return json.dumps({"error": "nmap is not installed"})
    except Exception as e:
        return json.dumps({"error": str(e), "traceback": traceback.format_exc()})


def get_scan_history(ip: str = "") -> str:
    """Retrieve past nmap scan results, optionally filtered by IP."""
    try:
        conn = sqlite3.connect(NMAP_RESULTS_PATH)
        conn.row_factory = sqlite3.Row
        if ip:
            rows = conn.execute(
                "SELECT id, scanned_at, target, scan_type, results FROM nmap_results "
                "WHERE target LIKE ? ORDER BY scanned_at DESC LIMIT 20",
                (f"%{ip}%",),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, scanned_at, target, scan_type, results FROM nmap_results "
                "ORDER BY scanned_at DESC LIMIT 20"
            ).fetchall()
        conn.close()

        data = []
        for r in rows:
            entry = {
                "id": r["id"],
                "scanned_at": r["scanned_at"],
                "target": r["target"],
                "scan_type": r["scan_type"],
            }
            try:
                entry["results"] = json.loads(r["results"])
            except (json.JSONDecodeError, TypeError):
                entry["results"] = r["results"]
            data.append(entry)

        return json.dumps({"count": len(data), "scans": data}, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


def rag_search_threat_intel(query: str, top_k: int = 5) -> str:
    """Semantic search over local Suricata rule database for threat intel context."""
    import ollama as _ollama

    try:
        client = _ollama.Client(host=OLLAMA_HOST)
        embed_resp = client.embed(model=EMBED_MODEL, input=query)
        query_embedding = embed_resp.embeddings[0]
    except Exception as e:
        return json.dumps({"results": [], "message": f"Embedding failed: {e}"})

    try:
        db = duckdb.connect(RAG_DUCKDB_PATH, read_only=True)
        try:
            rows = db.execute(
                """
                SELECT sid, msg, classtype, chunk_text,
                       list_cosine_similarity(embedding, ?) AS score
                FROM rag_threat_intel
                WHERE embedding IS NOT NULL
                ORDER BY score DESC
                LIMIT ?
                """,
                [query_embedding, int(top_k)],
            ).fetchall()
        finally:
            db.close()

        results = []
        for sid, msg, classtype, chunk_text, score in rows:
            results.append({
                "sid": sid,
                "msg": msg,
                "classtype": classtype or "unknown",
                "context": chunk_text,
                "similarity": round(float(score), 4) if score is not None else 0.0,
            })
        return json.dumps({"results": results, "count": len(results)})

    except FileNotFoundError:
        return json.dumps({
            "results": [],
            "message": "RAG database not yet built. Run suricata-update first to populate rules.",
        })
    except Exception as e:
        return json.dumps({"results": [], "message": f"RAG search failed: {e}"})


# --- Tool schemas for Ollama ---

TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "query_events",
            "description": (
                "Execute a read-only SQL SELECT query against the DuckDB IDS database. "
                "Use this for any analytical question about network events, traffic, devices, etc. "
                "Available tables: events, devices, external_ips, oui_lookup, geoip_lookup. "
                "Results are capped at 50 rows."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "sql": {
                        "type": "string",
                        "description": "A SQL SELECT query to execute against DuckDB."
                    }
                },
                "required": ["sql"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_devices",
            "description": (
                "List internal network devices with MAC address, manufacturer, hostname, "
                "connection count, bytes transferred, protocols, and services. "
                "Use for: device inventory, top talkers, chatty/noisy devices, device lookup."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "sort_by": {
                        "type": "string",
                        "enum": ["bytes", "conns", "last_seen"],
                        "description": "Sort order: 'bytes' (most traffic), 'conns' (most connections), 'last_seen' (most recent). Default: 'bytes'."
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Number of devices to return (1-50). Default: 50. Use 5 or 10 for 'top N' questions."
                    }
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_alerts",
            "description": (
                "Get recent Suricata IDS alerts (signature-based threat detections). "
                "Returns alert signature, severity, category, source/destination IPs and ports."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "hours": {
                        "type": "integer",
                        "description": "Number of hours to look back (default: 24)."
                    }
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_external_connections",
            "description": (
                "Get external (non-local) IP addresses that have communicated with the network, "
                "with GeoIP country data. Optionally filter by 2-letter country code."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "country": {
                        "type": "string",
                        "description": "Optional 2-letter country code to filter by (e.g., 'CN', 'RU', 'US')."
                    }
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_dns_top_domains",
            "description": (
                "Get the most queried DNS domains. Use this for any question about "
                "DNS queries, domain lookups, or most visited domains."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "hours": {
                        "type": "integer",
                        "description": "Hours to look back (default: 24)."
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Number of top domains to return (default: 10)."
                    }
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_traffic_by_protocol",
            "description": (
                "Get network traffic broken down by protocol (TCP, UDP, ICMP, etc.). "
                "Shows connection count and total bytes per protocol."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "hours": {
                        "type": "integer",
                        "description": "Hours to look back (default: 24)."
                    }
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_event_stats",
            "description": (
                "Get total event counts grouped by source (suricata/zeek) and log type. "
                "Use this when asked about total events, database size, or event breakdown."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_whitelist",
            "description": (
                "Manage the IP whitelist. Actions: 'list' (show all), 'check' (check if IP is whitelisted), "
                "'add' (add IP to whitelist), 'remove' (remove IP from whitelist)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["list", "check", "add", "remove"],
                        "description": "The action to perform."
                    },
                    "ip": {
                        "type": "string",
                        "description": "IP address (required for check/add/remove)."
                    },
                    "description": {
                        "type": "string",
                        "description": "Description for the whitelist entry (used with 'add')."
                    }
                },
                "required": ["action"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "send_notification",
            "description": (
                "Send a notification alert via configured channels (email, Slack, etc.). "
                "Use this when the user asks to be alerted about something or to send a report."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Notification title/subject."
                    },
                    "body": {
                        "type": "string",
                        "description": "Notification body content."
                    }
                },
                "required": ["title", "body"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "nmap_scan",
            "description": (
                "Run an nmap port scan against a local network target (RFC1918 only). "
                "Use this when asked to scan a device, check open ports, or discover services. "
                "Scan types: 'quick' (top 100 ports), 'full' (top 1000 ports), 'service' (version detection)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP address or CIDR range (e.g., '192.168.2.1' or '192.168.2.0/24'). Must be RFC1918."
                    },
                    "scan_type": {
                        "type": "string",
                        "enum": ["quick", "full", "service"],
                        "description": "Scan type: 'quick' (top 100 ports), 'full' (top 1000), 'service' (version detection). Default: 'quick'."
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_scan_history",
            "description": (
                "Retrieve previous nmap scan results. Optionally filter by IP address. "
                "Use this when asked about past scans, previous scan results, or port history."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "Optional IP address to filter scan history."
                    }
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "send_email",
            "description": (
                "Send an email via Gmail. Use this when the user asks you to email them "
                "a report, summary, device list, or any information from the IDS. "
                "Compose a clear, well-formatted email body with the requested data."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "subject": {
                        "type": "string",
                        "description": "Email subject line."
                    },
                    "body": {
                        "type": "string",
                        "description": "Email body in plain text. Format the data clearly with sections and line breaks."
                    },
                    "recipient": {
                        "type": "string",
                        "description": "Optional recipient email address. If not provided, uses the configured default."
                    }
                },
                "required": ["subject", "body"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "rag_search_threat_intel",
            "description": (
                "Semantic search over the local Suricata rule database. "
                "Use this when you see a Suricata alert signature and want to understand "
                "what it detects, what attack category it belongs to, or what response is appropriate. "
                "Use this BEFORE explaining any Suricata alert — input the exact signature string."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Alert signature name or natural language description of the threat to look up."
                    },
                    "top_k": {
                        "type": "integer",
                        "description": "Number of matching rules to return (default: 5)."
                    }
                },
                "required": ["query"]
            }
        }
    }
]

# Map tool names to callables
TOOL_MAP = {
    "query_events": lambda args: query_events(args.get("sql", "")),
    "get_devices": lambda args: get_devices(sort_by=args.get("sort_by", "bytes"), limit=args.get("limit", 50)),
    "get_alerts": lambda args: get_alerts(args.get("hours", 24)),
    "get_external_connections": lambda args: get_external_connections(args.get("country", "")),
    "get_dns_top_domains": lambda args: get_dns_top_domains(args.get("hours", 24), args.get("limit", 10)),
    "get_traffic_by_protocol": lambda args: get_traffic_by_protocol(args.get("hours", 24)),
    "get_event_stats": lambda args: get_event_stats(),
    "check_whitelist": lambda args: check_whitelist(
        action=args.get("action", "list"),
        ip=args.get("ip", ""),
        description=args.get("description", "")
    ),
    "nmap_scan": lambda args: nmap_scan(
        target=args.get("target", ""),
        scan_type=args.get("scan_type", "quick"),
    ),
    "get_scan_history": lambda args: get_scan_history(ip=args.get("ip", "")),
    "send_notification": lambda args: send_notification(
        title=args.get("title", ""),
        body=args.get("body", "")
    ),
    "send_email": lambda args: send_email(
        subject=args.get("subject", ""),
        body=args.get("body", ""),
        recipient=args.get("recipient", ""),
    ),
    "rag_search_threat_intel": lambda args: rag_search_threat_intel(
        query=args.get("query", ""),
        top_k=args.get("top_k", 5),
    ),
}

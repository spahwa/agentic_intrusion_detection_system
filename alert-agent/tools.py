"""Tool definitions and implementations for the alert agent."""

import json
import os
import smtplib
import time
import traceback
from email.mime.text import MIMEText

import duckdb
import ollama as _ollama

DUCKDB_PATH = os.environ.get("DUCKDB_PATH", "/var/log/ids/duckdb/ids_readonly.duckdb")
RAG_DUCKDB_PATH = os.environ.get("RAG_DUCKDB_PATH", "/var/log/ids/duckdb/rag.duckdb")
EMBED_MODEL = os.environ.get("EMBED_MODEL", "nomic-embed-text")
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
MAX_ROWS = 50


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


def query_events(sql: str) -> str:
    """Execute a read-only SELECT query against DuckDB."""
    sql_stripped = sql.strip()
    if not sql_stripped.upper().startswith("SELECT"):
        return json.dumps({"error": "Only SELECT queries are allowed."})

    last_err = None
    for attempt in range(3):
        try:
            db = duckdb.connect(DUCKDB_PATH, read_only=True)
            try:
                if "LIMIT" not in sql_stripped.upper():
                    sql_stripped = sql_stripped.rstrip(";") + f" LIMIT {MAX_ROWS}"

                result = db.execute(sql_stripped)
                columns = [desc[0] for desc in result.description]
                rows = result.fetchmany(MAX_ROWS)
                data = [dict(zip(columns, row)) for row in rows]

                for row in data:
                    for k, v in row.items():
                        if not isinstance(v, (str, int, float, bool, type(None))):
                            row[k] = str(v)

                return json.dumps({"columns": columns, "row_count": len(data), "data": data}, default=str)
            finally:
                db.close()
        except duckdb.IOException:
            last_err = traceback.format_exc()
            time.sleep(2)
        except Exception as e:
            return json.dumps({"error": str(e), "traceback": traceback.format_exc()})
    return json.dumps({"error": "DuckDB locked after 3 retries", "traceback": last_err})


def send_email(subject: str, body: str) -> str:
    """Send an email alert via Gmail SMTP."""
    if not GMAIL_USER or not GMAIL_APP_PASSWORD or not ALERT_RECIPIENT:
        return json.dumps({
            "error": "Gmail credentials not configured. "
            "Set GMAIL_USER, GMAIL_APP_PASSWORD, and ALERT_RECIPIENT environment variables."
        })

    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = GMAIL_USER
        msg["To"] = ALERT_RECIPIENT

        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=15) as server:
            server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
            server.send_message(msg)

        return json.dumps({"success": True, "subject": subject, "recipient": ALERT_RECIPIENT})
    except Exception as e:
        return json.dumps({"error": str(e), "traceback": traceback.format_exc()})


def rag_search_threat_intel(query: str, top_k: int = 5) -> str:
    """Semantic search over local Suricata rule database for threat intel context."""
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
            "message": "RAG database not yet built. Rules not indexed yet.",
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
                "Use this to gather additional context about an anomaly — recent connections, "
                "DNS queries, or alert history for specific IPs. "
                "Available tables: events, devices, external_ips. Results capped at 50 rows."
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
            "name": "send_email",
            "description": (
                "Send an email alert to the configured recipient. "
                "ALWAYS call this after analyzing an anomaly to deliver the alert notification."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "subject": {
                        "type": "string",
                        "description": "Email subject line, e.g. '[IDS Alert] High - New Unknown Device'"
                    },
                    "body": {
                        "type": "string",
                        "description": "Email body in plain text. Include: what happened, key details, recommended action."
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
                "Use this to understand a Suricata alert signature — what it detects, "
                "what attack category it belongs to, and what response is appropriate. "
                "Input the exact signature string from the anomaly details."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Alert signature name or natural language description of the threat."
                    },
                    "top_k": {
                        "type": "integer",
                        "description": "Number of matching rules to return (default: 3)."
                    }
                },
                "required": ["query"]
            }
        }
    }
]

TOOL_MAP = {
    "query_events": lambda args: query_events(args.get("sql", "")),
    "send_email": lambda args: send_email(
        subject=args.get("subject", ""),
        body=args.get("body", ""),
    ),
    "rag_search_threat_intel": lambda args: rag_search_threat_intel(
        query=args.get("query", ""),
        top_k=args.get("top_k", 3),
    ),
}

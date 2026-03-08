"""Streamlit chat UI for Agentic IDS — Chat with your Network."""

import json
import os
import time

import duckdb
import ollama
import streamlit as st

from system_prompt import SYSTEM_PROMPT
from tools import TOOL_DEFINITIONS, TOOL_MAP

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen3.5:2b")
DUCKDB_PATH = os.environ.get("DUCKDB_PATH", "/var/log/ids/duckdb/ids_readonly.duckdb")
MAX_TOOL_ROUNDS = 5
NUM_CTX = 4096
NUM_THREAD = int(os.environ.get("OLLAMA_NUM_THREAD", "4"))


def get_ollama_client():
    """Get Ollama client instance."""
    return ollama.Client(host=OLLAMA_HOST)


def get_db_stats():
    """Get quick DuckDB stats for sidebar."""
    try:
        db = duckdb.connect(DUCKDB_PATH, read_only=True)
        try:
            event_count = db.execute("SELECT count(*) FROM events").fetchone()[0]
            device_count = db.execute("SELECT count(*) FROM devices").fetchone()[0]
            return {"events": event_count, "devices": device_count}
        finally:
            db.close()
    except Exception as e:
        return {"error": str(e)}


def execute_tool(fn_name, fn_args):
    """Execute a tool and return the result string."""
    if fn_name in TOOL_MAP:
        return TOOL_MAP[fn_name](fn_args)
    return json.dumps({"error": f"Unknown tool: {fn_name}"})


# --- Page config ---
st.set_page_config(
    page_title="Agentic IDS - Chat",
    page_icon="🔒",
    layout="wide",
)

st.title("Chat with your Network")
st.caption("Ask questions about your network traffic, devices, and security events")

# --- Sidebar ---
with st.sidebar:
    st.header("System Status")

    try:
        client = get_ollama_client()
        models = client.list()
        model_names = [m.model for m in models.models]
        ollama_ok = any(OLLAMA_MODEL in name for name in model_names)
        st.success("Ollama: Connected")
        st.text(f"Model: {OLLAMA_MODEL}")
        if not ollama_ok:
            st.warning(f"Model {OLLAMA_MODEL} not found!")
    except Exception as e:
        st.error("Ollama: Disconnected")
        st.text(str(e))
        client = None

    st.divider()

    stats = get_db_stats()
    if "error" in stats:
        st.error(f"DuckDB: {stats['error']}")
    else:
        st.metric("Events (24h)", f"{stats['events']:,}")
        st.metric("Known Devices", stats["devices"])

    st.divider()
    if st.button("Clear Chat"):
        st.session_state.messages = []
        st.rerun()

# --- Chat ---
if "messages" not in st.session_state:
    st.session_state.messages = []

# Display chat history
for msg in st.session_state.messages:
    if msg["role"] == "user":
        with st.chat_message("user"):
            st.markdown(msg["content"])
    elif msg["role"] == "assistant":
        with st.chat_message("assistant"):
            st.markdown(msg["content"])
            if msg.get("tool_log"):
                with st.expander(f"Tool calls ({len(msg['tool_log'])})"):
                    for entry in msg["tool_log"]:
                        st.markdown(f"**{entry['tool']}**")
                        if entry.get("args"):
                            st.code(json.dumps(entry["args"], indent=2), language="json")
                        if entry.get("result"):
                            try:
                                parsed = json.loads(entry["result"])
                                st.json(parsed)
                            except (json.JSONDecodeError, TypeError):
                                st.text(str(entry["result"])[:2000])

# Chat input
if prompt := st.chat_input("Ask about your network..."):
    with st.chat_message("user"):
        st.markdown(prompt)

    st.session_state.messages.append({"role": "user", "content": prompt})

    if client is None:
        with st.chat_message("assistant"):
            st.error("Cannot connect to Ollama. Please check that Ollama is running.")
        st.session_state.messages.append({
            "role": "assistant", "content": "Cannot connect to Ollama."
        })
    else:
        # Build message history for Ollama (system + last 6 turns to limit context)
        ollama_messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        recent = st.session_state.messages[-6:]
        for msg in recent:
            if msg["role"] in ("user", "assistant"):
                ollama_messages.append({"role": msg["role"], "content": msg["content"]})

        tool_log = []

        with st.chat_message("assistant"):
            status_area = st.container()
            response_area = st.empty()

            final_text = ""

            for round_num in range(MAX_TOOL_ROUNDS):
                # --- Tool-calling round: non-streaming to get proper tool_calls ---
                with status_area:
                    step_status = st.status(
                        "Thinking..." if round_num == 0 else "Analyzing results...",
                        expanded=True,
                    )
                    step_status.write("Waiting for model response...")

                t0 = time.monotonic()
                response = client.chat(
                    model=OLLAMA_MODEL,
                    messages=ollama_messages,
                    tools=TOOL_DEFINITIONS,
                    options={"num_ctx": NUM_CTX, "num_thread": NUM_THREAD},
                )
                elapsed = time.monotonic() - t0
                msg = response.message

                ollama_messages.append(msg)

                # If no tool calls, check if we got a real answer
                if not msg.tool_calls:
                    final_text = msg.content or ""

                    # If response is empty/too short and no tools were called yet,
                    # nudge the LLM to use its tools
                    if len(final_text.strip()) < 20 and not tool_log and round_num < MAX_TOOL_ROUNDS - 1:
                        step_status.update(
                            label=f"Retrying ({elapsed:.1f}s)", state="running", expanded=False
                        )
                        ollama_messages.append({
                            "role": "user",
                            "content": (
                                "You did not call any tools. You MUST use one of your available tools "
                                "to answer the question. Use get_devices, get_alerts, query_events, etc. "
                                "Re-read the original question and call the appropriate tool now."
                            ),
                        })
                        continue

                    step_status.update(
                        label=f"Done ({elapsed:.1f}s)", state="complete", expanded=False
                    )
                    response_area.markdown(final_text)
                    break

                # Tool calls detected — execute them with visible progress
                step_status.update(
                    label=f"Planning ({elapsed:.1f}s)", state="complete", expanded=False
                )

                for tool_call in msg.tool_calls:
                    fn_name = tool_call.function.name
                    fn_args = tool_call.function.arguments

                    with status_area:
                        with st.status(f"Running: {fn_name}", expanded=True) as tool_st:
                            if fn_args:
                                tool_st.code(json.dumps(fn_args, indent=2), language="json")

                            t1 = time.monotonic()
                            result = execute_tool(fn_name, fn_args)
                            tool_elapsed = time.monotonic() - t1

                            tool_log.append({
                                "tool": fn_name, "args": fn_args, "result": result,
                            })

                            try:
                                parsed = json.loads(result)
                                row_count = parsed.get("row_count", "?")
                                tool_st.caption(f"{row_count} rows in {tool_elapsed:.1f}s")
                            except (json.JSONDecodeError, TypeError):
                                tool_st.caption(f"Done in {tool_elapsed:.1f}s")

                            tool_st.update(
                                label=f"Done: {fn_name} ({tool_elapsed:.1f}s)",
                                state="complete", expanded=False,
                            )

                    ollama_messages.append({"role": "tool", "content": result})

            else:
                # Hit max rounds — show whatever we have
                final_text = msg.content or "Reached maximum tool call rounds."
                response_area.markdown(final_text)

            # Show detailed tool log in expander
            if tool_log:
                with st.expander(f"Tool calls ({len(tool_log)})"):
                    for entry in tool_log:
                        st.markdown(f"**{entry['tool']}**")
                        if entry.get("args"):
                            st.code(json.dumps(entry["args"], indent=2), language="json")
                        if entry.get("result"):
                            try:
                                parsed = json.loads(entry["result"])
                                st.json(parsed)
                            except (json.JSONDecodeError, TypeError):
                                st.text(str(entry["result"])[:2000])

        st.session_state.messages.append({
            "role": "assistant",
            "content": final_text,
            "tool_log": tool_log,
        })

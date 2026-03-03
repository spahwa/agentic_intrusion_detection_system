"""Quick benchmark: qwen3:4b (think=False) on 3 IDS queries."""

import json
import os
import sys
import time

sys.path.insert(0, "/app")

import ollama
from tools import TOOL_DEFINITIONS, TOOL_MAP
from system_prompt import SYSTEM_PROMPT

client = ollama.Client(host=os.environ.get("OLLAMA_HOST", "http://localhost:11434"))
MODEL = "qwen3:4b"
NUM_CTX = 4096

TEST_QUERIES = [
    ("Simple count", "How many events are in the database?"),
    ("Country filter", "Any connections from China?"),
    ("Complex SQL", "What are the top 5 DNS domains queried in the last 6 hours?"),
]

print("=" * 70)
print("qwen3:4b (think=False) — 3 queries")
print("=" * 70)

# Warm up: load model into memory
print("\nWarming up model...")
sys.stdout.flush()
t0 = time.monotonic()
client.chat(model=MODEL, messages=[{"role": "user", "content": "hi"}], think=False, options={"num_ctx": NUM_CTX})
print("Warm-up done in %.1fs\n" % (time.monotonic() - t0))
sys.stdout.flush()

for label, query in TEST_QUERIES:
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": query},
    ]

    # Round 1
    t0 = time.monotonic()
    resp = client.chat(model=MODEL, messages=messages, tools=TOOL_DEFINITIONS,
                       options={"num_ctx": NUM_CTX}, think=False)
    t1 = time.monotonic()
    msg = resp.message
    r1 = t1 - t0
    has_tools = bool(msg.tool_calls)

    r2 = 0.0
    answer = ""
    tool_name = ""
    status = "NO_TOOL"

    if has_tools:
        messages.append(msg)
        tc = msg.tool_calls[0]
        tool_name = tc.function.name
        try:
            result = TOOL_MAP[tool_name](tc.function.arguments)
            parsed = json.loads(result)
            tool_ok = "error" not in parsed
        except Exception as e:
            result = json.dumps({"error": str(e)})
            tool_ok = False

        messages.append({"role": "tool", "content": result})

        t2 = time.monotonic()
        resp2 = client.chat(model=MODEL, messages=messages, tools=TOOL_DEFINITIONS,
                            options={"num_ctx": NUM_CTX}, think=False)
        t3 = time.monotonic()
        r2 = t3 - t2
        answer = (resp2.message.content or "")[:200]
        status = "TOOL_OK" if tool_ok else "TOOL_ERR"
    else:
        answer = (msg.content or "")[:200]

    total = r1 + r2
    print("[%s] %s" % (status, label))
    print("  R1=%.1fs  R2=%.1fs  Total=%.1fs  tool=%s" % (r1, r2, total, tool_name or "-"))
    print("  -> %s" % answer.replace("\n", " ").strip()[:120])
    print()
    sys.stdout.flush()

print("Done.")

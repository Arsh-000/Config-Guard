# ConfigGuard — RAG-Grounded Network Compliance Agent

ConfigGuard is an AI agent that pulls a live device configuration, retrieves relevant company security policy clauses from a knowledge base (RAG), compares the two, and proposes a policy-cited fix — all without touching the device itself.

## What makes it different from a plain diagnostics agent
Most "network + AI" demos only check live device state. ConfigGuard adds a second, independent source of truth — a policy knowledge base — and requires the agent to reason across both: "what does the device actually say" vs. "what is it supposed to say according to policy," producing a finding that cites the specific rule violated. This is the RAG grounding principle applied to compliance instead of Q&A.

## Architecture
```
"Check SSH access compliance"
        │
        ▼
   agent.py (ReAct loop — Groq llama-3.3-70b-versatile)
        │
        ├──► pull_running_config()  ──► Netmiko ──► real device (read-only)
        │
        ├──► retrieve_policy()      ──► TF-IDF similarity search over
        │                               POLICY_DOCS (RAG component)
        │
        └──► propose_compliance_fix() ──► logged only, human approves
                                          before any device change
```

## Key Design Decisions
1. **RAG over a policy knowledge base** — the agent doesn't just check device state, it retrieves the relevant policy clause and cites it in the finding.
2. **TF-IDF as a fast, dependency-light embedder** — same retrieval mechanism as a full vector database, without needing to download a large embedding model. Swap in `sentence-transformers` for production use.
3. **Flat Pydantic schemas** — device credentials are read from environment variables, not passed through the LLM, keeping tool schemas simple and provider-compatible.
4. **propose_compliance_fix never touches the device** — it only logs a structured, human-reviewable recommendation.

## Tech Stack
- Python 3.10+
- [Groq API](https://console.groq.com) (llama-3.3-70b-versatile) via OpenAI-compatible client
- [Netmiko](https://github.com/ktbyers/netmiko) for SSH-based config retrieval
- [scikit-learn](https://scikit-learn.org/) TF-IDF for policy retrieval (RAG component)
- [Pydantic](https://docs.pydantic.dev/) for tool input validation
- [Cisco DevNet Always-On Sandbox](https://devnetsandbox.cisco.com) for live device testing

## Setup

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Get a free Groq API key
Sign up at [console.groq.com](https://console.groq.com) — free, no credit card required.

### 3. Get a free Cisco DevNet sandbox
1. Go to [devnetsandbox.cisco.com](https://devnetsandbox.cisco.com)
2. Search for **"Catalyst 8000 Always-On"**
3. Click Launch — credentials are shown in the Instructions tab

### 4. Set environment variables
```bash
# Windows PowerShell
$env:GROQ_API_KEY="your-groq-key"
$env:NET_DEVICE_HOST="devnetsandboxiosxec8k.cisco.com"
$env:NET_DEVICE_USER="your-sandbox-username"
$env:NET_DEVICE_PASS="your-sandbox-password"

# Mac/Linux
export GROQ_API_KEY="your-groq-key"
export NET_DEVICE_HOST="devnetsandboxiosxec8k.cisco.com"
export NET_DEVICE_USER="your-sandbox-username"
export NET_DEVICE_PASS="your-sandbox-password"
```

### 5. Run the offline dry-run first
```bash
python test_dry_run.py
```
Expected output:
```
✅ Dry run passed: config-pull -> RAG policy retrieval -> compliance fix proposal all work correctly.
```

### 6. Run for real
```bash
python agent.py
```

## Project Structure
```
configguard/
├── agent.py          # ReAct loop — main agent orchestrator
├── tools.py          # Netmiko config pull + RAG policy retrieval + propose fix
├── schemas.py        # Pydantic input schemas for every tool
├── policy_store.py   # Policy knowledge base + TF-IDF retrieval (RAG component)
├── audit_log.py      # JSONL audit logger
├── test_dry_run.py   # Offline test — validates full loop without API or device
├── requirements.txt
└── README.md
```

## Policy Knowledge Base
`policy_store.py` contains 8 network security policy clauses (SSH restrictions, SNMP hardening, unused interface shutdown, logging requirements, etc.). The agent retrieves the top-3 most relevant clauses for whatever area it's checking using TF-IDF similarity search — the same retrieval mechanism as a full vector database, just with a lightweight in-memory implementation suitable for demos and small knowledge bases.

## Guardrails
- `propose_compliance_fix` never executes anything on the device
- Every tool call validated against Pydantic schemas before execution
- MAX_ITERATIONS hard cap prevents infinite loops
- All decisions logged to `audit_log.jsonl` for full auditability



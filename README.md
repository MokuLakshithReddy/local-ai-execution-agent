# Local-First, Model-Agnostic AI Execution Agent

A local-first engineering execution agent built to delegate real development work on your computer with bounded safety, human-in-the-loop approvals, model choice, and verifiable evidence.

---

## 🌟 Key Features

1. **Model-Agnostic Reasoning**
   - Connect any model: **Google Gemini**, **OpenAI**, **Anthropic Claude**, or offline local inference via **Ollama** (`qwen2.5-coder`, `llama3.1`).
   - Standardized provider adapters normalize tool calls, schemas, and token metrics.

2. **Autonomous Bounded Execution Loop**
   - Controlled 7-phase lifecycle: *Understand &rarr; Inspect &rarr; Plan &rarr; Validate &rarr; Execute &rarr; Iterate & Verify &rarr; Report*.
   - Protection against runaway loops: step caps, timeout bounds, and repeated action detection.

3. **Multi-Tiered Permission & Safety System**
   - **Read-Only**: Inspected automatically within the selected workspace boundary.
   - **Routine Modification**: File writing and atomic patching within authorized workspace.
   - **Sensitive Operations**: Shell commands, package installations, and builds require human review (or policy override).
   - **Destructive Operations**: Prevented or strictly gated behind interactive approval dialogs.
   - **Path Traversal Guards**: Strict workspace isolation preventing escape outside authorized project folders.
   - **Prompt Injection Defense & Secret Masking**: Untrusted file content and shell outputs are defensively fenced; API keys are redacted from logs and contexts.

4. **Verifiable Results & Evidence Subsystem**
   - Distinguishes between what an LLM *claims* vs what actually *passed*.
   - Executes verification tools (`run_verification` for pytest, npm test, linters, builds).
   - Records exit codes, captures diffs, and synthesizes a structured completion report with verified vs partial outcomes.

5. **Local-First Architecture**
   - Embedded SQLite persistence (`agent_state.db`) for task state, execution history, and approvals.
   - Premium React + Vite dark mode dashboard with real-time WebSocket activity timeline, git diff viewer, and approval queue.

---

## 🚀 Quickstart

### 1. Requirements
- Python 3.10+
- Node.js 18+ (for building UI bundle)
- Git

### 2. Start the Agent Service & Dashboard
Run with the provided virtual environment:
```powershell
.\venv\Scripts\python.exe main.py
```
Open **[http://127.0.0.1:8000](http://127.0.0.1:8000)** in your browser.

### 3. Run Tests
```powershell
.\venv\Scripts\pytest.exe tests/
```

---

## 🏗️ Architecture Layout

```
├── agent/
│   ├── core/           # Execution loop, loop guards, state machine, data models
│   ├── providers/      # Model adapters (Gemini, OpenAI, Anthropic, Ollama)
│   ├── tools/          # Safe filesystem, bounded terminal, git, verification registry
│   ├── security/       # Permission policy engine, secret redactor, injection guard
│   ├── verification/   # Verifier engine & structured completion report generator
│   ├── persistence/    # SQLite database repository
│   └── api/            # FastAPI REST & real-time WebSocket server
├── ui/                 # React + TypeScript + Vite modern web application
├── tests/              # Unit & integration test suite
└── main.py             # Desktop daemon entrypoint
```

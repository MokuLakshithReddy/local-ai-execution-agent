<div align="center">

# Local-First, Model-Agnostic AI Execution Agent

**A secure, developer-centric agentic framework for delegating real software engineering tasks to LLMs on local environments.**

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![React + Vite](https://img.shields.io/badge/React-19%20%7C%20Vite-646CFF.svg)](https://vitejs.dev/)
[![SQLite](https://img.shields.io/badge/SQLite-Local--First-003B57.svg)](https://sqlite.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

---

## 📑 Table of Contents

- [System Architecture](#-system-architecture)
- [Core Engineering Pillars](#-core-engineering-pillars)
  - [1. Bounded Orchestration Loop & Loop-Guards](#1-bounded-orchestration-loop--loop-guards)
  - [2. Model-Agnostic Provider Adapters](#2-model-agnostic-provider-adapters)
  - [3. Modular Tool Registry & Extending Tools](#3-modular-tool-registry--extending-tools)
  - [4. Permission Sandbox & Injection Defense](#4-permission-sandbox--injection-defense)
  - [5. Verification & Verifiable Evidence Engine](#5-verification--verifiable-evidence-engine)
  - [6. Persistence Layer & State Machine](#6-persistence-layer--state-machine)
- [API & WebSocket Protocol](#-api--websocket-protocol)
  - [REST Endpoints](#rest-endpoints)
  - [WebSocket Event Streams](#websocket-event-streams)
- [Developer Setup & Contributing](#-developer-setup--contributing)
  - [Prerequisites](#prerequisites)
  - [Backend Setup](#backend-setup)
  - [Frontend Development](#frontend-development)
  - [Running the Test Suite](#running-the-test-suite)
- [Project Directory Layout](#-project-directory-layout)
- [License](#-license)

---

## 🏛️ System Architecture

The agent strictly decouples **reasoning** (delegated to any LLM) from **execution and authorization** (controlled by the local runtime):

```
┌────────────────────────────────────────────────────────────────────────┐
│                        User / Web Interface                            │
│           (React + TypeScript + Vite + Glassmorphic UI)                │
└───────────────────▲────────────────────────────────▲───────────────────┘
                    │ REST API                       │ WebSocket Feed
                    │ (/api/tasks, /api/approvals)   │ (ws://localhost:8000/ws)
┌───────────────────▼────────────────────────────────┴───────────────────┐
│                        FastAPI Server Bridge                           │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                      Agent Orchestration Engine                        │
│ ┌──────────────────────┐  ┌────────────────────┐  ┌──────────────────┐ │
│ │ Bounded Exec Loop    │  │ Task State Machine │  │ Loop-Guard &     │ │
│ │ (Plan -> Act -> Ver) │  │ (9 Discrete States)│  │ Timeout Watchdog │ │
│ └──────────────────────┘  └────────────────────┘  └──────────────────┘ │
└──────────┬────────────────────────┬─────────────────────────┬──────────┘
           │                        │                         │
           ▼                        ▼                         ▼
┌───────────────────────┐ ┌───────────────────┐ ┌────────────────────────┐
│   Provider Adapters   │ │   Security Engine │ │     Tool Registry      │
│ ├─ Google Gemini      │ │ ├─ Permission Mgr │ │ ├─ Safe Filesystem     │
│ ├─ OpenAI / Compatible│ │ ├─ Path Sandbox   │ │ ├─ Bounded Terminal    │
│ ├─ Anthropic Claude   │ │ ├─ Secret Redactor│ │ ├─ Git Status & Diff   │
│ └─ Ollama (Local LLM) │ │ └─ Injection Fence│ │ └─ Verification Runner │
└───────────────────────┘ └───────────────────┘ └───────────┬────────────┘
                                                            │
                                                            ▼
                                                ┌────────────────────────┐
                                                │   Verification Engine  │
                                                │ ├─ Test Execution      │
                                                │ ├─ Exit Code Checking  │
                                                │ ├─ Git Diff Synthesizer│
                                                │ └─ Final Task Report   │
                                                └────────────────────────┘
```

---

## ⚙️ Core Engineering Pillars

### 1. Bounded Orchestration Loop & Loop-Guards

Located in `agent/core/engine.py`. The execution loop implements a controlled 7-stage lifecycle:
1. **Understand Request**: Ingest user goal, bind workspace directory, sanitize context.
2. **Inspect Context**: Explore repository structure (`list_dir`, `search_files`, `read_file`).
3. **Plan Actions**: Construct concise sequence of steps and hypotheses.
4. **Authorize Action**: Intercept tool calls through `PermissionManager`. If sensitive, suspend execution into `PENDING_APPROVAL`.
5. **Execute & Observe**: Execute permitted tools within workspace boundaries and scrub output.
6. **Iterate & Guard**: Detect repeated identical actions (loop-guard triggers if tool + arguments repeat 3 times without progress). Check maximum step limits (default: 30 steps).
7. **Verify & Report**: Record verification commands (pytest, npm test, etc.), inspect working tree diffs, and construct the final structured report.

### 2. Model-Agnostic Provider Adapters

Located in `agent/providers/`. All models are normalized behind `BaseProviderAdapter` (`base.py`):

```python
class BaseProviderAdapter(ABC):
    @abstractmethod
    async def chat_completion(
        self,
        messages: List[LLMMessage],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.2,
    ) -> ProviderResponse:
        pass
```

- **OpenAI Adapter** (`openai_adapter.py`): Supports `gpt-4o`, `gpt-4o-mini`, `o1`/`o3`, as well as any OpenAI-compatible custom base URL (vLLM, LMStudio, OpenRouter, DeepSeek).
- **Anthropic Adapter** (`anthropic_adapter.py`): Supports `claude-3-7-sonnet`, `claude-3-5-sonnet`, mapping Anthropic `tool_use` blocks to standard `LLMToolCall`s.
- **Gemini Adapter** (`gemini_adapter.py`): Supports native Google Gemini function declarations (`generateContent` with `functionCall`/`functionResponse`).
- **Ollama Adapter** (`ollama_adapter.py`): Offline local inference with local models (`qwen2.5-coder:latest`, `llama3.1`).

### 3. Modular Tool Registry & Extending Tools

Located in `agent/tools/`. Every tool subclasses `BaseTool` (`base.py`):

```python
from agent.tools.base import BaseTool
from agent.core.models import PermissionLevel, ActionResult

class CustomLinterTool(BaseTool):
    name = "custom_lint"
    description = "Run custom style checks on source files."
    permission_level = PermissionLevel.READ_ONLY

    def get_parameters_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Target file relative to workspace."}
            },
            "required": ["file_path"]
        }

    async def execute(self, workspace_path: str, **kwargs) -> ActionResult:
        # Implementation with resolve_safe_path
        ...
```

Register your tool with `tool_registry.register(CustomLinterTool())`.

#### Built-in Tools:
| Tool Name | Risk / Permission | Purpose |
|---|---|---|
| `list_dir` | `READ_ONLY` | Directory tree inspection with depth & size limits. |
| `read_file` | `READ_ONLY` | File content inspection with slice notation (`start_line`, `end_line`). |
| `write_file` | `ROUTINE_MODIFICATION` | Create or overwrite files inside the workspace. |
| `patch_file` | `ROUTINE_MODIFICATION` | Atomic exact-block replacement (prevents accidental destructive overwrites). |
| `search_files` | `READ_ONLY` | Fast workspace regex/literal search honoring ignore rules (`.git`, `node_modules`). |
| `run_command` | `SENSITIVE_OPERATION` | Subprocess execution with process timeouts, output caps (50KB limit), and environment scrubbing. |
| `git_status` | `READ_ONLY` | Inspect staged, unstaged, and untracked changes. |
| `git_diff` | `READ_ONLY` | Generate unified repository diff against `HEAD`. |
| `run_verification` | `SENSITIVE_OPERATION` | Executes automated tests/builds and captures exit codes as verifiable evidence. |

### 4. Permission Sandbox & Injection Defense

Located in `agent/security/`.
- **Path Boundary Enforcer**: `resolve_safe_path()` checks `os.path.commonpath` against the canonical absolute workspace root. Any `../` traversal escape raises `ValueError` immediately.
- **Permission Matrix**:
  - `READ_ONLY`: Auto-approved within workspace.
  - `ROUTINE_MODIFICATION`: Auto-approved by default policy; diff recorded.
  - `SENSITIVE_OPERATION`: Triggers human approval modal in UI unless explicitly enabled in policy.
  - `DESTRUCTIVE_OPERATION`: Blocked or requires explicit human approval.
  - `EXTERNAL_SIDE_EFFECT`: Gated behind authorization.
- **Secret Redactor**: Scrub credentials (`sk-*`, `ghp_*`, `AIza*`, bearer tokens) before logging or returning to prompts.
- **Prompt Injection Demarcation**: Wraps all untrusted external content (files, command outputs) inside `=== BEGIN UNTRUSTED DATA ===` fences and flags adversarial strings (e.g. `ignore previous instructions`).

### 5. Verification & Verifiable Evidence Engine

Located in `agent/verification/`.
- Rather than accepting an LLM's assertion ("*I fixed the bug and verified everything works*"), the engine audits:
  1. Did a verification tool (`run_verification`) execute?
  2. Was the command exit code `0`?
  3. Does the git diff reflect the expected changes?
- **Status Truth Table**:
  - `COMPLETED`: Automated verification tests ran and all exited with code 0.
  - `PARTIALLY_COMPLETED`: Code modified, but tests were either skipped, not present, or exited with non-zero code.
  - `FAILED`: Execution threw unrecoverable errors.

### 6. Persistence Layer & State Machine

Located in `agent/persistence/db.py`. Embedded asynchronous SQLite database (`agent_state.db`):
- `tasks`: Task ID, goal, workspace, provider, status, steps count, JSON plan, and final report.
- `task_steps`: Step-by-step reasoning thoughts, tool calls, and execution latencies.
- `approvals`: Pending and resolved human-in-the-loop authorizations.
- `settings`: API keys, auto-approval toggles, and active workspace paths.

#### 9-State Task Lifecycle:
`IDLE` &rarr; `PLANNING` &rarr; `EXECUTING` &harr; `PENDING_APPROVAL` &rarr; `VERIFYING` &rarr; `COMPLETED` | `PARTIALLY_COMPLETED` | `BLOCKED` | `FAILED` | `CANCELLED`

---

## 🌐 API & WebSocket Protocol

### REST Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Health check & service status. |
| `GET` | `/api/workspaces` | Retrieve active & available workspaces. |
| `GET` | `/api/models` | List supported providers & models. |
| `GET` | `/api/settings` | Get masked settings & policy toggles. |
| `POST` | `/api/settings` | Update API keys and approval policies. |
| `POST` | `/api/tasks` | Ingest task goal & launch async execution loop. |
| `GET` | `/api/tasks` | List recent tasks and execution states. |
| `GET` | `/api/tasks/{task_id}` | Retrieve task details, steps, and final report. |
| `POST` | `/api/tasks/{task_id}/cancel` | Request graceful task termination. |
| `GET` | `/api/approvals/pending` | List pending approval requests. |
| `POST` | `/api/approvals/{id}` | Resolve approval (`{"approved": true/false}`). |
| `GET` | `/api/diff` | Get active workspace unified diff. |

### WebSocket Event Streams

Connect to `ws://localhost:8000/ws` for live streaming:

```json
{
  "type": "step_start" | "agent_thought" | "tool_executing" | "tool_result" | "approval_required" | "task_completed" | "task_error",
  "data": { ... }
}
```

---

## 🛠️ Developer Setup & Contributing

### Prerequisites
- **Python**: `>= 3.10`
- **Node.js**: `>= 18.0` & `npm`
- **Git**

### Backend Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/MokuLakshithReddy/local-ai-execution-agent.git
   cd local-ai-execution-agent
   ```

2. **Create and activate a virtual environment:**
   ```bash
   # Windows
   python -m venv venv
   .\venv\Scripts\activate

   # Linux / macOS
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install fastapi uvicorn pydantic httpx python-dotenv aiosqlite pytest pytest-asyncio
   ```

4. **Launch the agent service:**
   ```bash
   python main.py
   ```
   *The server starts on `http://127.0.0.1:8000` and automatically opens the dashboard.*

### Frontend Development

The frontend is a Vite + React + TypeScript single-page app located in `ui/`:

```bash
cd ui
npm install
npm run dev
```

To compile production static assets into `ui/dist` (served directly by FastAPI):
```bash
npm run build
```

### Running the Test Suite

The test suite validates security constraints, tool lifecycles, path sandbox enforcement, and the verification engine:

```bash
pytest tests/ -v
```

---

## 📂 Project Directory Layout

```
.
├── agent/
│   ├── core/
│   │   ├── models.py              # Pydantic domain models & state definitions
│   │   └── engine.py              # Bounded execution loop & loop-guards
│   ├── providers/
│   │   ├── base.py                # BaseProviderAdapter abstraction
│   │   ├── openai_adapter.py      # OpenAI & compatible endpoint handler
│   │   ├── anthropic_adapter.py   # Anthropic Claude adapter
│   │   ├── gemini_adapter.py      # Google Gemini adapter
│   │   ├── ollama_adapter.py      # Offline Ollama adapter
│   │   └── registry.py            # Dynamic provider factory
│   ├── tools/
│   │   ├── base.py                # BaseTool definition
│   │   ├── filesystem.py          # Safe list, read, write, patch, search
│   │   ├── terminal.py            # Bounded subprocess runner with timeouts
│   │   ├── git.py                 # Git status & diff tools
│   │   ├── verification.py        # Automated test & build runner
│   │   └── registry.py            # Tool schema exporter (OpenAI/Claude/Gemini)
│   ├── security/
│   │   ├── permissions.py         # Multi-tiered permission & approval logic
│   │   └── sanitizer.py           # Secret masking & prompt injection defense
│   ├── verification/
│   │   └── verifier.py            # Outcome verifier & report synthesizer
│   ├── persistence/
│   │   └── db.py                  # aiosqlite repository
│   └── api/
│       └── server.py              # FastAPI app & WebSocket event broadcaster
├── ui/                            # React 19 + TypeScript + Vite UI
│   ├── src/
│   │   ├── App.tsx                # Interactive dashboard, diff viewer & modals
│   │   ├── App.css                # Scoped component styles
│   │   └── index.css              # Design tokens & dark glassmorphic theme
├── tests/
│   └── test_core_and_tools.py     # Comprehensive unit tests
├── main.py                        # Service entrypoint
├── pytest.ini                     # Pytest configuration
└── README.md                      # Developer documentation
```

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).

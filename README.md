<div align="center">

# Local-First, Model-Agnostic AI Execution Agent

**An Evidence-Driven, Local-First Engineering Framework Delegating Real Computer Work to LLMs with Verifiable Proof.**

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![React + Vite](https://img.shields.io/badge/React-19%20%7C%20Vite-646CFF.svg)](https://vitejs.dev/)
[![SQLite](https://img.shields.io/badge/SQLite-Local--First-003B57.svg)](https://sqlite.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Verification: Passed](https://img.shields.io/badge/Verification-29%20Passed-10b981.svg)](#-live-verification-evidence-log)

</div>

---

## 🎯 The Evidence-Driven Philosophy

> **"Plausible code is not working code. An AI execution agent is only as dependable as the evidence it produces."**

Most AI coding assistants rely on subjective completion: the model writes code, declares victory in chat, and leaves verification to the human. 

This agent is built around **strict evidence separation**:
1. **Model Claims** *(Subjective)*: What the LLM believes or intends to do.
2. **Tool Telemetry** *(Observed)*: Raw stdin/stdout, exit codes, modified files, and execution timestamps.
3. **Verification Subsystem** *(Objective Evidence)*: Independent test suites, linters, builds, and git diff audits.

An action is **never** considered complete simply because an LLM claims it is done. Every completion must be anchored in captured machine evidence.

---

## 📑 Table of Contents

- [The Evidence-Driven Philosophy](#-the-evidence-driven-philosophy)
- [Evidence Architecture & Truth Table](#-evidence-architecture--truth-table)
- [Live Verification Evidence Log](#-live-verification-evidence-log)
- [Hardened Defenses & Security Invariants](#-hardened-defenses--security-invariants)
- [Sample Structured Task Report](#-sample-structured-task-report)
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
- [Developer Setup & Reproducible Verification](#-developer-setup--reproducible-verification)
- [Project Directory Layout](#-project-directory-layout)
- [License](#-license)

---

## 📊 Evidence Architecture & Truth Table

The verification engine (`agent/verification/verifier.py`) enforces an unambiguous status matrix. The agent cannot forge a `COMPLETED` status:

| Code Modified? | Verification Tests Executed? | Exit Code | Resulting Task Status | Rationale |
|:---:|:---:|:---:|:---:|---|
| **Yes** | **Yes** | `0` (Success) | `COMPLETED` | **Verified Completion**: Changes made and validated by passing test suites. |
| **Yes** | **Yes** | `!= 0` (Fail) | `PARTIALLY_COMPLETED` | **Failed Verification**: Tests failed; agent cannot claim victory. |
| **Yes** | **No** | N/A | `PARTIALLY_COMPLETED` | **Unverified Changes**: Files modified, but no automated checks verified them. |
| **No** | N/A | N/A | `COMPLETED` | **Informational Task**: Read-only exploration (e.g. architecture review). |
| Any | Timeout / Block | Error | `FAILED` / `BLOCKED` | **Execution Failure**: Runaway loop detected or resource budget exhausted. |

---

## 🧪 Live Verification Evidence Log

The test suite in [`tests/test_core_and_tools.py`](tests/test_core_and_tools.py) tests security invariants, tool bounds, and verifiable outcomes across all 29 automated integration tests.

### Verified Test Telemetry:
```
============================= test session starts =============================
platform win32 -- Python 3.12.10, pytest-9.1.1, pluggy-1.7.0
rootdir: C:\Users\nsrfl\OneDrive\Desktop\MAKE LLM TO CODE
configfile: pytest.ini
plugins: anyio-4.15.1, asyncio-1.4.1
collected 29 items

tests/test_core_and_tools.py::test_resolve_safe_path_security PASSED     [  3%]
tests/test_core_and_tools.py::test_symlink_containment_security PASSED   [  6%]
tests/test_core_and_tools.py::test_credential_vault_encryption PASSED    [ 10%]
tests/test_core_and_tools.py::test_database_credential_encryption_and_sanitization PASSED [ 13%]
tests/test_core_and_tools.py::test_security_sanitizer_redaction PASSED   [ 17%]
tests/test_core_and_tools.py::test_security_sanitizer_injection_defense PASSED [ 20%]
tests/test_core_and_tools.py::test_permission_manager_levels PASSED      [ 24%]
tests/test_core_and_tools.py::test_terminal_environment_allowlist PASSED [ 27%]
tests/test_core_and_tools.py::test_filesystem_tools_lifecycle PASSED     [ 31%]
tests/test_core_and_tools.py::test_criteria_driven_verification PASSED   [ 34%]
tests/test_core_and_tools.py::test_api_security_authorization PASSED     [ 37%]
tests/test_core_and_tools.py::test_adversarial_bootstrap_attacks PASSED  [ 41%]
tests/test_core_and_tools.py::test_token_file_acl_protection PASSED      [ 44%]
tests/test_core_and_tools.py::test_credential_vault_corruption_and_migration PASSED [ 48%]
tests/test_core_and_tools.py::test_dpapi_failure_fails_closed PASSED     [ 51%]
tests/test_core_and_tools.py::test_real_process_tree_termination PASSED  [ 55%]
tests/test_core_and_tools.py::test_verifier_relevance_and_anti_overstating PASSED [ 58%]
tests/test_core_and_tools.py::test_approval_race_conditions PASSED       [ 62%]
tests/test_core_and_tools.py::test_task_interruption_and_server_restart PASSED [ 65%]
tests/test_core_and_tools.py::test_end_to_end_edit_test_fix_lifecycle PASSED [ 68%]
tests/test_core_and_tools.py::test_legacy_migration_failure_fails_closed PASSED [ 72%]
tests/test_core_and_tools.py::test_terminal_sandbox_boundaries PASSED    [ 75%]
tests/test_core_and_tools.py::test_verifier_criteria_mapping_and_evidence PASSED [ 79%]
tests/test_core_and_tools.py::test_api_host_ipv6_and_token_permission_failure PASSED [ 82%]
tests/test_core_and_tools.py::test_database_write_error_propagation PASSED [ 86%]
tests/test_core_and_tools.py::test_posix_vault_key_failure_handling PASSED [ 89%]
tests/test_core_and_tools.py::test_verifier_strict_structured_evidence_mapping PASSED [ 93%]
tests/test_core_and_tools.py::test_credential_migration_multi_key_corrupted_and_recovery PASSED [ 96%]
tests/test_core_and_tools.py::test_terminal_os_sandbox_job_limits_and_container_config PASSED [100%]

======================= 29 passed, 3 warnings in 3.61s ========================
```

---

## 🛡️ Hardened Defenses & Security Invariants

In response to rigorous security assessments and adversarial analysis, the agent enforces a multi-tiered defense architecture:

### 1. Terminal Containment Architecture (Evidence-Based Separation)
The terminal execution subsystem (`agent/tools/terminal.py`) explicitly separates **syntactic pre-flight policies** from **OS kernel boundaries** and **containerized isolation**:

- **Tier 1 — Pre-Execution Policy Guard**:
  - `validate_sandbox_command()` parses tokens, quotes, and traversal patterns prior to execution.
  - Rejects obvious dangerous shell commands (`cd ..`, `pushd`, unquoted traversals) and hazardous command names (`curl`, `wget`, `nc`, `ssh`) when network is disabled.
  - *Accurate Boundary*: A text policy filter catches syntax mistakes but does not prevent internal interpreter execution (e.g. `python -c "import socket; ..."`). Kernel or container sandboxing is required for hard containment.

- **Tier 2 — OS Kernel Resource & Process Sandboxing**:
  - **Windows Job Objects (`WindowsJobSandbox`)**: Every host subprocess is bound to a native Windows Job Object configured via `ctypes.windll.kernel32`:
    - `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE (0x2000)`: Guarantees that if the agent exits, times out, or closes the job handle, the OS kernel terminates the entire child process tree immediately.
    - `JOB_OBJECT_LIMIT_ACTIVE_PROCESS (0x0008)`: Enforces hard limits on active processes (default: 16) to prevent fork-bombs and runaway child trees.
    - `JOB_OBJECT_LIMIT_JOB_MEMORY (0x0200)`: Restricts total job memory (default: 512 MB).
  - **Environment Scrubbing**: Only essential variables (`PATH`, `SYSTEMROOT`, `COMSPEC`) in `SAFE_ENV_ALLOWLIST` are exposed; cloud and host credentials are scrubbed.
  - **Proxy Blackholing**: Sets `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY = 127.0.0.1:0` to blackhole outbound requests.

- **Tier 3 — Containerized Execution Isolation (`build_container_command`)**:
  - When container sandboxing is enabled, commands run inside an isolated OCI container:
    - **Kernel Network Namespace Isolation**: `--network none` strips network access completely at the kernel level (raw sockets, python scripts, and compiled binaries cannot transmit traffic).
    - **Read-Only Root Filesystem**: `--read-only` prevents mutations to system directories.
    - **Filesystem Boundary**: Only the target workspace directory is mounted read-write (`-v {workspace}:/workspace:rw`).
    - **Resource Caps**: `--memory 512m`, `--pids-limit 32`, and `--cap-drop=ALL`.

### 2. Strict Structured Evidence Verification (Anti-Overstating)
- **Beyond Generic Exit Status**: In `agent/verification/verifier.py`, an exit status of 0 is no longer sufficient by itself to claim that specific criteria were demonstrated.
- **Structured Assertion Linking**: Every acceptance criterion is evaluated into a `CriterionEvidence` record with explicit `verification_tier`:
  - `VERIFIED_TARGETED_TEST`: An explicit test node (e.g. `test_token_auth_missing_token_401 PASSED`) specifically targeted and demonstrated the criterion.
  - `VERIFIED_ASSERTION`: A structured output assertion proved the requirement with multiple semantic matches.
  - `UNVERIFIED`: If checks passed generally without an assertion or targeted test case for that requirement, the criterion is flagged as `UNVERIFIED` and the task remains `PARTIALLY_COMPLETED`.

### 3. POSIX Vault Key Hardening & Fail-Closed Startup
- **Fail-Closed on Write or Permission Failure**: In `agent/persistence/credentials.py`, `_get_or_create_posix_key()` fails startup by raising `CredentialEncryptionError` if the key directory is unwritable or restrictive permissions (`0600`) cannot be verified.
- **Corrupted / Insecure Key Detection**: If an existing vault key file is group/world readable (`st_mode & 0o077 != 0`), initialization is aborted.
- **Restart Recovery**: Valid keys persist reliably and allow seamless credential decryption across server restarts.

### 4. Comprehensive Credential Migration Failure Paths & Recovery
- **Multi-Key Migration**: Safely migrates multiple provider keys (`openai`, `anthropic`, `gemini`) stored together in a single settings object.
- **Corrupted Legacy Value Handling**: Corrupted legacy base64 strings are nullified safely rather than returning garbled ciphertext.
- **Failure-Path & Recovery**: If an intermediate SQLite disk write fails during migration, `CredentialMigrationError` is raised and unmigrated secrets are wiped from memory. Once the disk error resolves, subsequent requests cleanly complete migration and persist OS-native encrypted credentials.

### 5. Local API, IPv6, & Token Failure Defenses
- **Fail-Safe Token Permissions**: `_lock_down_token_file()` raises `RuntimeError` if ACLs cannot be locked down via `icacls` or `chmod 0600`.
- **RFC-Compliant IPv4 & IPv6 Parsing**: `_extract_hostname()` accurately parses IPv4, bare IPv6 (`::1`), bracketed IPv6 (`[::1]:8000`), and rejects hostile domains (`evil.attacker.com`).
- **Persistence Error Propagation**: `Database.save_setting()` propagates `DatabaseWriteError` on SQLite failures, returning `HTTP 500`.


Every executed task persists a verifiable `TaskReport` (`agent/core/models.py`) containing the exact trail of evidence:

```json
{
  "task_id": "83f1aa41-88a4-42a6-9c37-0fc0db7a4e34",
  "goal": "Implement input validator in auth.py and verify test coverage with pytest.",
  "status": "COMPLETED",
  "summary_of_actions": [
    "Inspected auth.py via read_file (lines 1-80)",
    "Applied validation logic via patch_file",
    "Executed verification command: pytest tests/test_auth.py"
  ],
  "files_created_or_modified": [
    "src/auth.py",
    "tests/test_auth.py"
  ],
  "diff_summary": "diff --git a/src/auth.py b/src/auth.py\n+ def validate_token(token: str) -> bool:\n+     return len(token) > 16",
  "executed_verification_checks": [
    {
      "check_name": "Authentication Unit Tests",
      "check_type": "test",
      "command": "pytest tests/test_auth.py",
      "success": true,
      "exit_code": 0,
      "output": "tests/test_auth.py .. [100%]\n2 passed in 0.08s",
      "evidence_summary": "Verification Check 'Authentication Unit Tests' (test) exited with code 0. PASSED."
    }
  ],
  "skipped_or_failed_checks": [],
  "unresolved_risks_or_limitations": []
}
```

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

Located in `agent/verification/verifier.py`.
- Rather than accepting an LLM's assertion ("*I fixed the bug and verified everything works*"), the engine audits:
  1. Did a verification tool (`run_verification`) execute?
  2. Was the command exit code `0`?
  3. Does the git diff reflect the expected changes?

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

## 🛠️ Developer Setup & Reproducible Verification

### Prerequisites
- **Python**: `>= 3.10`
- **Node.js**: `>= 18.0` & `npm`
- **Git**

### 1. Setup & Reproduce Verification Evidence
Clone the repository and run the test suite to independently reproduce the verification telemetry:

```bash
git clone https://github.com/MokuLakshithReddy/local-ai-execution-agent.git
cd local-ai-execution-agent

# Windows
python -m venv venv
.\venv\Scripts\activate
pip install fastapi uvicorn pydantic httpx python-dotenv aiosqlite pytest pytest-asyncio

# Execute test suite and verify evidence
pytest tests/ -v
```

### 2. Launch Local Agent Service & Dashboard
```bash
python main.py
```
Open **[http://127.0.0.1:8000](http://127.0.0.1:8000)** in your browser.

### 3. Frontend Development
```bash
cd ui
npm install
npm run dev
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
├── LICENSE                        # MIT License
└── README.md                      # Evidence-driven developer documentation
```

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).

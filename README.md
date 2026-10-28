<div align="center">

# ⚡ Local-First, Model-Agnostic AI Execution Agent

### *Stop trusting what AI chatbots say. Start verifying what AI agents actually do.*

An open-source, evidence-driven autonomous coding framework that delegates real software engineering tasks to LLMs—with **OS/container containment**, **cryptographic execution provenance**, and **verifiable machine proof**.

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![React 19](https://img.shields.io/badge/React-19%20%7C%20Vite-646CFF.svg)](https://vitejs.dev/)
[![SQLite](https://img.shields.io/badge/SQLite-Local--First-003B57.svg)](https://sqlite.org/)
[![CI](https://github.com/MokuLakshithReddy/local-ai-execution-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/MokuLakshithReddy/local-ai-execution-agent/actions/workflows/ci.yml)
[![Verification: 48 Passed](https://img.shields.io/badge/Verification-48%20Passed-10b981.svg)](#-live-verification-evidence-log)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

---

## 💡 The Big Idea in 30 Seconds

Most AI coding assistants (Copilot, Cursor, chat interfaces) are **"chatbots with text editors."** 
When an AI finishes writing code, it declares: 
> *"I have fixed the issue, refactored the module, and everything is working perfectly!"*

**In reality, you don't know if the code compiles, if tests actually ran, or if the agent hallucinated.** 

This project flips the paradigm from **subjective belief** to **objective proof**:
1. **Never Trust Claims**: The LLM's opinion is treated as an unverified hypothesis.
2. **Require Machine Evidence**: A task is **only** marked `COMPLETED` when independent test runners (e.g., `pytest`, `npm test`) exit with code `0`, git diffs confirm the modifications, and JUnit XML records are cryptographically verified.
3. **Execute Safely in Containment**: All commands execute inside **isolated Docker containers** (or native Windows Job Objects) with kernel-level network blocks (`--network=none`), read-only root filesystems, memory caps, and process limits.
4. **100% Local & Model-Agnostic**: Works with local models via **Ollama** (offline privacy) or cloud providers (**Gemini, Claude, GPT-4o**). Your codebase and credentials never leave your control.

---

## 🤔 Why This Matters: The Chatbot vs. Evidence Agent

| Capability | Standard AI Assistant / Chatbot | This AI Execution Agent |
|---|---|---|
| **Completion Criteria** | Subjective: LLM says *"Done!"* in chat. | **Objective**: Test runners exit `0`, assertions pass, and git diffs match. |
| **Output Integrity** | Can print fake test logs and claim they passed. | **Cryptographic Provenance**: JUnit XML signed with HMAC-SHA256 (RFC 8785). |
| **Process Execution** | Runs arbitrary commands directly on host terminal. | **Hard Containment**: Docker container sandbox (`--network=none`, `--read-only`). |
| **Escapes & Traversal** | Vulnerable to `cd ..`, path traversal, or env leaks. | **Strict Path Jail**: Canonical path sandboxing + strict env scrubbing. |
| **Runaway Loops** | Loops infinitely if it gets confused. | **Loop-Guards**: Repetitive action detection and hard step/timeout budgets. |
| **Model Lock-In** | Bound to one proprietary API. | **Model-Agnostic**: Ollama (Qwen, Llama), Claude, Gemini, OpenAI. |
| **Privacy & Storage** | Cloud-synced telemetry and histories. | **Local-First**: Embedded SQLite, local tokens, OS DPAPI / POSIX vault. |

---

## 🎬 How It Works: The Verifiable Lifecycle

When you ask the agent: *"Fix the authentication token expiry bug and verify with unit tests"*:

```
   ┌──────────────────────────────────────────────────────────────┐
   │ 1. INGEST & PLAN                                             │
   │ The agent explores workspace files (safe read_file, search). │
   │ Proposes step-by-step action plan and identifies criteria.   │
   └──────────────────────────────┬───────────────────────────────┘
                                  ▼
   ┌──────────────────────────────────────────────────────────────┐
   │ 2. AUTHORIZATION & HUMAN-IN-THE-LOOP                         │
   │ Routine file edits proceed; sensitive operations trigger     │
   │ human approval modals in the Glassmorphic Web Dashboard.     │
   └──────────────────────────────┬───────────────────────────────┘
                                  ▼
   ┌──────────────────────────────────────────────────────────────┐
   │ 3. SANDBOXED EXECUTION (DOCKER / JOB OBJECTS)                │
   │ Modifies files via patch_file. Executes test runner inside   │
   │ container (--network=none, memory caps, non-root user).      │
   └──────────────────────────────┬───────────────────────────────┘
                                  ▼
   ┌──────────────────────────────────────────────────────────────┐
   │ 4. OBJECTIVE MACHINE EVIDENCE GATHERING                      │
   │ Parses structured JUnit XML directly from test process.      │
   │ Partitions outcomes: passed, failed, and skipped tests.      │
   └──────────────────────────────┬───────────────────────────────┘
                                  ▼
   ┌──────────────────────────────────────────────────────────────┐
   │ 5. CRYPTOGRAPHIC PROVENANCE & REPORT                         │
   │ Issues a tamper-evident TrustedExecutionRecord (HMAC-SHA256).│
   │ Generates audited TaskReport with diffs and exit codes.      │
   └──────────────────────────────────────────────────────────────┘
```

---

## 📊 The Truth Table: Why the Agent Cannot Lie

The verification engine (`agent/verification/verifier.py`) enforces an immutable outcome matrix:

| Code Modified? | Verification Tests Executed? | Exit Code | Resulting Task Status | What Actually Happened |
|:---:|:---:|:---:|:---:|---|
| **Yes** | **Yes** | `0` (Success) | **`COMPLETED`** | ✅ **Verified Completion**: Tests ran inside sandbox, passed, and diff matches. |
| **Yes** | **Yes** | `!= 0` (Fail) | **`PARTIALLY_COMPLETED`** | ❌ **Failed Verification**: Tests failed. Agent is forbidden from claiming victory. |
| **Yes** | **No** | N/A | **`PARTIALLY_COMPLETED`** | ⚠️ **Unverified Modification**: Files were edited, but no automated test proved it. |
| **No** | N/A | N/A | **`COMPLETED`** | ℹ️ **Informational Task**: Read-only exploration (e.g., architecture audit). |
| Any | Timeout / Block | Error | **`FAILED` / `BLOCKED`** | 🛑 **Execution Failure**: Sandbox violation or resource budget exhausted. |

---

## 🚀 Quick Start (Up & Running in 2 Minutes)

### Prerequisites
- **Python 3.10+**
- **Node.js 18+** & `npm`
- **Docker** (optional, recommended for full container isolation)

### 1. Clone & Set Up Virtual Environment

```bash
# Clone the repository
git clone https://github.com/MokuLakshithReddy/local-ai-execution-agent.git
cd local-ai-execution-agent

# Set up Python virtual environment
# Windows:
python -m venv venv
.\venv\Scripts\activate

# Linux / macOS:
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Verify Your Environment (48 Passing Tests)

Run the automated test suite to verify kernel job limits, sandbox boundaries, and provenance hashing:

```bash
pytest tests/ -v
```

### 3. Launch the Agent & Web Dashboard

```bash
python main.py
```

Open your browser to:
👉 **[http://localhost:8000](http://localhost:8000)**

### 4. (Optional) Start the React UI in Dev Mode

```bash
cd ui
npm install
npm run dev
```

---

## 🛡️ Hardened Defenses & Security Invariants

In response to extensive adversarial testing, the runtime implements 5 layers of defense:

### 1. Container Sandbox & Terminal Containment
- **Container-First by Default**: `RunCommandTool` defaults to `sandbox_mode="container"`. Host execution is rejected when containment is required.
- **Kernel-Level Isolation**: Spawns commands via `asyncio.create_subprocess_exec("docker", "run", ...)` with:
  - `--network=none`: Blocks outbound network connections at the kernel level (raw sockets and scripts cannot leak data).
  - `--read-only`: Prevents modification of root system files.
  - `-v {workspace}:/workspace:rw`: Only the target workspace folder is accessible.
  - `--memory=512m`, `--pids-limit=32`, `--cap-drop=ALL`.
- **Windows Kernel Job Objects**: On Windows host fallback, processes are bound to native Job Objects via `ctypes.windll.kernel32`:
  - `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`: Instant child process termination on exit or timeout.
  - Hard caps on active processes (16) and memory (512 MB).
- **Timeout Cleanup & Daemon Pruning**: Deterministically named containers (`agent-sandbox-<uuid>`) are forcibly stopped (`docker rm -f`) and verified removed if a command times out.

### 2. Cryptographic Provenance (HMAC-SHA256 via RFC 8785)
- **Zero Fabrication**: Prevents agents or malicious scripts from outputting fake `1 passed in 0.05s` strings to trick verification.
- **Deterministic Canonical JSON**: All test results (`run_id`, `runner`, `command`, `exit_code`, `total`, `passed`, `failed`, `skipped`, `nodes`, `timestamp`) are serialized into canonical JSON (RFC 8785 semantics: sorted keys, compact separators) and signed using HMAC-SHA256.
- **Skipped-Test Isolation**: Skipped tests are recorded separately (`skipped_nodes`) and **never** counted as passed. Reports with zero passing tests or count inconsistencies are rejected immediately.
- **Persistent Key Lifecycle**: Signing keys are stored securely in `~/.config/ai_execution_agent/verification.key` (permission `0600` on POSIX, user ACL on Windows) or configured via `AGENT_VERIFICATION_SECRET`, preserving verification validity across process restarts.

### 3. Path Traversal & Symlink Defense
- Every filesystem operation passes through `resolve_safe_path()`, resolving canonical real paths and verifying `os.path.commonpath([resolved, workspace]) == workspace`.
- Prevents symlink attacks, directory traversal (`../../etc/passwd`), and out-of-boundary access.

### 4. Credential Vault & In-Memory Sanitization
- **OS-Native Key Storage**: Windows DPAPI (`CryptProtectData`) on Windows; Fernet key with atomic permissions on POSIX.
- **Automatic Redaction**: Scrubbing engine masks API keys (`sk-*`, `ghp_*`, `AIza*`, bearer tokens) from all stdout and agent thoughts before storage.

### 5. Loop-Guards & Execution Budgets
- Detects repetitive or looping behavior (3 identical tool calls with identical arguments triggers emergency brake).
- Enforces a hard step limit (default: 30 steps) and execution timeouts to prevent runaway LLM costs.

---

## 🏛️ System Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                        User / Web Interface                            │
│           (React 19 + TypeScript + Vite + Glassmorphic UI)             │
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
                                                │ └─ Signed Task Report  │
                                                └────────────────────────┘
```

---

## 🧪 Live Verification Evidence Log

Every release and commit is backed by reproducible automated tests in [`tests/test_core_and_tools.py`](tests/test_core_and_tools.py).

### Latest CI Telemetry:
```text
============================= test session starts =============================
platform win32 -- Python 3.12.10, pytest-9.1.1, pluggy-1.7.0
rootdir: C:\Users\nsrfl\OneDrive\Desktop\MAKE LLM TO CODE
configfile: pytest.ini
plugins: anyio-4.15.1, asyncio-1.4.1
collected 48 items

tests/test_core_and_tools.py::test_resolve_safe_path_security PASSED     [  2%]
tests/test_core_and_tools.py::test_symlink_containment_security PASSED   [  4%]
tests/test_core_and_tools.py::test_credential_vault_encryption PASSED    [  6%]
tests/test_core_and_tools.py::test_database_credential_encryption_and_sanitization PASSED [  8%]
tests/test_core_and_tools.py::test_security_sanitizer_redaction PASSED   [ 10%]
tests/test_core_and_tools.py::test_security_sanitizer_injection_defense PASSED [ 12%]
tests/test_core_and_tools.py::test_permission_manager_levels PASSED      [ 14%]
tests/test_core_and_tools.py::test_terminal_environment_allowlist PASSED [ 16%]
tests/test_core_and_tools.py::test_filesystem_tools_lifecycle PASSED     [ 18%]
tests/test_core_and_tools.py::test_criteria_driven_verification PASSED   [ 20%]
tests/test_core_and_tools.py::test_api_security_authorization PASSED     [ 22%]
tests/test_core_and_tools.py::test_adversarial_bootstrap_attacks PASSED  [ 25%]
tests/test_core_and_tools.py::test_token_file_acl_protection PASSED      [ 27%]
tests/test_core_and_tools.py::test_credential_vault_corruption_and_migration PASSED [ 29%]
tests/test_core_and_tools.py::test_dpapi_failure_fails_closed PASSED     [ 31%]
tests/test_core_and_tools.py::test_real_process_tree_termination PASSED  [ 33%]
tests/test_core_and_tools.py::test_verifier_relevance_and_anti_overstating PASSED [ 35%]
tests/test_core_and_tools.py::test_approval_race_conditions PASSED       [ 37%]
tests/test_core_and_tools.py::test_task_interruption_and_server_restart PASSED [ 39%]
tests/test_core_and_tools.py::test_end_to_end_edit_test_fix_lifecycle PASSED [ 41%]
tests/test_core_and_tools.py::test_legacy_migration_failure_fails_closed PASSED [ 43%]
tests/test_core_and_tools.py::test_terminal_sandbox_boundaries PASSED    [ 45%]
tests/test_core_and_tools.py::test_verifier_criteria_mapping_and_evidence PASSED [ 47%]
tests/test_core_and_tools.py::test_api_host_ipv6_and_token_permission_failure PASSED [ 50%]
tests/test_core_and_tools.py::test_database_write_error_propagation PASSED [ 52%]
tests/test_core_and_tools.py::test_posix_vault_key_failure_handling PASSED [ 54%]
tests/test_core_and_tools.py::test_verifier_strict_structured_evidence_mapping PASSED [ 56%]
tests/test_core_and_tools.py::test_credential_migration_multi_key_corrupted_and_recovery PASSED [ 58%]
tests/test_core_and_tools.py::test_terminal_os_sandbox_job_limits_and_container_config PASSED [ 60%]
tests/test_core_and_tools.py::test_verifier_adversarial_irrelevant_passing_test_rejected PASSED [ 62%]
tests/test_core_and_tools.py::test_terminal_container_execution_fail_closed_and_dispatch PASSED [ 64%]
tests/test_core_and_tools.py::test_terminal_default_is_container_and_host_rejected_when_sandboxed PASSED [ 66%]
tests/test_core_and_tools.py::test_posix_key_directory_permissions_and_symlink_rejection PASSED [ 68%]
tests/test_core_and_tools.py::test_credential_migration_partial_failure_stages PASSED [ 70%]
tests/test_core_and_tools.py::test_container_hardening_non_root_image_validation_and_timeout_cleanup PASSED [ 72%]
tests/test_core_and_tools.py::test_credential_vault_concurrent_creation_race_and_validation PASSED [ 75%]
tests/test_core_and_tools.py::test_verifier_rejects_fabricated_output_and_unbacked_assertion_records PASSED [ 77%]
tests/test_core_and_tools.py::test_verifier_rejects_exit_zero_generic_word_without_test_execution PASSED [ 79%]
tests/test_core_and_tools.py::test_real_docker_container_security_boundaries PASSED [ 81%]
tests/test_core_and_tools.py::test_verifier_rejects_fabricated_runner_output_without_trusted_execution_record PASSED [ 83%]
tests/test_core_and_tools.py::test_credential_vault_stress_slow_writes_interrupted_and_permissions PASSED [ 85%]
tests/test_core_and_tools.py::test_verifier_rejects_forged_execution_record PASSED [ 87%]
tests/test_core_and_tools.py::test_run_verification_tool_structured_record_e2e PASSED [ 89%]
tests/test_core_and_tools.py::test_credential_vault_multiprocess_concurrency_and_crash_recovery PASSED [ 91%]
tests/test_core_and_tools.py::test_trusted_execution_record_individual_field_tampering_rejected PASSED [ 93%]
tests/test_core_and_tools.py::test_parse_junit_xml_report_rejects_zero_tests_and_counts_cases_accurately PASSED [ 95%]
tests/test_core_and_tools.py::test_junit_xml_report_skipped_tests_handling_and_verification_rejection PASSED [ 97%]
tests/test_core_and_tools.py::test_verification_secret_lifecycle_persistence_and_restart PASSED [100%]

======================== 48 passed in 16.15s (100% Green CI) ========================
```

---

## 📁 Project Directory Layout

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
│   │   ├── terminal.py            # Subprocess runner with container sandbox & timeouts
│   │   ├── git.py                 # Git status & diff tools
│   │   ├── verification.py        # Automated test & build runner with JUnit parsing
│   │   └── registry.py            # Tool schema exporter
│   ├── security/
│   │   ├── permissions.py         # Multi-tiered permission & approval logic
│   │   ├── sanitizer.py           # Secret masking & prompt injection defense
│   │   └── provenance.py          # Cryptographic HMAC-SHA256 signing & secret lifecycle
│   ├── verification/
│   │   └── verifier.py            # Outcome verifier & report synthesizer
│   ├── persistence/
│   │   ├── credentials.py         # OS-native CredentialVault (DPAPI + POSIX)
│   │   └── db.py                  # aiosqlite repository
│   └── api/
│       └── server.py              # FastAPI app & WebSocket event broadcaster
├── ui/                            # React 19 + TypeScript + Vite UI
│   ├── src/
│   │   ├── App.tsx                # Interactive dashboard, diff viewer & modals
│   │   ├── App.css                # Scoped component styles
│   │   └── index.css              # Design tokens & dark glassmorphic theme
├── tests/
│   └── test_core_and_tools.py     # 48 comprehensive unit, integration, and security tests
├── main.py                        # Service entrypoint
├── pytest.ini                     # Pytest configuration
├── LICENSE                        # MIT License
└── README.md                      # Evidence-driven developer documentation
```

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).

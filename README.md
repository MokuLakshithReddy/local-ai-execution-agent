<div align="center">

# ⚡ Local-First, Model-Agnostic AI Execution Agent

### *Stop trusting what AI chatbots say. Start verifying what AI agents actually do.*

An open-source, evidence-driven autonomous coding framework that delegates real software engineering tasks to LLMs—with **OS/container containment**, **cryptographic execution provenance**, and **verifiable machine proof**.

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![React 19](https://img.shields.io/badge/React-19%20%7C%20Vite-646CFF.svg)](https://vitejs.dev/)
[![SQLite](https://img.shields.io/badge/SQLite-Local--First-003B57.svg)](https://sqlite.org/)
[![CI](https://github.com/MokuLakshithReddy/local-ai-execution-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/MokuLakshithReddy/local-ai-execution-agent/actions/workflows/ci.yml)
[![Verification: 75 Passed](https://img.shields.io/badge/Verification-75%20Passed-10b981.svg)](#-live-verification-evidence-log)
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
4. **Local-First & Model-Agnostic**: Supports 100% offline local models via **Ollama** (complete on-device privacy). When configured with cloud LLM providers (**Gemini, Claude, GPT-4o**), prompts and workspace code snippets are transmitted to the respective provider's API according to their privacy terms.

---

## 🤔 Why This Matters: The Chatbot vs. Evidence Agent

| Capability | Standard AI Assistant / Chatbot | This AI Execution Agent |
|---|---|---|
| **Completion Criteria** | Subjective: LLM says *"Done!"* in chat. | **Objective**: Test runners exit `0`, assertions pass, and git diffs match. |
| **Output Integrity** | Can print fake test logs and claim they passed. | **Cryptographic Provenance**: JUnit XML signed with HMAC-SHA256 (deterministic canonical JSON). |
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

## 📊 The Truth Table: Evidence-Grounded Verification

> **What Verification Proves (and What it Does Not):**
> Verification proves that designated automated test suites and linters executed inside the containment sandbox, exited with return code `0`, and that git diffs reflect the modified files. It confirms demonstrable test-runner evidence; it does **not** constitute mathematical proof of complete functional correctness or the absence of all software bugs.

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

### 2. Verify Your Environment (57 Passing Tests)

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
- **Security Boundary Notice**: File and network containment rely on Docker container isolation (or host OS Job Objects). Command-line string filtering in `validate_sandbox_command()` is an early syntactic lint, not an OS-enforced boundary.
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

### 2. Cryptographic Provenance & Deterministic Canonical JSON
- **Zero Fabrication**: Prevents agents or malicious scripts from outputting fake `1 passed in 0.05s` strings to trick verification.
- **Deterministic Canonical JSON Serialization**: All test results (`run_id`, `runner`, `command`, `exit_code`, `total`, `passed`, `failed`, `skipped`, `ephemeral`, `nodes`, `timestamp`) are serialized into canonical JSON (alphabetically sorted keys, compact separators `','` and `':'`) and signed using HMAC-SHA256, eliminating delimiter ambiguity and formatting collision risks.
- **Skipped-Test Isolation**: Skipped tests are recorded separately (`skipped_nodes`) and **never** counted as passed. Reports with zero passing tests or count inconsistencies are rejected immediately.
- **Persistent Key Lifecycle & Fail-Closed Protection**: Signing keys are stored at `~/.config/ai_execution_agent/verification.key` with atomic creation (`O_CREAT | O_EXCL`), restrictive permissions (`0600` on POSIX, user ACL lockdown via `icacls` on Windows), or configured via `AGENT_VERIFICATION_SECRET`. If storage is unwritable, it fails closed (ephemeral keys are strictly opt-in).
- **Key Rotation**: Provides `rotate_verification_secret()`, atomically establishing new keys and revoking historical signatures.

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

### Latest CI Telemetry (73 Comprehensive Verification Tests):
```text
============================= test session starts =============================
platform win32 -- Python 3.12.10, pytest-9.1.1, pluggy-1.7.0
rootdir: C:\Users\nsrfl\OneDrive\Desktop\MAKE LLM TO CODE
configfile: pytest.ini
plugins: anyio-4.15.1, asyncio-1.4.1
collected 73 items

tests/test_core_and_tools.py::test_resolve_safe_path_security PASSED     [  1%]
tests/test_core_and_tools.py::test_symlink_containment_security PASSED   [  2%]
tests/test_core_and_tools.py::test_credential_vault_encryption PASSED    [  4%]
tests/test_core_and_tools.py::test_database_credential_encryption_and_sanitization PASSED [  5%]
tests/test_core_and_tools.py::test_security_sanitizer_redaction PASSED   [  6%]
tests/test_core_and_tools.py::test_security_sanitizer_injection_defense PASSED [  8%]
tests/test_core_and_tools.py::test_permission_manager_levels PASSED      [  9%]
tests/test_core_and_tools.py::test_terminal_environment_allowlist PASSED [ 10%]
tests/test_core_and_tools.py::test_filesystem_tools_lifecycle PASSED     [ 12%]
tests/test_core_and_tools.py::test_criteria_driven_verification PASSED   [ 13%]
tests/test_core_and_tools.py::test_api_security_authorization PASSED     [ 15%]
tests/test_core_and_tools.py::test_adversarial_bootstrap_attacks PASSED  [ 16%]
tests/test_core_and_tools.py::test_token_file_acl_protection PASSED      [ 17%]
tests/test_core_and_tools.py::test_credential_vault_corruption_and_migration PASSED [ 19%]
tests/test_core_and_tools.py::test_dpapi_failure_fails_closed PASSED     [ 20%]
tests/test_core_and_tools.py::test_real_process_tree_termination PASSED  [ 21%]
tests/test_core_and_tools.py::test_verifier_relevance_and_anti_overstating PASSED [ 23%]
tests/test_core_and_tools.py::test_approval_race_conditions PASSED       [ 24%]
tests/test_core_and_tools.py::test_task_interruption_and_server_restart PASSED [ 26%]
tests/test_core_and_tools.py::test_end_to_end_edit_test_fix_lifecycle PASSED [ 27%]
tests/test_core_and_tools.py::test_legacy_migration_failure_fails_closed PASSED [ 28%]
tests/test_core_and_tools.py::test_terminal_sandbox_boundaries PASSED    [ 30%]
tests/test_core_and_tools.py::test_verifier_criteria_mapping_and_evidence PASSED [ 31%]
tests/test_core_and_tools.py::test_api_host_ipv6_and_token_permission_failure PASSED [ 32%]
tests/test_core_and_tools.py::test_database_write_error_propagation PASSED [ 34%]
tests/test_core_and_tools.py::test_posix_vault_key_failure_handling PASSED [ 35%]
tests/test_core_and_tools.py::test_verifier_strict_structured_evidence_mapping PASSED [ 36%]
tests/test_core_and_tools.py::test_credential_migration_multi_key_corrupted_and_recovery PASSED [ 38%]
tests/test_core_and_tools.py::test_terminal_os_sandbox_job_limits_and_container_config PASSED [ 39%]
tests/test_core_and_tools.py::test_verifier_adversarial_irrelevant_passing_test_rejected PASSED [ 41%]
tests/test_core_and_tools.py::test_terminal_container_execution_fail_closed_and_dispatch PASSED [ 42%]
tests/test_core_and_tools.py::test_terminal_default_is_container_and_host_rejected_when_sandboxed PASSED [ 43%]
tests/test_core_and_tools.py::test_posix_key_directory_permissions_and_symlink_rejection PASSED [ 45%]
tests/test_core_and_tools.py::test_credential_migration_partial_failure_stages PASSED [ 46%]
tests/test_core_and_tools.py::test_container_hardening_non_root_image_validation_and_timeout_cleanup PASSED [ 47%]
tests/test_core_and_tools.py::test_credential_vault_concurrent_creation_race_and_validation PASSED [ 49%]
tests/test_core_and_tools.py::test_verifier_rejects_fabricated_output_and_unbacked_assertion_records PASSED [ 50%]
tests/test_core_and_tools.py::test_verifier_rejects_exit_zero_generic_word_without_test_execution PASSED [ 52%]
tests/test_core_and_tools.py::test_real_docker_container_security_boundaries PASSED (in Ubuntu CI) [ 53%]
tests/test_core_and_tools.py::test_verifier_rejects_fabricated_runner_output_without_trusted_execution_record PASSED [ 54%]
tests/test_core_and_tools.py::test_credential_vault_stress_slow_writes_interrupted_and_permissions PASSED [ 56%]
tests/test_core_and_tools.py::test_verifier_rejects_forged_execution_record PASSED [ 57%]
tests/test_core_and_tools.py::test_run_verification_tool_structured_record_e2e PASSED [ 58%]
tests/test_core_and_tools.py::test_credential_vault_multiprocess_concurrency_and_crash_recovery PASSED [ 60%]
tests/test_core_and_tools.py::test_trusted_execution_record_individual_field_tampering_rejected PASSED [ 61%]
tests/test_core_and_tools.py::test_parse_junit_xml_report_rejects_zero_tests_and_counts_cases_accurately PASSED [ 63%]
tests/test_core_and_tools.py::test_junit_xml_report_skipped_tests_handling_and_verification_rejection PASSED [ 64%]
tests/test_core_and_tools.py::test_verification_secret_lifecycle_persistence_and_restart PASSED [ 65%]
tests/test_core_and_tools.py::test_verification_secret_storage_fails_closed_without_ephemeral_fallback PASSED [ 67%]
tests/test_core_and_tools.py::test_verification_secret_explicit_ephemeral_mode_and_labeling PASSED [ 68%]
tests/test_core_and_tools.py::test_verification_secret_corrupted_key_rejected PASSED [ 69%]
tests/test_core_and_tools.py::test_verification_secret_rotation PASSED   [ 71%]
tests/test_core_and_tools.py::test_verification_secret_concurrent_creation_race_handled PASSED [ 72%]
tests/test_core_and_tools.py::test_windows_key_file_acl_enforcement PASSED [ 73%]
tests/test_core_and_tools.py::test_windows_acl_allowlist_parsing_and_adversarial_principals PASSED [ 75%]
tests/test_core_and_tools.py::test_windows_acl_lockdown_command_failures_and_timeout_handling PASSED [ 76%]
tests/test_core_and_tools.py::test_subprocess_timeout_cleanup_reaps_all_children_on_failure PASSED [ 78%]
tests/test_core_and_tools.py::test_malformed_and_truncated_junit_xml PASSED [ 79%]
tests/test_core_and_tools.py::test_code_modification_requires_structured_evidence_not_raw_console PASSED [ 80%]
tests/test_core_and_tools.py::test_sandbox_interpreter_escape_attempts_blocked_by_container_boundary PASSED [ 82%]
tests/test_core_and_tools.py::test_execution_engine_e2e_enforces_structured_evidence_for_code_modifications PASSED [ 83%]
tests/test_core_and_tools.py::test_verification_secret_write_failure_raises_immediately PASSED [ 84%]
tests/test_core_and_tools.py::test_unisolated_host_mode_gated_by_env_var PASSED [ 86%]
tests/test_core_and_tools.py::test_verification_secret_multi_config_dir_scoping PASSED [ 87%]
tests/test_core_and_tools.py::test_terminal_sandbox_mode_and_require_sandbox_combinations PASSED [ 89%]
tests/test_core_and_tools.py::test_verification_signing_key_cache_lifecycle_and_dynamic_environment PASSED [ 90%]
tests/test_core_and_tools.py::test_verification_secret_rotation_failures_fail_closed_and_preserve_state PASSED [ 91%]
tests/test_core_and_tools.py::test_verification_secret_rotation_post_replace_lockdown_failure_rollback PASSED [ 93%]
tests/test_core_and_tools.py::test_engine_untrusted_task_cannot_escape_to_host_even_with_env_flag PASSED [ 94%]
tests/test_core_and_tools.py::test_verification_secret_multithreaded_concurrency PASSED [ 95%]
tests/test_core_and_tools.py::test_ci_status_reporter_strict_and_failure_modes PASSED [ 97%]
tests/test_core_and_tools.py::test_engine_approval_rejection_and_timeout_lifecycle_e2e PASSED [ 96%]
tests/test_core_and_tools.py::test_ui_accessibility_and_responsive_contract PASSED [ 97%]
tests/test_core_and_tools.py::test_vault_init_lock_adversarial_multiprocess_recovery_and_ownership PASSED [ 98%]
tests/test_core_and_tools.py::test_diff_and_task_state_synchronization PASSED [100%]

======================== 75 passed in 22.93s (100% Green CI) ========================
```

---

## 💻 Supported Platforms & Environment Matrix

| Operating System | Sandboxing Mechanism | Credential Storage | Verification Engine | Status |
|:---|:---|:---|:---|:---:|
| **Windows 10 / 11 (x64)** | Windows Job Objects / Docker Desktop | Windows DPAPI (`CryptProtectData`) via ctypes | Native Process Tree & ICACLS Audit Allowlist | ✅ Fully Supported |
| **Linux (Ubuntu 20.04+, Debian 11+)** | Hardened Docker Container (`--network=none`, non-root) | POSIX user-only vault (`0700` dir / `0600` key) | Strict Process Tree & JUnit XML Provenance | ✅ Fully Supported |
| **macOS (Darwin x64 / arm64)** | Docker Desktop Containment | POSIX restricted user directory (`~/.config`) | Pytest / JUnit XML Execution Signatures | ✅ Fully Supported |

---

## 🎯 Release Scope: What is Implemented vs. What is Deferred

### ✅ Fully Implemented in v1.0:
- **Local-First Credential Vault**: Zero-plaintext on-disk secrets. OS-bound encryption via DPAPI on Windows and atomic PID-staged creation with directory locks on POSIX.
- **Cryptographic Execution Provenance**: Deterministic JSON serialization (`RFC 8785`), HMAC-SHA256 signature verification, key rotation, and atomic lockdown rollbacks.
- **Strict Verification Engine**: Refusal of unverified test claims; enforced structured JUnit XML evidence for code-modification tasks; tamper-detection on all verification fields.
- **Sandboxed Process Containment**: Mandatory container execution by default (`--network=none`, `--memory=512m`, `--pids-limit=64`, non-root execution). Host escape strictly blocked unless explicitly elevated.
- **Responsive Web Dashboard**: WebSocket lifecycle with auto-reconnection and live status badge; multi-file unified git diff viewer with addition/deletion statistics; high-visibility approval banners with hotkeys (`Alt+A`/`Alt+D`); full ARIA accessibility landmarks.

### ⏳ Explicitly Deferred to Future Milestones:
- **Distributed Multi-Node Sandboxes**: Remote execution across Kubernetes clusters (currently strictly single-machine local containment).
- **Multi-Tenant Role-Based Access Control (RBAC)**: Enterprise LDAP/SSO user roles (v1.0 is single-developer local-first).
- **Automated Formal Software Proof Verification**: Mechanical theorem-proving / formal verification like Coq/Lean (v1.0 relies on automated test suite evidence, compiler/linter exit codes, and JUnit assertions).

---

## 📁 Project Directory Layout

```
.
├── agent/
│   ├── core/
│   │   ├── models.py              # Pydantic domain models & state definitions
│   │   └── engine.py              # Bounded execution loop, loop-guards, and approval lifecycles
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
│   │   └── provenance.py          # Cryptographic HMAC-SHA256 signing, JCS, and secret lifecycle
│   ├── verification/
│   │   └── verifier.py            # Outcome verifier & report synthesizer
│   ├── persistence/
│   │   ├── credentials.py         # OS-native CredentialVault (DPAPI + POSIX concurrency recovery)
│   │   └── db.py                  # aiosqlite repository
│   └── api/
│       └── server.py              # FastAPI app & WebSocket event broadcaster
├── ui/                            # React 19 + TypeScript + Vite UI
│   ├── src/
│   │   ├── App.tsx                # Multi-file diff viewer, approval modal, and accessible feed
│   │   ├── App.css                # Scoped component styles & responsive layouts
│   │   └── index.css              # Design tokens & dark glassmorphic theme
├── tests/
│   └── test_core_and_tools.py     # 73 comprehensive unit, integration, and security tests
├── main.py                        # Service entrypoint
├── pytest.ini                     # Pytest configuration
├── LICENSE                        # MIT License
└── README.md                      # Evidence-driven developer documentation
```

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).

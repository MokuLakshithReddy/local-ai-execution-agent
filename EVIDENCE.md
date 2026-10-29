# Formal Verification & Evidence Report

> **Notice**: This document is generated automatically by CI and local test runner telemetry. Do not edit this document manually.

## 1. Provenance & Execution Context

- **Commit SHA**: `a07fc550ba35bd522c41d1b11a2a4076d7bc033c`
- **Git Branch**: `main`
- **Generated At**: `2026-10-29 22:33:18 UTC`
- **Operating System**: `Windows 11 (AMD64)`
- **Python Runtime**: `3.12.10`
- **Primary Sandbox Mode**: `Kernel Job Object / Local Host Supervisor`

## 2. Test Suite Execution Telemetry

| Metric | Observed Value | Status |
|---|---|---|
| **Total Tests** | `108` | Verified |
| **Tests Passed** | `108` | Pass |
| **Tests Failed** | `0` | Pass (0 failures) |
| **Tests Skipped** | `0` | Deselected / Platform Conditional |
| **Execution Duration** | `43.46s` | Bounded |
| **Pass Rate** | `**100.0%**` | 100.0% Pass |

## 3. Security Boundary Verification Summary

| ID | Boundary | Threat Profile Tested | Enforcement Mechanism | Status |
|---|---|---|---|---|
| **ADV-01** | **Filesystem Containment** | Path traversal (`../../`), root escapes, external symlinks | Canonical realpath containment & `os.path.realpath` symlink dereferencing | **PASS** |
| **ADV-02** | **Secret Redaction** | Host API keys/tokens exposed in tools or stored in SQLite | Centralized `SecuritySanitizer` regex & exact string scrubbing across DB & logs | **PASS** |
| **ADV-03** | **Execution Boundary** | Host root erasure (`rm -rf /`, `rd /s /q`) & container bypass | `validate_sandbox_command` blocklist, Docker `--read-only` rootfs & non-root user | **PASS** |
| **ADV-04** | **Input Sanitization** | Prompt injection instructions in repo files (`README.md`) | `SecuritySanitizer` delimiter fencing (`=== BEGIN UNTRUSTED DATA ===`) & Verifier | **PASS** |
| **ADV-05** | **Environment Isolation** | Task subshell dumping environment to steal host credentials | `get_isolated_environment()` strict allowlist (`SAFE_ENV_ALLOWLIST`) | **PASS** |
| **ADV-06** | **Network Namespace** | Outbound HTTP/socket exfiltration & `allow_network=True` | Docker `--network=none`, proxy loopback blackholing, model schema stripping | **PASS** |
| **ADV-07** | **Process Supervision** | Hanging background loops, orphan fork bombs, excessive memory | Bounded streaming cap (50 KB), task timeouts, `_kill_process_tree` process groups | **PASS** |

## 4. Platform Sandboxing Capabilities & Differences

### Linux / Ubuntu (Production CI Target)
- **Container Sandboxing**: Docker container (`python:3.12-slim`) with `--network=none`, `--read-only` rootfs, `--cap-drop=ALL`, `--memory=512m`, `--pids-limit=64`, non-root user (`agent`), and 64MB isolated `/tmp` tmpfs.
- **Cryptographic Secret Lifecycle**: Persistent 256-bit key at `~/.config/ai_execution_agent/verification.key` secured to POSIX `0o600` (directory `0o700`) with atomic `O_CREAT | O_EXCL` concurrency.
- **Fail-Closed Default**: Host execution without container sandbox is strictly rejected for automated agent tasks.

### Windows (Local Developer Environment)
- **Kernel Job Objects**: Windows Job Sandbox (`CreateJobObjectW`) enforcers `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, `JOB_OBJECT_LIMIT_ACTIVE_PROCESS`, and `JOB_OBJECT_LIMIT_JOB_MEMORY`.
- **ACL Hardening**: Persistent key protected with native Windows discretionary ACLs (`icacls`), inheritance stripped, granted exclusively to current user SID.
- **Fallback Policy**: When Docker is not available locally, tasks require explicit developer flag `AGENT_ALLOW_UNISOLATED_HOST_EXECUTION=1`; untrusted automated tasks cannot escape to host execution without it.

## 5. Verification Provenance & Cryptographic Binding

- All successful test runs produce an authentic, tamper-evident `TrustedExecutionRecord`.
- Deterministic canonical JSON serialization with HMAC-SHA256 digests.
- Verifier cross-validates console execution output line-by-line against JUnit XML `<testcase>` identities before issuing or honoring execution proofs.

# Formal Verification & Evidence Report

> **Notice**: This document is generated automatically by CI and local test runner telemetry. Do not edit this document manually.

## 1. Provenance & Execution Context

- **Report Scope**: `Canonical Linux / Docker Container Environment (Production Target)`
- **Commit SHA**: `02b49cf4b620618ca08d58a49a52437aa5604dd0`
- **Git Branch**: `main`
- **CI Run ID**: `41283454897`
- **CI Run URL**: https://github.com/MokuLakshithReddy/local-ai-execution-agent/actions/runs/41283454897
- **Canonical CI Pipeline**: [https://github.com/MokuLakshithReddy/local-ai-execution-agent/actions/workflows/ci.yml](https://github.com/MokuLakshithReddy/local-ai-execution-agent/actions/workflows/ci.yml)
- **Working Tree**: `Clean (Verified)`
- **Generated At**: `2026-11-01 07:08:21 UTC`
- **Operating System**: `Linux (Ubuntu 24.04 LTS / GitHub Actions CI)`
- **Python Runtime**: `3.12.10`
- **Primary Sandbox Mode**: `Docker Container (--read-only, --network=none)`

## 2. CI Verification & Artifact Provenance

- **Canonical Multi-Platform CI**: GitHub Actions executes on both Ubuntu (`ubuntu-latest`) and Windows (`windows-latest`).
- **Official CI Artifacts**: Every commit archives the machine-generated `EVIDENCE.md`, `DEMO_RUN.md`, `junit-results.xml`, and (on Linux) `junit-docker-results.xml` in the official `execution-evidence-reports` workflow artifact.
- **Audit Verification URL**: https://github.com/MokuLakshithReddy/local-ai-execution-agent/actions/runs/41283454897

## 3. Test Suite Execution Telemetry

| Metric | Observed Value | Status |
|---|---|---|
| **Total Tests** | `141` | Verified |
| **Tests Passed** | `141` | Pass |
| **Tests Failed** | `0` | Pass (0 failures) |
| **Tests Skipped** | `0` | Deselected / Platform Conditional |
| **Execution Duration** | `49.2s` | Bounded |
| **Pass Rate** | `**100.0%**` | 100.0% Pass |

## 4. Security Boundary Verification Summary

| ID | Boundary | Threat Profile Tested | Enforcement Mechanism | Verifying Test Identifier | Platform Scope | Status |
|---|---|---|---|---|---|:---:|
| **ADV-01** | **Filesystem Path Containment** | Path traversal ('../../'), root escapes, external symlinks | Canonical realpath containment & symlink dereferencing in ReadFileTool and SearchFilesTool | `tests/test_adversarial_benchmark.py::test_adversarial_scenario_1_path_traversal` | Cross-platform Host Policy | **PASS** |
| **ADV-02** | **Secret Redaction & Masking** | Host credentials, tokens, or private keys leaking to SQLite or logs | Centralized SecuritySanitizer regex & exact string scrubbing across DB & output streams | `tests/test_adversarial_benchmark.py::test_adversarial_scenario_2_secret_redaction` | Cross-platform Host Policy | **PASS** |
| **ADV-03** | **Destructive Command Filtering & Host Isolation** | Host root erasure ('rm -rf /', 'rd /s /q') & unisolated execution | validate_sandbox_command syntax filtering & fail-closed host rejection | `tests/test_adversarial_benchmark.py::test_adversarial_scenario_3_destructive_commands` | Cross-platform Host Policy | **PASS** |
| **ADV-04** | **Hostile Instruction & Prompt Injection Fencing** | Hostile repo instructions attempting to commandeer agent behavior or fake success | SecuritySanitizer delimiter fencing ('=== BEGIN UNTRUSTED DATA ===') & Verifier truth check | `tests/test_adversarial_benchmark.py::test_adversarial_scenario_4_prompt_injection` | Cross-platform Host Policy | **PASS** |
| **ADV-05** | **Environment Variable Isolation** | Subshell dumping environment to steal host credentials (AWS, OpenAI, SSH) | _get_isolated_environment() strict variable allowlist (SAFE_ENV_ALLOWLIST) | `tests/test_adversarial_benchmark.py::test_adversarial_scenario_5_env_leakage` | Cross-platform Host Policy | **PASS** |
| **ADV-06** | **Command-Level Outbound Network Blocking** | Outbound exfiltration commands ('curl', 'wget') & unauthorized network enablement | validate_sandbox_command network command rejection & schema enforcement | `tests/test_adversarial_benchmark.py::test_adversarial_scenario_6_network_isolation` | Cross-platform Host Policy | **PASS** |
| **ADV-07** | **Process Supervision & Timeout Bounds** | Hanging background loops, orphan fork bombs, memory runaway | Streaming cap (50 KB), async task timeouts, and _kill_process_tree process group termination | `tests/test_adversarial_benchmark.py::test_adversarial_scenario_7_subprocess_timeout` | Cross-platform Host Policy | **PASS** |
| **DOCKER-01** | **Container Rootfs & Non-Root UID Boundary** | Modifying container OS rootfs or privilege escalation inside container | Docker '--read-only' rootfs, '--cap-drop=ALL', non-root execution ('--user 1000:1000') | `tests/test_core_and_tools.py::test_real_docker_container_security_boundaries` | Linux / Docker Container | **PASS** |
| **DOCKER-02** | **Kernel Network Namespace Isolation** | Raw socket creation or unauthorized outbound TCP/UDP traffic from inside container | Docker '--network=none' kernel network namespace detachment | `tests/test_core_and_tools.py::test_real_docker_container_security_boundaries` | Linux / Docker Container | **PASS** |

## 5. Platform Sandboxing Capabilities & Differences

### Linux / Ubuntu (Production CI Target)
- **Container Sandboxing**: Docker container (`python:3.12-slim`) with `--network=none`, `--read-only` rootfs, `--cap-drop=ALL`, `--memory=512m`, `--pids-limit=64`, non-root user (`agent`), isolated `/tmp` tmpfs, and read-only test mounts (`:ro`).
- **Live Container Integration**: All live container isolation tests (`test_real_docker_*`) execute and are verified exclusively on Linux/Ubuntu.
- **Fail-Closed Default**: Host execution without container sandbox is strictly rejected for automated agent tasks.

### Windows (Local Developer Environment)
- **Kernel Job Objects**: Process isolation enforced via native Windows Job Objects (`ctypes.windll.kernel32`, `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, `JOB_OBJECT_LIMIT_ACTIVE_PROCESS`, `JOB_OBJECT_LIMIT_JOB_MEMORY`).
- **Best-Effort Host Attribute Protection**: In unisolated host fallback mode, designated test files are temporarily set to read-only (`stat.S_IREAD`). Note that Windows Job Objects provide process lifecycle and memory isolation, but do not provide filesystem access-control boundaries; full container isolation (e.g., Docker read-only bind mounts `:ro`) is required for untrusted execution, and unisolated host execution is strictly prohibited for automated untrusted workloads.
- **Platform Boundary Notice**: GitHub Actions Windows runners (`windows-latest`) do not run Linux Docker containers; live Docker security boundaries are tested and proven on Linux/Ubuntu CI only.
- **Fallback Policy**: Unisolated host fallback requires explicit developer opt-in `AGENT_ALLOW_UNISOLATED_HOST_EXECUTION=1`.

## 6. Verification Provenance & Cryptographic Binding

- All successful test runs produce an authentic, tamper-evident `TrustedExecutionRecord`.
- Deterministic canonical JSON serialization with HMAC-SHA256 digests.
- Verifier cross-validates console execution output line-by-line against JUnit XML `<testcase>` identities before issuing or honoring execution proofs.

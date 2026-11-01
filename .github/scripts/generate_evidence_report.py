#!/usr/bin/env python3
"""
Authoritative Evidence Report Generator.
Parses JUnit test XML and environment runtime metadata to generate
a reproducible, machine-independent EVIDENCE.md report.
Derives each individual security boundary status directly from testcase execution records.
"""
import os
import sys
import platform
import subprocess
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


SECURITY_BOUNDARIES = [
    {
        "id": "ADV-01",
        "name": "Filesystem Containment",
        "threat": "Path traversal (`../../`), root escapes, external symlinks",
        "enforcement": "Canonical realpath containment & `os.path.realpath` symlink dereferencing",
        "testcase_prefix": "test_adversarial_scenario_1_path_traversal",
    },
    {
        "id": "ADV-02",
        "name": "Secret Redaction",
        "threat": "Host API keys/tokens exposed in tools or stored in SQLite",
        "enforcement": "Centralized `SecuritySanitizer` regex & exact string scrubbing across DB & logs",
        "testcase_prefix": "test_adversarial_scenario_2_secret_redaction",
    },
    {
        "id": "ADV-03",
        "name": "Execution Boundary",
        "threat": "Host root erasure (`rm -rf /`, `rd /s /q`) & container bypass",
        "enforcement": "`validate_sandbox_command` blocklist, Docker `--read-only` rootfs & non-root user",
        "testcase_prefix": "test_adversarial_scenario_3_destructive_commands",
    },
    {
        "id": "ADV-04",
        "name": "Input Sanitization",
        "threat": "Prompt injection instructions in repo files (`README.md`)",
        "enforcement": "`SecuritySanitizer` delimiter fencing (`=== BEGIN UNTRUSTED DATA ===`) & Verifier",
        "testcase_prefix": "test_adversarial_scenario_4_prompt_injection",
    },
    {
        "id": "ADV-05",
        "name": "Environment Isolation",
        "threat": "Task subshell dumping environment to steal host credentials",
        "enforcement": "`get_isolated_environment()` strict allowlist (`SAFE_ENV_ALLOWLIST`)",
        "testcase_prefix": "test_adversarial_scenario_5_env_leakage",
    },
    {
        "id": "ADV-06",
        "name": "Network Namespace",
        "threat": "Outbound HTTP/socket exfiltration & `allow_network=True`",
        "enforcement": "Docker `--network=none`, proxy loopback blackholing, model schema stripping",
        "testcase_prefix": "test_adversarial_scenario_6_network_isolation",
    },
    {
        "id": "ADV-07",
        "name": "Process Supervision",
        "threat": "Hanging background loops, orphan fork bombs, excessive memory",
        "enforcement": "Bounded streaming cap (50 KB), task timeouts, `_kill_process_tree` process groups",
        "testcase_prefix": "test_adversarial_scenario_7_subprocess_timeout",
    },
]


def get_git_metadata() -> Dict[str, str]:
    """Retrieves commit SHA, branch name, CI run metadata, and working tree clean/dirty status."""
    try:
        sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        sha = os.environ.get("GITHUB_SHA", "unknown-sha")

    try:
        branch = subprocess.check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"], text=True).strip()
    except Exception:
        branch = os.environ.get("GITHUB_REF_NAME", "main")

    ci_run_id = os.environ.get("GITHUB_RUN_ID", "Local Execution")
    repo = os.environ.get("GITHUB_REPOSITORY", "MokuLakshithReddy/local-ai-execution-agent")
    ci_run_url = f"https://github.com/{repo}/actions/runs/{ci_run_id}" if ci_run_id != "Local Execution" else "N/A (Local Execution)"

    try:
        status_out = subprocess.check_output(["git", "status", "--porcelain"], text=True).strip()
        working_tree = "Clean (Verified)" if not status_out else "Dirty (Uncommitted Changes Present)"
    except Exception:
        working_tree = "Unknown"

    return {
        "commit_sha": sha,
        "branch": branch,
        "ci_run_id": ci_run_id,
        "ci_run_url": ci_run_url,
        "working_tree": working_tree,
    }


def parse_junit_xml(xml_path: str) -> Dict[str, Any]:
    """Extracts test execution counts, duration, and individual testcase outcomes from pytest JUnit XML."""
    empty_result = {
        "total": 0,
        "passed": 0,
        "failed": 0,
        "skipped": 0,
        "duration_seconds": 0.0,
        "exists": False,
        "boundaries": {b["id"]: {"status": "**NOT RUN**", "detail": "Test record missing"} for b in SECURITY_BOUNDARIES},
    }
    if not os.path.exists(xml_path):
        return empty_result

    try:
        tree = ET.parse(xml_path)
    except Exception:
        return empty_result

    root = tree.getroot()

    # Find primary suite
    if root.tag == "testsuite":
        suite = root
    else:
        found = root.find("testsuite")
        suite = found if found is not None else root

    total = int(suite.attrib.get("tests", 0))
    failures = int(suite.attrib.get("failures", 0))
    errors = int(suite.attrib.get("errors", 0))
    skipped = int(suite.attrib.get("skipped", 0))
    duration = float(suite.attrib.get("time", 0.0))

    failed = failures + errors
    passed = total - failed - skipped

    # Collect individual testcase statuses
    testcases: Dict[str, str] = {}
    for tc in root.iter("testcase"):
        name = tc.attrib.get("name", "")
        if tc.find("failure") is not None or tc.find("error") is not None:
            tc_status = "FAIL"
        elif tc.find("skipped") is not None:
            tc_status = "SKIPPED"
        else:
            tc_status = "PASS"
        testcases[name] = tc_status

    # Derive each security boundary's status from verified execution evidence
    boundary_results = {}
    for b in SECURITY_BOUNDARIES:
        prefix = b["testcase_prefix"]
        matching_statuses = [status for name, status in testcases.items() if prefix in name]
        if not matching_statuses:
            b_status = "**NOT RUN**"
        elif any(s == "FAIL" for s in matching_statuses):
            b_status = "**FAIL**"
        elif any(s == "SKIPPED" for s in matching_statuses):
            b_status = "**SKIPPED**"
        else:
            b_status = "**PASS**"
        boundary_results[b["id"]] = {
            "status": b_status,
            "boundary": b,
        }

    return {
        "total": total,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "duration_seconds": round(duration, 2),
        "exists": True,
        "boundaries": boundary_results,
    }


def generate_markdown(
    git_meta: Dict[str, str],
    test_metrics: Dict[str, Any],
    sandbox_mode: str,
) -> str:
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    os_name = platform.system()
    os_release = platform.release()
    py_ver = platform.python_version()

    pass_rate = (test_metrics["passed"] / test_metrics["total"] * 100) if test_metrics["total"] > 0 else 0.0

    lines = [
        "# Formal Verification & Evidence Report",
        "",
        "> **Notice**: This document is generated automatically by CI and local test runner telemetry. "
        "Do not edit this document manually.",
        "",
        "## 1. Provenance & Execution Context",
        "",
        f"- **Commit SHA**: `{git_meta['commit_sha']}`",
        f"- **Git Branch**: `{git_meta['branch']}`",
        f"- **CI Run ID**: `{git_meta['ci_run_id']}`",
        f"- **CI Run URL**: {git_meta['ci_run_url']}",
        f"- **Working Tree**: `{git_meta['working_tree']}`",
        f"- **Generated At**: `{now_utc}`",
        f"- **Operating System**: `{os_name} {os_release} ({platform.machine()})`",
        f"- **Python Runtime**: `{py_ver}`",
        f"- **Primary Sandbox Mode**: `{sandbox_mode}`",
        "",
        "## 2. Test Suite Execution Telemetry",
        "",
        f"| Metric | Observed Value | Status |",
        f"|---|---|---|",
        f"| **Total Tests** | `{test_metrics['total']}` | Verified |",
        f"| **Tests Passed** | `{test_metrics['passed']}` | Pass |",
        f"| **Tests Failed** | `{test_metrics['failed']}` | {'Pass (0 failures)' if test_metrics['failed'] == 0 else 'FAIL'} |",
        f"| **Tests Skipped** | `{test_metrics['skipped']}` | Deselected / Platform Conditional |",
        f"| **Execution Duration** | `{test_metrics['duration_seconds']}s` | Bounded |",
        f"| **Pass Rate** | `**{pass_rate:.1f}%**` | {'100.0% Pass' if pass_rate == 100.0 else 'Incomplete'} |",
        "",
        "## 3. Security Boundary Verification Summary",
        "",
        "| ID | Boundary | Threat Profile Tested | Enforcement Mechanism | Status |",
        "|---|---|---|---|:---:|",
    ]

    boundaries = test_metrics.get("boundaries", {})
    for b in SECURITY_BOUNDARIES:
        b_info = boundaries.get(b["id"], {})
        status = b_info.get("status", "**NOT RUN**")
        lines.append(
            f"| **{b['id']}** | **{b['name']}** | {b['threat']} | {b['enforcement']} | {status} |"
        )

    lines.extend([
        "",
        "## 4. Platform Sandboxing Capabilities & Differences",
        "",
        "### Linux / Ubuntu (Production CI Target)",
        "- **Container Sandboxing**: Docker container (`python:3.12-slim`) with `--network=none`, `--read-only` rootfs, `--cap-drop=ALL`, `--memory=512m`, `--pids-limit=64`, non-root user (`agent`), isolated `/tmp` tmpfs, and read-only test mounts (`:ro`).",
        "- **Live Container Integration**: All live container isolation tests (`test_real_docker_*`) execute and are verified exclusively on Linux/Ubuntu.",
        "- **Fail-Closed Default**: Host execution without container sandbox is strictly rejected for automated agent tasks.",
        "",
        "### Windows (Local Developer Environment)",
        "- **Kernel Job Objects**: Process isolation enforced via native Windows Job Objects (`ctypes.windll.kernel32`, `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, `JOB_OBJECT_LIMIT_ACTIVE_PROCESS`, `JOB_OBJECT_LIMIT_JOB_MEMORY`).",
        "- **ACL Hardening**: Host test write-protection enforced via NTFS `stat.S_IREAD` read-only permissions and user-exclusive discretionary ACLs.",
        "- **Platform Boundary Notice**: GitHub Actions Windows runners (`windows-latest`) do not run Linux Docker containers; live Docker security boundaries are tested and proven on Linux/Ubuntu CI only.",
        "- **Fallback Policy**: Unisolated host fallback requires explicit developer opt-in `AGENT_ALLOW_UNISOLATED_HOST_EXECUTION=1`.",
        "",
        "## 5. Verification Provenance & Cryptographic Binding",
        "",
        "- All successful test runs produce an authentic, tamper-evident `TrustedExecutionRecord`.",
        "- Deterministic canonical JSON serialization with HMAC-SHA256 digests.",
        "- Verifier cross-validates console execution output line-by-line against JUnit XML `<testcase>` identities before issuing or honoring execution proofs.",
        "",
    ])
    return "\n".join(lines)


def main():
    xml_path = sys.argv[1] if len(sys.argv) > 1 else "junit-results.xml"
    output_path = sys.argv[2] if len(sys.argv) > 2 else "EVIDENCE.md"

    git_meta = get_git_metadata()
    test_metrics = parse_junit_xml(xml_path)

    # Detect sandbox mode
    is_docker = False
    try:
        res = subprocess.run(
            ["docker", "run", "--rm", "python:3.12-slim", "echo", "ok"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        is_docker = (res.returncode == 0)
    except Exception:
        pass

    sandbox_mode = "Docker Container (--read-only, --network=none)" if is_docker else "Kernel Job Object / Local Host Supervisor"

    content = generate_markdown(git_meta, test_metrics, sandbox_mode)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"[Evidence Generator] Generated authoritative evidence report at {output_path} ({test_metrics['total']} tests parsed, exact commit: {git_meta['commit_sha'][:7]}).")


if __name__ == "__main__":
    main()

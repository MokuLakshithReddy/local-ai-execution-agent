"""
Verification engine and completion report builder.
Distinguishes between model claims, executed tools, and observed verifiable evidence.
Enforces criteria-based completion, relevance matching, skipped-check tracking, and state consistency.
"""
from typing import List, Optional, Dict
import os
import re
import time
from agent.security.provenance import verify_trusted_execution_record, TrustedExecutionRecord
from agent.core.models import (
    TaskStatus,
    TaskType,
    VerificationCheck,
    TaskReport,
    CriterionEvidence,
    StructuredAssertion,
)

# Legitimate verification runners
VALID_CHECK_RUNNERS = [
    "pytest",
    "unittest",
    "npm test",
    "npm run",
    "npx vitest",
    "jest",
    "tsc",
    "cargo test",
    "cargo check",
    "go test",
    "flake8",
    "mypy",
    "ruff",
    "eslint",
    "python -m test",
]

# Trivial/Dummy commands that cannot count as verification
DUMMY_COMMANDS = ["echo", "dir", "true", "type", "cat", "whoami", "hostname", "pwd"]


def infer_task_type(goal: str) -> TaskType:
    """Infers whether a user task is informational or requires code execution/verification."""
    g = goal.lower()
    mod_triggers = ["fix", "implement", "add", "create", "write", "modify", "update", "patch", "refactor", "delete"]
    test_triggers = ["test", "verify", "check", "assert", "benchmark", "coverage", "run tests"]

    if any(t in g for t in test_triggers) and not any(m in g for m in mod_triggers):
        return TaskType.TEST_AND_VERIFY
    if any(m in g for m in mod_triggers):
        return TaskType.CODE_MODIFICATION
    return TaskType.INFORMATIONAL


def _is_legitimate_and_relevant_check(
    check: VerificationCheck,
    goal: str,
    modified_files: List[str],
) -> bool:
    """
    Validates that a check is not a dummy command (like `echo 1`)
    and is strictly relevant to the task's modified components or project test suite.
    Rejects unrelated tests and zero-assertion runs.
    """
    cmd = (check.command or "").strip().lower()
    if not cmd:
        return False

    # 1. Reject trivial / dummy commands
    for dummy in DUMMY_COMMANDS:
        if cmd == dummy or cmd.startswith(dummy + " ") or cmd.startswith(dummy + ".") or f"&& {dummy}" in cmd or f"; {dummy}" in cmd:
            return False

    # Reject inline script execution or print commands posing as tests
    if any(fake in cmd for fake in ("python -c", "python3 -c", "node -e", "print(", "printf ", "echo ")):
        return False

    # 2. Must invoke a recognized test/build/lint runner or custom script
    is_valid_runner = any(runner in cmd for runner in VALID_CHECK_RUNNERS) or (
        check.check_type in ("test", "build", "lint", "typecheck") and len(cmd) > 3
    )
    if not is_valid_runner:
        return False

    # 3. Reject empty test runs (e.g., "0 passed", "collected 0 items", "no tests were found")
    out_lower = (check.output or "").lower()
    if "collected 0 items" in out_lower or "no tests were found" in out_lower or "0 passed, 0 failed" in out_lower:
        return False

    # 4. Check for unrelated targeted tests
    # If the command targets specific test files or filters (e.g. "pytest tests/test_unrelated.py"):
    args = [arg.replace("\\", "/") for arg in cmd.split() if not arg.startswith("-")]
    targeted_args = [a for a in args[1:] if "/" in a or a.endswith(".py") or a.endswith(".js") or a.endswith(".ts")]

    goal_words = set(re.findall(r"[a-zA-Z0-9_-]{3,}", goal.lower()))
    goal_words = {w for w in goal_words if w not in {"the", "and", "for", "with", "this", "that", "from", "task", "file", "code", "agent"}}
    modified_stems = {
        os.path.splitext(os.path.basename(f))[0].lower() for f in modified_files if f
    }
    relevant_tokens = goal_words.union(modified_stems)

    if targeted_args:
        # If specific test target was specified, it MUST match at least one relevant token
        target_stems = {os.path.splitext(os.path.basename(t))[0].lower() for t in targeted_args}
        has_match = any(
            any(tok in stem or stem in tok for tok in relevant_tokens)
            for stem in target_stems
        )
        if not has_match:
            # Targeted test did not touch any modified file or goal keyword!
            return False
        return True

    # 5. Whole-suite runners (e.g. "pytest", "pytest -v", "npm test", "cargo test")
    if any(cmd.startswith(runner) for runner in ("pytest", "npm test", "npm run", "tsc", "cargo test", "go test")):
        return True

    for token in relevant_tokens:
        if token in cmd or token in check.check_name.lower():
            return True

    return False


def _extract_executed_passed_test_nodes(check: VerificationCheck) -> List[str]:
    """
    Extracts test node IDs, file targets, and test functions that were demonstrably EXECUTED and PASSED by a runner.
    Only valid if check exited with exit_code == 0 and check.success is True.
    Prioritizes trusted structured runner execution records directly from the process.
    Rejects targets appearing merely in command arguments, summary strings, arbitrary script outputs, or failure traces.
    """
    if check.exit_code != 0 or not check.success:
        return []

    # 1. Validate cryptographic provenance of trusted execution record
    if check.trusted_execution_record:
        if verify_trusted_execution_record(check.trusted_execution_record):
            if isinstance(check.trusted_execution_record, dict):
                nodes = check.trusted_execution_record.get("passed_nodes", [])
            else:
                nodes = getattr(check.trusted_execution_record, "passed_nodes", [])
            return [str(n).lower() for n in nodes]
        else:
            # Forged or tampered execution record detected: refuse immediately
            return []

    # 2. Reject commands that are not direct executions of recognized test runners
    cmd = (check.command or "").strip().lower()
    if not cmd:
        return []

    # Reject inline code or scripts pretending to be test runners
    if any(fake in cmd for fake in ("python -c", "python3 -c", "node -e", "print(", "printf ", "echo ")):
        return []

    is_direct_runner = any(
        cmd.startswith(runner) or cmd.startswith(f"python -m {runner}") or cmd.startswith(f"python3 -m {runner}")
        for runner in ("pytest", "unittest", "npx vitest", "jest", "cargo test", "go test")
    )
    if not is_direct_runner:
        # Script execution (e.g. python custom_script.py) without a trusted runner record cannot prove targeted test execution
        return []

    output = check.output or ""
    passed_nodes = []

    # 1. Pytest verbose: "tests/test_auth.py::test_login PASSED" or "test_login PASSED"
    for m in re.finditer(r"(?:^|\s)((?:[\w./\\]+::)?(test_[a-zA-Z0-9_]+))\s+(?:PASSED|passed)\b", output, re.MULTILINE):
        full_node = m.group(1).lower()
        test_fn = m.group(2).lower()
        passed_nodes.append(full_node)
        passed_nodes.append(test_fn)
        if "::" in full_node:
            file_part = full_node.split("::")[0]
            passed_nodes.append(file_part)
            passed_nodes.append(os.path.basename(file_part))
            passed_nodes.append(os.path.splitext(os.path.basename(file_part))[0])

    # 2. Pytest prefixed: "PASSED tests/test_auth.py::test_login"
    for m in re.finditer(r"\bPASSED\s+((?:[\w./\\]+::)?(test_[a-zA-Z0-9_]+))\b", output):
        full_node = m.group(1).lower()
        test_fn = m.group(2).lower()
        passed_nodes.append(full_node)
        passed_nodes.append(test_fn)
        if "::" in full_node:
            file_part = full_node.split("::")[0]
            passed_nodes.append(file_part)
            passed_nodes.append(os.path.basename(file_part))
            passed_nodes.append(os.path.splitext(os.path.basename(file_part))[0])

    # 3. Unittest: "test_login (tests.test_auth.AuthTests) ... ok" or "test_login ... ok"
    for m in re.finditer(r"(?:^|\s)(test_[a-zA-Z0-9_]+)\s*(?:\(([\w.]+)\))?\s*\.\.\.\s*ok\b", output, re.IGNORECASE | re.MULTILINE):
        test_fn = m.group(1).lower()
        passed_nodes.append(test_fn)
        if m.group(2):
            mod_part = m.group(2).lower()
            passed_nodes.append(mod_part)
            for part in mod_part.split("."):
                passed_nodes.append(part)
                passed_nodes.append(f"{part}.py")

    # 4. Jest / Vitest: "✓ test_login" or "PASS ... > test_login"
    for m in re.finditer(r"(?:✓|PASS)\s+(?:[\w./\\]+>\s*)?(test_[a-zA-Z0-9_]+)", output):
        passed_nodes.append(m.group(1).lower())

    return list(set(passed_nodes))


class VerificationEngine:
    def __init__(self):
        self.recorded_checks: List[VerificationCheck] = []

    def record_check(self, check: VerificationCheck):
        self.recorded_checks.append(check)

    def evaluate_completion(
        self,
        task_id: str,
        goal: str,
        actions_taken: List[str],
        modified_files: List[str],
        task_type: TaskType = TaskType.CODE_MODIFICATION,
        task_current_status: TaskStatus = TaskStatus.EXECUTING,
        git_diff_summary: Optional[str] = None,
        unresolved_notes: Optional[List[str]] = None,
        acceptance_criteria: Optional[List[str]] = None,
        criterion_bindings: Optional[Dict[str, str]] = None,
    ) -> TaskReport:
        """
        Synthesizes observed evidence into a structured completion report.
        Strictly requires evidence linking checks to acceptance criteria.
        Requires explicit criterion-to-test mappings or structured verification results.
        Rejects keyword overlap, coincidental word-matching, or fabricated output strings.
        Guarantees that CANCELLED, BLOCKED, or FAILED tasks never report false success.
        """
        # Determine the latest outcome for each verification command/check
        latest_checks = {}
        for c in self.recorded_checks:
            key = (c.command or c.check_name).strip()
            latest_checks[key] = c

        passed_checks = [c for c in latest_checks.values() if c.success and c.exit_code == 0]
        unresolved_failed_checks = [c for c in latest_checks.values() if not (c.success and c.exit_code == 0)]

        # Filter for legitimate & relevant checks
        relevant_passed_checks = [
            c for c in passed_checks if _is_legitimate_and_relevant_check(c, goal, modified_files)
        ]

        skipped_or_failed = []
        for fc in unresolved_failed_checks:
            skipped_or_failed.append(
                f"Check '{fc.check_name}' failed with exit code {fc.exit_code}. Summary: {fc.evidence_summary}"
            )

        criteria_evidence: List[CriterionEvidence] = []
        g_lower = goal.lower()

        # Consolidate criterion bindings (from evaluate_completion parameter and checks)
        all_bindings: Dict[str, str] = dict(criterion_bindings or {})
        for c in self.recorded_checks:
            if hasattr(c, "criterion_bindings") and c.criterion_bindings:
                all_bindings.update(c.criterion_bindings)

        # 1. Process explicit acceptance criteria if provided
        if acceptance_criteria:
            for criterion in acceptance_criteria:
                matching_check = None
                matched_proof = None
                matched_artifact = None
                verification_tier = "UNVERIFIED"

                # Check 1: Explicit criterion binding (maps criterion -> exact test node/file/target)
                target_test = None
                for b_crit, b_target in all_bindings.items():
                    if b_crit.strip().lower() == criterion.strip().lower() or b_crit.strip() == criterion.strip():
                        target_test = b_target
                        break

                if target_test:
                    target_test_clean = target_test.strip().lower()
                    target_test_stem = os.path.splitext(os.path.basename(target_test_clean))[0]
                    target_test_name = target_test_clean.split("::")[-1].replace(".py", "")

                    for check in relevant_passed_checks:
                        passed_nodes = _extract_executed_passed_test_nodes(check)

                        # Must match an actually executed and passed test node parsed from runner telemetry
                        node_matched = (
                            target_test_clean in passed_nodes
                            or target_test_name in passed_nodes
                            or target_test_stem in passed_nodes
                            or any(
                                p == target_test_clean
                                or p == target_test_name
                                or p == target_test_stem
                                or p.endswith(f"::{target_test_name}")
                                or p.endswith(f"/{target_test_clean}")
                                or p.endswith(f"\\{target_test_clean}")
                                for p in passed_nodes
                            )
                        )

                        if node_matched:
                            matching_check = check
                            matched_proof = f"Executed test node '{target_test}' passed with exit code 0"
                            matched_artifact = check.evidence_artifact or (check.command or check.check_name)
                            verification_tier = "VERIFIED_TARGETED_TEST"
                            break

                # Check 2: Structured verification assertion on check model
                if not matching_check:
                    for check in relevant_passed_checks:
                        passed_nodes = _extract_executed_passed_test_nodes(check)

                        for sa in getattr(check, "structured_assertions", []):
                            if sa.criterion.strip().lower() == criterion.strip().lower():
                                if sa.result.upper() != "PASSED":
                                    continue

                                target_clean = sa.target_test_or_assertion.strip().lower()
                                target_name = target_clean.split("::")[-1]

                                # Assertion MUST be execution-backed by an executed test node OR a verified artifact file
                                is_grounded = (
                                    target_name in passed_nodes
                                    or any(target_clean in p or p in target_clean for p in passed_nodes)
                                    or (
                                        sa.evidence_artifact
                                        and os.path.exists(sa.evidence_artifact)
                                        and target_clean in (check.output or "").lower()
                                        and ("passed" in (check.output or "").lower() or "ok" in (check.output or "").lower())
                                    )
                                )

                                if not is_grounded:
                                    # Fabricated or unbacked assertion record without execution proof
                                    continue

                                matching_check = check
                                matched_proof = f"Structured assertion: '{sa.target_test_or_assertion}' (result: PASSED, execution-backed)"
                                matched_artifact = sa.evidence_artifact or check.evidence_artifact or (check.command or check.check_name)
                                verification_tier = "VERIFIED_ASSERTION"
                                break
                        if matching_check:
                            break

                # If no explicit binding or structured assertion, retain UNVERIFIED.
                # Word-overlap or coincidental substring matching in test names is rejected.
                if matching_check:
                    criteria_evidence.append(
                        CriterionEvidence(
                            criterion=criterion,
                            requirement=f"Evidence verified via {matching_check.check_name}",
                            demonstrated=True,
                            evidence_type="assertion_verified" if verification_tier == "VERIFIED_ASSERTION" else "test_execution",
                            evidence_summary=matching_check.evidence_summary,
                            linked_check=matching_check.command or matching_check.check_name,
                            exit_status=matching_check.exit_code,
                            test_node_or_assertion=matched_proof,
                            evidence_artifact=matched_artifact,
                            verification_tier=verification_tier,
                        )
                    )
                else:
                    best_general = relevant_passed_checks[0] if relevant_passed_checks else None
                    criteria_evidence.append(
                        CriterionEvidence(
                            criterion=criterion,
                            requirement="Explicit criterion-to-test binding or structured assertion proving requirement",
                            demonstrated=False,
                            evidence_type="unverified",
                            evidence_summary=(
                                f"Check '{best_general.check_name}' exited 0, but no explicit test binding or structured assertion proved this criterion."
                                if best_general
                                else "No passing check executed for this criterion."
                            ),
                            linked_check=best_general.command if best_general else None,
                            exit_status=best_general.exit_code if best_general else None,
                            test_node_or_assertion=None,
                            evidence_artifact=None,
                            verification_tier="UNVERIFIED",
                        )
                    )
                    skipped_or_failed.append(
                        f"Unmet Acceptance Criterion: '{criterion}' was not proven by an explicit test binding or structured assertion."
                    )


        # 2. Derive required criteria from goal keywords
        required_criteria = []
        if any(w in g_lower for w in ("lint", "linter", "eslint", "ruff", "flake8")):
            required_criteria.append(("Linting", ["lint", "flake8", "ruff", "eslint"], "linter_clean"))
        if any(w in g_lower for w in ("test", "tests", "unit test", "pytest", "coverage")):
            required_criteria.append(("Automated Tests", ["test", "pytest", "unittest", "jest", "vitest"], "test_execution"))
        if any(w in g_lower for w in ("typecheck", "mypy", "typescript", "tsc")):
            required_criteria.append(("Type Checking", ["mypy", "tsc", "typecheck"], "build_verification"))
        if any(w in g_lower for w in ("build", "compile")):
            required_criteria.append(("Build / Compilation", ["build", "compile", "tsc"], "build_verification"))

        for criterion_name, keywords, ev_type in required_criteria:
            matching_checks = [
                c for c in relevant_passed_checks
                if any(kw in (c.command or "").lower() or kw in c.check_type.lower() or kw in c.check_name.lower() for kw in keywords)
            ]
            if matching_checks:
                best = matching_checks[0]
                criteria_evidence.append(
                    CriterionEvidence(
                        criterion=f"Goal requirement: {criterion_name}",
                        requirement=f"Execute {criterion_name} suite with exit code 0",
                        demonstrated=True,
                        evidence_type=ev_type,
                        evidence_summary=best.evidence_summary,
                        linked_check=best.command or best.check_name,
                    )
                )
            else:
                criteria_evidence.append(
                    CriterionEvidence(
                        criterion=f"Goal requirement: {criterion_name}",
                        requirement=f"Execute {criterion_name} suite with exit code 0",
                        demonstrated=False,
                        evidence_type="missing_evidence",
                        evidence_summary=f"No passing check executed for requested {criterion_name}.",
                        linked_check=None,
                    )
                )
                skipped_or_failed.append(
                    f"Required criterion '{criterion_name}' was requested in goal but no corresponding check was executed or verified."
                )

        risks = list(unresolved_notes or [])
        any_undemonstrated = any(not ce.demonstrated for ce in criteria_evidence)

        # 1. State Consistency Guard:
        # If the task was cancelled, blocked, or failed in the engine, preserve that status
        if task_current_status in (TaskStatus.CANCELLED, TaskStatus.BLOCKED, TaskStatus.FAILED):
            final_status = task_current_status
            criteria_satisfied = False

        # 2. Criteria Evaluation based on TaskType
        elif task_type == TaskType.INFORMATIONAL:
            # Informational tasks (inspect architecture, search, explain) do not require code changes
            if unresolved_failed_checks or any_undemonstrated:
                final_status = TaskStatus.PARTIALLY_COMPLETED
                criteria_satisfied = False
            else:
                final_status = TaskStatus.COMPLETED
                criteria_satisfied = True

        elif task_type == TaskType.CODE_MODIFICATION:
            # Code modifications MUST prove that files were actually changed AND verified
            if not modified_files:
                final_status = TaskStatus.PARTIALLY_COMPLETED
                criteria_satisfied = False
                risks.append(
                    "Unmet Acceptance Criteria: Task requested code modifications, but no files were created or modified in the workspace."
                )
            elif unresolved_failed_checks:
                final_status = TaskStatus.PARTIALLY_COMPLETED
                criteria_satisfied = False
                risks.append(
                    f"Unmet Acceptance Criteria: {len(unresolved_failed_checks)} verification checks failed during execution."
                )
            elif not relevant_passed_checks:
                final_status = TaskStatus.PARTIALLY_COMPLETED
                criteria_satisfied = False
                if not self.recorded_checks:
                    risks.append(
                        "Unverified Changes: Source files were modified, but no automated verification checks were executed."
                    )
                else:
                    risks.append(
                        "Irrelevant Verification: Executed checks did not demonstrate relevance to the modified files or task acceptance criteria (trivial/dummy command rejected)."
                    )
            elif any_undemonstrated or skipped_or_failed:
                final_status = TaskStatus.PARTIALLY_COMPLETED
                criteria_satisfied = False
                risks.append("Partial Acceptance Criteria: Some requested requirements were not demonstrated by concrete evidence.")
            else:
                final_status = TaskStatus.COMPLETED
                criteria_satisfied = True

        elif task_type == TaskType.TEST_AND_VERIFY:
            # Verification tasks require at least one passing relevant check and zero failing checks
            if not relevant_passed_checks:
                final_status = TaskStatus.PARTIALLY_COMPLETED
                criteria_satisfied = False
                risks.append("No valid verification check was executed for a verification-specific goal.")
            elif unresolved_failed_checks or any_undemonstrated or skipped_or_failed:
                final_status = TaskStatus.PARTIALLY_COMPLETED
                criteria_satisfied = False
            else:
                final_status = TaskStatus.COMPLETED
                criteria_satisfied = True
        else:
            final_status = TaskStatus.PARTIALLY_COMPLETED
            criteria_satisfied = False

        report = TaskReport(
            task_id=task_id,
            goal=goal,
            task_type=task_type,
            status=final_status,
            summary_of_actions=actions_taken,
            files_created_or_modified=list(set(modified_files)),
            diff_summary=git_diff_summary or "(no git diff available)",
            executed_verification_checks=self.recorded_checks,
            skipped_or_failed_checks=skipped_or_failed,
            criteria_evidence=criteria_evidence,
            unresolved_risks_or_limitations=risks,
            acceptance_criteria_satisfied=criteria_satisfied,
            created_at=time.time(),
            completed_at=time.time(),
        )
        return report

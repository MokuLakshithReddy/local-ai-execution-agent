"""
Verification engine and completion report builder.
Distinguishes between model claims, executed tools, and observed verifiable evidence.
Enforces criteria-based completion, relevance matching, skipped-check tracking, and state consistency.
"""
from typing import List, Optional
import os
import re
import time
from agent.core.models import TaskStatus, TaskType, VerificationCheck, TaskReport, CriterionEvidence

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
    ) -> TaskReport:
        """
        Synthesizes observed evidence into a structured completion report.
        Strictly requires evidence linking checks to acceptance criteria.
        Distinguishes generic 'command passed' from concrete 'requirement demonstrated'.
        Guarantees that CANCELLED, BLOCKED, or FAILED tasks never report false success.
        """
        # Determine the latest outcome for each verification command/check
        latest_checks = {}
        for c in self.recorded_checks:
            key = (c.command or c.check_name).strip()
            latest_checks[key] = c

        passed_checks = [c for c in latest_checks.values() if c.success]
        unresolved_failed_checks = [c for c in latest_checks.values() if not c.success]

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

        # 1. Process explicit acceptance criteria if provided
        if acceptance_criteria:
            for criterion in acceptance_criteria:
                c_lower = criterion.lower()
                c_words = set(re.findall(r"[a-zA-Z0-9_-]{3,}", c_lower))
                c_words = {w for w in c_words if w not in {"the", "and", "for", "with", "this", "that", "from", "should", "must", "verify", "check"}}

                # Find relevant check whose command, output, or name explicitly exercises this criterion
                matching_check = None
                for check in relevant_passed_checks:
                    check_text = f"{(check.command or '')} {check.check_name} {check.output}".lower()
                    if any(w in check_text for w in c_words):
                        matching_check = check
                        break

                if matching_check:
                    criteria_evidence.append(
                        CriterionEvidence(
                            criterion=criterion,
                            requirement=f"Evidence verified via {matching_check.check_name}",
                            demonstrated=True,
                            evidence_type="test_execution",
                            evidence_summary=matching_check.evidence_summary,
                            linked_check=matching_check.command or matching_check.check_name,
                        )
                    )
                else:
                    criteria_evidence.append(
                        CriterionEvidence(
                            criterion=criterion,
                            requirement="Concrete test execution demonstrating requirement",
                            demonstrated=False,
                            evidence_type="missing_evidence",
                            evidence_summary="No executed check demonstrated coverage of this specific criterion.",
                            linked_check=None,
                        )
                    )
                    skipped_or_failed.append(
                        f"Unmet Acceptance Criterion: '{criterion}' was not demonstrated by concrete verification evidence."
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

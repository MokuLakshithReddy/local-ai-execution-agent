"""
Verification engine and completion report builder.
Distinguishes between model claims, executed tools, and observed verifiable evidence.
Enforces criteria-based completion and guarantees state consistency.
"""
from typing import List, Optional
import time
from agent.core.models import TaskStatus, TaskType, VerificationCheck, TaskReport


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
    ) -> TaskReport:
        """
        Synthesizes observed evidence into a structured completion report.
        Strictly requires evidence for task-specific criteria.
        Guarantees that CANCELLED, BLOCKED, or FAILED tasks never report false success.
        """
        passed_checks = [c for c in self.recorded_checks if c.success]
        failed_checks = [c for c in self.recorded_checks if not c.success]

        skipped_or_failed = []
        for fc in failed_checks:
            skipped_or_failed.append(
                f"Check '{fc.check_name}' failed with exit code {fc.exit_code}. Summary: {fc.evidence_summary}"
            )

        risks = list(unresolved_notes or [])

        # 1. State Consistency Guard:
        # If the task was cancelled, blocked, or failed in the engine, preserve that status
        if task_current_status in (TaskStatus.CANCELLED, TaskStatus.BLOCKED, TaskStatus.FAILED):
            final_status = task_current_status
            criteria_satisfied = False

        # 2. Criteria Evaluation based on TaskType
        elif task_type == TaskType.INFORMATIONAL:
            # Informational tasks (inspect architecture, search, explain) do not require code changes
            if failed_checks:
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
            elif failed_checks:
                final_status = TaskStatus.PARTIALLY_COMPLETED
                criteria_satisfied = False
                risks.append(
                    f"Unmet Acceptance Criteria: {len(failed_checks)} verification checks failed during execution."
                )
            elif not self.recorded_checks:
                final_status = TaskStatus.PARTIALLY_COMPLETED
                criteria_satisfied = False
                risks.append(
                    "Unverified Changes: Source files were modified, but no automated verification checks (e.g. pytest, npm test, lint) were executed to prove correctness."
                )
            else:
                final_status = TaskStatus.COMPLETED
                criteria_satisfied = True

        elif task_type == TaskType.TEST_AND_VERIFY:
            # Verification tasks require at least one passing check and zero failing checks
            if not self.recorded_checks:
                final_status = TaskStatus.PARTIALLY_COMPLETED
                criteria_satisfied = False
                risks.append("No verification checks were executed for a verification-specific goal.")
            elif failed_checks:
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
            unresolved_risks_or_limitations=risks,
            acceptance_criteria_satisfied=criteria_satisfied,
            created_at=time.time(),
            completed_at=time.time(),
        )
        return report

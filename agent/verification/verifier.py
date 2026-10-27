"""
Verification engine and completion report builder.
Distinguishes between model claims, executed tools, and observed verifiable evidence.
"""
from typing import List, Optional
import time
from agent.core.models import TaskStatus, VerificationCheck, TaskReport


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
        git_diff_summary: Optional[str] = None,
        unresolved_notes: Optional[List[str]] = None,
    ) -> TaskReport:
        """
        Synthesizes observed evidence into a structured completion report.
        Strictly determines verified vs partial completion.
        """
        passed_checks = [c for c in self.recorded_checks if c.success]
        failed_checks = [c for c in self.recorded_checks if not c.success]

        skipped_or_failed = []
        for fc in failed_checks:
            skipped_or_failed.append(
                f"Check '{fc.check_name}' failed with exit code {fc.exit_code}. Summary: {fc.evidence_summary}"
            )

        risks = list(unresolved_notes or [])
        if not self.recorded_checks:
            risks.append(
                "No automated verification tests or build checks were executed. Changes are unverified by automated tests."
            )

        # Status determination:
        # If any checks failed -> PARTIALLY_COMPLETED (or BLOCKED)
        # If checks ran and all passed -> COMPLETED
        # If no checks ran but changes were made -> PARTIALLY_COMPLETED
        if failed_checks:
            final_status = TaskStatus.PARTIALLY_COMPLETED
        elif passed_checks and not failed_checks:
            final_status = TaskStatus.COMPLETED
        elif modified_files and not self.recorded_checks:
            final_status = TaskStatus.PARTIALLY_COMPLETED
        else:
            final_status = TaskStatus.COMPLETED

        report = TaskReport(
            task_id=task_id,
            goal=goal,
            status=final_status,
            summary_of_actions=actions_taken,
            files_created_or_modified=list(set(modified_files)),
            diff_summary=git_diff_summary or "(no git diff available)",
            executed_verification_checks=self.recorded_checks,
            skipped_or_failed_checks=skipped_or_failed,
            unresolved_risks_or_limitations=risks,
            created_at=time.time(),
            completed_at=time.time(),
        )
        return report

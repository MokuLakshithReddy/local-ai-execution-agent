"""
Verification tools: runs tests, linters, builds, and registers verifiable outcomes.
"""
import time
from typing import Any, Dict
from agent.tools.base import BaseTool
from agent.tools.terminal import RunCommandTool
from agent.core.models import PermissionLevel, ActionResult


class RunVerificationCheckTool(BaseTool):
    name = "run_verification"
    description = (
        "Execute a formal verification command (e.g. pytest, npm test, cargo test, tsc, flake8) "
        "and record its exit code, output, and verifiable status."
    )
    permission_level = PermissionLevel.SENSITIVE_OPERATION

    def __init__(self):
        self._command_tool = RunCommandTool()

    def get_parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "check_name": {
                    "type": "string",
                    "description": "Descriptive name for the verification check (e.g. 'Unit Tests', 'TypeScript Compile').",
                },
                "check_type": {
                    "type": "string",
                    "description": "Category: 'test', 'build', 'lint', 'typecheck', or 'custom'.",
                    "default": "test",
                },
                "command": {
                    "type": "string",
                    "description": "Shell command line to execute.",
                },
            },
            "required": ["check_name", "command"],
        }

    async def execute(self, workspace_path: str, **kwargs) -> ActionResult:
        t0 = time.time()
        call_id = kwargs.get("call_id", "run_verification")
        check_name = kwargs.get("check_name", "Verification Check")
        check_type = kwargs.get("check_type", "test")
        command = kwargs.get("command", "")

        res = await self._command_tool.execute(
            workspace_path=workspace_path,
            call_id=call_id,
            command=command,
            timeout_seconds=90,
        )

        exit_code = res.artifacts.get("exit_code") if res.artifacts else None
        is_success = (exit_code == 0)

        evidence = (
            f"Verification Check '{check_name}' ({check_type}) exited with code {exit_code}. "
            f"{'PASSED' if is_success else 'FAILED'}."
        )

        return ActionResult(
            call_id=call_id,
            tool_name=self.name,
            success=is_success,
            output=res.output,
            error=res.error,
            artifacts={
                "check_name": check_name,
                "check_type": check_type,
                "command": command,
                "exit_code": exit_code,
                "evidence_summary": evidence,
                "passed": is_success,
            },
            execution_time_ms=(time.time() - t0) * 1000,
        )

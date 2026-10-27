"""
Git inspection and safe checkpoint tools.
"""
import asyncio
import time
from typing import Any, Dict
from agent.tools.base import BaseTool
from agent.core.models import PermissionLevel, ActionResult


async def _run_git(args: list[str], cwd: str) -> tuple[int, str, str]:
    cmd = ["git"] + args
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=cwd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    return (
        proc.returncode or 0,
        stdout.decode("utf-8", errors="replace"),
        stderr.decode("utf-8", errors="replace"),
    )


class GitStatusTool(BaseTool):
    name = "git_status"
    description = "Inspect repository status, staged files, modified files, and untracked files."
    permission_level = PermissionLevel.READ_ONLY

    def get_parameters_schema(self) -> Dict[str, Any]:
        return {"type": "object", "properties": {}}

    async def execute(self, workspace_path: str, **kwargs) -> ActionResult:
        t0 = time.time()
        call_id = kwargs.get("call_id", "git_status")
        code, out, err = await _run_git(["status", "--porcelain", "-b"], workspace_path)

        if code != 0:
            return ActionResult(
                call_id=call_id,
                tool_name=self.name,
                success=False,
                output="",
                error=f"Git status failed or not a git repository: {err.strip()}",
                execution_time_ms=(time.time() - t0) * 1000,
            )

        return ActionResult(
            call_id=call_id,
            tool_name=self.name,
            success=True,
            output=out if out.strip() else "(working tree clean)",
            execution_time_ms=(time.time() - t0) * 1000,
        )


class GitDiffTool(BaseTool):
    name = "git_diff"
    description = "Inspect the unified diff of changes made in the workspace repository."
    permission_level = PermissionLevel.READ_ONLY

    def get_parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Optional file path to view diff for a specific file only.",
                    "default": "",
                }
            },
        }

    async def execute(self, workspace_path: str, **kwargs) -> ActionResult:
        t0 = time.time()
        call_id = kwargs.get("call_id", "git_diff")
        file_path = kwargs.get("file_path", "")

        args = ["diff", "HEAD"] if not file_path else ["diff", "HEAD", "--", file_path]
        code, out, err = await _run_git(args, workspace_path)

        # Fallback to plain diff if HEAD doesn't exist yet (e.g., brand new repo)
        if code != 0:
            fallback_args = ["diff"] if not file_path else ["diff", "--", file_path]
            code, out, err = await _run_git(fallback_args, workspace_path)

        if code != 0:
            return ActionResult(
                call_id=call_id,
                tool_name=self.name,
                success=False,
                output="",
                error=f"Git diff error: {err.strip()}",
                execution_time_ms=(time.time() - t0) * 1000,
            )

        return ActionResult(
            call_id=call_id,
            tool_name=self.name,
            success=True,
            output=out if out.strip() else "(no uncommitted diff)",
            execution_time_ms=(time.time() - t0) * 1000,
        )

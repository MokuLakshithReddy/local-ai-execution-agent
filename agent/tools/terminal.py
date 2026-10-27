"""
Terminal and process execution tool with bounded execution, timeouts, and security isolation.
"""
import asyncio
import os
import time
from typing import Any, Dict
from agent.tools.base import BaseTool
from agent.core.models import PermissionLevel, ActionResult

DANGEROUS_COMMAND_PATTERNS = [
    "rm -rf /",
    "format c:",
    "del /s /q c:",
    ":(){ :|:& };:",
    "mkfs",
    "dd if=",
]

SENSITIVE_ENV_VARS = {
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "GITHUB_TOKEN",
    "PERSONAL_ACCESS_TOKEN",
}


class RunCommandTool(BaseTool):
    name = "run_command"
    description = (
        "Execute a terminal shell command (tests, builds, linter, git) within the workspace directory. "
        "Commands run with a timeout and bounded output capture."
    )
    permission_level = PermissionLevel.SENSITIVE_OPERATION

    def get_parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Shell command line to execute.",
                },
                "timeout_seconds": {
                    "type": "integer",
                    "description": "Maximum seconds to wait before terminating the process (default: 60).",
                    "default": 60,
                },
            },
            "required": ["command"],
        }

    async def execute(self, workspace_path: str, **kwargs) -> ActionResult:
        t0 = time.time()
        call_id = kwargs.get("call_id", "run_command")
        command = kwargs.get("command", "").strip()
        timeout = min(kwargs.get("timeout_seconds", 60), 300)

        # Basic danger guard
        for dangerous in DANGEROUS_COMMAND_PATTERNS:
            if dangerous in command.lower():
                return ActionResult(
                    call_id=call_id,
                    tool_name=self.name,
                    success=False,
                    output="",
                    error=f"Command blocked by safety policy: contains '{dangerous}'",
                    execution_time_ms=(time.time() - t0) * 1000,
                )

        # Sanitize environment variables so child process cannot read agent API keys
        sanitized_env = os.environ.copy()
        for key in SENSITIVE_ENV_VARS:
            sanitized_env.pop(key, None)

        try:
            # On Windows, execute via cmd /c or powershell
            process = await asyncio.create_subprocess_shell(
                command,
                cwd=workspace_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=sanitized_env,
            )

            try:
                stdout_data, stderr_data = await asyncio.wait_for(
                    process.communicate(), timeout=float(timeout)
                )
            except asyncio.TimeoutError:
                try:
                    process.terminate()
                    await asyncio.sleep(0.5)
                    process.kill()
                except Exception:
                    pass
                return ActionResult(
                    call_id=call_id,
                    tool_name=self.name,
                    success=False,
                    output="",
                    error=f"Command timed out after {timeout} seconds.",
                    execution_time_ms=(time.time() - t0) * 1000,
                )

            exit_code = process.returncode
            stdout_str = stdout_data.decode("utf-8", errors="replace")
            stderr_str = stderr_data.decode("utf-8", errors="replace")

            # Bounded output limit: truncate if exceeding 50 KB
            combined_output = []
            if stdout_str:
                combined_output.append(stdout_str)
            if stderr_str:
                combined_output.append(f"\n[STDERR]:\n{stderr_str}")

            full_text = "\n".join(combined_output)
            if len(full_text) > 50_000:
                full_text = full_text[:40_000] + "\n... [OUTPUT TRUNCATED DUE TO SIZE LIMIT] ...\n" + full_text[-10_000:]

            return ActionResult(
                call_id=call_id,
                tool_name=self.name,
                success=(exit_code == 0),
                output=full_text if full_text else "(command produced no output)",
                error=f"Exit code: {exit_code}" if exit_code != 0 else None,
                artifacts={"exit_code": exit_code, "command": command},
                execution_time_ms=(time.time() - t0) * 1000,
            )
        except Exception as e:
            return ActionResult(
                call_id=call_id,
                tool_name=self.name,
                success=False,
                output="",
                error=str(e),
                execution_time_ms=(time.time() - t0) * 1000,
            )

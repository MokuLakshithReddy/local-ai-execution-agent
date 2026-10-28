"""
Terminal and process execution tool with process-tree sandboxing,
streaming buffer memory limits, strict environment variable allowlists, and cancellation.
"""
import asyncio
import os
import sys
import time
from typing import Any, Dict
import psutil
from agent.tools.base import BaseTool
from agent.core.models import PermissionLevel, ActionResult

MAX_OUTPUT_BYTES = 50_000  # 50 KB hard cap on streaming collected output

# Strict Environment Allowlist - only essentials required for compilers, interpreters, and git
SAFE_ENV_ALLOWLIST = {
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "TEMP",
    "TMP",
    "TMPDIR",
    "USERPROFILE",
    "HOME",
    "HOMEDRIVE",
    "HOMEPATH",
    "LANG",
    "LC_ALL",
    "TERM",
    "OS",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
    "VIRTUAL_ENV",
}


def _kill_process_tree(pid: int):
    """Recursively terminates all child processes and process tree to prevent orphaned background tasks."""
    try:
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        for child in children:
            try:
                child.kill()
            except Exception:
                pass
        parent.kill()
    except Exception:
        pass

    # Secondary Windows-native fail-safe
    if sys.platform == "win32":
        try:
            import subprocess
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            pass


async def _read_bounded_stream(stream: asyncio.StreamReader, max_bytes: int) -> tuple[bytes, bool]:
    """Reads stream chunks incrementally, strictly bounding memory consumption."""
    buffer = bytearray()
    truncated = False

    while True:
        chunk = await stream.read(4096)
        if not chunk:
            break
        if len(buffer) + len(chunk) <= max_bytes:
            buffer.extend(chunk)
        else:
            remaining = max_bytes - len(buffer)
            if remaining > 0:
                buffer.extend(chunk[:remaining])
            truncated = True
            # Drain the rest without allocating memory to prevent pipe deadlocks
            while True:
                drain = await stream.read(16384)
                if not drain:
                    break
            break

    return bytes(buffer), truncated


class RunCommandTool(BaseTool):
    name = "run_command"
    description = (
        "Execute a terminal shell command (tests, builds, linter, git) within the workspace directory. "
        "Commands run with process-tree isolation, bounded memory streaming, and timeouts."
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
                    "description": "Maximum seconds to wait before terminating the process tree (default: 60).",
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

        # Enforce canonical workspace path
        real_workspace = os.path.realpath(workspace_path)
        if not os.path.exists(real_workspace):
            return ActionResult(
                call_id=call_id,
                tool_name=self.name,
                success=False,
                output="",
                error=f"Workspace path does not exist: {workspace_path}",
                execution_time_ms=(time.time() - t0) * 1000,
            )

        # Build isolated environment using strict allowlist (scrubs all API keys and host secrets)
        isolated_env = {}
        for key in SAFE_ENV_ALLOWLIST:
            if key in os.environ:
                isolated_env[key] = os.environ[key]

        # Set clean python unbuffered output
        isolated_env["PYTHONUNBUFFERED"] = "1"

        try:
            process = await asyncio.create_subprocess_shell(
                command,
                cwd=real_workspace,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=isolated_env,
            )

            try:
                # Read streams with memory bound
                stdout_coro = _read_bounded_stream(process.stdout, MAX_OUTPUT_BYTES)
                stderr_coro = _read_bounded_stream(process.stderr, MAX_OUTPUT_BYTES // 2)

                (stdout_bytes, stdout_trunc), (stderr_bytes, stderr_trunc) = await asyncio.wait_for(
                    asyncio.gather(stdout_coro, stderr_coro),
                    timeout=float(timeout),
                )
                await process.wait()

            except asyncio.TimeoutError:
                if process.pid:
                    _kill_process_tree(process.pid)
                return ActionResult(
                    call_id=call_id,
                    tool_name=self.name,
                    success=False,
                    output="",
                    error=f"Command timed out after {timeout} seconds and process tree was terminated.",
                    execution_time_ms=(time.time() - t0) * 1000,
                )

            exit_code = process.returncode
            stdout_str = stdout_bytes.decode("utf-8", errors="replace")
            stderr_str = stderr_bytes.decode("utf-8", errors="replace")

            combined_output = []
            if stdout_str:
                combined_output.append(stdout_str)
                if stdout_trunc:
                    combined_output.append("\n[STDOUT TRUNCATED DUE TO BUFFER LIMIT]")
            if stderr_str:
                combined_output.append(f"\n[STDERR]:\n{stderr_str}")
                if stderr_trunc:
                    combined_output.append("\n[STDERR TRUNCATED DUE TO BUFFER LIMIT]")

            full_text = "\n".join(combined_output)
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

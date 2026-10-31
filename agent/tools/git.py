"""
Git inspection and safe checkpoint tools.
Hardened against repository-configured command execution (fsmonitor, textconv, ext-diff).
Uses scrubbed environments, strict timeouts, bounded output buffers, and safe git configuration overrides.
"""
import asyncio
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple
from agent.tools.base import BaseTool
from agent.core.models import PermissionLevel, ActionResult
from agent.tools.terminal import get_isolated_environment, _kill_process_tree

MAX_GIT_OUTPUT_BYTES = 100_000  # 100 KB hard cap on git diff/status output
GIT_SUBPROCESS_TIMEOUT_SECONDS = 15.0  # 15s timeout for git inspection

# Mandatory git configuration overrides to neutralize repository-controlled hooks/helpers
SAFE_GIT_CONFIG_OVERRIDES = [
    "-c", "core.fsmonitor=false",
    "-c", "core.hooksPath=",
    "-c", "diff.autorefreshindex=false",
    "-c", "core.pager=cat",
]


async def _read_bounded_stream(stream: Optional[asyncio.StreamReader], max_bytes: int) -> Tuple[bytes, bool]:
    """Reads a process stream incrementally, collecting up to max_bytes while discarding excess to bound memory."""
    if not stream:
        return b"", False
    chunks = []
    collected = 0
    truncated = False
    while True:
        chunk = await stream.read(4096)
        if not chunk:
            break
        if collected < max_bytes:
            to_take = min(len(chunk), max_bytes - collected)
            chunks.append(chunk[:to_take])
            collected += to_take
        else:
            truncated = True
    return b"".join(chunks), truncated


async def _run_git(
    args: list[str],
    cwd: str,
    timeout: float = GIT_SUBPROCESS_TIMEOUT_SECONDS,
    max_output_bytes: int = MAX_GIT_OUTPUT_BYTES,
) -> tuple[int, str, str]:
    """
    Executes a Git inspection command with strict security guardrails:
    - Neutralizes core.fsmonitor, core.hooksPath, and external diff/textconv helpers.
    - Uses an isolated environment (scrubs all host API keys and tokens).
    - Enforces subprocess timeout with recursive process tree termination.
    - Limits streaming output memory to prevent denial of service.
    """
    try:
        # Build command with safe global config overrides preceding user arguments
        cmd = ["git"] + SAFE_GIT_CONFIG_OVERRIDES + args

        # Scrub environment: only safe allowlisted variables, zero API keys
        env = get_isolated_environment(allow_network=False)
        env["GIT_CONFIG_NOSYSTEM"] = "1"
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GIT_OPTIONAL_LOCKS"] = "0"
        env["GIT_NO_LAZY_FETCH"] = "1"

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )

        try:
            (stdout_data, out_truncated), (stderr_data, err_truncated), _ = await asyncio.wait_for(
                asyncio.gather(
                    _read_bounded_stream(proc.stdout, max_output_bytes),
                    _read_bounded_stream(proc.stderr, max_output_bytes),
                    proc.wait(),
                ),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            if proc.pid:
                _kill_process_tree(proc.pid)
            try:
                proc.kill()
            except Exception:
                pass
            return (-1, "", f"Git execution timed out after {timeout:.1f} seconds.")

        out_str = stdout_data.decode("utf-8", errors="replace")
        err_str = stderr_data.decode("utf-8", errors="replace")

        if out_truncated:
            out_str += f"\n... [GIT OUTPUT TRUNCATED AT {max_output_bytes} BYTES]"
        if err_truncated:
            err_str += f"\n... [GIT STDERR TRUNCATED AT {max_output_bytes} BYTES]"

        return (
            proc.returncode if proc.returncode is not None else 0,
            out_str,
            err_str,
        )
    except FileNotFoundError:
        return (-1, "", "Git binary not found in system PATH.")
    except Exception as e:
        return (-1, "", f"Git execution error: {str(e)}")


class GitStatusTool(BaseTool):
    name = "git_status"
    description = "Inspect repository status, staged files, modified files, and untracked files."
    permission_level = PermissionLevel.READ_ONLY

    def get_parameters_schema(self) -> Dict[str, Any]:
        return {"type": "object", "properties": {}, "additionalProperties": False}

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
            "additionalProperties": False,
        }

    async def execute(self, workspace_path: str, **kwargs) -> ActionResult:
        t0 = time.time()
        call_id = kwargs.get("call_id", "git_diff")
        file_path = kwargs.get("file_path", "")

        # Explicitly disable external diff and textconv helpers to prevent host execution attacks
        base_diff_args = ["diff", "--no-ext-diff", "--no-textconv"]

        args = base_diff_args + ["HEAD"] if not file_path else base_diff_args + ["HEAD", "--", file_path]
        code, out, err = await _run_git(args, workspace_path)

        # Fallback to plain diff if HEAD doesn't exist yet (e.g., brand new repo before initial commit)
        if code != 0:
            fallback_args = base_diff_args if not file_path else base_diff_args + ["--", file_path]
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

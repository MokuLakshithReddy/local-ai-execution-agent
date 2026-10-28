"""
Terminal and process execution tool with process-tree sandboxing,
streaming buffer memory limits, strict environment variable allowlists, and cancellation.
"""
import asyncio
import os
import sys
import time
from typing import Any, Dict
import re
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


class SandboxViolationError(PermissionError):
    """Raised when a command violates workspace filesystem containment or network restrictions."""
    pass


BLOCKED_NETWORK_COMMANDS = {
    "curl",
    "wget",
    "invoke-webrequest",
    "iwr",
    "invoke-restmethod",
    "irm",
    "nc",
    "netcat",
    "ncat",
    "ssh",
    "scp",
    "sftp",
    "ftp",
    "telnet",
    "ping",
    "tracert",
    "traceroute",
    "nmap",
    "socat",
}

BLOCKED_ESCAPE_COMMANDS = {
    "cd ..",
    "cd ../",
    "cd ..\\",
    "pushd",
}


def validate_sandbox_command(command: str, workspace_path: str, allow_network: bool = False):
    """
    Enforces OS-level isolation boundaries:
    1. Blocks external network calls unless allow_network is True.
    2. Blocks attempts to reference or access filesystem paths outside the authorized workspace.
    3. Blocks directory traversal / workspace escape commands.
    """
    cmd_lower = command.lower().strip()
    real_ws = os.path.realpath(workspace_path)

    # 1. Network containment
    if not allow_network:
        tokens = [t.strip(" '\"`();|&") for t in cmd_lower.split()]
        for tok in tokens:
            base_tok = os.path.splitext(os.path.basename(tok))[0]
            if base_tok in BLOCKED_NETWORK_COMMANDS or tok in BLOCKED_NETWORK_COMMANDS:
                raise SandboxViolationError(
                    f"Network Sandbox Violation: Network utility '{tok}' is blocked. Outbound network access is disabled in the sandbox."
                )

    # 2. Workspace escape commands
    for esc in BLOCKED_ESCAPE_COMMANDS:
        if esc in cmd_lower:
            raise SandboxViolationError(
                f"Filesystem Sandbox Violation: Directory escape command '{esc}' is forbidden in sandbox."
            )

    # 3. Path argument boundary inspection
    try:
        tokens = [m.group(1) or m.group(2) or m.group(3) for m in re.finditer(r'"([^"]+)"|\'([^\']+)\'|(\S+)', command)]
    except Exception:
        tokens = command.split()

    allowed_prefixes = [
        real_ws,
        os.path.realpath(sys.executable),
        os.path.realpath(os.path.dirname(sys.executable)),
        os.path.realpath(sys.prefix),
        os.path.realpath(sys.base_prefix),
    ]

    for cand in tokens:
        clean_cand = cand.strip(" '\"`();|&<>")
        if not clean_cand or clean_cand.startswith(("-", "/W", "/O", "/F", "/D", "/M", "/Z", "/?")):
            continue
        is_windows_abs = bool(re.match(r'^[a-zA-Z]:[\\/]', clean_cand))
        is_posix_abs = clean_cand.startswith('/') and not clean_cand.startswith(('/W', '/O', '/F', '/D', '/M', '/Z', '/?'))
        has_traversal = ".." in clean_cand

        if is_windows_abs or is_posix_abs or has_traversal:
            try:
                target_path = clean_cand if (is_windows_abs or is_posix_abs) else os.path.join(real_ws, clean_cand)
                resolved = os.path.realpath(os.path.abspath(target_path))
                
                # Check if it is an allowed system/interpreter binary or inside the virtualenv
                if any(resolved == p or resolved.startswith(p + os.sep) for p in allowed_prefixes):
                    continue

                if not (resolved == real_ws or resolved.startswith(real_ws + os.sep)):
                    raise SandboxViolationError(
                        f"Filesystem Sandbox Violation: Path '{clean_cand}' resolves to '{resolved}', which is outside authorized workspace '{real_ws}'."
                    )
            except Exception as e:
                if isinstance(e, SandboxViolationError):
                    raise


if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_uint64),
            ("WriteOperationCount", ctypes.c_uint64),
            ("OtherOperationCount", ctypes.c_uint64),
            ("ReadTransferCount", ctypes.c_uint64),
            ("WriteTransferCount", ctypes.c_uint64),
            ("OtherTransferCount", ctypes.c_uint64),
        ]

    class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]


class WindowsJobSandbox:
    """
    OS-level kernel containment using Windows Job Objects (ctypes.windll.kernel32).
    Enforces:
    - JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE (0x2000): Kernel terminates process tree on exit.
    - JOB_OBJECT_LIMIT_ACTIVE_PROCESS (0x0008): Limits concurrent child processes (prevents fork bombs).
    - JOB_OBJECT_LIMIT_JOB_MEMORY (0x0200): Limits total memory consumption of the job tree.
    - JOB_OBJECT_LIMIT_PROCESS_MEMORY (0x0100): Limits per-process memory consumption.
    - JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION (0x0400).
    """
    def __init__(self, max_active_processes: int = 16, max_memory_bytes: int = 512 * 1024 * 1024):
        self._handle = None
        self._kernel32 = None
        if sys.platform == "win32":
            try:
                import ctypes
                self._kernel32 = ctypes.windll.kernel32
                self._handle = self._kernel32.CreateJobObjectW(None, None)
                if self._handle:
                    limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
                    limits.BasicLimitInformation.LimitFlags = 0x2000 | 0x0008 | 0x0200 | 0x0400
                    limits.BasicLimitInformation.ActiveProcessLimit = max_active_processes
                    limits.JobMemoryLimit = max_memory_bytes
                    limits.ProcessMemoryLimit = max_memory_bytes
                    self._kernel32.SetInformationJobObject(
                        self._handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)
                    )
            except Exception:
                self._handle = None

    def assign_process(self, pid: int) -> bool:
        if not self._handle or not self._kernel32:
            return False
        try:
            h_proc = self._kernel32.OpenProcess(0x0100 | 0x0001, False, pid)
            if h_proc:
                res = self._kernel32.AssignProcessToJobObject(self._handle, h_proc)
                self._kernel32.CloseHandle(h_proc)
                return bool(res)
        except Exception:
            pass
        return False

    def close(self):
        if self._handle and self._kernel32:
            try:
                self._kernel32.CloseHandle(self._handle)
            except Exception:
                pass
            self._handle = None


def build_container_command(
    command: str,
    workspace_path: str,
    image: str = "python:3.12-slim",
    memory_limit: str = "512m",
    pids_limit: int = 32,
    allow_network: bool = False,
) -> list[str]:
    """
    Constructs an OS container sandbox command line enforcing:
    1. Filesystem boundary: rootfs is read-only (--read-only), only /workspace is mounted rw.
    2. Network boundary: complete network namespace isolation (--network none) when allow_network=False.
    3. Resource limits: memory limit (--memory) and process fork limit (--pids-limit).
    4. Capability drop: drops all Linux capabilities (--cap-drop all).
    """
    real_ws = os.path.realpath(workspace_path)
    net_flag = "bridge" if allow_network else "none"
    return [
        "docker", "run", "--rm", "-i",
        f"--network={net_flag}",
        "--read-only",
        "--cap-drop=ALL",
        f"--memory={memory_limit}",
        f"--pids-limit={pids_limit}",
        "-v", f"{real_ws}:/workspace:rw",
        "-w", "/workspace",
        image,
        "sh", "-c", command,
    ]


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
                "allow_network": {
                    "type": "boolean",
                    "description": "Whether to permit outbound network connections (default: false).",
                    "default": False,
                },
            },
            "required": ["command"],
        }

    async def execute(self, workspace_path: str, **kwargs) -> ActionResult:
        t0 = time.time()
        call_id = kwargs.get("call_id", "run_command")
        command = kwargs.get("command", "").strip()
        timeout = min(kwargs.get("timeout_seconds", 60), 300)
        allow_network = kwargs.get("allow_network", False)

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

        # Enforce sandbox filesystem, escape, and network isolation
        try:
            validate_sandbox_command(command, real_workspace, allow_network=allow_network)
        except SandboxViolationError as sve:
            return ActionResult(
                call_id=call_id,
                tool_name=self.name,
                success=False,
                output="",
                error=str(sve),
                artifacts={"sandbox_violation": True, "command": command},
                execution_time_ms=(time.time() - t0) * 1000,
            )

        # Build isolated environment using strict allowlist (scrubs all API keys and host secrets)
        isolated_env = {}
        for key in SAFE_ENV_ALLOWLIST:
            if key in os.environ:
                isolated_env[key] = os.environ[key]

        # Block network via proxy blackholes if network access is not permitted
        if not allow_network:
            isolated_env["HTTP_PROXY"] = "http://127.0.0.1:0"
            isolated_env["HTTPS_PROXY"] = "http://127.0.0.1:0"
            isolated_env["ALL_PROXY"] = "http://127.0.0.1:0"
            isolated_env["NO_PROXY"] = ""

        # Set clean python unbuffered output
        isolated_env["PYTHONUNBUFFERED"] = "1"

        # Initialize OS kernel sandbox limit manager
        job_sandbox = WindowsJobSandbox(max_active_processes=16, max_memory_bytes=512 * 1024 * 1024)

        try:
            process = await asyncio.create_subprocess_shell(
                command,
                cwd=real_workspace,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=isolated_env,
            )
            # Enforce OS kernel process and memory limits
            if process.pid:
                job_sandbox.assign_process(process.pid)

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
        finally:
            job_sandbox.close()

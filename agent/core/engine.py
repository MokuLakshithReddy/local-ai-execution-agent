"""
Agent Orchestration Engine: Controlled, bounded execution loop.
Coordinates LLM reasoning, Tool Registry, Permission System, and Verification Engine.
"""
import asyncio
import hashlib
import json
import os
import time
import uuid
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple
from agent.core.models import (
    Task,
    TaskStatus,
    TaskType,
    PermissionLevel,
    VerificationCheck,
    ActionResult,
)
from agent.providers.base import LLMMessage, LLMToolCall
from agent.providers.registry import ProviderRegistry
from agent.tools.registry import ToolRegistry
from agent.tools.terminal import terminate_task_processes
from agent.security.permissions import PermissionManager
from agent.security.sanitizer import SecuritySanitizer
from agent.verification.verifier import VerificationEngine, infer_task_type
from agent.persistence.db import Database


SYSTEM_PROMPT = """You are an advanced, local-first AI software engineering execution agent.
You operate directly on the user's local workspace to complete real development tasks.

CORE WORKFLOW:
1. UNDERSTAND & INSPECT: First inspect the codebase structure using `list_dir` or `search_files`. Read relevant files using `read_file`.
2. PLAN: Formulate or update a concise plan of concrete steps.
3. EXECUTE SAFELY: Modify code using `write_file` or `patch_file`. Run necessary commands via `run_command`.
4. VERIFY WITH EVIDENCE: You MUST run automated verification checks via `run_verification` (e.g., tests, linter, builds) to prove that your solution works.
5. REPORT: When finished, summarize your actions, evidence, and any remaining limitations.

CRITICAL RULES:
- Never assume an action succeeded without checking tool outputs.
- Never forge verification results. An exit code of 0 from `run_verification` is required to claim verified completion.
- Keep modifications clean, minimal, and directly addressing the user's goal.
- If you encounter a test failure, analyze the output, adjust your solution, and rerun verification.
- Always operate strictly within the provided workspace.
"""


MAX_SNAPSHOT_FILE_BYTES = 50 * 1024 * 1024  # 50 MB individual file limit
MAX_SNAPSHOT_TOTAL_BYTES = 500 * 1024 * 1024  # 500 MB total workspace snapshot limit
SNAPSHOT_CHUNK_SIZE = 64 * 1024  # 64 KB streaming read buffer


def _snapshot_workspace_hashes(workspace_path: str) -> Tuple[Dict[str, str], bool, Optional[str]]:
    """
    Computes a mapping of relative file paths to SHA-256 hashes across the workspace.
    Reads files incrementally in bounded 64 KB chunks to guarantee constant O(1) memory consumption.
    All files are content-hashed (no metadata-only shortcuts).
    Enforces total workspace size budget (500 MB).
    Returns: (hashes_dict, is_complete_bool, error_message_or_None).
    """
    hashes: Dict[str, str] = {}
    total_bytes_hashed = 0

    try:
        ws_real = os.path.realpath(workspace_path)
        if not os.path.isdir(ws_real):
            return hashes, False, f"Workspace path does not exist or is not a directory: {workspace_path}"

        skip_dirs = {".git", "venv", ".venv", "node_modules", "__pycache__", ".pytest_cache"}
        for root, dirs, files in os.walk(ws_real, topdown=True, followlinks=False):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for f in files:
                full_p = os.path.join(root, f)
                if os.path.islink(full_p) or f.endswith((".db", ".sqlite", ".sqlite3", ".log", ".lock")):
                    continue

                try:
                    file_stat = os.stat(full_p)
                    f_size = file_stat.st_size
                    rel_p = os.path.relpath(full_p, ws_real).replace("\\", "/")

                    if total_bytes_hashed + f_size > MAX_SNAPSHOT_TOTAL_BYTES:
                        return hashes, False, f"Workspace snapshot exceeded total budget limit of {MAX_SNAPSHOT_TOTAL_BYTES // (1024 * 1024)} MB."

                    hasher = hashlib.sha256()
                    with open(full_p, "rb") as fp:
                        while True:
                            chunk = fp.read(SNAPSHOT_CHUNK_SIZE)
                            if not chunk:
                                break
                            hasher.update(chunk)
                            total_bytes_hashed += len(chunk)
                    hashes[rel_p] = hasher.hexdigest()
                except (OSError, IOError) as read_err:
                    return hashes, False, f"Failed to snapshot workspace file '{f}': {read_err}"
    except Exception as scan_err:
        return hashes, False, f"Workspace traversal failed: {scan_err}"

    return hashes, True, None


class ExecutionEngine:
    def __init__(
        self,
        db: Database,
        tool_registry: ToolRegistry = None,
        permission_manager: PermissionManager = None,
        on_event: Optional[Callable[[str, Dict[str, Any]], Coroutine[Any, Any, None]]] = None,
    ):
        self.db = db
        self.tool_registry = tool_registry or ToolRegistry()
        self.permission_manager = permission_manager or PermissionManager()
        self.sanitizer = SecuritySanitizer()
        self.on_event = on_event
        self._active_tasks: Dict[str, bool] = {}  # task_id -> is_running
        self._running_async_tasks: Dict[str, asyncio.Task] = {}

    def _sanitize_dict(self, obj: Any) -> Any:
        if isinstance(obj, str):
            return self.sanitizer.redact_secrets(obj)
        elif isinstance(obj, dict):
            return {k: self._sanitize_dict(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._sanitize_dict(item) for item in obj]
        return obj

    async def emit(self, event_type: str, data: Dict[str, Any]):
        if self.on_event:
            try:
                sanitized_data = self._sanitize_dict(data)
                await self.on_event(event_type, sanitized_data)
            except Exception as e:
                print(f"Error emitting event: {e}")

    def register_running_task(self, task_id: str, async_task: asyncio.Task):
        self._running_async_tasks[task_id] = async_task
        self._active_tasks[task_id] = True

        def _cleanup(_):
            self._active_tasks.pop(task_id, None)
            self._running_async_tasks.pop(task_id, None)

        async_task.add_done_callback(_cleanup)

    def cancel_task(self, task_id: str):
        if task_id in self._active_tasks:
            self._active_tasks[task_id] = False
        terminate_task_processes(task_id)
        self.permission_manager.cancel_task_approvals(task_id)
        async_task = self._running_async_tasks.get(task_id)
        if async_task and not async_task.done():
            async_task.cancel()

    async def run_task(
        self,
        task: Task,
        api_key: str,
        custom_base_url: Optional[str] = None,
    ) -> Task:
        """Runs the bounded execution loop until completion, failure, block, or cancellation."""
        self._active_tasks[task.id] = True
        self.sanitizer.register_secret(api_key)

        task_type = getattr(task, "task_type", None) or infer_task_type(task.goal)
        task.task_type = task_type
        task.max_steps = min(max(1, getattr(task, "max_steps", 30)), 100)
        overall_deadline = float(getattr(task, "timeout_seconds", 600) or 600)
        task_start_time = time.monotonic()

        verifier = VerificationEngine()
        actions_taken: List[str] = []
        modified_files: List[str] = []
        actually_modified_files: List[str] = []
        recent_tool_signatures: List[str] = []
        initial_file_hashes, init_snap_ok, init_snap_err = _snapshot_workspace_hashes(task.workspace_path)
        tampered_immutable_files: set[str] = set()
        immutable_test_specs: List[str] = list(getattr(task, "immutable_test_files", []) or [])
        immutable_baseline_hashes: Dict[str, str] = {}
        ws_real = os.path.realpath(task.workspace_path)
        for itf in immutable_test_specs:
            clean_itf = itf.strip().replace("\\", "/")
            full_itf = os.path.join(ws_real, clean_itf) if not os.path.isabs(clean_itf) else os.path.realpath(clean_itf)
            if not os.path.exists(full_itf) or not os.path.isfile(full_itf) or os.path.islink(full_itf):
                task.status = TaskStatus.FAILED
                task.error = f"Immutable test specification '{itf}' does not exist, is a directory, or is an unauthorized symlink."
                await self.db.save_task(task)
                await self.emit("task_error", {"task_id": task.id, "error": task.error})
                self._active_tasks.pop(task.id, None)
                self._running_async_tasks.pop(task.id, None)
                return task
            try:
                h_base = hashlib.sha256()
                with open(full_itf, "rb") as fp:
                    while True:
                        chunk = fp.read(SNAPSHOT_CHUNK_SIZE)
                        if not chunk:
                            break
                        h_base.update(chunk)
                rel_itf = os.path.relpath(full_itf, ws_real).replace("\\", "/")
                immutable_baseline_hashes[rel_itf] = h_base.hexdigest()
            except Exception as e:
                task.status = TaskStatus.FAILED
                task.error = f"Failed to compute baseline hash for immutable test specification '{itf}': {e}"
                await self.db.save_task(task)
                await self.emit("task_error", {"task_id": task.id, "error": task.error})
                self._active_tasks.pop(task.id, None)
                self._running_async_tasks.pop(task.id, None)
                return task

        # Initialize task in database
        task.status = TaskStatus.PLANNING
        await self.db.save_task(task)
        await self.emit("task_status", {"task_id": task.id, "status": task.status.value})

        # Initialize provider adapter
        try:
            adapter = ProviderRegistry.get_adapter(
                provider=task.model_provider,
                api_key=api_key,
                model_name=task.model_name,
                base_url=custom_base_url,
            )
        except Exception as e:
            task.status = TaskStatus.FAILED
            task.error = f"Failed to initialize model adapter: {str(e)}"
            await self.db.save_task(task)
            await self.emit("task_error", {"task_id": task.id, "error": task.error})
            self._active_tasks.pop(task.id, None)
            self._running_async_tasks.pop(task.id, None)
            return task

        try:

            # Prepare messages
            messages: List[LLMMessage] = [
                LLMMessage(role="system", content=SYSTEM_PROMPT),
                LLMMessage(
                    role="user",
                    content=(
                        f"WORKSPACE DIRECTORY: {os.path.abspath(task.workspace_path)}\n\n"
                        f"USER TASK:\n{task.goal}\n\n"
                        "Begin by inspecting the workspace or relevant files, plan your changes, execute them, and run verification."
                    ),
                ),
            ]

            provider_tool_type = (
                "gemini" if "gemini" in task.model_provider.lower()
                else "anthropic" if "anthropic" in task.model_provider.lower()
                else "openai"
            )
            tool_schemas = self.tool_registry.export_schemas_for_provider(provider_tool_type)

            task.status = TaskStatus.EXECUTING
            await self.db.save_task(task)
            await self.emit("task_status", {"task_id": task.id, "status": task.status.value})

            # Bounded execution loop
            while task.current_step < task.max_steps:
                # Enforce overall task execution deadline
                if (time.monotonic() - task_start_time) > overall_deadline:
                    task.status = TaskStatus.FAILED
                    task.error = f"Task exceeded overall execution deadline of {overall_deadline:.0f} seconds."
                    await self.emit("task_error", {"task_id": task.id, "error": task.error})
                    break

                # Check cancellation token
                if not self._active_tasks.get(task.id, True):
                    task.status = TaskStatus.CANCELLED
                    task.error = "Task was cancelled by user."
                    break

                task.current_step += 1
                step_num = task.current_step

                await self.emit("step_start", {
                    "task_id": task.id,
                    "step": step_num,
                    "max_steps": task.max_steps,
                })

                # Call Model with strict wall-clock timeout
                try:
                    t_rem = max(0.1, overall_deadline - (time.monotonic() - task_start_time))
                    response = await asyncio.wait_for(
                        adapter.chat_completion(
                            messages=messages,
                            tools=tool_schemas,
                            temperature=0.2,
                        ),
                        timeout=t_rem,
                    )
                except Exception as e:
                    task.status = TaskStatus.FAILED
                    task.error = f"Model API invocation error: {str(e)}"
                    await self.emit("task_error", {"task_id": task.id, "error": task.error})
                    break

                thought_text = response.content or ""
                if thought_text.strip():
                    await self.db.log_step(
                        step_id=str(uuid.uuid4()),
                        task_id=task.id,
                        step_num=step_num,
                        step_type="thought",
                        content=thought_text,
                    )
                    await self.emit("agent_thought", {
                        "task_id": task.id,
                        "step": step_num,
                        "thought": thought_text,
                    })

                # Append assistant message to context
                messages.append(
                    LLMMessage(
                        role="assistant",
                        content=response.content,
                        tool_calls=response.tool_calls if response.tool_calls else None,
                    )
                )

                # If no tool calls were requested, the model has finished or is answering
                if not response.tool_calls:
                    actions_taken.append("Model provided final summary without additional tool actions.")
                    break

                # Execute tool calls
                for tool_call in response.tool_calls:
                    # Check cancellation between tool calls
                    if not self._active_tasks.get(task.id, True):
                        task.status = TaskStatus.CANCELLED
                        task.error = "Task cancelled by user."
                        break

                    tool_name = tool_call.name
                    tool_args = tool_call.arguments
                    sig = f"{tool_name}:{json.dumps(tool_args, sort_keys=True)}"

                    # Loop guard: detect repeated identical actions without progress
                    recent_tool_signatures.append(sig)
                    if len(recent_tool_signatures) >= 3 and recent_tool_signatures[-1] == recent_tool_signatures[-2] == recent_tool_signatures[-3]:
                        task.status = TaskStatus.BLOCKED
                        task.error = f"Loop guard detected: Repeated identical action '{tool_name}' 3 times without making progress."
                        await self.emit("task_blocked", {"task_id": task.id, "error": task.error})
                        break

                    # Retrieve tool metadata
                    tool_inst = self.tool_registry.get(tool_name)
                    if not tool_inst:
                        result = ActionResult(
                            call_id=tool_call.id,
                            tool_name=tool_name,
                            success=False,
                            output="",
                            error=f"Tool '{tool_name}' not found.",
                        )
                        messages.append(LLMMessage(role="tool", content=result.error, tool_call_id=tool_call.id, name=tool_name))
                        continue

                    # Proactively strip dangerous container/sandbox control arguments if attempted by model
                    FORBIDDEN_MODEL_ARGS = {
                        "extra_mounts", "allowed_paths", "container_user", "container_image",
                        "image", "memory_limit", "pids_limit", "sandbox_mode", "require_sandbox",
                        "untrusted_workload", "trusted_development_only", "container_memory",
                        "container_pids", "allow_network", "container_name",
                    }
                    for bad_arg in FORBIDDEN_MODEL_ARGS:
                        tool_args.pop(bad_arg, None)

                    permission_level = tool_inst.permission_level

                    # Evaluate permissions
                    is_permitted, perm_reason, approval_req = self.permission_manager.evaluate_action(
                        task_id=task.id,
                        tool_name=tool_name,
                        arguments=tool_args,
                        permission_level=permission_level,
                        workspace_path=task.workspace_path,
                    )

                    if not is_permitted:
                        if approval_req:
                            # Enter pending approval state
                            task.status = TaskStatus.PENDING_APPROVAL
                            await self.db.save_task(task)
                            await self.emit("approval_required", {
                                "task_id": task.id,
                                "approval": approval_req.model_dump(),
                            })

                            # Wait for user approval resolution (poll pending_approvals)
                            approved = False
                            timeout_approval = 300  # 5 min approval timeout
                            t_start = time.time()
                            while time.time() - t_start < timeout_approval:
                                if not self._active_tasks.get(task.id, True):
                                    break
                                if approval_req.approval_id in self.permission_manager.approval_history:
                                    resolved = self.permission_manager.approval_history[approval_req.approval_id]
                                    approved = (resolved.status == "APPROVED")
                                    break
                                await asyncio.sleep(1.0)

                            if not approved:
                                # Expire pending approval in manager and broadcast resolution
                                expired_req = self.permission_manager.expire_approval(approval_req.approval_id)
                                if expired_req:
                                    await self.emit("approval_resolved", {
                                        "approval_id": approval_req.approval_id,
                                        "task_id": task.id,
                                        "status": "EXPIRED",
                                    })

                                # Revert status from PENDING_APPROVAL back to EXECUTING as engine processes rejection
                                task.status = TaskStatus.EXECUTING
                                await self.db.save_task(task)
                                await self.emit("task_status", {"task_id": task.id, "status": task.status.value})

                                result = ActionResult(
                                    call_id=tool_call.id,
                                    tool_name=tool_name,
                                    success=False,
                                    output="",
                                    error=f"Action '{tool_name}' was rejected by user or timed out.",
                                )
                                tool_result_str = self.sanitizer.wrap_untrusted_content(tool_name, result.error)
                                messages.append(
                                    LLMMessage(
                                        role="tool",
                                        content=tool_result_str,
                                        tool_call_id=tool_call.id,
                                        name=tool_name,
                                    )
                                )
                                continue

                            # If approved, resume EXECUTING status
                            task.status = TaskStatus.EXECUTING
                            await self.db.save_task(task)
                            await self.emit("task_status", {"task_id": task.id, "status": task.status.value})
                        else:
                            # Denied by policy directly
                            result = ActionResult(
                                call_id=tool_call.id,
                                tool_name=tool_name,
                                success=False,
                                output="",
                                error=perm_reason,
                            )
                            messages.append(
                                LLMMessage(
                                    role="tool",
                                    content=result.error,
                                    tool_call_id=tool_call.id,
                                    name=tool_name,
                                )
                            )
                            continue

                    # Execute permitted tool
                    # Strict runtime schema validation: reject unknown tool arguments against declared properties
                    schema = tool_inst.get_parameters_schema() if tool_inst else {}
                    properties = schema.get("properties")
                    if isinstance(properties, dict) and properties:
                        allowed_props = set(properties.keys())
                        unknown_args = [k for k in tool_args.keys() if k not in allowed_props]
                        if unknown_args:
                            result = ActionResult(
                                call_id=tool_call.id,
                                tool_name=tool_name,
                                success=False,
                                output="",
                                error=f"Invalid arguments for tool '{tool_name}': unexpected parameters {unknown_args}. Allowed parameters are: {sorted(list(allowed_props))}.",
                            )
                            messages.append(LLMMessage(role="tool", content=result.error, tool_call_id=tool_call.id, name=tool_name))
                            continue

                    await self.emit("tool_executing", {
                        "task_id": task.id,
                        "tool": tool_name,
                        "arguments": tool_args,
                    })

                    # Strictly sanitize model-supplied arguments: strip any unauthorized host/container overrides
                    for bad_arg in (
                        "extra_mounts", "allowed_paths", "container_user", "container_image",
                        "image", "memory_limit", "pids_limit", "sandbox_mode", "require_sandbox",
                        "untrusted_workload", "trusted_development_only", "container_memory",
                        "container_pids", "container_name", "allow_network",
                    ):
                        tool_args.pop(bad_arg, None)

                    # Enforce container sandboxing & network isolation for all automated task executions.
                    # Automated code and model tool calls can NEVER execute on the host or access outbound network.
                    if tool_name in ("run_command", "run_verification"):
                        tool_args["task_id"] = task.id
                        tool_args["sandbox_mode"] = "container"
                        tool_args["require_sandbox"] = True
                        tool_args["untrusted_workload"] = True
                        tool_args["allow_network"] = False
                        tool_args["immutable_test_files"] = immutable_test_specs

                    if tool_name in ("write_file", "patch_file"):
                        tool_args["immutable_test_files"] = immutable_test_specs

                    # Proactively block direct file modification tools from modifying immutable test files
                    if tool_name in ("write_file", "patch_file") and immutable_test_specs:
                        target_arg = tool_args.get("file_path") or tool_args.get("path") or ""
                        if target_arg:
                            ws_real = os.path.realpath(task.workspace_path)
                            target_real = os.path.realpath(os.path.join(ws_real, target_arg))
                            blocked_file = None
                            for itf in immutable_test_specs:
                                itf_clean = itf.strip().replace("\\", "/").lower()
                                itf_real = os.path.realpath(os.path.join(ws_real, itf.strip()))
                                rel_target = os.path.relpath(target_real, ws_real).replace("\\", "/").lower()
                                if target_real == itf_real or rel_target == itf_clean or rel_target.endswith(f"/{itf_clean}"):
                                    blocked_file = itf
                                    break
                            if blocked_file:
                                tampered_immutable_files.add(blocked_file)
                                result = ActionResult(
                                    call_id=tool_call.id,
                                    tool_name=tool_name,
                                    success=False,
                                    output="",
                                    error=f"Permission Denied: File '{target_arg}' is an immutable test specification and cannot be modified or overwritten.",
                                    artifacts={"file_path": target_arg, "tampering_prevented": True},
                                )
                                tool_result_str = self.sanitizer.wrap_untrusted_content(tool_name, result.error)
                                messages.append(
                                    LLMMessage(
                                        role="tool",
                                        content=tool_result_str,
                                        tool_call_id=tool_call.id,
                                        name=tool_name,
                                    )
                                )
                                actions_taken.append(f"Blocked {tool_name} targeting immutable test specification '{target_arg}'.")
                                continue

                    # Inspect command text for attempts to modify or overwrite immutable test files
                    if tool_name in ("run_command", "run_verification") and immutable_test_specs:
                        cmd_str = (tool_args.get("command") or "").lower()
                        for itf in immutable_test_specs:
                            itf_lower = itf.replace("\\", "/").strip().lower()
                            itf_base = os.path.basename(itf_lower)
                            if itf_lower in cmd_str or itf_base in cmd_str:
                                if any(tok in cmd_str for tok in (">", ">>", "rm ", "del ", "erase ", "sed ", "truncate", "git restore", "git checkout", "copy ", "cp ", "mv ", "open(", ".write(", "shutil.", "unlink", "remove(")):
                                    tampered_immutable_files.add(itf)

                    # Strict wall-clock deadline bounding for tool execution
                    t_rem = max(0.1, overall_deadline - (time.monotonic() - task_start_time))
                    try:
                        result = await asyncio.wait_for(
                            self.tool_registry.execute_tool(
                                name=tool_name,
                                workspace_path=task.workspace_path,
                                call_id=tool_call.id,
                                **tool_args,
                            ),
                            timeout=min(t_rem, 300.0),
                        )
                    except asyncio.TimeoutError:
                        from agent.tools.terminal import terminate_task_processes
                        terminate_task_processes(task.id)
                        task.status = TaskStatus.FAILED
                        task.error = f"Task exceeded overall execution deadline of {overall_deadline:.0f} seconds during tool execution."
                        await self.emit("task_error", {"task_id": task.id, "error": task.error})
                        break

                    # Record actions and modified files
                    action_desc = f"Executed {tool_name} with arguments {json.dumps(tool_args)[:120]}"
                    actions_taken.append(action_desc)

                    if tool_name in ("write_file", "patch_file") and result.success:
                        file_p = tool_args.get("file_path")
                        if file_p:
                            is_noop = False
                            if result.artifacts:
                                is_noop = result.artifacts.get("is_noop", False) or not result.artifacts.get("content_changed", True)
                            if not is_noop:
                                actually_modified_files.append(file_p)
                            modified_files.append(file_p)

                    # Continuous immutable test specification tampering detection
                    if immutable_test_specs:
                        ws_real = os.path.realpath(task.workspace_path)
                        for itf in immutable_test_specs:
                            itf_clean = itf.replace("\\", "/").strip().lower()
                            if tool_name in ("write_file", "patch_file"):
                                file_p = (tool_args.get("file_path") or "").replace("\\", "/").strip().lower()
                                if file_p and (itf_clean in file_p or file_p.endswith(itf_clean) or itf_clean.endswith(file_p)):
                                    tampered_immutable_files.add(itf)
                            full_itf = os.path.join(ws_real, itf) if not os.path.isabs(itf) else os.path.realpath(itf)
                            rel_itf = os.path.relpath(full_itf, ws_real).replace("\\", "/")
                            init_h = immutable_baseline_hashes.get(rel_itf) or initial_file_hashes.get(rel_itf)
                            if os.path.exists(full_itf) and not os.path.islink(full_itf):
                                try:
                                    h_cur = hashlib.sha256()
                                    with open(full_itf, "rb") as fp:
                                        while True:
                                            chunk = fp.read(SNAPSHOT_CHUNK_SIZE)
                                            if not chunk:
                                                break
                                            h_cur.update(chunk)
                                    if init_h is not None and h_cur.hexdigest() != init_h:
                                        tampered_immutable_files.add(itf)
                                except Exception:
                                    pass
                            elif init_h is not None:
                                tampered_immutable_files.add(itf)

                    # If verification tool, register in VerificationEngine
                    if tool_name == "run_verification" and result.artifacts:
                        v_check = VerificationCheck(
                            check_name=result.artifacts.get("check_name", "Verification"),
                            check_type=result.artifacts.get("check_type", "test"),
                            command=result.artifacts.get("command"),
                            success=result.artifacts.get("passed", False),
                            exit_code=result.artifacts.get("exit_code"),
                            output=result.output,
                            evidence_summary=result.artifacts.get("evidence_summary", ""),
                            trusted_execution_record=result.artifacts.get("trusted_execution_record"),
                        )
                        verifier.record_check(v_check)

                    await self.db.log_step(
                        step_id=str(uuid.uuid4()),
                        task_id=task.id,
                        step_num=step_num,
                        step_type="tool_result",
                        content=result.output if result.success else (result.error or ""),
                        metadata={"tool": tool_name, "success": result.success, "duration_ms": result.execution_time_ms},
                    )

                    await self.emit("tool_result", {
                        "task_id": task.id,
                        "tool": tool_name,
                        "success": result.success,
                        "output": result.output[:2000],
                        "error": result.error,
                    })

                    # Sanitize and fence tool output
                    raw_feedback = result.output if result.success else f"ERROR: {result.error}"
                    sanitized_feedback = self.sanitizer.wrap_untrusted_content(tool_name, raw_feedback)

                    messages.append(
                        LLMMessage(
                            role="tool",
                            content=sanitized_feedback,
                            tool_call_id=tool_call.id,
                            name=tool_name,
                        )
                    )

                if task.status in (TaskStatus.CANCELLED, TaskStatus.BLOCKED, TaskStatus.FAILED):
                    break

                # Check step budget limit
                if task.current_step >= task.max_steps and task.status == TaskStatus.EXECUTING:
                    task.status = TaskStatus.PARTIALLY_COMPLETED
                    task.error = f"Reached maximum allowed reasoning steps ({task.max_steps})."

        except asyncio.CancelledError:
            task.status = TaskStatus.CANCELLED
            task.error = "Task execution was cancelled."
        except Exception as e:
            task.status = TaskStatus.FAILED
            task.error = f"Unexpected execution error: {str(e)}"
        finally:
            try:
                # Guaranteed Verification & Final Report Generation
                git_diff_result = await self.tool_registry.execute_tool(
                    name="git_diff",
                    workspace_path=task.workspace_path,
                )
                diff_summary = git_diff_result.output if git_diff_result.success else None

                # Compute final workspace state hashes vs initial snapshot to detect changes that were completely reverted
                final_file_hashes, final_snap_ok, final_snap_err = _snapshot_workspace_hashes(task.workspace_path)
                snapshot_failed = (not init_snap_ok) or (not final_snap_ok)
                snapshot_error_msg = init_snap_err or final_snap_err

                net_changed_files = set()
                for rel_p, h in final_file_hashes.items():
                    if initial_file_hashes.get(rel_p) != h:
                        net_changed_files.add(rel_p)
                for rel_p in initial_file_hashes.keys():
                    if rel_p not in final_file_hashes:
                        net_changed_files.add(rel_p)

                verified_modified_files: List[str] = []
                ws_real = os.path.realpath(task.workspace_path)
                for mf in actually_modified_files:
                    try:
                        abs_mf = os.path.join(task.workspace_path, mf) if not os.path.isabs(mf) else os.path.realpath(mf)
                        rel_mf = os.path.relpath(abs_mf, ws_real).replace("\\", "/")
                        if rel_mf in net_changed_files:
                            verified_modified_files.append(mf)
                    except Exception:
                        if mf in net_changed_files:
                            verified_modified_files.append(mf)

                for ncf in net_changed_files:
                    if ncf not in verified_modified_files:
                        verified_modified_files.append(ncf)

                notes = [task.error] if task.error else []
                if snapshot_failed and task.task_type == TaskType.CODE_MODIFICATION:
                    notes.append(f"Workspace Baseline Verification Incomplete: Failed to compute complete workspace snapshot baseline ({snapshot_error_msg}).")

                final_report = verifier.evaluate_completion(
                    task_id=task.id,
                    goal=task.goal,
                    actions_taken=actions_taken,
                    modified_files=verified_modified_files,
                    task_type=task.task_type,
                    task_current_status=task.status,
                    git_diff_summary=diff_summary,
                    unresolved_notes=notes,
                    acceptance_criteria=task.acceptance_criteria,
                    criterion_bindings=task.criterion_bindings,
                    require_structured_evidence=(task.task_type in (TaskType.CODE_MODIFICATION, TaskType.TEST_AND_VERIFY)),
                    immutable_test_files=getattr(task, "immutable_test_files", None),
                    workspace_snapshot_verified=(not snapshot_failed),
                    tampered_immutable_files=list(tampered_immutable_files),
                )

                task.final_report = final_report
                # Never overwrite CANCELLED, BLOCKED, or FAILED into completed
                if task.status not in (TaskStatus.CANCELLED, TaskStatus.BLOCKED, TaskStatus.FAILED):
                    task.status = final_report.status

                await self.db.save_task(task)
                await self.emit("task_completed", {
                    "task_id": task.id,
                    "status": task.status.value,
                    "report": final_report.model_dump(),
                })
            except Exception:
                try:
                    await self.db.save_task(task)
                except Exception:
                    pass
            finally:
                self._active_tasks.pop(task.id, None)
                self._running_async_tasks.pop(task.id, None)

        return task

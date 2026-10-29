"""
Agent Orchestration Engine: Controlled, bounded execution loop.
Coordinates LLM reasoning, Tool Registry, Permission System, and Verification Engine.
"""
import asyncio
import json
import os
import time
import uuid
from typing import Any, Callable, Coroutine, Dict, List, Optional
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
        recent_tool_signatures: List[str] = []

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

                # Call Model
                try:
                    response = await adapter.chat_completion(
                        messages=messages,
                        tools=tool_schemas,
                        temperature=0.2,
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
                    permission_level = tool_inst.permission_level if tool_inst else PermissionLevel.SENSITIVE_OPERATION

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
                    await self.emit("tool_executing", {
                        "task_id": task.id,
                        "tool": tool_name,
                        "arguments": tool_args,
                    })

                    # Enforce container sandboxing for all automated task executions.
                    # Automated code and model tool calls can NEVER execute on the host even if host flags are set.
                    if tool_name in ("run_command", "run_verification"):
                        tool_args["task_id"] = task.id
                        tool_args["sandbox_mode"] = "container"
                        tool_args["require_sandbox"] = True
                        tool_args["untrusted_workload"] = True
                        tool_args.pop("trusted_development_only", None)

                    result = await self.tool_registry.execute_tool(
                        name=tool_name,
                        workspace_path=task.workspace_path,
                        call_id=tool_call.id,
                        **tool_args,
                    )

                    # Record actions and modified files
                    action_desc = f"Executed {tool_name} with arguments {json.dumps(tool_args)[:120]}"
                    actions_taken.append(action_desc)

                    if tool_name in ("write_file", "patch_file") and result.success:
                        file_p = tool_args.get("file_path")
                        if file_p:
                            modified_files.append(file_p)

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

                final_report = verifier.evaluate_completion(
                    task_id=task.id,
                    goal=task.goal,
                    actions_taken=actions_taken,
                    modified_files=modified_files,
                    task_type=task.task_type,
                    task_current_status=task.status,
                    git_diff_summary=diff_summary,
                    unresolved_notes=[task.error] if task.error else [],
                    acceptance_criteria=task.acceptance_criteria,
                    criterion_bindings=task.criterion_bindings,
                    require_structured_evidence=(task.task_type == TaskType.CODE_MODIFICATION),
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

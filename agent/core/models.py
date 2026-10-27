"""
Core domain models for the AI Execution Agent.
"""
from __future__ import annotations
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
import time


class TaskStatus(str, Enum):
    IDLE = "IDLE"
    PLANNING = "PLANNING"
    EXECUTING = "EXECUTING"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    VERIFYING = "VERIFYING"
    COMPLETED = "COMPLETED"
    PARTIALLY_COMPLETED = "PARTIALLY_COMPLETED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class PermissionLevel(str, Enum):
    READ_ONLY = "READ_ONLY"                   # e.g., inspect files, git status
    ROUTINE_MODIFICATION = "ROUTINE_MODIFICATION" # e.g., edit source code, write tests
    SENSITIVE_OPERATION = "SENSITIVE_OPERATION"   # e.g., run unknown script, install packages
    DESTRUCTIVE_OPERATION = "DESTRUCTIVE_OPERATION" # e.g., delete files, git reset
    EXTERNAL_SIDE_EFFECT = "EXTERNAL_SIDE_EFFECT" # e.g., deploy, mutate remote db


class ToolParameter(BaseModel):
    name: str
    type: str
    description: str
    required: bool = True
    default: Optional[Any] = None


class ToolDefinition(BaseModel):
    name: str
    description: str
    parameters: Dict[str, Any]
    permission_level: PermissionLevel
    requires_approval: bool = False


class ActionCall(BaseModel):
    call_id: str
    tool_name: str
    arguments: Dict[str, Any]
    thought: Optional[str] = None


class ActionResult(BaseModel):
    call_id: str
    tool_name: str
    success: bool
    output: str
    error: Optional[str] = None
    execution_time_ms: float = 0.0
    artifacts: Optional[Dict[str, Any]] = None


class ApprovalRequest(BaseModel):
    approval_id: str
    task_id: str
    tool_name: str
    arguments: Dict[str, Any]
    permission_level: PermissionLevel
    reason: str
    status: str = "PENDING"  # PENDING, APPROVED, REJECTED
    requested_at: float = Field(default_factory=time.time)
    resolved_at: Optional[float] = None


class VerificationCheck(BaseModel):
    check_name: str
    check_type: str  # test, build, lint, git_diff, custom
    command: Optional[str] = None
    success: bool
    exit_code: Optional[int] = None
    output: str
    evidence_summary: str


class TaskReport(BaseModel):
    task_id: str
    goal: str
    status: TaskStatus
    summary_of_actions: List[str] = Field(default_factory=list)
    files_created_or_modified: List[str] = Field(default_factory=list)
    diff_summary: Optional[str] = None
    executed_verification_checks: List[VerificationCheck] = Field(default_factory=list)
    skipped_or_failed_checks: List[str] = Field(default_factory=list)
    unresolved_risks_or_limitations: List[str] = Field(default_factory=list)
    created_at: float = Field(default_factory=time.time)
    completed_at: Optional[float] = None


class Task(BaseModel):
    id: str
    goal: str
    workspace_path: str
    model_provider: str
    model_name: str
    status: TaskStatus = TaskStatus.IDLE
    current_step: int = 0
    max_steps: int = 30
    timeout_seconds: int = 600
    plan: List[str] = Field(default_factory=list)
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)
    error: Optional[str] = None
    final_report: Optional[TaskReport] = None

"""
Permission and safety evaluation system.
Independent from LLM; enforces boundaries, workspace restrictions, and approval gates.
"""
from typing import Dict, Any, Tuple
import os
import uuid
from agent.core.models import PermissionLevel, ApprovalRequest


class PermissionPolicy:
    def __init__(
        self,
        auto_approve_routine: bool = True,
        auto_approve_sensitive: bool = False,
        require_approval_destructive: bool = True,
        require_approval_external: bool = True,
    ):
        self.auto_approve_routine = auto_approve_routine
        self.auto_approve_sensitive = auto_approve_sensitive
        self.require_approval_destructive = require_approval_destructive
        self.require_approval_external = require_approval_external


class PermissionManager:
    def __init__(self, policy: PermissionPolicy = None):
        self.policy = policy or PermissionPolicy()
        self.pending_approvals: Dict[str, ApprovalRequest] = {}
        self.approval_history: Dict[str, ApprovalRequest] = {}

    def evaluate_action(
        self,
        task_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
        permission_level: PermissionLevel,
        workspace_path: str,
    ) -> Tuple[bool, str, ApprovalRequest | None]:
        """
        Evaluates whether an action can execute immediately or requires human approval.
        Returns: (is_allowed_immediately, reason, approval_request_if_pending)
        """
        # 1. Path safety check for filesystem-affecting tools
        if "path" in arguments or "target_path" in arguments:
            path_arg = arguments.get("path") or arguments.get("target_path")
            if not self._is_path_within_workspace(str(path_arg), workspace_path):
                return (
                    False,
                    f"Forbidden: Path '{path_arg}' lies outside authorized workspace '{workspace_path}'.",
                    None,
                )

        # 2. Check permission level against policy
        if permission_level == PermissionLevel.READ_ONLY:
            return True, "Permitted: Read-only operation within workspace.", None

        if permission_level == PermissionLevel.ROUTINE_MODIFICATION:
            if self.policy.auto_approve_routine:
                return True, "Permitted: Routine modification within workspace.", None
            else:
                return self._create_approval_request(
                    task_id, tool_name, arguments, permission_level, "Routine modification requires review."
                )

        if permission_level == PermissionLevel.SENSITIVE_OPERATION:
            if self.policy.auto_approve_sensitive:
                return True, "Permitted: Sensitive operation enabled by policy.", None
            else:
                return self._create_approval_request(
                    task_id, tool_name, arguments, permission_level, "Sensitive action requires user authorization."
                )

        if permission_level == PermissionLevel.DESTRUCTIVE_OPERATION:
            if self.policy.require_approval_destructive:
                return self._create_approval_request(
                    task_id, tool_name, arguments, permission_level, "High risk: Destructive action requires explicit approval."
                )
            return True, "Permitted: Destructive action allowed by policy override.", None

        if permission_level == PermissionLevel.EXTERNAL_SIDE_EFFECT:
            if self.policy.require_approval_external:
                return self._create_approval_request(
                    task_id, tool_name, arguments, permission_level, "External side effect requires explicit approval."
                )
            return True, "Permitted: External side effect allowed by policy override.", None

        return False, "Unknown permission level: Denied by default.", None

    def _create_approval_request(
        self,
        task_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
        permission_level: PermissionLevel,
        reason: str,
    ) -> Tuple[bool, str, ApprovalRequest]:
        approval_id = str(uuid.uuid4())
        req = ApprovalRequest(
            approval_id=approval_id,
            task_id=task_id,
            tool_name=tool_name,
            arguments=arguments,
            permission_level=permission_level,
            reason=reason,
            status="PENDING",
        )
        self.pending_approvals[approval_id] = req
        return False, f"Pending User Approval: {reason}", req

    def resolve_approval(self, approval_id: str, approved: bool) -> ApprovalRequest | None:
        if approval_id not in self.pending_approvals:
            return None
        req = self.pending_approvals.pop(approval_id)
        req.status = "APPROVED" if approved else "REJECTED"
        import time
        req.resolved_at = time.time()
        self.approval_history[approval_id] = req
        return req

    @staticmethod
    def _is_path_within_workspace(path: str, workspace_path: str) -> bool:
        if not path or not workspace_path:
            return False
        abs_workspace = os.path.abspath(workspace_path)
        if os.path.isabs(path):
            abs_target = os.path.abspath(path)
        else:
            abs_target = os.path.abspath(os.path.join(abs_workspace, path))
        # Check common path
        try:
            common = os.path.commonpath([abs_target, abs_workspace])
            return os.path.abspath(common) == abs_workspace
        except Exception:
            return False

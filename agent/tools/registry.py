"""
Central Tool Registry.
Registers tools, exports schemas for LLMs, and coordinates execution with permissions.
"""
from typing import Dict, Any, List, Optional, Tuple
from agent.tools.base import BaseTool
from agent.tools.filesystem import ListDirTool, ReadFileTool, WriteFileTool, PatchFileTool, SearchFilesTool
from agent.tools.terminal import RunCommandTool
from agent.tools.git import GitStatusTool, GitDiffTool
from agent.tools.verification import RunVerificationCheckTool
from agent.core.models import ActionResult, ToolDefinition


def validate_tool_call_schema(tool: BaseTool, kwargs: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    Validates runtime tool arguments against the tool's JSON schema:
    - Enforces required parameters.
    - Validates data types (string, boolean, integer, number, array, object).
    - Validates allowed enum values.
    - Rejects undeclared extra parameters.
    """
    schema = tool.get_parameters_schema() or {}
    properties = schema.get("properties", {})
    required = schema.get("required", [])

    framework_args = {
        "call_id", "task_id", "run_id", "timeout_seconds",
        "sandbox_mode", "require_sandbox", "untrusted_workload",
        "allow_network", "extra_mounts", "allowed_paths",
        "target_content", "replacement_content"  # aliases accepted by PatchFileTool
    }

    # 1. Enforce required fields
    for req_field in required:
        # PatchFileTool accepts target_content or target, replacement_content or replacement
        if tool.name == "patch_file":
            if req_field == "target" and ("target" in kwargs or "target_content" in kwargs):
                continue
            if req_field == "replacement" and ("replacement" in kwargs or "replacement_content" in kwargs):
                continue
        if req_field not in kwargs or kwargs[req_field] is None:
            return False, f"Missing required parameter '{req_field}' for tool '{tool.name}'."

    # 2. Check each argument
    if properties:
        for arg_name, arg_val in kwargs.items():
            if arg_name in framework_args:
                continue
            if arg_name not in properties:
                return False, f"Unexpected parameter '{arg_name}' for tool '{tool.name}'."

            prop_spec = properties[arg_name]
            expected_type = prop_spec.get("type")

            if arg_val is not None and expected_type:
                if expected_type == "string":
                    if not isinstance(arg_val, str):
                        return False, f"Parameter '{arg_name}' must be a string, got {type(arg_val).__name__}."
                elif expected_type == "integer":
                    if not isinstance(arg_val, int) or isinstance(arg_val, bool):
                        return False, f"Parameter '{arg_name}' must be an integer, got {type(arg_val).__name__}."
                elif expected_type == "number":
                    if not isinstance(arg_val, (int, float)) or isinstance(arg_val, bool):
                        return False, f"Parameter '{arg_name}' must be a number, got {type(arg_val).__name__}."
                elif expected_type == "boolean":
                    if not isinstance(arg_val, bool):
                        return False, f"Parameter '{arg_name}' must be a boolean, got {type(arg_val).__name__}."
                elif expected_type == "array":
                    if not isinstance(arg_val, list):
                        return False, f"Parameter '{arg_name}' must be an array, got {type(arg_val).__name__}."
                elif expected_type == "object":
                    if not isinstance(arg_val, dict):
                        return False, f"Parameter '{arg_name}' must be an object, got {type(arg_val).__name__}."

            allowed_enums = prop_spec.get("enum")
            if allowed_enums and arg_val is not None:
                if arg_val not in allowed_enums:
                    return False, f"Parameter '{arg_name}' value '{arg_val}' is invalid. Allowed values: {allowed_enums}."

    return True, None


class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, BaseTool] = {}
        self._register_defaults()

    def register(self, tool: BaseTool):
        self._tools[tool.name] = tool

    def get(self, name: str) -> Optional[BaseTool]:
        return self._tools.get(name)

    def list_definitions(self) -> List[ToolDefinition]:
        return [t.to_definition() for t in self._tools.values()]

    def export_schemas_for_provider(self, provider_type: str = "openai") -> List[Dict[str, Any]]:
        """
        Exports tool definitions formatted for provider function calling:
        - openai / ollama: { "type": "function", "function": { "name": ..., "description": ..., "parameters": ... } }
        - anthropic: { "name": ..., "description": ..., "input_schema": ... }
        - gemini: { "function_declarations": [ ... ] }
        """
        schemas = []
        if provider_type in ("openai", "ollama", "compatible"):
            for tool in self._tools.values():
                schemas.append({
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description,
                        "parameters": tool.get_parameters_schema(),
                    },
                })
        elif provider_type == "anthropic":
            for tool in self._tools.values():
                schemas.append({
                    "name": tool.name,
                    "description": tool.description,
                    "input_schema": tool.get_parameters_schema(),
                })
        elif provider_type == "gemini":
            declarations = []
            for tool in self._tools.values():
                declarations.append({
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.get_parameters_schema(),
                })
            schemas = [{"function_declarations": declarations}]
        return schemas

    async def execute_tool(self, name: str, workspace_path: str, **kwargs) -> ActionResult:
        tool = self.get(name)
        if not tool:
            return ActionResult(
                call_id=kwargs.get("call_id", "unknown"),
                tool_name=name,
                success=False,
                output="",
                error=f"Tool '{name}' is not registered in the tool registry.",
            )
        is_valid, validation_err = validate_tool_call_schema(tool, kwargs)
        if not is_valid:
            return ActionResult(
                call_id=kwargs.get("call_id", "unknown"),
                tool_name=name,
                success=False,
                output="",
                error=f"Schema validation error: {validation_err}",
            )
        return await tool.execute(workspace_path=workspace_path, **kwargs)

    def _register_defaults(self):
        self.register(ListDirTool())
        self.register(ReadFileTool())
        self.register(WriteFileTool())
        self.register(PatchFileTool())
        self.register(SearchFilesTool())
        self.register(RunCommandTool())
        self.register(GitStatusTool())
        self.register(GitDiffTool())
        self.register(RunVerificationCheckTool())

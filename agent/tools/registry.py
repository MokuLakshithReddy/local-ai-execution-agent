"""
Central Tool Registry.
Registers tools, exports schemas for LLMs, and coordinates execution with permissions.
"""
from typing import Dict, Any, List, Optional
from agent.tools.base import BaseTool
from agent.tools.filesystem import ListDirTool, ReadFileTool, WriteFileTool, PatchFileTool, SearchFilesTool
from agent.tools.terminal import RunCommandTool
from agent.tools.git import GitStatusTool, GitDiffTool
from agent.tools.verification import RunVerificationCheckTool
from agent.core.models import ActionResult, ToolDefinition


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

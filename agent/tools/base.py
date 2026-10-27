"""
Base classes for tools in the AI Execution Agent.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict
from agent.core.models import PermissionLevel, ActionResult, ToolDefinition


class BaseTool(ABC):
    name: str
    description: str
    permission_level: PermissionLevel
    requires_approval: bool = False

    @abstractmethod
    def get_parameters_schema(self) -> Dict[str, Any]:
        """Returns JSON schema for tool parameters."""
        pass

    @abstractmethod
    async def execute(self, workspace_path: str, **kwargs) -> ActionResult:
        """Executes the tool within the designated workspace."""
        pass

    def to_definition(self) -> ToolDefinition:
        return ToolDefinition(
            name=self.name,
            description=self.description,
            parameters=self.get_parameters_schema(),
            permission_level=self.permission_level,
            requires_approval=self.requires_approval,
        )

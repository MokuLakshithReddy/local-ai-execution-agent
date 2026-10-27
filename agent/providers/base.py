"""
Base interfaces and data structures for model-agnostic provider adapters.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class LLMToolCall(BaseModel):
    id: str
    name: str
    arguments: Dict[str, Any]


class LLMMessage(BaseModel):
    role: str  # 'system', 'user', 'assistant', 'tool'
    content: Optional[str] = ""
    tool_calls: Optional[List[LLMToolCall]] = None
    tool_call_id: Optional[str] = None
    name: Optional[str] = None


class TokenUsage(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class ProviderResponse(BaseModel):
    content: Optional[str] = ""
    tool_calls: List[LLMToolCall] = Field(default_factory=list)
    finish_reason: Optional[str] = None
    usage: TokenUsage = Field(default_factory=TokenUsage)
    raw_response: Optional[Dict[str, Any]] = None


class BaseProviderAdapter(ABC):
    def __init__(self, api_key: str = "", base_url: str = "", model_name: str = ""):
        self.api_key = api_key
        self.base_url = base_url
        self.model_name = model_name

    @abstractmethod
    async def chat_completion(
        self,
        messages: List[LLMMessage],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.2,
    ) -> ProviderResponse:
        """Execute a chat completion request with normalized tool calling."""
        pass

"""
Ollama / Local inference adapter using Ollama's OpenAI-compatible or native chat endpoint.
"""
from typing import Any, Dict, List, Optional
from agent.providers.openai_adapter import OpenAIProviderAdapter
from agent.providers.base import LLMMessage, ProviderResponse


class OllamaProviderAdapter(OpenAIProviderAdapter):
    def __init__(self, base_url: str = "http://localhost:11434/v1", model_name: str = "qwen2.5-coder:latest"):
        super().__init__(
            api_key="ollama",  # Ollama does not require an API key
            base_url=base_url or "http://localhost:11434/v1",
            model_name=model_name or "qwen2.5-coder:latest",
        )

    async def chat_completion(
        self,
        messages: List[LLMMessage],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.2,
    ) -> ProviderResponse:
        try:
            return await super().chat_completion(messages, tools, temperature)
        except Exception as e:
            if "Connection refused" in str(e) or "ConnectError" in str(e):
                raise RuntimeError(
                    f"Could not connect to Ollama at {self.base_url}. Ensure Ollama is running (`ollama serve`)."
                )
            raise e

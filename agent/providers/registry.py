"""
Provider registry: dynamically resolves and instantiates LLM provider adapters.
"""
from typing import Optional
from agent.providers.base import BaseProviderAdapter
from agent.providers.openai_adapter import OpenAIProviderAdapter
from agent.providers.anthropic_adapter import AnthropicProviderAdapter
from agent.providers.gemini_adapter import GeminiProviderAdapter
from agent.providers.ollama_adapter import OllamaProviderAdapter


class ProviderRegistry:
    @staticmethod
    def get_adapter(
        provider: str,
        api_key: str = "",
        model_name: str = "",
        base_url: Optional[str] = None,
    ) -> BaseProviderAdapter:
        p = provider.lower().strip()
        if p == "openai":
            return OpenAIProviderAdapter(api_key=api_key, base_url=base_url or "", model_name=model_name or "gpt-4o")
        elif p == "anthropic":
            return AnthropicProviderAdapter(api_key=api_key, base_url=base_url or "", model_name=model_name or "claude-3-7-sonnet-20250219")
        elif p == "gemini":
            return GeminiProviderAdapter(api_key=api_key, base_url=base_url or "", model_name=model_name or "gemini-2.5-flash")
        elif p in ("ollama", "local"):
            return OllamaProviderAdapter(base_url=base_url or "http://localhost:11434/v1", model_name=model_name or "qwen2.5-coder:latest")
        elif p == "compatible":
            return OpenAIProviderAdapter(api_key=api_key, base_url=base_url or "", model_name=model_name or "custom")
        else:
            raise ValueError(f"Unsupported model provider: '{provider}'. Supported: openai, anthropic, gemini, ollama, compatible")

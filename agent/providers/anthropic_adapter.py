"""
Anthropic Claude provider adapter using httpx.
"""
from typing import Any, Dict, List, Optional
import httpx
from agent.providers.base import BaseProviderAdapter, LLMMessage, ProviderResponse, LLMToolCall, TokenUsage


class AnthropicProviderAdapter(BaseProviderAdapter):
    def __init__(self, api_key: str = "", base_url: str = "", model_name: str = "claude-3-7-sonnet-20250219"):
        super().__init__(
            api_key=api_key,
            base_url=base_url or "https://api.anthropic.com/v1",
            model_name=model_name or "claude-3-7-sonnet-20250219",
        )

    async def chat_completion(
        self,
        messages: List[LLMMessage],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.2,
    ) -> ProviderResponse:
        url = f"{self.base_url.rstrip('/')}/messages"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }

        system_prompt = ""
        anthropic_messages = []

        for m in messages:
            if m.role == "system":
                system_prompt += (m.content or "") + "\n"
            elif m.role == "tool":
                anthropic_messages.append({
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": m.tool_call_id,
                            "content": m.content or "",
                        }
                    ],
                })
            elif m.role == "assistant":
                content_blocks = []
                if m.content:
                    content_blocks.append({"type": "text", "text": m.content})
                if m.tool_calls:
                    for tc in m.tool_calls:
                        content_blocks.append({
                            "type": "tool_use",
                            "id": tc.id,
                            "name": tc.name,
                            "input": tc.arguments,
                        })
                anthropic_messages.append({"role": "assistant", "content": content_blocks or m.content})
            else:
                anthropic_messages.append({"role": "user", "content": m.content or ""})

        payload: Dict[str, Any] = {
            "model": self.model_name,
            "max_tokens": 4096,
            "temperature": temperature,
            "messages": anthropic_messages,
        }

        if system_prompt.strip():
            payload["system"] = system_prompt.strip()

        if tools:
            payload["tools"] = tools

        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(url, headers=headers, json=payload)
            if resp.status_code != 200:
                raise RuntimeError(f"Anthropic API Error ({resp.status_code}): {resp.text}")

            data = resp.json()
            content_text = ""
            tool_calls = []

            for block in data.get("content", []):
                if block.get("type") == "text":
                    content_text += block.get("text", "")
                elif block.get("type") == "tool_use":
                    tool_calls.append(
                        LLMToolCall(
                            id=block.get("id", ""),
                            name=block.get("name", ""),
                            arguments=block.get("input", {}),
                        )
                    )

            usage_obj = data.get("usage", {})
            usage = TokenUsage(
                prompt_tokens=usage_obj.get("input_tokens", 0),
                completion_tokens=usage_obj.get("output_tokens", 0),
                total_tokens=usage_obj.get("input_tokens", 0) + usage_obj.get("output_tokens", 0),
            )

            return ProviderResponse(
                content=content_text,
                tool_calls=tool_calls,
                finish_reason=data.get("stop_reason"),
                usage=usage,
                raw_response=data,
            )

"""
OpenAI & OpenAI-compatible provider adapter using httpx.
"""
import json
from typing import Any, Dict, List, Optional
import httpx
from agent.providers.base import BaseProviderAdapter, LLMMessage, ProviderResponse, LLMToolCall, TokenUsage


class OpenAIProviderAdapter(BaseProviderAdapter):
    def __init__(self, api_key: str = "", base_url: str = "", model_name: str = "gpt-4o"):
        super().__init__(
            api_key=api_key,
            base_url=base_url or "https://api.openai.com/v1",
            model_name=model_name or "gpt-4o",
        )

    async def chat_completion(
        self,
        messages: List[LLMMessage],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.2,
    ) -> ProviderResponse:
        url = f"{self.base_url.rstrip('/')}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        # Convert messages
        formatted_messages = []
        for m in messages:
            msg_dict: Dict[str, Any] = {"role": m.role, "content": m.content or ""}
            if m.tool_calls:
                msg_dict["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.name,
                            "arguments": json.dumps(tc.arguments),
                        },
                    }
                    for tc in m.tool_calls
                ]
            if m.tool_call_id:
                msg_dict["tool_call_id"] = m.tool_call_id
            formatted_messages.append(msg_dict)

        payload: Dict[str, Any] = {
            "model": self.model_name,
            "messages": formatted_messages,
            "temperature": temperature,
        }

        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(url, headers=headers, json=payload)
            if resp.status_code != 200:
                raise RuntimeError(f"OpenAI API Error ({resp.status_code}): {resp.text}")

            data = resp.json()
            choice = data.get("choices", [{}])[0]
            message_obj = choice.get("message", {})
            content = message_obj.get("content", "")

            tool_calls = []
            for tc in message_obj.get("tool_calls", []):
                fn = tc.get("function", {})
                args_raw = fn.get("arguments", "{}")
                try:
                    args = json.loads(args_raw) if isinstance(args_raw, str) else args_raw
                except Exception:
                    args = {}
                tool_calls.append(
                    LLMToolCall(
                        id=tc.get("id", ""),
                        name=fn.get("name", ""),
                        arguments=args,
                    )
                )

            usage_obj = data.get("usage", {})
            usage = TokenUsage(
                prompt_tokens=usage_obj.get("prompt_tokens", 0),
                completion_tokens=usage_obj.get("completion_tokens", 0),
                total_tokens=usage_obj.get("total_tokens", 0),
            )

            return ProviderResponse(
                content=content,
                tool_calls=tool_calls,
                finish_reason=choice.get("finish_reason"),
                usage=usage,
                raw_response=data,
            )

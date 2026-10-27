"""
Google Gemini provider adapter using httpx.
"""
import uuid
from typing import Any, Dict, List, Optional
import httpx
from agent.providers.base import BaseProviderAdapter, LLMMessage, ProviderResponse, LLMToolCall, TokenUsage


class GeminiProviderAdapter(BaseProviderAdapter):
    def __init__(self, api_key: str = "", base_url: str = "", model_name: str = "gemini-2.5-flash"):
        super().__init__(
            api_key=api_key,
            base_url=base_url or "https://generativelanguage.googleapis.com/v1beta",
            model_name=model_name or "gemini-2.5-flash",
        )

    async def chat_completion(
        self,
        messages: List[LLMMessage],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.2,
    ) -> ProviderResponse:
        url = f"{self.base_url.rstrip('/')}/models/{self.model_name}:generateContent?key={self.api_key}"
        headers = {"Content-Type": "application/json"}

        gemini_contents = []
        system_instruction = None

        for m in messages:
            if m.role == "system":
                system_instruction = {"parts": [{"text": m.content or ""}]}
            elif m.role == "tool":
                gemini_contents.append({
                    "role": "function",
                    "parts": [
                        {
                            "functionResponse": {
                                "name": m.name or "tool_result",
                                "response": {"result": m.content or ""},
                            }
                        }
                    ],
                })
            elif m.role == "assistant":
                parts = []
                if m.content:
                    parts.append({"text": m.content})
                if m.tool_calls:
                    for tc in m.tool_calls:
                        parts.append({
                            "functionCall": {
                                "name": tc.name,
                                "args": tc.arguments,
                            }
                        })
                gemini_contents.append({"role": "model", "parts": parts})
            else:
                gemini_contents.append({"role": "user", "parts": [{"text": m.content or ""}]})

        payload: Dict[str, Any] = {
            "contents": gemini_contents,
            "generationConfig": {"temperature": temperature},
        }

        if system_instruction:
            payload["systemInstruction"] = system_instruction

        if tools:
            payload["tools"] = tools

        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(url, headers=headers, json=payload)
            if resp.status_code != 200:
                raise RuntimeError(f"Gemini API Error ({resp.status_code}): {resp.text}")

            data = resp.json()
            candidates = data.get("candidates", [{}])
            candidate = candidates[0] if candidates else {}
            parts = candidate.get("content", {}).get("parts", [])

            content_text = ""
            tool_calls = []

            for part in parts:
                if "text" in part:
                    content_text += part["text"]
                elif "functionCall" in part:
                    fn = part["functionCall"]
                    tool_calls.append(
                        LLMToolCall(
                            id=str(uuid.uuid4())[:8],
                            name=fn.get("name", ""),
                            arguments=fn.get("args", {}),
                        )
                    )

            usage_meta = data.get("usageMetadata", {})
            usage = TokenUsage(
                prompt_tokens=usage_meta.get("promptTokenCount", 0),
                completion_tokens=usage_meta.get("candidatesTokenCount", 0),
                total_tokens=usage_meta.get("totalTokenCount", 0),
            )

            return ProviderResponse(
                content=content_text,
                tool_calls=tool_calls,
                finish_reason=candidate.get("finishReason"),
                usage=usage,
                raw_response=data,
            )

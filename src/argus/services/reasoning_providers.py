"""Reasoning providers + registry.

- OllamaProvider (default): local, private, free. Talks to the Ollama
  HTTP API. No client data leaves the host.
- AnthropicProvider (optional drop-in): used only if an API key is set.
  Absent key => provider simply unavailable; nothing breaks.

Provider chosen per request or by ARGUS_REASONING_PROVIDER default.
"""

import httpx

from argus.core.config import get_settings
from argus.domain.reasoning import ReasoningRequest, ReasoningResponse


class OllamaProvider:
    name = "ollama"

    def __init__(self, base_url: str, model: str):
        self._base_url = base_url.rstrip("/")
        self._model = model

    async def complete(self, req: ReasoningRequest) -> ReasoningResponse:
        payload = {
            "model": self._model,
            "prompt": req.prompt,
            "system": req.system,
            "stream": False,
            "options": {"temperature": req.temperature, "num_predict": req.max_tokens},
        }
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(f"{self._base_url}/api/generate", json=payload)
            resp.raise_for_status()
            data = resp.json()
        return ReasoningResponse(
            text=data.get("response", "").strip(), provider=self.name, model=self._model
        )


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, api_key: str, model: str):
        self._api_key = api_key
        self._model = model

    async def complete(self, req: ReasoningRequest) -> ReasoningResponse:
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self._api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": self._model,
                    "max_tokens": req.max_tokens,
                    "temperature": req.temperature,
                    "system": req.system,
                    "messages": [{"role": "user", "content": req.prompt}],
                },
            )
            resp.raise_for_status()
            data = resp.json()
        text = "".join(b.get("text", "") for b in data.get("content", []))
        return ReasoningResponse(text=text.strip(), provider=self.name, model=self._model)


def get_reasoning_provider(name: str | None = None):
    """Return the requested (or default) provider, or None if unavailable."""
    s = get_settings()
    choice = name or s.reasoning_provider
    if choice == "ollama":
        return OllamaProvider(s.ollama_base_url, s.ollama_model)
    if choice == "anthropic":
        if not s.anthropic_api_key:
            return None  # no key -> unavailable, caller handles gracefully
        return AnthropicProvider(s.anthropic_api_key, s.anthropic_model)
    return None


def available_providers() -> list[str]:
    s = get_settings()
    out = ["ollama"]  # always available (may still fail if Ollama is down)
    if s.anthropic_api_key:
        out.append("anthropic")
    return out

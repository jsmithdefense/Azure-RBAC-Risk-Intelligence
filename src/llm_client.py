"""
Provider-agnostic LLM client.

Speaks the OpenAI-compatible chat completions protocol
(``POST {base_url}/chat/completions``). That is not a decision to use OpenAI --
it is the protocol nearly every hosted provider and every local inference server
already implements, so one client covers all of them:

    OpenRouter      https://openrouter.ai/api/v1
    Ollama          http://localhost:11434/v1
    LM Studio       http://localhost:1234/v1
    llama.cpp       http://localhost:8080/v1
    vLLM            http://localhost:8000/v1
    OpenAI          https://api.openai.com/v1
    Anthropic       https://api.anthropic.com/v1   (compatibility endpoint)

Three settings select the provider and nothing else changes: ``base_url``,
``model``, ``api_key``. A hosted endpoint and a local model take the same code
path -- there is no special case for either.

Implemented on ``urllib`` from the standard library rather than a vendor SDK.
The request is a single JSON POST, the project already uses ``urllib`` for its
Microsoft Graph calls, and this way the dependency list gets shorter instead of
longer -- and no vendor SDK remains to create an accidental path back to one
provider.

Privacy note, stated accurately: this tool must reach ``management.azure.com``
and ``graph.microsoft.com`` to do its job, so it is not a no-network tool. What
this module guarantees is narrower and still worth having -- analysis data goes
only to the endpoint you configure. Point ``base_url`` at a local server and the
RBAC data never leaves your network. ``describe_endpoint()`` exists so the caller
can show the user where data is about to be sent before it is sent.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Optional

# Hosts that never leave the machine or the local network. Used only to label the
# endpoint for the user -- non-local endpoints are fully supported, not blocked.
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal"}


class LLMError(RuntimeError):
    """Raised when the endpoint cannot be reached or returns an unusable reply."""


@dataclass(frozen=True)
class LLMConfig:
    """
    Everything needed to talk to one endpoint.

    api_key is optional because local servers generally do not require one.
    """

    base_url: str
    model: str
    api_key: Optional[str] = None
    max_tokens: int = 4000
    temperature: float = 0.0
    timeout_seconds: int = 300
    # Optional, for cost estimation only. None means "price unknown" -- which is
    # the honest answer for a local model (free) or an unfamiliar endpoint.
    input_per_mtok: Optional[float] = None
    output_per_mtok: Optional[float] = None

    @property
    def host(self) -> str:
        return urllib.parse.urlparse(self.base_url).hostname or ""

    @property
    def is_local(self) -> bool:
        """True when the endpoint is loopback or a private-range address."""
        host = self.host.lower()
        if host in _LOCAL_HOSTS:
            return True
        # Private IPv4 ranges, so a LAN inference box also counts as local.
        return (
            host.startswith("10.")
            or host.startswith("192.168.")
            or any(host.startswith(f"172.{n}.") for n in range(16, 32))
        )

    def describe_endpoint(self) -> str:
        """
        One line naming where data will be sent.

        Callers should print this before the first request. Users deserve to know
        whether their RBAC data is leaving the machine.
        """
        location = "local - data stays on your network" if self.is_local else "remote"
        return f"{self.model} via {self.base_url} ({location})"


def resolve_config(
    file_defaults: dict[str, Any],
    env: dict[str, str],
    model_override: Optional[str] = None,
) -> LLMConfig:
    """
    Build an LLMConfig from file defaults, environment overrides, and an optional
    explicit model choice.

    Precedence, lowest to highest: config file, environment, explicit argument.
    The API key is read *only* from the environment -- never from the config file,
    so a key cannot end up in a tracked file.
    """
    base_url = (env.get("LLM_BASE_URL") or file_defaults.get("base_url") or "").strip()
    model = (model_override or env.get("LLM_MODEL") or file_defaults.get("model") or "").strip()

    if not base_url:
        raise LLMError(
            "No LLM endpoint configured. Set LLM_BASE_URL or add base_url to "
            "config/llm.json. Examples: https://openrouter.ai/api/v1 for "
            "OpenRouter, http://localhost:11434/v1 for Ollama."
        )
    if not model:
        raise LLMError(
            "No model configured. Set LLM_MODEL or add model to config/llm.json."
        )

    pricing = (file_defaults.get("pricing") or {}).get(model, {})

    return LLMConfig(
        base_url=base_url.rstrip("/"),
        model=model,
        api_key=(env.get("LLM_API_KEY") or "").strip() or None,
        max_tokens=int(file_defaults.get("max_tokens", 4000)),
        temperature=float(file_defaults.get("temperature", 0.0)),
        timeout_seconds=int(file_defaults.get("timeout_seconds", 300)),
        input_per_mtok=pricing.get("input_per_mtok"),
        output_per_mtok=pricing.get("output_per_mtok"),
    )


def complete_json(
    cfg: LLMConfig,
    system_prompt: str,
    user_content: str,
) -> dict[str, Any]:
    """
    Ask the model for a JSON object and return it parsed.

    ``response_format`` is sent as a hint. Endpoints that support it (OpenAI,
    OpenRouter on many models, Ollama, vLLM, llama.cpp) constrain the output to
    valid JSON; endpoints that do not simply ignore the field. Either way the
    reply is parsed defensively below, because a model may still wrap JSON in
    prose or a markdown fence.

    Raises LLMError with an actionable message on transport or parse failure.
    """
    body = {
        "model": cfg.model,
        "max_tokens": cfg.max_tokens,
        "temperature": cfg.temperature,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ],
        "response_format": {"type": "json_object"},
    }

    text = _post_chat(cfg, body)
    return _parse_json_reply(text)


def _post_chat(cfg: LLMConfig, body: dict[str, Any]) -> str:
    """POST to /chat/completions and return the assistant message text."""
    url = f"{cfg.base_url}/chat/completions"
    headers = {"Content-Type": "application/json"}
    if cfg.api_key:
        headers["Authorization"] = f"Bearer {cfg.api_key}"

    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers=headers,
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=cfg.timeout_seconds) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = _read_error_body(exc)
        if exc.code in (401, 403):
            raise LLMError(
                f"{cfg.base_url} rejected the credential ({exc.code}). "
                "Check LLM_API_KEY. Local servers usually need no key at all."
                + detail
            ) from exc
        if exc.code == 404:
            raise LLMError(
                f"{url} returned 404. base_url should be the API root including "
                "the version, for example http://localhost:11434/v1 -- not the "
                "bare host and not the full /chat/completions path." + detail
            ) from exc
        raise LLMError(f"{url} returned HTTP {exc.code}.{detail}") from exc
    except urllib.error.URLError as exc:
        raise LLMError(
            f"Could not reach {cfg.base_url} ({exc.reason}). "
            "If this is a local server, confirm it is running and that the port "
            "is correct."
        ) from exc
    except TimeoutError as exc:
        raise LLMError(
            f"{cfg.base_url} did not respond within {cfg.timeout_seconds}s. "
            "Local models on modest hardware can be slow -- raise "
            "timeout_seconds in config/llm.json."
        ) from exc

    return _extract_message_text(payload, cfg)


def _read_error_body(exc: urllib.error.HTTPError) -> str:
    """Include the endpoint's own error text when it provides one."""
    try:
        raw = exc.read().decode("utf-8", errors="replace").strip()
    except Exception:
        return ""
    return f" Endpoint said: {raw[:400]}" if raw else ""


def _extract_message_text(payload: dict[str, Any], cfg: LLMConfig) -> str:
    """
    Pull the assistant text out of an OpenAI-shaped response.

    Some endpoints (reasoning models especially) return an empty ``content`` and
    put the text in ``reasoning``; fall back to that before giving up.
    """
    choices = payload.get("choices") or []
    if not choices:
        error = payload.get("error")
        if error:
            message = error.get("message") if isinstance(error, dict) else str(error)
            raise LLMError(f"{cfg.base_url} returned an error: {message}")
        raise LLMError(
            f"{cfg.base_url} returned no choices. This usually means the model "
            f"name '{cfg.model}' is not available at that endpoint."
        )

    message = choices[0].get("message") or {}
    text = (message.get("content") or "").strip()

    if not text:
        text = (message.get("reasoning") or "").strip()

    if not text:
        finish = choices[0].get("finish_reason")
        raise LLMError(
            f"{cfg.model} returned an empty response (finish_reason={finish!r}). "
            "If finish_reason is 'length', raise max_tokens in config/llm.json."
        )

    return text


def _parse_json_reply(text: str) -> dict[str, Any]:
    """
    Parse a JSON object out of the reply.

    Tries the whole string first, then a ```json fence, then the outermost brace
    pair. Small local models often add a sentence or a fence even when asked not
    to, and that should not fail the run.
    """
    candidates = [text]

    fence_start = text.find("```")
    if fence_start != -1:
        after = text[fence_start + 3 :]
        if after.lower().startswith("json"):
            after = after[4:]
        fence_end = after.find("```")
        if fence_end != -1:
            candidates.append(after[:fence_end])

    first, last = text.find("{"), text.rfind("}")
    if first != -1 and last > first:
        candidates.append(text[first : last + 1])

    for candidate in candidates:
        candidate = candidate.strip()
        if not candidate:
            continue
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed

    raise LLMError(
        "The model did not return valid JSON. First 300 characters of the reply:\n"
        f"{text[:300]}\n"
        "Smaller models sometimes ignore the JSON instruction. Try a larger "
        "model, or one whose endpoint supports constrained JSON output."
    )


def estimate_tokens(text: str) -> int:
    """
    Rough token estimate: about four characters per token.

    Deliberately approximate. It is used to size a request and to give the user a
    sense of scale before sending, not for billing.
    """
    return max(1, len(text) // 4)


def estimate_cost_usd(
    cfg: LLMConfig,
    input_tokens: int,
    output_tokens: int,
) -> Optional[float]:
    """
    Estimated cost, or None when no price is known.

    None is the correct answer for a local model (it is free) and for an endpoint
    whose pricing is not in config. Callers must handle None rather than printing
    a fabricated $0.00.
    """
    if cfg.input_per_mtok is None or cfg.output_per_mtok is None:
        return None
    return (
        input_tokens / 1_000_000 * cfg.input_per_mtok
        + output_tokens / 1_000_000 * cfg.output_per_mtok
    )

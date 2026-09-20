"""
Client for an AI model. The client does not depend on one supplier.

The client speaks the OpenAI-compatible chat completions protocol
(``POST {base_url}/chat/completions``). This is not a decision to use OpenAI.
Almost all suppliers and all local model servers accept this protocol. Thus one
client is sufficient for all of them:

    OpenRouter      https://openrouter.ai/api/v1
    Ollama          http://localhost:11434/v1
    LM Studio       http://localhost:1234/v1
    llama.cpp       http://localhost:8080/v1
    vLLM            http://localhost:8000/v1
    OpenAI          https://api.openai.com/v1
    Anthropic       https://api.anthropic.com/v1   (compatible endpoint)

Three settings select the supplier: ``base_url``, ``model`` and ``api_key``.
Nothing else changes. A remote service and a local model use the same code. There
is no special condition for one or the other.

This module uses ``urllib`` from the standard library. It does not use a supplier
SDK. There are three reasons:
- The request is one JSON POST.
- The project already uses ``urllib`` for the Microsoft Graph requests.
- The list of requirements becomes shorter, not longer.

Be accurate about privacy. This tool must connect to ``management.azure.com`` and
to ``graph.microsoft.com``. That is its function. Thus the tool does use the
network. This module gives a smaller guarantee: analysis data goes only to the
endpoint that you configure. If ``base_url`` points to a local server, the RBAC
data stays in your network. Use ``describe_endpoint()`` to show the user where
the data goes before you send it.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Optional

# These hosts are on your machine or in your network. The tool uses this set only
# to tell the user where the data goes. The tool does not block remote endpoints.
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal"}


class LLMError(RuntimeError):
    """The endpoint did not answer, or its answer is not usable."""


@dataclass(frozen=True)
class LLMConfig:
    """
    All the settings for one endpoint.

    The api_key is optional. Most local servers do not need a key.
    """

    base_url: str
    model: str
    api_key: Optional[str] = None
    max_tokens: int = 4000
    temperature: float = 0.0
    timeout_seconds: int = 300
    # These two prices are optional. The tool uses them only to estimate cost.
    # None means the price is not known. That is correct for a local model,
    # because a local model is free.
    input_per_mtok: Optional[float] = None
    output_per_mtok: Optional[float] = None

    @property
    def host(self) -> str:
        return urllib.parse.urlparse(self.base_url).hostname or ""

    @property
    def is_local(self) -> bool:
        """Return True if the endpoint is on your machine or in your network."""
        host = self.host.lower()
        if host in _LOCAL_HOSTS:
            return True
        # These are the private IPv4 ranges. Thus a model server in your network
        # is also local.
        return (
            host.startswith("10.")
            or host.startswith("192.168.")
            or any(host.startswith(f"172.{n}.") for n in range(16, 32))
        )

    def describe_endpoint(self) -> str:
        """
        Give one line that tells where the data goes.

        Show this line before the first request. The user must know if the RBAC
        data goes out of the machine.
        """
        location = "local - data stays on your network" if self.is_local else "remote"
        return f"{self.model} via {self.base_url} ({location})"


def resolve_config(
    file_defaults: dict[str, Any],
    env: dict[str, str],
    model_override: Optional[str] = None,
) -> LLMConfig:
    """
    Make an LLMConfig from the configuration file, the environment and an
    optional model name.

    The order of precedence is: the file first, then the environment, then the
    model_override argument.

    The tool reads the API key only from the environment. It does not read the
    key from the configuration file. Thus a key cannot go into a file that git
    controls.
    """
    base_url = (env.get("LLM_BASE_URL") or file_defaults.get("base_url") or "").strip()
    model = (model_override or env.get("LLM_MODEL") or file_defaults.get("model") or "").strip()

    if not base_url:
        raise LLMError(
            "No LLM endpoint is configured. Set LLM_BASE_URL, or add base_url to "
            "config/llm.json. For example, use https://openrouter.ai/api/v1 for "
            "OpenRouter, or http://localhost:11434/v1 for Ollama."
        )
    if not model:
        raise LLMError(
            "No model is configured. Set LLM_MODEL, or add model to config/llm.json."
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
    Ask the model for a JSON object. Return the object.

    The request contains ``response_format``. Some endpoints obey this field and
    make only correct JSON. Other endpoints ignore the field. Thus the function
    always examines the answer with care, because a model can put the JSON in
    prose or in a markdown block.

    If the request fails, or if the answer is not JSON, the function raises
    LLMError with a message that tells the user what to do.
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
    """Send the request to /chat/completions. Return the text of the answer."""
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
                f"{cfg.base_url} refused the credential ({exc.code}). "
                "Examine LLM_API_KEY. Most local servers do not need a key."
                + detail
            ) from exc
        if exc.code == 404:
            raise LLMError(
                f"{url} gave the answer 404. The base_url must be the root of the "
                "API and must include the version. For example, use "
                "http://localhost:11434/v1. Do not use only the host name. Do not "
                "include /chat/completions." + detail
            ) from exc
        raise LLMError(f"{url} gave the answer HTTP {exc.code}.{detail}") from exc
    except urllib.error.URLError as exc:
        raise LLMError(
            f"The tool cannot connect to {cfg.base_url} ({exc.reason}). "
            "If this is a local server, make sure that the server operates and "
            "that the port is correct."
        ) from exc
    except TimeoutError as exc:
        raise LLMError(
            f"{cfg.base_url} did not answer in {cfg.timeout_seconds} seconds. "
            "A local model on a small computer can be slow. Increase "
            "timeout_seconds in config/llm.json."
        ) from exc

    return _extract_message_text(payload, cfg)


def _read_error_body(exc: urllib.error.HTTPError) -> str:
    """Get the error text from the endpoint, if the endpoint sends one."""
    try:
        raw = exc.read().decode("utf-8", errors="replace").strip()
    except Exception:
        return ""
    return f" The endpoint says: {raw[:400]}" if raw else ""


def _extract_message_text(payload: dict[str, Any], cfg: LLMConfig) -> str:
    """
    Get the text of the answer from an OpenAI-compatible reply.

    Some models put the text in ``reasoning`` and leave ``content`` empty. Thus
    the function examines ``reasoning`` also, before it raises an error.
    """
    choices = payload.get("choices") or []
    if not choices:
        error = payload.get("error")
        if error:
            message = error.get("message") if isinstance(error, dict) else str(error)
            raise LLMError(f"{cfg.base_url} sent this error: {message}")
        raise LLMError(
            f"{cfg.base_url} sent no choices. Usually this means that the model "
            f"'{cfg.model}' is not available at that endpoint."
        )

    message = choices[0].get("message") or {}
    text = (message.get("content") or "").strip()

    if not text:
        text = (message.get("reasoning") or "").strip()

    if not text:
        finish = choices[0].get("finish_reason")
        raise LLMError(
            f"{cfg.model} sent an empty answer (finish_reason={finish!r}). "
            "If finish_reason is 'length', increase max_tokens in config/llm.json."
        )

    return text


def _parse_json_reply(text: str) -> dict[str, Any]:
    """
    Find a JSON object in the answer and return it.

    The function makes three attempts. First it reads the full text. Then it
    reads the content of a ```json block. Then it reads the text between the
    first brace and the last brace. Small models frequently add a sentence or a
    block, and that must not stop the analysis.
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
        "The model did not send correct JSON. These are the first 300 characters "
        f"of the answer:\n{text[:300]}\n"
        "Small models sometimes do not obey the JSON instruction. Use a larger "
        "model, or use an endpoint that can make only correct JSON."
    )


def estimate_tokens(text: str) -> int:
    """
    Estimate the number of tokens. Use four characters for one token.

    This value is approximate. The tool uses it to show the size of a request to
    the user. Do not use this value to calculate a bill.
    """
    return max(1, len(text) // 4)


def estimate_cost_usd(
    cfg: LLMConfig,
    input_tokens: int,
    output_tokens: int,
) -> Optional[float]:
    """
    Estimate the cost in US dollars. Return None if the price is not known.

    None is the correct result for a local model, because a local model is free.
    None is also correct for an endpoint that has no price in the configuration.
    The caller must accept None. The caller must not show a false cost of $0.00.
    """
    if cfg.input_per_mtok is None or cfg.output_per_mtok is None:
        return None
    return (
        input_tokens / 1_000_000 * cfg.input_per_mtok
        + output_tokens / 1_000_000 * cfg.output_per_mtok
    )

"""LLM-model factory and configuration for LLM_Datalog_QL.

Mirrors `bin_datalog/agent_factory.py` so the two projects share the
same configuration surface. Adapts to two consumers:

  1. ADK agents (Coordinator, ExtractionAgent, AnalysisAgent, …) build
     a `LiteLlm` instance via `create_model()`. ADK's wrapper forwards
     `**kwargs` to `litellm.acompletion()`.
  2. The standalone fact extractor (`llm_extractor.py`) calls
     `litellm.completion()` / `acompletion()` directly. It uses
     `base_completion_kwargs()` to pick up the same provider/api-base/
     extra-body configuration without hard-coding it.

Reads env on every call (no module-level capture) so .env edits between
runs take effect immediately.

Env vars (full set; subset for simple Anthropic / OpenAI setups):

  MODEL_NAME           — provider/model id. Default anthropic/claude-sonnet-4-6.
  LITE_MODEL_NAME      — cheaper model for sub-agents (extraction, CVE
                         lookups). Default = MODEL_NAME.
  MODEL_BASE_URL       — OpenAI-compatible endpoint base URL. Set when
                         routing to DeepSeek, NVIDIA build, vLLM, etc.
                         Forwarded to LiteLLM as `api_base`.
                         Combine with `openai/<id>` model name so LiteLLM
                         uses its OpenAI client.
  MODEL_API_KEY_ENV    — name of an env var holding the API key
                         (e.g. `MODEL_API_KEY_ENV=DEEPSEEK_API_KEY`). See
                         `resolve_api_key`.
  API_KEY              — direct one-shot key override (highest priority).
  MODEL_TIMEOUT        — per-request timeout in seconds (180).
  MODEL_NUM_RETRIES    — automatic retries on 429/etc. (4).
  MODEL_MAX_TOKENS     — output token cap (auto-derived; usually leave unset).
  MODEL_TEMPERATURE    — sampling temperature override (default: model's).
  MODEL_TOP_P          — nucleus cutoff (deepseek-v4-pro wants 0.95).
  MODEL_EXTRA_BODY     — JSON object merged into `extra_body` per call.
  MODEL_CACHE_TTL      — "5m" or "1h" (anthropic/* only; default 1h).
  MODEL_THINKING_BUDGET — extended-thinking budget tokens (10000;
                          set 0 to disable; anthropic/* only).
  MODEL_THINKING       — tri-state cross-provider toggle "on" / "off" /
                         "" (default "" = no-op). When set, synthesizes
                         the right dialect for the active model:
                         - anthropic/*: "off" zeroes the thinking budget.
                         - openai/* (DeepSeek/GLM/Qwen3): merges
                           `chat_template_kwargs.thinking` AND
                           `chat_template_kwargs.enable_thinking` into
                           `extra_body`. Servers that don't recognize
                           the keys ignore them silently. User-supplied
                           `MODEL_EXTRA_BODY` keys take precedence.
"""

from __future__ import annotations

import json
import os
from typing import Optional


def resolve_api_key(model_name: Optional[str] = None) -> Optional[str]:
    """Pick the right API key for the active model.

    Resolution order:
      1. `API_KEY` — direct one-shot override (highest priority)
      2. `MODEL_API_KEY_ENV` — name of an env var holding the key
         (e.g. `MODEL_API_KEY_ENV=DEEPSEEK_API_KEY`).
      3. Provider prefix on `MODEL_NAME`:
         - `anthropic/*` → `ANTHROPIC_API_KEY`
         - `openai/*`    → `OPENAI_API_KEY`
         - `deepseek/*`  → `DEEPSEEK_API_KEY`
         - `gemini/*` / `google/*` → `GOOGLE_API_KEY` or `GEMINI_API_KEY`
      4. Fallback to whichever provider key is set.
    """
    explicit = os.getenv("API_KEY")
    if explicit:
        return explicit
    indirect = os.getenv("MODEL_API_KEY_ENV")
    if indirect:
        val = os.getenv(indirect)
        if val:
            return val
    name = model_name if model_name is not None else os.getenv("MODEL_NAME", "")
    if name.startswith("anthropic/"):
        return os.getenv("ANTHROPIC_API_KEY")
    if name.startswith("openai/"):
        return os.getenv("OPENAI_API_KEY")
    if name.startswith("deepseek/"):
        return os.getenv("DEEPSEEK_API_KEY")
    if name.startswith("gemini/") or name.startswith("google/"):
        return os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
    return (os.getenv("OPENAI_API_KEY")
            or os.getenv("ANTHROPIC_API_KEY")
            or os.getenv("DEEPSEEK_API_KEY"))


def _resolve_model_name(lite: bool) -> str:
    """Pick MODEL_NAME or LITE_MODEL_NAME based on `lite`. LITE falls
    back to MODEL_NAME when unset."""
    primary = os.getenv("MODEL_NAME", "anthropic/claude-sonnet-4-6")
    if not lite:
        return primary
    return os.getenv("LITE_MODEL_NAME") or primary


def base_completion_kwargs(
    model_name: Optional[str] = None,
    lite: bool = False,
    thinking: Optional[str] = None,
) -> dict:
    """Return the LiteLLM kwargs (model, api_key, api_base, extra_body,
    top_p, etc.) common to both the ADK LiteLlm wrapper and direct
    `litellm.completion()` calls.

    Caller is expected to add `messages`, `max_tokens`, `temperature`,
    and any task-specific knobs (e.g. `response_format`). Any key the
    caller sets explicitly should be popped from the returned dict
    before merging to avoid duplicate-keyword errors.

    Args:
        model_name: Override the resolved model name. When None, picks
                    LITE_MODEL_NAME (if `lite`) or MODEL_NAME from env.
        lite:       If True and model_name is None, prefer LITE_MODEL_NAME.
        thinking:   Per-call thinking-mode override ("on" / "off" / None).
                    Takes precedence over the MODEL_THINKING env var.
                    None (default) means "fall back to env". This is the
                    knob the agent layer uses to enable thinking for the
                    low-volume reasoning agents (Analysis, Interpreter,
                    Phase C synth) without globally enabling it for the
                    high-volume smell-pass call sites.
    """
    if model_name is None:
        model_name = _resolve_model_name(lite)

    timeout = int(os.getenv("MODEL_TIMEOUT", "180"))
    num_retries = int(os.getenv("MODEL_NUM_RETRIES", "4"))
    cache_ttl = os.getenv("MODEL_CACHE_TTL", "1h").lower()
    thinking_budget = int(os.getenv("MODEL_THINKING_BUDGET", "10000"))
    if thinking is not None:
        thinking_mode = str(thinking).strip().lower()
    else:
        thinking_mode = os.getenv("MODEL_THINKING", "").strip().lower()
    if thinking_mode == "off":
        thinking_budget = 0

    max_tokens_default = max(4096, thinking_budget + 4096)
    max_tokens_str = os.getenv("MODEL_MAX_TOKENS", "").strip()
    max_tokens = int(max_tokens_str) if max_tokens_str else max_tokens_default

    kwargs: dict = {
        "model": model_name,
        "api_key": resolve_api_key(model_name),
        "timeout": timeout,
        "num_retries": num_retries,
        "max_tokens": max_tokens,
    }

    base_url = os.getenv("MODEL_BASE_URL", "").strip()
    if base_url:
        kwargs["api_base"] = base_url

    top_p_str = os.getenv("MODEL_TOP_P", "").strip()
    if top_p_str:
        kwargs["top_p"] = float(top_p_str)

    temperature_str = os.getenv("MODEL_TEMPERATURE", "").strip()
    if temperature_str:
        kwargs["temperature"] = float(temperature_str)

    extra_body_str = os.getenv("MODEL_EXTRA_BODY", "").strip()
    if extra_body_str:
        kwargs["extra_body"] = json.loads(extra_body_str)

    # Cross-provider thinking toggle. Only fills MISSING extra_body keys;
    # user-supplied MODEL_EXTRA_BODY wins on conflict. Skips anthropic/*
    # which has its own native `thinking` parameter handled below.
    if thinking_mode in ("on", "off") and not model_name.startswith("anthropic/"):
        flag = (thinking_mode == "on")
        eb = kwargs.setdefault("extra_body", {})
        ctk = eb.setdefault("chat_template_kwargs", {})
        ctk.setdefault("thinking", flag)         # DeepSeek / GLM family
        ctk.setdefault("enable_thinking", flag)  # Qwen3 family

    if model_name.startswith("anthropic/"):
        # Prompt-cache the system prompt (one breakpoint, cache-all-up-to).
        control: dict = {"type": "ephemeral"}
        if cache_ttl == "1h":
            control["ttl"] = "1h"
            kwargs["extra_headers"] = {
                "anthropic-beta":
                    "prompt-caching-2024-07-31,extended-cache-ttl-2025-04-11",
            }
        kwargs["cache_control_injection_points"] = [
            {
                "location": "message",
                "role": "system",
                "index": 0,
                "control": control,
            },
        ]
        if thinking_budget > 0:
            kwargs["thinking"] = {
                "type": "enabled",
                "budget_tokens": thinking_budget,
            }
            # Anthropic forces temperature=1 when thinking is active.
            kwargs["temperature"] = 1.0

    return kwargs


def create_model(lite: bool = False, thinking: Optional[str] = None):
    """Build an ADK LiteLlm wrapper from env.

    Args:
        lite:     If True, picks LITE_MODEL_NAME (cheaper sub-agent
                  model). The two-tier split is documented at the
                  agent definitions in agent.py.
        thinking: Per-agent thinking-mode override ("on" / "off" / None).
                  Forwarded to base_completion_kwargs. Use "on" for
                  low-volume reasoning agents (AnalysisAgent,
                  InterpreterAgent, Phase C synth); leave None for
                  high-volume / orchestration agents so they inherit
                  the global MODEL_THINKING env (typically "off" in
                  production runners).
    """
    # Imported lazily so non-ADK callers (e.g. llm_extractor) don't
    # depend on google.adk being installed.
    from google.adk.models.lite_llm import LiteLlm
    kwargs = base_completion_kwargs(lite=lite, thinking=thinking)
    return LiteLlm(**kwargs)


# ── Smell-pass and tier-collision helpers ──────────────────────────

def apply_smell_pass_env(default_lite: str = "openai/deepseek-v4-flash") -> None:
    """Force the smell-pass tier env vars after `.env` load.

    Several runners (`run_ffmpeg_target.py`, `run_libxml2_target.py`,
    …) need to make sure the high-volume smell pass uses a Lite model
    even if the project's `.env` defaults LITE_MODEL_NAME to a heavy
    one. Centralising the override here means that policy lives in one
    place; runners only call `apply_smell_pass_env()` after
    `load_dotenv()`.

    Behaviour:
      - LITE_MODEL_NAME ← LITE_MODEL_NAME_OVERRIDE if set, else
        `default_lite` (DeepSeek V4-Flash on the OpenAI-compatible
        endpoint). Always overwritten — `.env`'s LITE_MODEL_NAME is
        ignored for runners that opt in.
      - MODEL_THINKING ← "off" globally, so the smell-pass calls do
        not pay thinking-mode latency. The Heavy reasoning agents that
        want thinking-mode ON pass `thinking="on"` to `create_model()`
        (per-call override; precedence over the env).
    """
    os.environ["LITE_MODEL_NAME"] = os.environ.get(
        "LITE_MODEL_NAME_OVERRIDE", default_lite)
    os.environ["MODEL_THINKING"] = "off"


def warn_if_tiers_collide() -> Optional[str]:
    """Emit a one-line warning if MODEL_NAME and LITE_MODEL_NAME
    resolve to the same model.

    The collision is silent in normal operation: both
    `create_model(lite=False)` and `create_model(lite=True)` succeed
    and the caller pays the heavy-tier bill on every smell-pass
    call. Returns the warning message (also prints to stderr) so a
    test harness can assert against it.
    """
    heavy = _resolve_model_name(lite=False)
    lite_  = _resolve_model_name(lite=True)
    if heavy == lite_:
        msg = (f"[agent_factory] WARNING: MODEL_NAME and LITE_MODEL_NAME "
               f"both resolve to {heavy!r}. The smell pass will pay the "
               f"heavy-tier bill on every call. Set LITE_MODEL_NAME (or "
               f"LITE_MODEL_NAME_OVERRIDE for the runners that call "
               f"apply_smell_pass_env()).")
        import sys
        print(msg, file=sys.stderr)
        return msg
    return None

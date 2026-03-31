"""
LLM Fact Extractor — Uses an LLM to extract Datalog facts from C/C++ source code.

Sends function source with line numbers to the LLM API (via LiteLLM),
parses the JSON response into Fact objects compatible with Souffle.
"""

import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import litellm

from fact_schema import Fact, FactKind, write_facts

# Load the fact extraction prompt
_PROMPT_PATH = Path(__file__).parent / "prompts" / "fact_extraction.md"
_SYSTEM_PROMPT = _PROMPT_PATH.read_text() if _PROMPT_PATH.exists() else ""

# Map kind strings to FactKind enum
_KIND_MAP = {k.value: k for k in FactKind}


@dataclass
class ExtractionMetrics:
    """Metrics from a single LLM extraction call."""
    func_name: str = ""
    source_lines: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    wall_time_s: float = 0.0
    facts_extracted: int = 0
    model: str = ""
    retried: bool = False
    # Estimated cost (USD) — populated if litellm.completion_cost works
    estimated_cost_usd: float = 0.0

    def summary(self) -> str:
        cost_str = f"${self.estimated_cost_usd:.4f}" if self.estimated_cost_usd else "n/a"
        return (
            f"{self.func_name}: {self.source_lines} lines → {self.facts_extracted} facts | "
            f"{self.prompt_tokens}+{self.completion_tokens}={self.total_tokens} tokens | "
            f"{self.wall_time_s:.1f}s | cost={cost_str}"
        )


# Accumulator for per-session metrics
_session_metrics: list[ExtractionMetrics] = []


def get_session_metrics() -> list[ExtractionMetrics]:
    """Return all extraction metrics from this session."""
    return list(_session_metrics)


def reset_session_metrics():
    """Clear accumulated metrics."""
    _session_metrics.clear()


def session_summary() -> dict:
    """Return aggregate session metrics."""
    if not _session_metrics:
        return {"extractions": 0}
    total_prompt = sum(m.prompt_tokens for m in _session_metrics)
    total_completion = sum(m.completion_tokens for m in _session_metrics)
    total_tokens = sum(m.total_tokens for m in _session_metrics)
    total_time = sum(m.wall_time_s for m in _session_metrics)
    total_cost = sum(m.estimated_cost_usd for m in _session_metrics)
    total_facts = sum(m.facts_extracted for m in _session_metrics)
    total_lines = sum(m.source_lines for m in _session_metrics)
    return {
        "extractions": len(_session_metrics),
        "total_source_lines": total_lines,
        "total_facts": total_facts,
        "total_prompt_tokens": total_prompt,
        "total_completion_tokens": total_completion,
        "total_tokens": total_tokens,
        "total_wall_time_s": round(total_time, 1),
        "total_estimated_cost_usd": round(total_cost, 6),
        "avg_tokens_per_line": round(total_tokens / total_lines, 1) if total_lines else 0,
        "avg_facts_per_line": round(total_facts / total_lines, 2) if total_lines else 0,
        "model": _session_metrics[0].model if _session_metrics else "",
        "per_function": [m.summary() for m in _session_metrics],
    }


def _estimate_max_tokens(source: str) -> int:
    """Estimate max_tokens needed based on function size.

    Heuristic: each line of C produces ~8-12 facts, each fact ~80 tokens in JSON.
    Small functions (<50 lines) need ~8K, medium (<150) ~16K, large (150+) ~32K.
    """
    line_count = source.count('\n') + 1
    if line_count > 150:
        return 32000
    if line_count > 50:
        return 16384
    return 8192


def extract_facts_llm(
    function_source: str,
    func_name: str,
    file_path: str = "<unknown>",
    model: str | None = None,
    api_key: str | None = None,
) -> list[Fact]:
    """Extract Datalog facts from a C/C++ function using an LLM.

    Args:
        function_source: The function source code (with or without line numbers).
        func_name: Name of the function.
        file_path: Source file path (for context).
        model: LiteLLM model identifier. Defaults to MODEL_NAME env var.
        api_key: API key. Defaults to env vars.

    Returns:
        List of Fact objects.
    """
    if model is None:
        model = os.environ.get("MODEL_NAME", "anthropic/claude-sonnet-4-6")
    if api_key is None:
        api_key = _resolve_api_key(model)

    # Ensure function source has line numbers
    if not _has_line_numbers(function_source):
        function_source = _add_line_numbers(function_source)

    # Adaptive max_tokens based on function size
    max_tokens = _estimate_max_tokens(function_source)
    line_count = function_source.count('\n') + 1

    # For large functions, add an explicit thoroughness instruction
    size_hint = ""
    if line_count > 100:
        size_hint = (
            f" The function is {line_count} lines long. "
            "Extract ALL facts thoroughly — do not skip any section."
        )

    user_msg = (
        f"Extract Datalog facts from this C function `{func_name}` "
        f"in file `{file_path}`.{size_hint}"
        f"\n\n```c\n{function_source}\n```"
    )

    metrics = ExtractionMetrics(
        func_name=func_name,
        source_lines=line_count,
        model=model,
    )

    t0 = time.monotonic()
    response = litellm.completion(
        model=model,
        api_key=api_key,
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ],
        temperature=0.0,
        max_tokens=max_tokens,
        response_format={"type": "json_object"},
    )
    metrics.wall_time_s = time.monotonic() - t0

    # Capture token usage
    _update_metrics(metrics, response)

    raw = response.choices[0].message.content
    facts = _parse_response(raw, func_name)

    # If we got 0 facts from a non-trivial function, retry with higher token limit
    if not facts and line_count > 20:
        print(f"  [WARN] 0 facts from {line_count}-line function, retrying with max_tokens={max_tokens * 2}")
        metrics.retried = True
        t0 = time.monotonic()
        response = litellm.completion(
            model=model,
            api_key=api_key,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
            ],
            temperature=0.0,
            max_tokens=min(max_tokens * 2, 64000),
            response_format={"type": "json_object"},
        )
        metrics.wall_time_s += time.monotonic() - t0
        _update_metrics(metrics, response, accumulate=True)
        raw = response.choices[0].message.content
        facts = _parse_response(raw, func_name)

    metrics.facts_extracted = len(facts)
    _session_metrics.append(metrics)
    print(f"    [{metrics.summary()}]")

    return facts


def _update_metrics(metrics: ExtractionMetrics, response, accumulate: bool = False):
    """Extract token usage and cost from LiteLLM response."""
    usage = getattr(response, "usage", None)
    if usage:
        if accumulate:
            metrics.prompt_tokens += getattr(usage, "prompt_tokens", 0) or 0
            metrics.completion_tokens += getattr(usage, "completion_tokens", 0) or 0
            metrics.total_tokens += getattr(usage, "total_tokens", 0) or 0
        else:
            metrics.prompt_tokens = getattr(usage, "prompt_tokens", 0) or 0
            metrics.completion_tokens = getattr(usage, "completion_tokens", 0) or 0
            metrics.total_tokens = getattr(usage, "total_tokens", 0) or 0

    # Try to estimate cost via litellm
    try:
        cost = litellm.completion_cost(completion_response=response)
        if accumulate:
            metrics.estimated_cost_usd += cost
        else:
            metrics.estimated_cost_usd = cost
    except Exception:
        pass


def _resolve_api_key(model: str) -> str | None:
    """Resolve API key from env vars based on model prefix."""
    key = os.environ.get("API_KEY")
    if key:
        return key
    if model.startswith("anthropic/"):
        return os.environ.get("ANTHROPIC_API_KEY")
    if model.startswith("openai/"):
        return os.environ.get("OPENAI_API_KEY")
    if model.startswith("gemini/") or model.startswith("google/"):
        return os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")
    return None


def _has_line_numbers(source: str) -> bool:
    """Check if source already has line number prefixes."""
    lines = source.strip().split('\n')
    if not lines:
        return False
    # Check first non-empty line for pattern like "  10| "
    for line in lines:
        stripped = line.lstrip()
        if stripped:
            return bool(stripped[0].isdigit() and '|' in line.split('|')[0])
    return False


def _add_line_numbers(source: str, start_line: int = 1) -> str:
    """Add line numbers to source code."""
    lines = source.split('\n')
    numbered = []
    for i, line in enumerate(lines):
        numbered.append(f"{start_line + i:4d}| {line}")
    return '\n'.join(numbered)


def _parse_response(raw_json: str, func_name: str) -> list[Fact]:
    """Parse LLM JSON response into Fact objects."""
    # Strip markdown code fences if present
    text = raw_json.strip()
    if text.startswith("```"):
        lines = text.split('\n')
        # Remove first and last lines (fences)
        lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = '\n'.join(lines)

    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        print(f"  [ERROR] Failed to parse LLM response as JSON: {e}")
        print(f"  Response preview: {text[:200]}")
        return []

    facts_list = data.get("facts", [])
    if not isinstance(facts_list, list):
        print(f"  [ERROR] Expected 'facts' array, got {type(facts_list)}")
        return []

    # Top-level keys that are NOT field values
    _META_KEYS = {"kind", "func", "addr", "fields"}

    facts = []
    for item in facts_list:
        kind_str = item.get("kind", "")
        kind = _KIND_MAP.get(kind_str)
        if not kind:
            print(f"  [WARN] Unknown fact kind: {kind_str}")
            continue

        func = item.get("func", func_name)
        addr = item.get("addr", 0)
        fields = item.get("fields", {})

        # Handle LLMs that flatten fields to the top level instead of
        # nesting under "fields": {}.  Merge any non-meta top-level keys
        # into fields (fields dict takes precedence if both exist).
        extra = {k: v for k, v in item.items() if k not in _META_KEYS}
        if extra and not fields:
            fields = extra
        elif extra:
            merged = dict(extra)
            merged.update(fields)
            fields = merged

        # Ensure addr is an integer
        if isinstance(addr, str):
            try:
                addr = int(addr)
            except ValueError:
                addr = 0

        facts.append(Fact(kind=kind, func=func, addr=addr, fields=fields))

    return facts


async def extract_facts_llm_async(
    function_source: str,
    func_name: str,
    file_path: str = "<unknown>",
    model: str | None = None,
    api_key: str | None = None,
    semaphore: "asyncio.Semaphore | None" = None,
) -> list[Fact]:
    """Async version of extract_facts_llm for parallel extraction."""
    import asyncio

    if model is None:
        model = os.environ.get("MODEL_NAME", "anthropic/claude-sonnet-4-6")
    if api_key is None:
        api_key = _resolve_api_key(model)

    if not _has_line_numbers(function_source):
        function_source = _add_line_numbers(function_source)

    max_tokens = _estimate_max_tokens(function_source)
    line_count = function_source.count('\n') + 1

    size_hint = ""
    if line_count > 100:
        size_hint = (
            f" The function is {line_count} lines long. "
            "Extract ALL facts thoroughly — do not skip any section."
        )

    user_msg = (
        f"Extract Datalog facts from this C function `{func_name}` "
        f"in file `{file_path}`.{size_hint}"
        f"\n\n```c\n{function_source}\n```"
    )

    metrics = ExtractionMetrics(
        func_name=func_name,
        source_lines=line_count,
        model=model,
    )

    async def _call_with_retry(max_retries=5):
        import asyncio as _aio
        for attempt in range(max_retries):
            try:
                t0 = time.monotonic()
                response = await litellm.acompletion(
                    model=model,
                    api_key=api_key,
                    messages=[
                        {"role": "system", "content": _SYSTEM_PROMPT},
                        {"role": "user", "content": user_msg},
                    ],
                    temperature=0.0,
                    max_tokens=max_tokens,
                    response_format={"type": "json_object"},
                )
                metrics.wall_time_s += time.monotonic() - t0
                return response
            except Exception as e:
                if "rate_limit" in str(e).lower() and attempt < max_retries - 1:
                    wait = 15 * (attempt + 1)
                    print(f"    [rate limit] {func_name}: waiting {wait}s (attempt {attempt+1})")
                    await _aio.sleep(wait)
                else:
                    raise

    if semaphore:
        async with semaphore:
            response = await _call_with_retry()
    else:
        response = await _call_with_retry()

    _update_metrics(metrics, response)
    raw = response.choices[0].message.content
    facts = _parse_response(raw, func_name)

    # Retry on empty result for non-trivial functions
    if not facts and line_count > 20:
        print(f"  [WARN] 0 facts from {line_count}-line {func_name}, retrying...")
        metrics.retried = True
        max_tokens = min(max_tokens * 2, 64000)
        if semaphore:
            async with semaphore:
                response = await _call_with_retry()
        else:
            response = await _call_with_retry()
        _update_metrics(metrics, response, accumulate=True)
        raw = response.choices[0].message.content
        facts = _parse_response(raw, func_name)

    metrics.facts_extracted = len(facts)
    _session_metrics.append(metrics)
    print(f"    [{metrics.summary()}]")
    return facts


def extract_facts_for_functions(
    func_sources: list[dict],
    model: str | None = None,
    api_key: str | None = None,
) -> list[Fact]:
    """Extract facts for multiple functions.

    Args:
        func_sources: List of dicts with keys: name, source, file_path, start_line
        model: LiteLLM model identifier.
        api_key: API key.

    Returns:
        Combined list of Fact objects for all functions.
    """
    all_facts = []
    for i, func in enumerate(func_sources):
        name = func["name"]
        source = func["source"]
        file_path = func.get("file_path", "<unknown>")
        start_line = func.get("start_line", 1)

        print(f"  [{i+1}/{len(func_sources)}] Extracting facts for {name}...")

        # Add line numbers if not present
        if not _has_line_numbers(source):
            source = _add_line_numbers(source, start_line)

        try:
            facts = extract_facts_llm(
                function_source=source,
                func_name=name,
                file_path=file_path,
                model=model,
                api_key=api_key,
            )
            print(f"    → {len(facts)} facts extracted")
            all_facts.extend(facts)
        except Exception as e:
            print(f"    → ERROR: {e}")

    return all_facts


# ── CLI ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from tree_sitter_nav import get_function_with_lines, enumerate_functions

    if len(sys.argv) < 3:
        print("Usage: python llm_extractor.py <file.c> <func_name> [output_dir]")
        print("  Extracts Datalog facts for a function using the LLM.")
        print("  Requires MODEL_NAME and appropriate API key in .env or environment.")
        sys.exit(1)

    # Load .env if present
    env_path = Path(__file__).parent / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, val = line.partition("=")
                os.environ.setdefault(key.strip(), val.strip().strip('"'))

    file_path = sys.argv[1]
    func_name = sys.argv[2]
    output_dir = sys.argv[3] if len(sys.argv) > 3 else "facts"

    result = get_function_with_lines(file_path, func_name)
    if not result:
        print(f"Function '{func_name}' not found in {file_path}")
        sys.exit(1)

    numbered_source, start_line = result
    print(f"Function source ({start_line}+):")
    print(numbered_source)
    print()

    facts = extract_facts_llm(
        function_source=numbered_source,
        func_name=func_name,
        file_path=file_path,
    )

    print(f"\nExtracted {len(facts)} facts:")
    for f in facts:
        print(f"  {f}")

    stats = write_facts(facts, output_dir)
    print(f"\nWrote facts to {output_dir}/:")
    for filename, count in sorted(stats.items()):
        print(f"  {filename:25s} {count} rows")

"""
LLM Smell Pass — runs an LLM over (function source, mechanical facts)
to produce a small structured residual:

    { additions, corrections, flags, wrappers, coverage_confidence }

This is the *ceiling* of the extraction pipeline. Mechanical extraction
is the floor; the smell pass adds what the AST cannot derive on its own.
Output is small (typically <500 tokens), so truncation is no longer a
silent failure mode.

Public API mirrors llm_extractor.py:
  - smell_function(...)            sync, single-function
  - smell_function_async(...)      async, with optional semaphore
  - smell_functions(...)           batch helper
"""

from __future__ import annotations

import json
import os
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import litellm

from agent_factory import base_completion_kwargs, resolve_api_key
from fact_schema import Fact, FactKind

_PROMPT_PATH = Path(__file__).parent / "prompts" / "smell_pass.md"
_SYSTEM_PROMPT = _PROMPT_PATH.read_text() if _PROMPT_PATH.exists() else ""
_KIND_MAP = {k.value: k for k in FactKind}


@dataclass
class SmellResult:
    func_name: str = ""
    additions: list[Fact] = field(default_factory=list)
    corrections: list[dict] = field(default_factory=list)  # raw shape, applied later
    flags: list[dict] = field(default_factory=list)
    wrappers: list[dict] = field(default_factory=list)
    bounded_fields: list[dict] = field(default_factory=list)
    coverage_confidence: str = "high"
    # bookkeeping
    prompt_tokens: int = 0
    completion_tokens: int = 0
    wall_time_s: float = 0.0
    estimated_cost_usd: float = 0.0
    raw_response: str = ""

    def summary(self) -> str:
        cost = f"${self.estimated_cost_usd:.4f}" if self.estimated_cost_usd else "n/a"
        return (
            f"{self.func_name}: +{len(self.additions)} ~{len(self.corrections)} "
            f"!{len(self.flags)} W{len(self.wrappers)} conf={self.coverage_confidence} "
            f"| {self.prompt_tokens}+{self.completion_tokens}t {self.wall_time_s:.1f}s {cost}"
        )


_session: list[SmellResult] = []


def get_session() -> list[SmellResult]:
    return list(_session)


def reset_session():
    _session.clear()


def session_summary() -> dict:
    if not _session:
        return {"calls": 0}
    return {
        "calls": len(_session),
        "total_additions": sum(len(s.additions) for s in _session),
        "total_corrections": sum(len(s.corrections) for s in _session),
        "total_flags": sum(len(s.flags) for s in _session),
        "total_wrappers": sum(len(s.wrappers) for s in _session),
        "low_confidence_count": sum(1 for s in _session
                                    if s.coverage_confidence == "low"),
        "total_prompt_tokens": sum(s.prompt_tokens for s in _session),
        "total_completion_tokens": sum(s.completion_tokens for s in _session),
        "total_wall_time_s": round(sum(s.wall_time_s for s in _session), 1),
        "total_estimated_cost_usd": round(
            sum(s.estimated_cost_usd for s in _session), 6),
    }


# ── Public entry points ──────────────────────────────────────────────────────

def smell_function(
    function_source: str,
    func_name: str,
    mech_facts: list[Fact],
    file_path: str = "<unknown>",
    model: Optional[str] = None,
    api_key: Optional[str] = None,
) -> SmellResult:
    if model is None:
        model = os.environ.get("LITE_MODEL_NAME") or os.environ.get(
            "MODEL_NAME", "anthropic/claude-sonnet-4-6")
    if api_key is None:
        api_key = resolve_api_key(model)

    user_msg = _build_user_message(function_source, func_name, mech_facts, file_path)
    completion_kwargs = _completion_kwargs(model)
    if api_key is not None:
        completion_kwargs["api_key"] = api_key

    t0 = time.monotonic()
    response = litellm.completion(
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ],
        **completion_kwargs,
    )
    elapsed = time.monotonic() - t0

    raw = response.choices[0].message.content
    result = _parse_response(raw, func_name)
    result.wall_time_s = elapsed
    result.raw_response = raw
    _populate_usage(result, response)
    _session.append(result)
    print(f"    [smell] {result.summary()}")
    return result


async def smell_function_async(
    function_source: str,
    func_name: str,
    mech_facts: list[Fact],
    file_path: str = "<unknown>",
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    semaphore=None,
) -> SmellResult:
    import asyncio as _aio

    if model is None:
        model = os.environ.get("LITE_MODEL_NAME") or os.environ.get(
            "MODEL_NAME", "anthropic/claude-sonnet-4-6")
    if api_key is None:
        api_key = resolve_api_key(model)

    user_msg = _build_user_message(function_source, func_name, mech_facts, file_path)
    completion_kwargs = _completion_kwargs(model)
    if api_key is not None:
        completion_kwargs["api_key"] = api_key

    async def _call_with_retry(max_retries=4):
        for attempt in range(max_retries):
            try:
                t0 = time.monotonic()
                response = await litellm.acompletion(
                    messages=[
                        {"role": "system", "content": _SYSTEM_PROMPT},
                        {"role": "user", "content": user_msg},
                    ],
                    **completion_kwargs,
                )
                return response, time.monotonic() - t0
            except Exception as e:
                if "rate_limit" in str(e).lower() and attempt < max_retries - 1:
                    wait = 10 * (attempt + 1)
                    print(f"    [smell rate-limit] {func_name}: waiting {wait}s")
                    await _aio.sleep(wait)
                else:
                    raise

    if semaphore:
        async with semaphore:
            response, elapsed = await _call_with_retry()
    else:
        response, elapsed = await _call_with_retry()

    raw = response.choices[0].message.content
    result = _parse_response(raw, func_name)
    result.wall_time_s = elapsed
    result.raw_response = raw
    _populate_usage(result, response)
    _session.append(result)
    print(f"    [smell] {result.summary()}")
    return result


def smell_functions(
    functions: list[dict],
    mech_facts_by_func: dict[str, list[Fact]],
    model: Optional[str] = None,
    api_key: Optional[str] = None,
) -> dict[str, SmellResult]:
    """Sequential helper; for parallel use, call smell_function_async with
    a semaphore directly."""
    out: dict[str, SmellResult] = {}
    for i, fn in enumerate(functions):
        name = fn["name"]
        src = fn["source"]
        fp = fn.get("file_path", "<unknown>")
        mech = mech_facts_by_func.get(name, [])
        print(f"  [{i+1}/{len(functions)}] smell {name}")
        try:
            out[name] = smell_function(src, name, mech, fp, model=model, api_key=api_key)
        except Exception as e:
            print(f"    [ERROR] smell({name}): {e}")
    return out


# ── Reconciliation ──────────────────────────────────────────────────────────

def reconcile(
    mech_facts: list[Fact],
    smell_results: dict[str, SmellResult],
) -> tuple[list[Fact], list[dict], list[dict]]:
    """Merge smell additions/corrections into the mechanical fact base.
    Returns (final_facts, flags, wrappers).

    Dedup key: (kind, func, addr, sorted(fields_items_as_str))
    """
    def key_of(f: Fact) -> tuple:
        return (f.kind.value, f.func, f.addr,
                tuple(sorted((k, str(v)) for k, v in f.fields.items())))

    fact_index: dict[tuple, Fact] = {key_of(f): f for f in mech_facts}

    # Apply corrections first so additions don't fight them.
    for sr in smell_results.values():
        for corr in sr.corrections:
            old = corr.get("old", {})
            new = corr.get("new", {})
            if not isinstance(old, dict) or not isinstance(new, dict):
                continue
            old_fact = _dict_to_fact(old, default_func=sr.func_name)
            new_fact = _dict_to_fact(new, default_func=sr.func_name)
            if old_fact is None or new_fact is None:
                continue
            ok = key_of(old_fact)
            if ok in fact_index:
                del fact_index[ok]
            fact_index[key_of(new_fact)] = new_fact

    for sr in smell_results.values():
        for f in sr.additions:
            fact_index.setdefault(key_of(f), f)

    final = list(fact_index.values())

    flags: list[dict] = []
    wrappers: list[dict] = []
    for sr in smell_results.values():
        for fl in sr.flags:
            flags.append({**fl, "func": sr.func_name})
        for w in sr.wrappers:
            wrappers.append({**w, "func": sr.func_name})

    return final, flags, wrappers


def write_llm_relations(
    flags: list[dict],
    wrappers: list[dict],
    output_dir: str | Path,
    smell_results: Optional[dict] = None,
):
    """Write LLMFlag.facts and IsValidator/IsAllocator/IsFree/
    IsTaintSource/IsTaintSink.facts so Datalog rules can consume them.

    If `smell_results` is provided, additionally write BoundedField.facts
    from each result's `bounded_fields` list (G8: spec-bounded struct
    fields validated by parser functions, used by consumer functions
    without local guards).
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # LLMFlag(func, addr, kind, reason)
    flag_rows = sorted({
        (str(fl.get("func", "")), str(fl.get("addr", 0)),
         str(fl.get("kind", "")), str(fl.get("reason", "")).replace("\t", " "))
        for fl in flags
    })
    (output_dir / "LLMFlag.facts").write_text(
        "\n".join("\t".join(r) for r in flag_rows) + ("\n" if flag_rows else ""))

    role_to_file = {
        "validator": "IsValidator.facts",
        "allocator": "IsAllocator.facts",
        "free": "IsFree.facts",
        "free_struct": "IsFree.facts",          # alias — frees the struct itself
        "free_members": "IsFreeMembers.facts",   # frees only the struct's
                                                  # inner pointers, not the
                                                  # struct's own slot.
        "taint_source": "IsTaintSource.facts",
        "taint_sink": "IsTaintSink.facts",
        "identity": "IsIdentity.facts",
    }
    role_buckets: dict[str, set[tuple]] = {f: set() for f in role_to_file.values()}
    # Per-arg detail for validators (so rules can scope guards to checked
    # args rather than every actual_arg).
    validator_arg_rows: set[tuple] = set()
    for w in wrappers:
        role = w.get("role", "")
        fn = role_to_file.get(role)
        if not fn:
            continue
        name = str(w.get("name", ""))
        if not name:
            continue
        role_buckets[fn].add((name,))
        if role == "validator":
            for i in w.get("checks_args", []):
                try:
                    validator_arg_rows.add((name, str(int(i))))
                except (TypeError, ValueError):
                    continue

    for fn, rows in role_buckets.items():
        rows_sorted = sorted(rows)
        (output_dir / fn).write_text(
            "\n".join("\t".join(r) for r in rows_sorted)
            + ("\n" if rows_sorted else ""))

    va_rows = sorted(validator_arg_rows)
    (output_dir / "IsValidatorArg.facts").write_text(
        "\n".join("\t".join(r) for r in va_rows) + ("\n" if va_rows else ""))

    # G8: BoundedField.facts — single column (field name).
    bf_rows: set[tuple] = set()
    if smell_results is not None:
        for sr in smell_results.values():
            for bf in getattr(sr, "bounded_fields", []) or []:
                fld = str(bf.get("field", "")).strip()
                if fld:
                    bf_rows.add((fld,))
    bf_sorted = sorted(bf_rows)
    (output_dir / "BoundedField.facts").write_text(
        "\n".join("\t".join(r) for r in bf_sorted) + ("\n" if bf_sorted else ""))


# ── Internals ────────────────────────────────────────────────────────────────

def _build_user_message(source: str, func_name: str,
                         mech_facts: list[Fact], file_path: str) -> str:
    summary = _summarise_facts(mech_facts)
    return (
        f"## Function under review\n"
        f"`{func_name}` in `{file_path}`\n\n"
        f"### Source\n```c\n{source}\n```\n\n"
        f"### Mechanical fact summary\n"
        f"Total: {len(mech_facts)} facts. Per-kind counts:\n{summary}\n\n"
        f"Review the source against the mechanical extraction above. Emit only "
        f"the small structured residual described in the system prompt — "
        f"additions/corrections/flags/wrappers/coverage_confidence."
    )


def _summarise_facts(facts: list[Fact]) -> str:
    if not facts:
        return "  (none)"
    counts = Counter(f.kind.value for f in facts)
    return "\n".join(f"  {k:15s} {v}" for k, v in sorted(counts.items()))


def _completion_kwargs(model: Optional[str]) -> dict:
    kwargs = base_completion_kwargs(model_name=model)
    kwargs["temperature"] = 0.0
    kwargs["max_tokens"] = 4000
    kwargs["response_format"] = {"type": "json_object"}
    return kwargs


def _parse_response(raw: str, func_name: str) -> SmellResult:
    text = raw.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        print(f"    [WARN] smell({func_name}): invalid JSON ({e}); treating as empty")
        return SmellResult(func_name=func_name, coverage_confidence="low")

    additions_raw = data.get("additions", []) or []
    additions: list[Fact] = []
    for item in additions_raw:
        if not isinstance(item, dict):
            continue
        f = _dict_to_fact(item, default_func=func_name)
        if f is not None:
            additions.append(f)

    corrections = [c for c in (data.get("corrections", []) or [])
                   if isinstance(c, dict)]
    flags = [fl for fl in (data.get("flags", []) or []) if isinstance(fl, dict)]
    wrappers = [w for w in (data.get("wrappers", []) or []) if isinstance(w, dict)]
    bounded_fields = [b for b in (data.get("bounded_fields", []) or [])
                      if isinstance(b, dict)]
    confidence = str(data.get("coverage_confidence", "high")).lower()
    if confidence not in ("high", "medium", "low"):
        confidence = "high"

    return SmellResult(
        func_name=func_name,
        additions=additions,
        corrections=corrections,
        flags=flags,
        wrappers=wrappers,
        bounded_fields=bounded_fields,
        coverage_confidence=confidence,
    )


def _dict_to_fact(d: dict, default_func: str) -> Optional[Fact]:
    kind_str = d.get("kind", "")
    kind = _KIND_MAP.get(kind_str)
    if kind is None:
        return None
    func = d.get("func", default_func)
    try:
        addr = int(d.get("addr", 0))
    except (TypeError, ValueError):
        addr = 0
    fields = d.get("fields", {})
    if not isinstance(fields, dict):
        # Some models flatten; pull non-meta keys into fields.
        fields = {k: v for k, v in d.items() if k not in ("kind", "func", "addr", "fields")}
    return Fact(kind=kind, func=func, addr=addr, fields=fields)


def _populate_usage(result: SmellResult, response):
    usage = getattr(response, "usage", None)
    if usage:
        result.prompt_tokens = getattr(usage, "prompt_tokens", 0) or 0
        result.completion_tokens = getattr(usage, "completion_tokens", 0) or 0
    try:
        result.estimated_cost_usd = litellm.completion_cost(completion_response=response)
    except Exception:
        pass


# ── CLI smoke test ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python smell_pass.py <file.c> <func_name>")
        sys.exit(1)

    env_path = Path(__file__).parent / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, val = line.partition("=")
                os.environ[key.strip()] = val.strip().strip('"')

    file_path = sys.argv[1]
    func_name = sys.argv[2]

    from mechanical_extractor import extract_facts
    from tree_sitter_nav import get_function_with_lines

    facts = extract_facts(file_path, func_name)
    print(f"Mechanical: {len(facts)} facts.")

    result = get_function_with_lines(file_path, func_name)
    if not result:
        print("Function not found.")
        sys.exit(1)
    numbered_source, _ = result

    sr = smell_function(numbered_source, func_name, facts, file_path=file_path)
    print()
    print(json.dumps({
        "additions": [_fact_to_dict(f) for f in sr.additions],
        "corrections": sr.corrections,
        "flags": sr.flags,
        "wrappers": sr.wrappers,
        "coverage_confidence": sr.coverage_confidence,
    }, indent=2))


def _fact_to_dict(f: Fact) -> dict:
    return {"kind": f.kind.value, "func": f.func, "addr": f.addr, "fields": f.fields}

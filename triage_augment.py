"""
LITE-LLM triage augmentor — adaptive re-ranking on top of triage_ranker.dl.

The deterministic ranker scores functions by a fixed catalog of structural
signals (ArithOp→sink, MemWrite-in-loop, etc.). That catalog is project-
neutral, so it misses codebase-specific intuition: a function named
`ReadHuffmanCode` in a codec is *obviously* a parser-of-untrusted-input
even if the structural-signal sum doesn't quite light up; a function
named `Init_VTable` is *obviously* not interesting even if it has a
MemWrite.

This module fills that gap with a single Lite-tier LLM call (V4-Flash
equivalent) that:
  1. Reads the baseline ranking (top-K by structural score).
  2. Reads the full function-name list (for context — what else is in
     the codebase).
  3. Proposes a small set of bounded score adjustments
     `{func, delta, reason}` with the constraint that deltas stay small
     (±2 to ±5) and the total list is ≤ 20 adjustments.

The adjustments are then merged into the score dict; the rest of the
pipeline (LLM extraction Phase 3) sees the adjusted ranking.

Cost: ~$0.01-0.05 per project (one LLM call, ~3-5K tokens). Off by
default — opt in via TRIAGE_AUGMENT=1.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Optional


_SYSTEM_PROMPT = """You are the triage augmentor for NeuroLog, a neuro-symbolic
static analyzer for C/C++. A deterministic Datalog ranker has scored every
function in the target project by a fixed catalog of structural risk
signals (ArithOp flowing to sink, MemWrite in loop body, unguarded ptr-arg
deref, Cast at sink arg, taint-source call, unchecked alloc, heavy MemWrite,
lifecycle sink). Your job is to propose codebase-specific adjustments to
this baseline ranking.

PRESERVE the deterministic ranking by default. Only suggest changes when you
have a clear name-based or signal-based reason.

BOOST a function (positive delta, +2 to +5) when:
  - Its name suggests parsing or decoding untrusted bitstream / file /
    network input (Read*, Decode*, Parse*, Get*Bits, *Chunk*, *Header*).
  - Its name suggests size/length computation on untrusted input
    (Compute*Size, Get*Length, Calc*Bytes).
  - Its name suggests memory-management bookkeeping on caller-provided
    buffers (Resize*, Reallocate*, Grow*, Append*).

DEMOTE a function (negative delta, -2 to -5) when:
  - Its name suggests it is a test helper or fixture (Test*, Mock*,
    Fixture*, *_test, *_debug, Verify*).
  - Its name suggests initialization or finalization with no untrusted
    inputs (Init*, Setup*, Cleanup*, Free*, Destroy*, *Reset).
  - Its name suggests a simple getter/setter or string helper
    (Get<Field>, Set<Field>, Is*, Has*, To*, From*Str).
  - Its name suggests debug/log output (*Log*, *Print*, *Dump*, *Trace*).

OUTPUT FORMAT: a single fenced ```json block containing an array of objects:
```json
[
  {"func": "BuildHuffmanTable", "delta": 3, "reason": "huffman code-length parser on untrusted bitstream"},
  {"func": "Init_VTable", "delta": -3, "reason": "module-init, no untrusted input"}
]
```

CONSTRAINTS:
  - At most 20 adjustments. Prefer high-confidence boosts over speculative ones.
  - delta must be in [-5, -2] ∪ [+2, +5].
  - Use the EXACT function name as it appears in the input.
  - Do not duplicate adjustments for the same function.
  - Do not output any text outside the fenced ```json block.
"""


def _build_user_prompt(project_basename: str,
                       ranked: list[tuple[str, int]],
                       all_funcs: list[str],
                       top_n_show: int = 50) -> str:
    """Render the user prompt: top-N ranked + the rest as name-only context."""
    ranked_block = "\n".join(
        f"{i+1:>3}. {f:<48} score={s}"
        for i, (f, s) in enumerate(ranked[:top_n_show])
    )
    scored_set = {f for f, _ in ranked}
    unscored = [f for f in all_funcs if f not in scored_set]
    # Compact the unscored list — names only, comma-separated, capped.
    unscored_block = ", ".join(unscored[:300])
    if len(unscored) > 300:
        unscored_block += f", … ({len(unscored) - 300} more)"
    return (
        f"# Project: {project_basename}\n\n"
        f"## Ranker baseline (top {min(len(ranked), top_n_show)} of "
        f"{len(ranked)} scored)\n\n"
        f"{ranked_block}\n\n"
        f"## Other functions in the project (unscored, for context)\n\n"
        f"{unscored_block}\n\n"
        f"## Your task\n\n"
        f"Propose adjustments per the rules in the system prompt. Output "
        f"only the fenced ```json block."
    )


def _parse_adjustments(reply: str) -> list[dict]:
    """Extract the JSON array from a fenced block (or raw JSON fallback)."""
    m = re.search(r"```(?:json)?\s*(\[[\s\S]*?\])\s*```", reply)
    payload = m.group(1) if m else None
    if payload is None:
        # Try raw JSON
        m = re.search(r"(\[[\s\S]*\])", reply)
        payload = m.group(1) if m else None
    if payload is None:
        return []
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []
    out: list[dict] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        func = item.get("func")
        delta = item.get("delta")
        if not isinstance(func, str) or not isinstance(delta, (int, float)):
            continue
        delta = int(delta)
        if delta == 0:
            continue
        # Clamp to ±5; reject obviously bad values
        if not (-5 <= delta <= 5):
            continue
        out.append({
            "func": func.strip(),
            "delta": delta,
            "reason": str(item.get("reason", ""))[:200],
        })
        if len(out) >= 20:
            break
    return out


def augment_ranking(scores: dict[str, int],
                    all_funcs: list[str],
                    project_basename: str,
                    *,
                    model_name: Optional[str] = None,
                    top_n_show: int = 50,
                    ) -> tuple[dict[str, int], list[dict]]:
    """Run one Lite-LLM call to propose adjustments, then apply them.

    Args:
        scores:        the deterministic ranker output (func → score).
        all_funcs:     full list of function names in the project (used as
                       context so the LLM can boost things outside the
                       scored set).
        project_basename: short label like "libwebp" or "ffmpeg" — feeds
                       the LLM's codebase-domain inference.
        model_name:    override the default Lite model. None → use the
                       LITE_MODEL_NAME env var.
        top_n_show:    how many top-scored functions to show with full
                       signal info. The rest are listed as names only.

    Returns:
        (adjusted_scores, applied_adjustments) — the new score dict plus
        the list of {func, delta, reason} actually applied. Functions
        outside `all_funcs` are silently dropped from the adjustments.
    """
    import litellm
    from agent_factory import base_completion_kwargs

    ranked = sorted(scores.items(), key=lambda kv: -kv[1])

    user_prompt = _build_user_prompt(project_basename, ranked, all_funcs,
                                       top_n_show=top_n_show)
    kwargs = base_completion_kwargs(
        model_name=model_name, lite=True, thinking="off")
    kwargs.update({
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user",   "content": user_prompt},
        ],
        "temperature": 0.3,
    })
    try:
        resp = litellm.completion(**kwargs)
        reply = resp["choices"][0]["message"]["content"]
    except Exception as e:
        print(f"  [triage-augment] LLM call failed: {e}")
        return dict(scores), []

    raw_adjustments = _parse_adjustments(reply)
    func_set = set(all_funcs)

    adjusted = dict(scores)
    applied: list[dict] = []
    for adj in raw_adjustments:
        f = adj["func"]
        if f not in func_set:
            continue
        new_score = adjusted.get(f, 0) + adj["delta"]
        adjusted[f] = max(0, new_score)
        applied.append(adj)

    return adjusted, applied


if __name__ == "__main__":
    # Smoke test: read FuncRiskScore.csv from a given facts dir + an
    # all-functions list, run the augmentor, print the diff.
    import sys
    if len(sys.argv) != 3:
        print("usage: python triage_augment.py <FuncRiskScore.csv> <all_funcs.txt>",
              file=sys.stderr)
        sys.exit(2)
    score_path = Path(sys.argv[1])
    funcs_path = Path(sys.argv[2])
    scores = {}
    for line in score_path.read_text().splitlines():
        parts = line.split("\t")
        if len(parts) == 2:
            scores[parts[0]] = int(parts[1])
    all_funcs = [l.strip() for l in funcs_path.read_text().splitlines()
                  if l.strip()]
    project = score_path.parent.parent.name or "unknown"
    adjusted, applied = augment_ranking(scores, all_funcs, project)
    print(f"baseline: {len(scores)} scored, top-3:",
          sorted(scores.items(), key=lambda kv: -kv[1])[:3])
    print(f"adjustments applied: {len(applied)}")
    for adj in applied:
        print(f"  {adj['delta']:+d}  {adj['func']:<40} — {adj['reason']}")
    new_ranked = sorted(adjusted.items(), key=lambda kv: -kv[1])
    print("\npost-augment top-15:")
    for f, s in new_ranked[:15]:
        delta = s - scores.get(f, 0)
        marker = f" ({delta:+d})" if delta else ""
        print(f"  {s:3d}  {f}{marker}")

"""
Crash-synthesis agent — multi-shot loop that turns a Phase-B-feasible
finding into a confirmed ASan-crashing input, without running a fuzzer.

The loop:
  1. Build a SynthesisContext (def-use chain + Z3 model + format hint
     + source snippet) for the finding.
  2. Prompt the LLM for N candidate Python emitters.
  3. Execute each emitter in a sandboxed subprocess to get the candidate
     blob; run each blob through the ASan-built harness; record the
     verdict.
  4. If any candidate crashes with the predicted bug class (and
     optionally the predicted source line), return it.
  5. Otherwise, feed the prior attempt(s) + verdicts back into the next
     round's prompt and loop until max_iterations.

This is the LLM-Datalog-QL equivalent of COTTONTAIL's Solve-Complete +
test-case validator loop, but driven by Datalog facts + Z3 SAT
witnesses rather than concolic execution.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

import litellm

from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent / ".env", override=True)

from symbex_encoder import Finding
from crash_synth import (
    SynthesisContext, build_context, build_synthesis_prompt,
    SYSTEM_PROMPT,
)
from crash_validator import ValidationResult, run_harness


@dataclass
class Candidate:
    rationale: str
    python_emitter: str
    blob: Optional[bytes] = None
    blob_size: int = 0
    emitter_error: Optional[str] = None
    verdict: Optional[ValidationResult] = None

    def verdict_dict(self) -> dict:
        if self.verdict is None:
            return {"crashed": False, "reason": "no verdict yet"}
        v = self.verdict
        return {
            "crashed": v.crashed, "bug_class": v.bug_class,
            "top_frame_func": v.top_frame_func,
            "top_frame_line": v.top_frame_line,
            "exit_code": v.exit_code,
            "stderr_tail": v.stderr_tail[-1024:],
            "parser_progress": v.parser_progress,
            "parser_frames": v.parser_frames[:16],
        }


@dataclass
class SynthesisLog:
    finding: Finding
    iterations: int
    confirmed_blob: Optional[bytes] = None
    confirmed_emitter: Optional[str] = None
    confirmed_rationale: Optional[str] = None
    matched_class: Optional[str] = None
    matched_func: Optional[str] = None
    matched_line: Optional[int] = None
    history: list[dict] = field(default_factory=list)
    elapsed_s: float = 0.0


# ── LLM call ───────────────────────────────────────────────────────────────

def _strong_model_name() -> Optional[str]:
    """Override via CRASH_SYNTH_MODEL; otherwise let
    base_completion_kwargs pick MODEL_NAME from .env."""
    return os.environ.get("CRASH_SYNTH_MODEL")


_JSON_BLOCK_RE = re.compile(r"\{[\s\S]+\}")


def _parse_candidates(reply: str) -> list[Candidate]:
    """Extract the JSON block and parse out candidates. Tolerates
    ```json fences and surrounding prose."""
    # Strip ```json / ``` fences if present.
    cleaned = reply.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```\s*$", "", cleaned)
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        m = _JSON_BLOCK_RE.search(reply)
        if not m:
            return []
        try:
            data = json.loads(m.group(0))
        except json.JSONDecodeError:
            return []
    cands = []
    for c in data.get("candidates", []) or []:
        rat = c.get("rationale", "") or ""
        emit = c.get("python_emitter", "") or ""
        if emit:
            cands.append(Candidate(rationale=rat, python_emitter=emit))
    return cands


def _call_llm(system_prompt: str, user_prompt: str,
              model: Optional[str] = None) -> str:
    """Use the project's `base_completion_kwargs` so we get the same
    api_base / api_key / extra_body / thinking handling as the rest of
    the pipeline. Override temperature for diversity across candidates.

    Crash-input synthesis is a multi-constraint code-generation task
    (format-validity + operand-extreme + Python correctness). Force
    `thinking="on"` so the Heavy model gets extended reasoning even
    when the global env has thinking disabled for cheap orchestration
    calls. This was the root cause behind the "emitter returns scaffold
    unchanged / NameError" failures observed in the libxml2 synth runs.
    """
    from agent_factory import base_completion_kwargs
    kwargs = base_completion_kwargs(
        model_name=(model or _strong_model_name()),
        thinking="on",
    )
    kwargs.update({
        "messages": [{"role": "system", "content": system_prompt},
                      {"role": "user", "content": user_prompt}],
        "temperature": 0.7,
    })
    resp = litellm.completion(**kwargs)
    return resp["choices"][0]["message"]["content"]


# ── Sandboxed emitter execution ────────────────────────────────────────────

def _execute_emitter(python_code: str, timeout_s: float = 8.0
                       ) -> tuple[Optional[bytes], Optional[str]]:
    """Run a python emitter, capturing stdout as the candidate blob.
    Returns (blob, error_string_or_None)."""
    # Prepend common imports so LLM-emitted code that forgets to import
    # `struct`/`zlib`/`io` doesn't NameError on first use. Belt-and-
    # suspenders: the emitter prompt asks for them, but Heavy/thinking
    # mode occasionally drops them under blob-size pressure.
    preamble = (
        "import sys, os, struct, zlib, io, math, random, base64\n"
        "from io import BytesIO\n"
    )
    full_code = preamble + python_code
    try:
        # Inherit env (no PYTHONIOENCODING override — sys.stdout.buffer.write
        # bypasses text encoding anyway, and bogus codec names crash Python
        # at init).
        p = subprocess.run(
            [sys.executable, "-c", full_code],
            capture_output=True, timeout=timeout_s,
            env=os.environ.copy(),
        )
        if p.returncode != 0:
            err = p.stderr.decode("latin1", "replace")[-2048:]
            return None, f"emitter exit {p.returncode}: {err}"
        if not p.stdout:
            return None, "emitter produced empty stdout"
        return p.stdout, None
    except subprocess.TimeoutExpired:
        return None, f"emitter timeout after {timeout_s}s"
    except Exception as e:
        return None, f"emitter exception: {type(e).__name__}: {e}"


# ── Main loop ──────────────────────────────────────────────────────────────

def synthesize_crash(eval_dir: str | Path, finding: Finding,
                       harness_cmd: list[str],
                       src_root: Optional[str | Path] = None,
                       file_hint: Optional[str] = None,
                       scaffold_path: Optional[str | Path] = None,
                       max_iterations: int = 5,
                       candidates_per_iter: int = 5,
                       want_func: Optional[str] = None,
                       want_line: Optional[int] = None,
                       harness_timeout_s: float = 10.0,
                       format_override: Optional[str] = None,
                       verbose: bool = True) -> SynthesisLog:
    """Run the multi-shot synthesis loop until a candidate crashes the
    harness with the predicted bug class (or `max_iterations` is hit)."""
    t0 = time.monotonic()
    log = SynthesisLog(finding=finding, iterations=0)

    ctx = build_context(eval_dir, finding, src_root=src_root,
                          file_hint=file_hint,
                          scaffold_path=scaffold_path,
                          format_override=format_override)
    if verbose:
        print(f"[synth] context built: {len(ctx.chain)} chain steps, "
              f"{len(ctx.taint_sources)} taint sources, "
              f"format={ctx.format_hint}, "
              f"|model|={len(ctx.z3_model)}")

    prior_attempts: list[dict] = []
    for it in range(1, max_iterations + 1):
        log.iterations = it
        if verbose:
            print(f"[synth] iter {it}/{max_iterations}")
        prompt = build_synthesis_prompt(
            ctx, prior_attempts=prior_attempts,
            n_candidates=candidates_per_iter)
        try:
            reply = _call_llm(SYSTEM_PROMPT, prompt)
        except Exception as e:
            if verbose:
                print(f"[synth] LLM call failed: {e}")
            log.history.append({"iter": it, "error": str(e)})
            continue
        candidates = _parse_candidates(reply)
        if verbose:
            print(f"[synth]   parsed {len(candidates)} candidate(s)")

        # Execute each emitter and validate.
        round_log: list[dict] = []
        for ci, cand in enumerate(candidates):
            blob, err = _execute_emitter(cand.python_emitter)
            cand.emitter_error = err
            if blob is None:
                cand.verdict = ValidationResult(crashed=False,
                                                  stderr_tail=err or "")
                round_log.append({
                    "candidate": ci, "rationale": cand.rationale,
                    "verdict": cand.verdict_dict(),
                    "emitter_error": err,
                })
                if verbose:
                    print(f"[synth]   cand {ci}: emitter failed — {err[:120]}")
                continue
            cand.blob = blob
            cand.blob_size = len(blob)
            # Detect the "scaffold returned unchanged" pathology — the
            # emitter wrote correct rationale text but the Python code
            # just dumped the scaffold bytes verbatim. This was the
            # dominant failure mode in the libwebp synth runs (9/9
            # attempts returned the scaffold bytes unmodified). Skip the
            # harness call for these — they cannot crash because they
            # ARE the known-good seed — and surface a strong signal in
            # the next iteration's prompt.
            unmutated = bool(ctx.scaffold_bytes) and blob == ctx.scaffold_bytes
            if unmutated:
                cand.verdict = ValidationResult(
                    crashed=False,
                    stderr_tail="unmutated: emitter returned the scaffold "
                                "bytes verbatim (no mutation applied)",
                )
                vd = cand.verdict_dict()
                vd["unmutated"] = True
                round_log.append({
                    "candidate": ci, "rationale": cand.rationale,
                    "blob_size": len(blob), "verdict": vd,
                })
                if verbose:
                    print(f"[synth]   cand {ci}: blob={len(blob)}B "
                          f"UNMUTATED (scaffold returned verbatim)")
                prior_attempts.append({
                    "rationale": cand.rationale,
                    "verdict": vd,
                })
                continue
            cand.verdict = run_harness(blob, harness_cmd,
                                         timeout_s=harness_timeout_s)
            v = cand.verdict
            if verbose:
                print(f"[synth]   cand {ci}: blob={len(blob)}B  "
                      f"crashed={v.crashed}  class={v.bug_class}  "
                      f"frame={v.top_frame_func}@L{v.top_frame_line}  "
                      f"progress={v.parser_progress}")
            round_log.append({
                "candidate": ci, "rationale": cand.rationale,
                "blob_size": len(blob), "verdict": cand.verdict_dict(),
            })
            if v.matches(_class_for_kind(finding.kind),
                         want_func, want_line):
                # Confirmed!
                log.confirmed_blob = blob
                log.confirmed_emitter = cand.python_emitter
                log.confirmed_rationale = cand.rationale
                log.matched_class = v.bug_class
                log.matched_func = v.top_frame_func
                log.matched_line = v.top_frame_line
                log.history.append({"iter": it, "candidates": round_log})
                log.elapsed_s = time.monotonic() - t0
                if verbose:
                    print(f"[synth] CONFIRMED at iter {it} cand {ci}")
                return log
            # Save for next-round prompt.
            prior_attempts.append({
                "rationale": cand.rationale,
                "verdict": cand.verdict_dict(),
            })
        log.history.append({"iter": it, "candidates": round_log})

    log.elapsed_s = time.monotonic() - t0
    if verbose:
        print(f"[synth] no confirmed crash after {max_iterations} iters")
    return log


def _class_for_kind(kind: str) -> Optional[str]:
    """Map a Datalog bug-kind to the ASan class we expect to see when
    the bug actually fires."""
    return {
        "narrow_arith_at_sink": "allocation_size_too_big",
        "signed_arg_at_sink": "allocation_size_too_big",
        "truncation_cast": None,            # any
        "unbounded_counter_at_sink": None,  # any (sentinel collision is custom)
        "potential_arith_overflow": "allocation_size_too_big",
        "sentinel_collision": None,
        "unguarded_dangerous_cast": None,
    }.get(kind)


# ── ADK tool wrappers ───────────────────────────────────────────────────────

def tool_synthesize_crash(eval_dir: str, func: str, addr: int, var: str,
                            kind: str, harness_cmd: str,
                            src_root: str = "",
                            file_hint: str = "",
                            max_iterations: int = 5,
                            candidates_per_iter: int = 5) -> dict:
    """Run multi-shot crash-input synthesis on a feasible finding and
    validate against an ASan-built harness. `harness_cmd` is shell-split
    (e.g. `/path/to/fuzz_vorbis`)."""
    import shlex
    finding = Finding(func=func, addr=int(addr), var=var, kind=kind)
    cmd = shlex.split(harness_cmd)
    log = synthesize_crash(
        eval_dir=eval_dir, finding=finding, harness_cmd=cmd,
        src_root=src_root or None, file_hint=file_hint or None,
        max_iterations=max_iterations,
        candidates_per_iter=candidates_per_iter)
    out = {
        "confirmed": log.confirmed_blob is not None,
        "iterations": log.iterations,
        "elapsed_s": log.elapsed_s,
        "matched": (None if log.confirmed_blob is None else {
            "bug_class": log.matched_class,
            "top_frame_func": log.matched_func,
            "top_frame_line": log.matched_line,
            "blob_size": len(log.confirmed_blob),
            "rationale": log.confirmed_rationale,
        }),
        "history_summary": [
            {"iter": h.get("iter"),
             "n_candidates": len(h.get("candidates", [])),
             "n_crashed": sum(1 for c in h.get("candidates", [])
                              if c.get("verdict", {}).get("crashed"))}
            for h in log.history
        ],
    }
    return out


# ── CLI driver ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="Multi-shot crash-input synthesis from a feasible finding.")
    parser.add_argument("eval_dir")
    parser.add_argument("func")
    parser.add_argument("addr", type=int)
    parser.add_argument("var")
    parser.add_argument("kind")
    parser.add_argument("harness_cmd",
                          help="Shell-quoted harness command, e.g. '/.../fuzz_vorbis'")
    parser.add_argument("--src-root", default="")
    parser.add_argument("--file-hint", default="")
    parser.add_argument("--scaffold-seed", default="",
                          help="Path to a known-good seed input. When "
                               "provided, the LLM is instructed to "
                               "MUTATE this scaffold rather than emit a "
                               "blob from scratch. Required for deeply-"
                               "nested container formats.")
    parser.add_argument("--format", default="",
                          help="Override the auto-detected format hint "
                               "(e.g., 'webp/vp8l', 'matroska/ebml'). "
                               "Useful when the function name is "
                               "ambiguous across formats (e.g., "
                               "'BuildHuffmanTable' is shared between "
                               "WebP-VP8L and JPEG codepaths).")
    parser.add_argument("--iters", type=int, default=5)
    parser.add_argument("--cands", type=int, default=5)
    parser.add_argument("--save-confirmed",
                          help="Where to save the confirmed crash blob")
    parser.add_argument("--save-log",
                          help="Where to dump the JSON synthesis log")
    args = parser.parse_args()

    import shlex
    finding = Finding(func=args.func, addr=args.addr, var=args.var,
                       kind=args.kind)
    log = synthesize_crash(
        eval_dir=args.eval_dir, finding=finding,
        harness_cmd=shlex.split(args.harness_cmd),
        src_root=args.src_root or None,
        file_hint=args.file_hint or None,
        scaffold_path=args.scaffold_seed or None,
        format_override=args.format or None,
        max_iterations=args.iters, candidates_per_iter=args.cands)

    print()
    print("===")
    if log.confirmed_blob:
        print(f"CONFIRMED at iter {log.iterations}: "
              f"{log.matched_class} @ {log.matched_func}:{log.matched_line}")
        print(f"  rationale: {log.confirmed_rationale}")
        if args.save_confirmed:
            blob_path = Path(args.save_confirmed)
            blob_path.write_bytes(log.confirmed_blob)
            print(f"  blob → {blob_path}")
            # Save the emitter source as a sibling .py for reproducibility.
            if log.confirmed_emitter:
                emitter_path = blob_path.with_suffix(".emitter.py")
                emitter_path.write_text(
                    "# Auto-generated by crash_synth_agent.py\n"
                    f"# Confirmed at iteration {log.iterations}\n"
                    f"# Bug: {log.matched_class} @ {log.matched_func}:{log.matched_line}\n"
                    f"# Rationale: {log.confirmed_rationale}\n\n"
                    + log.confirmed_emitter)
                print(f"  emitter → {emitter_path}")
    else:
        print(f"NO CRASH after {log.iterations} iters / {log.elapsed_s:.1f}s")
    if args.save_log:
        Path(args.save_log).write_text(json.dumps({
            "finding": asdict(log.finding),
            "iterations": log.iterations,
            "elapsed_s": log.elapsed_s,
            "confirmed": log.confirmed_blob is not None,
            "matched_class": log.matched_class,
            "matched_func": log.matched_func,
            "matched_line": log.matched_line,
            "history": log.history,
        }, indent=2, default=str))
        print(f"  log → {args.save_log}")

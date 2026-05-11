#!/usr/bin/env python3
"""LLM-driven taint-source classifier for an arbitrary C/C++ project.

The premise (per IRIS, Li et al. ICSE'25) is that an LLM can identify
input-boundary functions of an unfamiliar codebase project-agnostically,
without per-project hardcoded lists.  The naive way to do this — ask
the LLM "is this function a taint source?" for every function in the
codebase — would burn the budget on thousands of questions.

This module instead **bootstraps from the project's own structure**,
which is how a human researcher onboards: look at the fuzz harness, the
test runner, public API headers, the OSS-Fuzz build script.  These
files are dense with the project's input-boundary idioms by design.

Phases:
  A) **Discovery** (1 LLM call):
     The LLM examines the top-level directory tree (names only, ~hundreds
     of entries) and returns up to 10 paths most likely to reveal input
     boundaries — fuzz/, test/, examples/, oss-fuzz config, public hdrs.
  B) **Classification** (1-3 LLM calls):
     The LLM reads those files (capped to ~200 lines each) and emits a
     TSV of (function_name, category, rationale) for every input-boundary
     API it identifies.
  C) **Mechanical filter**:
     Drop functions that don't appear as callees in Call.facts (avoids
     polluting the source list with unused names from headers).  Merge
     with the built-in libc set.

Total LLM calls: typically 2-4 per project.  Bounded.

Output: writes (or merges into) `<eval_dir>/facts/TaintSourceFunc.facts`
in the canonical 2-arity TSV format (name\\tcategory).

Usage:
  python llm_taint_classifier.py <eval_dir> [--src-root <path>] [--dry-run]

`--src-root` defaults to `project_config.json`'s `src_root` if present;
falls back to the eval_dir itself.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

PROJ = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJ))

from dotenv import load_dotenv
load_dotenv(PROJ / ".env", override=True)

from agent_factory import apply_smell_pass_env, base_completion_kwargs
apply_smell_pass_env()

from audit_log import log_step

import litellm  # noqa: E402


# Built-in libc source set, the floor below the LLM's per-project work.
# Same as agent.py's _BUILTIN_SOURCES — kept in sync.
_BUILTIN_SOURCES: list[tuple[str, str]] = [
    ("read", "byte_read"),
    ("recv", "byte_read"),
    ("recvfrom", "byte_read"),
    ("recvmsg", "byte_read"),
    ("fread", "byte_read"),
    ("fgets", "string_read"),
    ("gets", "string_read"),
    ("getline", "string_read"),
    ("getenv", "env_read"),
    ("scanf", "byte_read"),
    ("atoi", "byte_read"),
    ("strtol", "byte_read"),
    ("strtoul", "byte_read"),
    ("strtod", "byte_read"),
]


# ── Prompt templates ────────────────────────────────────────────────

DISCOVERY_PROMPT = """\
You are helping classify the input-boundary API of a C/C++ project. The
project's source tree (top two levels, file/dir names only — no contents)
is below. Identify up to 10 paths that are most likely to reveal which
functions read attacker-controlled bytes from a file / stdin / network /
environment. Strong signals: a fuzz/ or fuzzers/ directory, OSS-Fuzz
config files (oss-fuzz-build.sh), test/ or tests/ runner code, public
API headers (often named like the project), examples/.

Return STRICT JSON, this schema only:
  {"paths": ["<rel_path_1>", "<rel_path_2>", ...]}

Up to 10 paths. Prefer files over directories. Return relative paths
from the project root.

Project tree:
"""


CLASSIFY_PROMPT = """\
You are helping build a taint-source list for the C/C++ project. Below
are two pieces of context:

  (1) **Selected project files** — the fuzz harness, public headers,
      test runner.  Use these to understand HOW input enters the
      library.
  (2) **Callee inventory from Call.facts** — every distinct function
      name the static-analysis pipeline observed being called.  This
      is the universe of names that the downstream taint propagation
      can see.  If a function is not in this list, it is invisible to
      the pipeline and must NOT be returned.

Your task: from inventory (2), pick the functions whose **return value**
or **outparam buffer** carries attacker-controlled bytes when the fuzz
harness runs.  Use (1) to reason about which library API calls the
harness uses to feed input, then map those to the names in (2).

Return STRICT JSON, this schema only:
  {"sources": [
     {"func": "<name from Call.facts inventory>",
      "category": "<one of: byte_read | string_read | buffer_read | env_read | fuzz_input>",
      "rationale": "<one short sentence: how does this function's output
                     trace back to attacker-controlled bytes?>"},
     ...
  ]}

Rules:
  - **Names MUST appear in the Call.facts inventory below** — otherwise
    the pipeline cannot use them.
  - libc is already covered (read, fread, getenv, ...). Don't re-list.
  - Include functions that wrap libc reads (e.g., `avio_r8` wraps
    `read`; `xmlReadMemory` wraps memory-buffer parsing).
  - Be inclusive but precise: a logger or an allocator is NOT a source.
  - One row per name (no duplicates).
"""


# ── Phase A: Discovery ────────────────────────────────────────────────

def _list_tree(root: Path, max_entries: int = 400) -> str:
    """Return a compact two-level listing of the source tree, names only."""
    lines = []
    skip_dirs = {".git", ".github", "node_modules", "__pycache__", "build",
                 "dist", ".venv", "venv", "target"}
    for p in sorted(root.iterdir()):
        if p.name in skip_dirs:
            continue
        if p.is_dir():
            lines.append(f"{p.name}/")
            try:
                children = sorted(p.iterdir())[:30]
                for c in children:
                    if c.name.startswith(".") or c.name in skip_dirs:
                        continue
                    suffix = "/" if c.is_dir() else ""
                    lines.append(f"  {c.name}{suffix}")
            except PermissionError:
                pass
        else:
            lines.append(p.name)
        if len(lines) >= max_entries:
            lines.append(f"... (tree truncated at {max_entries} entries)")
            break
    return "\n".join(lines)


def _llm_call(system: str, user: str, max_tokens: int = 2000) -> str:
    kw = base_completion_kwargs()
    # Use Lite model for both phases — this is retrieval-style work,
    # not deep reasoning. (User can override via env.)
    kw["model"] = os.environ.get("LITE_MODEL_NAME") or kw.get("model")
    # base_completion_kwargs may already set max_tokens; let our value win
    kw.pop("max_tokens", None)
    resp = litellm.completion(
        messages=[
            {"role": "system", "content": system},
            {"role": "user",   "content": user},
        ],
        max_tokens=max_tokens,
        **kw,
    )
    return resp.choices[0].message.content or ""


def _extract_json(text: str) -> dict | None:
    """Pull JSON out of a possibly-fenced, possibly-truncated reply."""
    import re
    # Try strict fenced-JSON first
    m = re.search(r"```json\s*(\{.*?\})\s*```", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    # Try first complete balanced {...}
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            pass
    # Truncation salvage: scan inside `"sources": [ ... ]` for individual
    # `{...}` objects we can still parse, even if the outer JSON is cut off.
    arr = re.search(r'"sources"\s*:\s*\[', text)
    if arr is None:
        arr = re.search(r'"paths"\s*:\s*\[', text)
        if arr is None:
            return None
        # paths array contains plain strings; salvage by extracting them
        items = []
        body = text[arr.end():]
        for s in re.findall(r'"([^"\\]*)"', body):
            if "/" in s or s.endswith(".c") or s.endswith(".h") or s.endswith(".sh"):
                items.append(s)
        return {"paths": items[:20]} if items else None
    body = text[arr.end():]
    sources = []
    depth = 0
    obj_start = -1
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "{":
            if depth == 0:
                obj_start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and obj_start >= 0:
                snippet = body[obj_start:i + 1]
                try:
                    sources.append(json.loads(snippet))
                except json.JSONDecodeError:
                    pass
                obj_start = -1
        elif ch == "]" and depth == 0:
            break
        i += 1
    return {"sources": sources} if sources else None


def discover_signal_files(src_root: Path) -> list[Path]:
    tree = _list_tree(src_root)
    user = DISCOVERY_PROMPT + "\n" + tree
    sys_msg = ("You are a security researcher onboarding to an unfamiliar "
               "C/C++ project. Your only task is to find files most likely "
               "to reveal the project's input-boundary API.")
    reply = _llm_call(sys_msg, user, max_tokens=800)
    parsed = _extract_json(reply)
    if not parsed or "paths" not in parsed:
        print(f"[classifier] discovery returned unparseable: {reply[:200]}")
        return []
    paths = []
    for rel in parsed["paths"][:10]:
        p = (src_root / rel).resolve()
        # Hard guard: stay inside src_root
        try:
            p.relative_to(src_root.resolve())
        except ValueError:
            continue
        if p.exists() and p.is_file():
            paths.append(p)
    return paths


# ── Phase B: Classification ──────────────────────────────────────────

def _read_capped(path: Path, max_lines: int = 200) -> str:
    try:
        text = path.read_text(errors="replace")
    except Exception as e:
        return f"[unreadable: {e}]"
    lines = text.split("\n")
    if len(lines) > max_lines:
        return "\n".join(lines[:max_lines]) + f"\n... [{len(lines) - max_lines} more lines]"
    return text


def _callee_inventory(call_facts_path: Path,
                       max_callees: int = 400) -> tuple[str, set[str]]:
    """Build a string listing of distinct callees seen in Call.facts."""
    if not call_facts_path.exists():
        return "(Call.facts not available)", set()
    callees: dict[str, int] = {}
    for line in call_facts_path.read_text().splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            callees[parts[1]] = callees.get(parts[1], 0) + 1
    # Sort by call-count descending (most-used callees first)
    ranked = sorted(callees.items(), key=lambda kv: -kv[1])
    listed = ranked[:max_callees]
    text = "\n".join(name for name, _ in listed)
    if len(ranked) > max_callees:
        text += f"\n... ({len(ranked) - max_callees} more callees omitted)"
    return text, set(callees.keys())


def classify_sources(src_root: Path,
                      signal_paths: list[Path],
                      call_facts_path: Path | None = None
                      ) -> list[tuple[str, str, str]]:
    if not signal_paths:
        return []
    body_parts = []
    for p in signal_paths:
        rel = p.relative_to(src_root.resolve())
        body_parts.append(f"\n=== {rel} ===\n{_read_capped(p)}\n")
    inv_text = "(Call.facts not provided)"
    if call_facts_path is not None:
        inv_text, _ = _callee_inventory(call_facts_path)
    user = (CLASSIFY_PROMPT
            + "\n=== (1) Project files ===\n"
            + "\n".join(body_parts)
            + "\n=== (2) Call.facts callee inventory (call-count desc) ===\n"
            + inv_text + "\n"
            + "\n*** IMPORTANT ***\n"
            + "The fuzz-harness internal helpers (e.g., xmlFuzzReadInt, "
            + "AVCodecInternal, etc.) are NOT in the inventory and "
            + "therefore NOT useful as taint sources to return.  What "
            + "IS useful: trace what those helpers DO with the bytes "
            + "they read — typically they call a LIBRARY API like "
            + "xmlCtxtNewInputFromMemory / xmlReadMemory / avformat_open_input "
            + "/ avio_read with the attacker-controlled buffer.  THOSE "
            + "library API names are the boundary you should return — "
            + "and they DO appear in the inventory above.  Look "
            + "carefully at the harness for those calls.\n")
    sys_msg = ("You are a security researcher classifying input-boundary "
               "API functions of a C/C++ project from its fuzz harness, "
               "tests, and headers, restricted to names visible to the "
               "analysis pipeline (Call.facts inventory).")
    reply = _llm_call(sys_msg, user, max_tokens=6000)
    parsed = _extract_json(reply)
    if not parsed or "sources" not in parsed:
        print(f"[classifier] classification returned unparseable: "
              f"{reply[:200]}")
        return []
    out = []
    seen = set()
    for s in parsed["sources"]:
        name = (s.get("func") or "").strip()
        cat = (s.get("category") or "").strip()
        why = (s.get("rationale") or "").strip()
        if not name or not cat or name in seen:
            continue
        seen.add(name)
        out.append((name, cat, why))
    return out


# ── Phase C: Mechanical filter against Call.facts ────────────────────

def filter_against_call_facts(rows: list[tuple[str, str, str]],
                               call_facts_path: Path) -> list[tuple[str, str, str]]:
    """Drop functions that don't appear as a callee anywhere — likely
    classifier noise (functions named in headers but never wrapped)."""
    if not call_facts_path.exists():
        return rows  # no filter possible; trust the LLM
    callees = set()
    for line in call_facts_path.read_text().splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            callees.add(parts[1])
    kept = [r for r in rows if r[0] in callees]
    dropped = [r[0] for r in rows if r[0] not in callees]
    if dropped:
        print(f"[classifier] dropped {len(dropped)} callee-absent: "
              f"{dropped[:10]}{'...' if len(dropped) > 10 else ''}")
    return kept


# ── Top-level driver ─────────────────────────────────────────────────

def classify(eval_dir: Path, src_root: Path | None = None,
              dry_run: bool = False) -> dict:
    cfg_path = eval_dir / "project_config.json"
    if cfg_path.exists():
        try:
            cfg = json.loads(cfg_path.read_text())
        except Exception:
            cfg = {}
    else:
        cfg = {}
    if src_root is None:
        src_root_str = cfg.get("src_root") or str(eval_dir)
        src_root = Path(src_root_str).resolve()
    if not src_root.exists():
        print(f"[error] src_root does not exist: {src_root}")
        sys.exit(2)

    print(f"[classifier] eval_dir = {eval_dir}")
    print(f"[classifier] src_root = {src_root}")

    print("[classifier] phase A: discovery …")
    signal_paths = discover_signal_files(src_root)
    print(f"[classifier]   {len(signal_paths)} signal file(s):")
    for p in signal_paths:
        print(f"               {p.relative_to(src_root)}")
    log_step("classifier", "phase_a_done", str(eval_dir),
             f"signal_paths={len(signal_paths)}")

    call_facts = eval_dir / "facts" / "Call.facts"

    print("[classifier] phase B: classification …")
    raw_rows = classify_sources(src_root, signal_paths,
                                  call_facts_path=call_facts)
    print(f"[classifier]   raw LLM-classified: {len(raw_rows)} sources")

    print("[classifier] phase C: filter against Call.facts …")
    project_rows = filter_against_call_facts(raw_rows, call_facts)
    print(f"[classifier]   kept (callee-confirmed): {len(project_rows)}")

    # Merge with built-in libc set
    final_set = {(name, cat) for (name, cat, _) in project_rows}
    final_set.update(_BUILTIN_SOURCES)
    final_rows = sorted(final_set)

    out_path = eval_dir / "facts" / "TaintSourceFunc.facts"
    if dry_run:
        print(f"[classifier] DRY RUN — would write {len(final_rows)} rows "
              f"to {out_path}")
        for r in final_rows[:20]:
            print(f"               {r[0]}\\t{r[1]}")
        return {"final_rows": len(final_rows), "wrote": False,
                "path": str(out_path)}

    # Backup and write
    if out_path.exists():
        backup = out_path.with_suffix(".facts.bak")
        backup.write_bytes(out_path.read_bytes())
        print(f"[classifier]   backup → {backup.name}")
    with open(out_path, "w") as fp:
        for name, cat in final_rows:
            fp.write(f"{name}\t{cat}\n")
    print(f"[classifier] wrote {len(final_rows)} rows → {out_path}")
    log_step("classifier", "wrote_taint_sources", str(eval_dir),
             f"final={len(final_rows)} llm={len(project_rows)} "
             f"builtin={len(_BUILTIN_SOURCES)}")
    return {"final_rows": len(final_rows),
            "llm_classified": len(project_rows),
            "builtin": len(_BUILTIN_SOURCES),
            "wrote": True, "path": str(out_path)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("eval_dir")
    ap.add_argument("--src-root", default=None)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    eval_dir = Path(args.eval_dir).resolve()
    if not eval_dir.exists():
        print(f"[error] eval dir does not exist: {eval_dir}")
        return 2
    src_root = Path(args.src_root).resolve() if args.src_root else None
    classify(eval_dir, src_root=src_root, dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    sys.exit(main())

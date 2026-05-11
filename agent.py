# File: agent.py
# LLM-Datalog-QL — Datalog-powered source code analysis agent
# LLM extracts facts from C/C++ source, tree-sitter navigates, Souffle reasons.

import os
import sys
import json
import subprocess
import tempfile
import urllib.request
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Optional

# Ensure sibling modules are importable in both modes:
#   - Script mode:  python agent.py  (tree_sitter_nav is a top-level module)
#   - Package mode:  adk web / from LLM_Datalog_QL import root_agent
#     (tree_sitter_nav must be imported as LLM_Datalog_QL.tree_sitter_nav)
_PKG_DIR = str(Path(__file__).parent)
if _PKG_DIR not in sys.path:
    sys.path.insert(0, _PKG_DIR)


def _import(name: str):
    """Import a sibling module, trying package-relative first, then absolute."""
    import importlib
    pkg = __package__ or ""
    if pkg:
        try:
            return importlib.import_module(f".{name}", package=pkg)
        except ImportError:
            pass
    return importlib.import_module(name)

from dotenv import load_dotenv

from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool, ToolContext
from google.adk.models.lite_llm import LiteLlm

load_dotenv(override=True)

# =============================================================================
# Configuration
# =============================================================================
MODEL_NAME = os.getenv("MODEL_NAME", "anthropic/claude-sonnet-4-6")
# Sub-agents that don't need deep reasoning can use a cheaper model.
# Extraction + routing use LITE_MODEL; interpretation uses MODEL_NAME.
LITE_MODEL_NAME = os.getenv("LITE_MODEL_NAME", MODEL_NAME)

# Smart extraction routing: use batch API for jobs larger than this threshold
BATCH_THRESHOLD = int(os.getenv("BATCH_THRESHOLD", "5"))

PROJECT_DIR = Path(__file__).parent
RULES_DIR = PROJECT_DIR / "rules"
FACTS_DIR = PROJECT_DIR / "facts"
OUTPUT_DIR = PROJECT_DIR / "output"

# Context window budget: truncate tool returns to prevent ADK conversation overflow
# A ~1M context model ≈ 800K usable tokens; leave room for agent instruction + history
MAX_SOURCE_LINES_RETURN = int(os.getenv("MAX_SOURCE_LINES_RETURN", "300"))
MAX_FUNCTION_LINES_EXTRACT = int(os.getenv("MAX_FUNCTION_LINES_EXTRACT", "500"))


from agent_factory import resolve_api_key as _resolve_api_key_for_model
from agent_factory import create_model as _create_model_factory
from agent_factory import base_completion_kwargs as _base_completion_kwargs

# Phase C synthesis tool — exposed to InterpreterAgent so that a real-or-
# plausible candidate can be escalated to crash-input synthesis without
# leaving the agent loop. See INTERPRETER_INSTRUCTION for usage policy.
from crash_synth_agent import tool_synthesize_crash


def _resolve_api_key():
    """Pick the right API key for the active MODEL_NAME (or the lite
    sub-agent model if MODEL_NAME starts with `LITE_`). Delegates to
    agent_factory.resolve_api_key, which honours API_KEY,
    MODEL_API_KEY_ENV, and provider prefixes (incl. deepseek/)."""
    return _resolve_api_key_for_model()


def _use_batch_api() -> bool:
    """Check if batch API can be used (Anthropic model + SDK available)."""
    if not MODEL_NAME.startswith("anthropic/"):
        return False
    try:
        import anthropic  # noqa: F401
        return True
    except ImportError:
        return False


def create_model(lite: bool = False, thinking: Optional[str] = None):
    """Create a LiteLLM model instance via the shared factory.

    Args:
        lite:     If True, use LITE_MODEL_NAME (cheaper sub-agent model);
                  else MODEL_NAME (full model). Falls back to MODEL_NAME
                  if LITE_MODEL_NAME is unset.
        thinking: Per-agent thinking-mode override ("on" / "off" / None).
                  Takes precedence over the MODEL_THINKING env var.
                  Used to enable thinking on the low-volume reasoning
                  agents without globally enabling it for high-volume
                  smell-pass calls.

    The factory layers in MODEL_BASE_URL (api_base), MODEL_API_KEY_ENV,
    MODEL_EXTRA_BODY, MODEL_THINKING, prompt caching for anthropic/*,
    and the rest. See agent_factory.py for the full env contract.
    """
    return _create_model_factory(lite=lite, thinking=thinking)


# =============================================================================
# Extraction cache — avoid redundant LLM calls for the same project
# =============================================================================
import json
from datetime import datetime, timezone

EXTRACTION_META = FACTS_DIR / ".extraction_meta.json"


def _write_extraction_meta(project_dir: str, functions: list[str],
                           fact_kinds: list[str]):
    """Write metadata about the current extraction to facts/."""
    meta = {
        "project_dir": str(Path(project_dir).resolve()),
        "functions": sorted(functions),
        "fact_kinds": sorted(fact_kinds),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "model": MODEL_NAME,
    }
    FACTS_DIR.mkdir(parents=True, exist_ok=True)
    EXTRACTION_META.write_text(json.dumps(meta, indent=2))


def _read_extraction_meta() -> dict | None:
    """Read cached extraction metadata, or None if not present."""
    if EXTRACTION_META.exists():
        try:
            return json.loads(EXTRACTION_META.read_text())
        except (json.JSONDecodeError, OSError):
            return None
    return None


def _extraction_cache_valid(project_dir: str, functions: list[str]) -> tuple[bool, str]:
    """Check if cached extraction matches the requested project+functions.

    Returns (is_valid, reason_string).
    """
    meta = _read_extraction_meta()
    if meta is None:
        return False, "no cached extraction found"

    cached_path = meta.get("project_dir", "")
    requested_path = str(Path(project_dir).resolve())
    if cached_path != requested_path:
        return False, f"different project (cached: {Path(cached_path).name}, requested: {Path(requested_path).name})"

    cached_funcs = set(meta.get("functions", []))
    requested_funcs = set(functions)
    missing = requested_funcs - cached_funcs
    if missing:
        return False, f"{len(missing)} new functions not in cache: {sorted(missing)[:5]}"

    # Check that .facts files actually exist on disk
    fact_files = list(FACTS_DIR.glob("*.facts"))
    if len(fact_files) < 3:
        return False, f"only {len(fact_files)} .facts files on disk (corrupted cache?)"

    ts = meta.get("timestamp", "unknown")
    return True, f"cache valid (extracted {ts}, {len(cached_funcs)} functions, {len(fact_files)} fact files)"


# =============================================================================
# Tool: Clean workspace
# =============================================================================
def tool_clean_workspace(
    clean_facts: bool = True,
    clean_output: bool = True,
) -> dict:
    """Remove stale .facts and .csv files to start a fresh analysis.

    Call this before beginning a new analysis session to ensure no stale
    data from previous runs contaminates results.

    Args:
        clean_facts: If True, remove all .facts files from facts/ dir.
        clean_output: If True, remove all .csv files from output/ dir.

    Returns:
        Dict with counts of removed files.
    """
    removed = {"facts": 0, "output": 0}
    if clean_facts:
        for f in FACTS_DIR.glob("*.facts"):
            f.unlink()
            removed["facts"] += 1
        # Also clear extraction metadata when facts are cleaned
        if EXTRACTION_META.exists():
            EXTRACTION_META.unlink()
    if clean_output:
        for f in OUTPUT_DIR.glob("*.csv"):
            f.unlink()
            removed["output"] += 1
    return removed


# =============================================================================
# Tool: Scan project — enumerate functions, find sinks
# =============================================================================
def tool_scan_project(
    project_dir: str,
    extensions: str = ".c",
) -> dict:
    """Scan a C/C++ project directory to discover functions and dangerous sinks.

    Uses tree-sitter (no compilation required) to enumerate all functions,
    build a call graph, and identify functions calling dangerous sinks
    (memcpy, strcpy, free, malloc, read, sprintf, etc.).

    Args:
        project_dir: Path to the source code directory.
        extensions: Comma-separated file extensions (default: ".c").

    Returns:
        Dict with functions, call_graph, dangerous_sinks, and summary.
    """
    _tsn = _import("tree_sitter_nav")
    enumerate_functions = _tsn.enumerate_functions
    build_call_graph = _tsn.build_call_graph
    find_dangerous_sinks = _tsn.find_dangerous_sinks

    exts = tuple(e.strip() for e in extensions.split(","))
    funcs = enumerate_functions(project_dir, exts)
    cg = build_call_graph(project_dir, exts)
    sinks = find_dangerous_sinks(project_dir, exts)

    func_list = [
        {"name": f.name, "file": f.file_path,
         "lines": f"{f.start_line}-{f.end_line}",
         "params": f.params}
        for f in funcs
    ]

    cg_simple = {k: sorted(v) for k, v in cg.items()}

    # For large projects, return compact summaries to avoid context overflow
    if len(func_list) > 50:
        # Group by file, show counts per file + only sink-related functions in detail
        file_groups = {}
        for f in func_list:
            file_groups.setdefault(f["file"], []).append(f["name"])
        file_summary = {fp: {"count": len(names), "functions": names[:10],
                             "truncated": len(names) > 10}
                        for fp, names in file_groups.items()}
        return {
            "function_count": len(func_list),
            "files": file_summary,
            "call_graph_edges": sum(len(v) for v in cg_simple.values()),
            "dangerous_sinks": sinks,
            "sink_count": len(sinks),
            "note": (f"Large project ({len(func_list)} functions). "
                     f"Function list grouped by file (first 10 per file shown). "
                     f"Use tool_build_slice() to identify the targeted analysis set."),
        }

    return {
        "functions": func_list,
        "function_count": len(func_list),
        "call_graph": cg_simple,
        "dangerous_sinks": sinks,
        "sink_count": len(sinks),
    }


# =============================================================================
# Tool: Build backward slice from sinks
# =============================================================================
def tool_build_slice(
    project_dir: str,
    sink_functions: list[str] = None,
    depth: int = 3,
    extensions: str = ".c",
) -> dict:
    """Build a backward slice from dangerous sinks up to `depth` caller levels.

    Identifies which functions are reachable from sinks, going backwards
    through the call graph. Use this to determine the set of functions
    that need LLM fact extraction.

    Args:
        project_dir: Path to source code directory.
        sink_functions: Specific functions to trace from. If None, auto-detect
                        functions calling dangerous sinks (memcpy, free, etc.).
        depth: How many caller levels to trace backward (default: 3).
        extensions: Comma-separated file extensions.

    Returns:
        Dict with the sliced function list and their file locations.
    """
    slice_from_sinks = _import("tree_sitter_nav").slice_from_sinks

    exts = tuple(e.strip() for e in extensions.split(","))
    sliced = slice_from_sinks(project_dir, sink_functions, depth, exts)

    return {
        "slice": [
            {"name": f.name, "file": f.file_path,
             "lines": f"{f.start_line}-{f.end_line}",
             "params": f.params}
            for f in sliced
        ],
        "function_count": len(sliced),
    }


# =============================================================================
# Tool: Read source code
# =============================================================================
def tool_read_source(
    file_path: str,
    func_name: str = "",
    start_line: int = 0,
    end_line: int = 0,
) -> dict:
    """Read source code from a file, optionally extracting a specific function.

    Args:
        file_path: Path to the source file.
        func_name: If provided, extract just this function's source.
        start_line: Read from this line (1-indexed). 0 = beginning.
        end_line: Read up to this line. 0 = end of file.

    Returns:
        Dict with source code and line range.
    """
    if func_name:
        get_function_with_lines = _import("tree_sitter_nav").get_function_with_lines
        result = get_function_with_lines(file_path, func_name)
        if result:
            return {"source": result[0], "start_line": result[1],
                    "function": func_name, "file": file_path}
        return {"error": f"Function '{func_name}' not found in {file_path}"}

    p = Path(file_path)
    if not p.exists():
        return {"error": f"File not found: {file_path}"}

    lines = p.read_text().split('\n')
    total_lines = len(lines)
    start = max(0, start_line - 1) if start_line > 0 else 0
    end = end_line if end_line > 0 else total_lines
    selected = lines[start:end]

    # Truncate to prevent context window overflow in ADK conversation
    truncated = False
    if len(selected) > MAX_SOURCE_LINES_RETURN:
        selected = selected[:MAX_SOURCE_LINES_RETURN]
        truncated = True

    numbered = []
    for i, line in enumerate(selected):
        numbered.append(f"{start + i + 1:4d}| {line}")

    result = {"source": '\n'.join(numbered), "start_line": start + 1,
              "end_line": start + len(selected), "total_lines": total_lines,
              "file": file_path}
    if truncated:
        result["truncated"] = True
        result["warning"] = (
            f"File has {total_lines} lines — showing first {MAX_SOURCE_LINES_RETURN}. "
            f"Use start_line/end_line to read specific ranges, or func_name to "
            f"extract a specific function."
        )
    return result


# =============================================================================
# Tool: LLM fact extraction for a single function
# =============================================================================
def tool_extract_facts_llm(
    file_path: str,
    func_name: str,
) -> dict:
    """Extract Datalog facts from a C function using the LLM.

    The LLM reads the function source code and outputs structured facts
    (Def, Use, Call, ActualArg, MemRead, MemWrite, Guard, Cast, etc.)
    that are written as Souffle .facts TSV files.

    Facts are APPENDED to existing .facts files (accumulative extraction).
    Call tool_clean_workspace first if you want a fresh start.

    No compilation required — the LLM understands the code directly.

    Args:
        file_path: Path to the C source file.
        func_name: Name of the function to extract facts from.

    Returns:
        Dict with extraction summary: fact counts per kind, total facts.
    """
    get_function_with_lines = _import("tree_sitter_nav").get_function_with_lines
    _extract = _import("llm_extractor").extract_facts_llm
    write_facts = _import("fact_schema").write_facts

    result = get_function_with_lines(file_path, func_name)
    if not result:
        return {"error": f"Function '{func_name}' not found in {file_path}"}

    source, start_line = result
    source_lines = source.split('\n')

    # Large function chunking: split into overlapping chunks to stay within
    # the LLM context window. Each chunk gets extracted separately and facts
    # are merged.  Overlap ensures no facts are lost at chunk boundaries.
    if len(source_lines) > MAX_FUNCTION_LINES_EXTRACT:
        chunk_size = MAX_FUNCTION_LINES_EXTRACT
        overlap = 30  # lines of overlap between chunks
        facts = []
        chunk_idx = 0
        pos = 0
        while pos < len(source_lines):
            chunk_end = min(pos + chunk_size, len(source_lines))
            chunk = '\n'.join(source_lines[pos:chunk_end])
            chunk_idx += 1
            print(f"  [chunk {chunk_idx}] lines {pos+1}-{chunk_end} of {len(source_lines)}")
            try:
                chunk_facts = _extract(
                    function_source=chunk,
                    func_name=func_name,
                    file_path=file_path,
                    model=MODEL_NAME,
                    api_key=_resolve_api_key(),
                )
                facts.extend(chunk_facts)
            except Exception as e:
                print(f"  [chunk {chunk_idx} ERROR] {e}")
            pos = chunk_end - overlap if chunk_end < len(source_lines) else chunk_end

        # Deduplicate facts (same kind+func+addr+fields)
        seen = set()
        unique_facts = []
        for f in facts:
            key = (f.kind, f.func, f.addr, tuple(sorted(f.fields.items())))
            if key not in seen:
                seen.add(key)
                unique_facts.append(f)
        facts = unique_facts
    else:
        facts = _extract(
            function_source=source,
            func_name=func_name,
            file_path=file_path,
            model=MODEL_NAME,
            api_key=_resolve_api_key(),
        )

    stats = write_facts(facts, FACTS_DIR, append=True)

    # Verify files were actually written (catch silent extraction failures)
    verified = {}
    for filename, count in stats.items():
        fpath = FACTS_DIR / filename
        actual_lines = len(fpath.read_text().strip().splitlines()) if fpath.exists() else 0
        verified[filename] = actual_lines

    # Summarize by kind
    kind_counts = {}
    for f in facts:
        kind_counts[f.kind.value] = kind_counts.get(f.kind.value, 0) + 1

    total_on_disk = sum(verified.values())
    result = {
        "function": func_name,
        "file": file_path,
        "total_facts": len(facts),
        "facts_by_kind": kind_counts,
        "files_written": stats,
        "facts_on_disk": verified,
        "total_on_disk": total_on_disk,
    }
    if total_on_disk == 0 and len(facts) > 0:
        result["warning"] = (
            f"WRITE FAILURE: {len(facts)} facts extracted but 0 written to disk. "
            f"Check fact_schema.py extractor lambdas for KeyError on fields."
        )
    return result


# =============================================================================
# Tool: Extract facts for all functions in a slice
# =============================================================================
def tool_extract_slice(
    project_dir: str,
    function_names: list[str] = None,
    depth: int = 3,
    extensions: str = ".c",
) -> dict:
    """Extract LLM facts for a targeted slice of functions.

    If function_names is provided, extracts facts for those specific functions.
    Otherwise, auto-discovers via backward slicing from dangerous sinks.

    Automatically routes extraction for efficiency:
    - Small jobs (≤5 functions): synchronous sequential (fast turnaround)
    - Large jobs (>5 functions, Anthropic model): Anthropic Batch API
      (50% cheaper, no rate limits, processes asynchronously)
    - Large jobs (non-Anthropic model): synchronous sequential fallback

    The threshold is configurable via BATCH_THRESHOLD env var (default: 5).

    Args:
        project_dir: Path to source code directory.
        function_names: Explicit list of functions to extract. If None, auto-slice.
        depth: Backward slice depth (default: 3).
        extensions: Comma-separated file extensions.

    Returns:
        Dict with per-function extraction results and totals.
    """
    _tsn = _import("tree_sitter_nav")
    enumerate_functions = _tsn.enumerate_functions
    slice_from_sinks = _tsn.slice_from_sinks
    get_function_with_lines = _tsn.get_function_with_lines
    write_facts = _import("fact_schema").write_facts

    exts = tuple(e.strip() for e in extensions.split(","))

    # Determine target functions
    if function_names:
        all_funcs = enumerate_functions(project_dir, exts)
        func_map = {f.name: f for f in all_funcs}
        targets = [func_map[n] for n in function_names if n in func_map]
        missing = [n for n in function_names if n not in func_map]
    else:
        targets = slice_from_sinks(project_dir, depth=depth, extensions=exts)
        missing = []

    # Collect function sources
    func_sources = []
    skipped = []
    for func_info in targets:
        src_result = get_function_with_lines(func_info.file_path, func_info.name)
        if not src_result:
            skipped.append({"name": func_info.name, "error": "Could not extract source"})
            continue
        source, start_line = src_result
        func_sources.append({
            "name": func_info.name,
            "source": source,
            "file_path": func_info.file_path,
            "file_stem": Path(func_info.file_path).stem,
            "start_line": start_line,
        })

    # Route: batch API for large Anthropic jobs, sequential otherwise
    use_batch = (
        len(func_sources) > BATCH_THRESHOLD
        and _use_batch_api()
    )

    if use_batch:
        all_facts, results, mode = _extract_batch(func_sources, write_facts)
    else:
        all_facts, results, mode = _extract_sequential(func_sources, write_facts)

    results.extend(skipped)

    # Verify disk state
    verified = {}
    for f in FACTS_DIR.glob("*.facts"):
        actual_lines = len(f.read_text().strip().splitlines()) if f.stat().st_size > 0 else 0
        verified[f.name] = actual_lines

    total_on_disk = sum(verified.values())

    # Compact per-function results: only name, fact count, and errors
    compact_results = []
    for r in results:
        entry = {"name": r.get("name", "?")}
        if "facts" in r:
            entry["facts"] = r["facts"]
        if "error" in r:
            entry["error"] = r["error"]
        compact_results.append(entry)

    result_dict = {
        "extraction_mode": mode,
        "functions_extracted": len([r for r in results if "facts" in r]),
        "total_facts": len(all_facts),
        "per_function": compact_results,
        "facts_on_disk": verified,
        "total_on_disk": total_on_disk,
        "missing_functions": missing,
    }
    if total_on_disk == 0 and len(all_facts) > 0:
        result_dict["warning"] = (
            f"WRITE FAILURE: {len(all_facts)} facts extracted but 0 written to disk. "
            f"Check fact_schema.py extractor lambdas for KeyError on fields."
        )
    return result_dict


def _extract_sequential(func_sources: list[dict], write_facts) -> tuple:
    """Sequential LLM extraction (for small jobs or non-Anthropic models)."""
    _extract = _import("llm_extractor").extract_facts_llm
    results = []
    all_facts = []

    for fs in func_sources:
        entry = {"name": fs["name"], "file": fs["file_path"]}
        source_lines = fs["source"].split('\n')
        try:
            if len(source_lines) > MAX_FUNCTION_LINES_EXTRACT:
                # Chunk large functions
                facts = _extract_chunked(
                    _extract, fs["source"], fs["name"], fs["file_path"])
            else:
                facts = _extract(
                    function_source=fs["source"],
                    func_name=fs["name"],
                    file_path=fs["file_path"],
                    model=MODEL_NAME,
                    api_key=_resolve_api_key(),
                    facts_dir=FACTS_DIR,
                )
            entry["facts"] = len(facts)
            all_facts.extend(facts)
        except Exception as e:
            entry["error"] = str(e)
        results.append(entry)

    if all_facts:
        write_facts(all_facts, FACTS_DIR, append=True)

    return all_facts, results, "sequential"


def _extract_chunked(extract_fn, source: str, func_name: str, file_path: str) -> list:
    """Extract facts from a large function by splitting into overlapping chunks."""
    source_lines = source.split('\n')
    chunk_size = MAX_FUNCTION_LINES_EXTRACT
    overlap = 30
    facts = []
    chunk_idx = 0
    pos = 0
    while pos < len(source_lines):
        chunk_end = min(pos + chunk_size, len(source_lines))
        chunk = '\n'.join(source_lines[pos:chunk_end])
        chunk_idx += 1
        print(f"  [chunk {chunk_idx}] {func_name}: lines {pos+1}-{chunk_end} of {len(source_lines)}")
        try:
            chunk_facts = extract_fn(
                function_source=chunk,
                func_name=func_name,
                file_path=file_path,
                model=MODEL_NAME,
                api_key=_resolve_api_key(),
                facts_dir=FACTS_DIR,
            )
            facts.extend(chunk_facts)
        except Exception as e:
            print(f"  [chunk {chunk_idx} ERROR] {e}")
        pos = chunk_end - overlap if chunk_end < len(source_lines) else chunk_end

    # Deduplicate
    seen = set()
    unique = []
    for f in facts:
        key = (f.kind, f.func, f.addr, tuple(sorted(f.fields.items())))
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def _extract_batch(func_sources: list[dict], write_facts) -> tuple:
    """Batch API extraction (for large Anthropic jobs — 50% cheaper)."""
    from batch_extractor import (
        prepare_batch_requests, submit_batch, poll_batch, retrieve_results,
    )

    requests = prepare_batch_requests(func_sources, facts_dir=FACTS_DIR)
    batch_id = submit_batch(requests)
    status = poll_batch(batch_id)

    if status["status"] != "ended":
        # Fallback to sequential if batch fails
        return _extract_sequential(func_sources, write_facts)

    results_by_file = retrieve_results(batch_id)

    # Flatten all facts and write to FACTS_DIR
    all_facts = []
    results = []
    for fs in func_sources:
        file_stem = fs["file_stem"]
        func_name = fs["name"]
        file_facts = results_by_file.get(file_stem, [])
        # Filter to this function's facts
        func_facts = [f for f in file_facts if f.func == func_name]
        entry = {"name": func_name, "file": fs["file_path"], "facts": len(func_facts)}
        results.append(entry)
        all_facts.extend(func_facts)

    if all_facts:
        write_facts(all_facts, FACTS_DIR, append=True)

    mode = f"batch (id={batch_id}, {status.get('succeeded', 0)} succeeded)"
    return all_facts, results, mode


# =============================================================================
# Tool: Mechanical + smell-pass extraction (the new floor + ceiling pipeline)
# =============================================================================
def tool_extract_mechanical_with_smell(
    project_dir: str,
    function_names: list[str] = None,
    extensions: str = ".c",
    smell_concurrency: int = 15,
    skip_smell: bool = False,
    fallback_on_low_confidence: bool = True,
) -> dict:
    """Mechanical floor + LLM smell pass.

    Step 1 (mechanical): tree-sitter walks the AST and emits ~16 fact kinds
    deterministically. Zero LLM cost; cannot truncate.
    Step 2 (smell pass): per-function LLM call reviews the source against
    the mechanical facts and returns a small structured residual
    (additions / corrections / flags / wrappers / coverage_confidence).
    Step 3 (reconcile): merge into the fact base, dedup, write
    LLMFlag.facts and Is{Validator,Allocator,Free,TaintSource,TaintSink}.facts
    for Datalog consumption.
    Step 4 (low-confidence retry): for functions where the smell pass
    flagged low coverage, fall back to the legacy LLM extractor (full
    fact extraction with chunking) — we trust the floor everywhere
    *except* where the LLM itself says it isn't sure.

    Args:
        project_dir: Path to source tree.
        function_names: Targets. If None, uses backward slice from sinks.
        extensions: File extensions to scan (default .c).
        smell_concurrency: Parallel smell-pass calls (default 15).
        skip_smell: If True, write only the mechanical facts (debugging).
        fallback_on_low_confidence: If True, re-extract low-coverage
            functions via the legacy LLM extractor.

    Returns:
        Compact summary with phase stats and per-function fact counts.
    """
    import asyncio

    _tsn = _import("tree_sitter_nav")
    enumerate_functions = _tsn.enumerate_functions
    slice_from_sinks = _tsn.slice_from_sinks
    get_function_with_lines = _tsn.get_function_with_lines

    write_facts = _import("fact_schema").write_facts
    mech = _import("mechanical_extractor")
    smell_mod = _import("smell_pass")

    exts = tuple(e.strip() for e in extensions.split(","))

    if function_names:
        all_funcs = enumerate_functions(project_dir, exts)
        func_map = {f.name: f for f in all_funcs}
        targets = [func_map[n] for n in function_names if n in func_map]
        missing = [n for n in function_names if n not in func_map]
    else:
        targets = slice_from_sinks(project_dir, depth=3, extensions=exts)
        missing = []

    func_sources = []
    skipped = []
    for fi in targets:
        sr = get_function_with_lines(fi.file_path, fi.name)
        if not sr:
            skipped.append({"name": fi.name, "error": "no source"})
            continue
        source, start_line = sr
        func_sources.append({
            "name": fi.name,
            "source": source,
            "file_path": fi.file_path,
            "start_line": start_line,
        })

    # ── Phase 1: mechanical ──────────────────────────────────────────────
    mech_facts_by_func: dict[str, list] = {}
    all_mech_facts: list = []
    for fs in func_sources:
        try:
            facts = mech.extract_facts(fs["file_path"], fs["name"])
        except Exception as e:
            facts = []
            skipped.append({"name": fs["name"], "error": f"mech: {e}"})
        mech_facts_by_func[fs["name"]] = facts
        all_mech_facts.extend(facts)

    print(f"  [extract-v2] mechanical: {len(all_mech_facts)} facts "
          f"across {len(mech_facts_by_func)} functions")

    # ── Phase 2: smell pass (parallel) ──────────────────────────────────
    smell_results: dict = {}
    if not skip_smell:
        async def _run_all_smell():
            sem = asyncio.Semaphore(smell_concurrency)
            tasks = []
            for fs in func_sources:
                name = fs["name"]
                mech_facts = mech_facts_by_func.get(name, [])
                tasks.append(smell_mod.smell_function_async(
                    function_source=fs["source"],
                    func_name=name,
                    mech_facts=mech_facts,
                    file_path=fs["file_path"],
                    semaphore=sem,
                ))
            return await asyncio.gather(*tasks, return_exceptions=True)

        try:
            smell_mod.reset_session()
            results_list = asyncio.run(_run_all_smell())
            for fs, r in zip(func_sources, results_list):
                if isinstance(r, Exception):
                    print(f"    [smell-error] {fs['name']}: {r}")
                    continue
                smell_results[fs["name"]] = r
        except Exception as e:
            print(f"  [extract-v2] smell pass FAILED: {e}")

        smell_summary = smell_mod.session_summary()
        print(f"  [extract-v2] smell: {smell_summary}")

    # ── Phase 3: low-confidence fallback to legacy LLM ──────────────────
    legacy_recovered = []
    if fallback_on_low_confidence and smell_results:
        low_conf = [
            fs for fs in func_sources
            if smell_results.get(fs["name"]) and
               smell_results[fs["name"]].coverage_confidence == "low"
        ]
        if low_conf:
            print(f"  [extract-v2] low-coverage retry: {len(low_conf)} functions")
            _legacy = _import("llm_extractor").extract_facts_llm
            for fs in low_conf:
                try:
                    extra = _legacy(
                        function_source=fs["source"],
                        func_name=fs["name"],
                        file_path=fs["file_path"],
                        model=MODEL_NAME,
                        api_key=_resolve_api_key(),
                        facts_dir=FACTS_DIR,
                    )
                    mech_facts_by_func[fs["name"]].extend(extra)
                    all_mech_facts.extend(extra)
                    legacy_recovered.append({"name": fs["name"], "facts": len(extra)})
                except Exception as e:
                    print(f"    [legacy-error] {fs['name']}: {e}")

    # ── Phase 4: reconcile ──────────────────────────────────────────────
    final_facts, flags, wrappers = smell_mod.reconcile(all_mech_facts, smell_results)

    # ── Phase 5: write ──────────────────────────────────────────────────
    write_facts(final_facts, FACTS_DIR, append=False)
    smell_mod.write_llm_relations(flags, wrappers, FACTS_DIR)

    # ── Disk verification ───────────────────────────────────────────────
    verified = {}
    for f in FACTS_DIR.glob("*.facts"):
        verified[f.name] = (
            len(f.read_text().strip().splitlines()) if f.stat().st_size > 0 else 0)
    total_on_disk = sum(verified.values())

    per_function = []
    for fs in func_sources:
        n = fs["name"]
        sr = smell_results.get(n)
        per_function.append({
            "name": n,
            "mech_facts": len(mech_facts_by_func.get(n, [])),
            "smell_additions": len(sr.additions) if sr else 0,
            "smell_corrections": len(sr.corrections) if sr else 0,
            "smell_flags": len(sr.flags) if sr else 0,
            "coverage": sr.coverage_confidence if sr else "n/a",
        })

    return {
        "extraction_mode": "mechanical+smell",
        "functions_extracted": len(func_sources),
        "total_facts": len(final_facts),
        "facts_on_disk": verified,
        "total_on_disk": total_on_disk,
        "missing_functions": missing,
        "skipped": skipped,
        "smell_summary": smell_mod.session_summary() if not skip_smell else None,
        "legacy_recovered": legacy_recovered,
        "flags_emitted": len(flags),
        "wrappers_emitted": len(wrappers),
        "per_function": per_function,
    }


# =============================================================================
# Tool: Run Souffle Datalog query
# =============================================================================
def tool_run_souffle(
    rule_file: str = "",
    custom_rules: str = "",
    timeout_seconds: int = 30,
) -> dict:
    """Run a Souffle Datalog query against extracted facts.

    You can either:
    1. Run an existing rule file from rules/ (e.g. "taint.dl", "interproc.dl")
    2. Provide custom Datalog rules as a string

    Args:
        rule_file: Name of a rule file in rules/ dir (e.g., "interproc.dl").
                   Ignored if custom_rules is provided.
        custom_rules: Custom Souffle Datalog program as a string.
        timeout_seconds: Max execution time (default 30s).

    Returns:
        Dict with output files and their contents.
    """
    _run = _import("souffle_runner").run_souffle
    return _run(
        rule_file=rule_file if not custom_rules else None,
        custom_rules=custom_rules or None,
        facts_dir=FACTS_DIR,
        output_dir=OUTPUT_DIR,
        timeout=timeout_seconds,
    )


# =============================================================================
# Tool: Two-pass taint pipeline (alias → interproc)
# =============================================================================
def tool_run_taint_pipeline(
    timeout_seconds: int = 60,
) -> dict:
    """Run the full taint analysis pipeline: alias → interprocedural taint.

    Pass 1: Runs alias.dl to compute PointsTo facts (pointer analysis).
    Pass 2: Copies PointsTo to facts dir, runs interproc.dl with alias-enhanced
             1-CFA context-sensitive interprocedural taint tracking.

    Args:
        timeout_seconds: Max execution time per pass.

    Returns:
        Dict with results from both passes and combined output files.
    """
    _pipeline = _import("souffle_runner").run_taint_pipeline
    return _pipeline(facts_dir=FACTS_DIR, output_dir=OUTPUT_DIR, timeout=timeout_seconds)


# =============================================================================
# Tool: List available Datalog files
# =============================================================================
def tool_run_datalog_query(
    rule_text: str,
    facts_dir: str = "",
    output_relations: str = "",
    extra_inputs_json: str = "",
    timeout_seconds: int = 60,
) -> dict:
    """Run an ad-hoc Datalog query against an existing facts directory.

    This is the agent-side hook for hypothesis-driven follow-up
    analysis: read a finding from the precomputed catalog, form a
    follow-up question, and fire a narrowly-scoped Datalog query
    that grounds the next claim in mechanically-checkable evidence.
    Errors are returned in structured form (souffle stderr plus a
    line-numbered echo of the rule text) so you can fix the rule
    and retry without having to re-count lines from souffle's
    file:line:col diagnostics.

    Args:
        rule_text: Full .dl source. You MUST declare every input
                   relation you consume via `.decl X(...)` followed
                   by `.input X` (souffle does not auto-bind to
                   facts dirs). Likewise, every relation in
                   `output_relations` needs a corresponding
                   `.output Foo` directive.
        facts_dir: Directory containing the existing .facts files
                   (default: the project's facts/ dir).
        output_relations: Comma-separated names of derived relations
                   to read back, e.g. "MyResult,Aux".
        extra_inputs_json: Optional JSON object mapping
                   `{relation_name: path_to_csv_or_facts}` for
                   staging pre-derived relations from a previous
                   pipeline run as additional `.input` sources
                   (e.g. `{"ResolvedVarType":
                   "eval/results/.../output/ResolvedVarType.csv"}`).
                   Without this you can only read raw facts; with
                   it you can also query everything Souffle wrote
                   to output/ on the last batch run.
        timeout_seconds: Per-query timeout (default 60s).

    Returns:
        One of:
          status="ok": {outputs: {rel: {rows, row_count, truncated}}}
          status="error": {souffle_stderr, rule_text_with_line_numbers}
          status="timeout": {timeout_seconds, elapsed_seconds}
          status="no_outputs": {souffle_stderr, outputs (empty)}
        See dl_runtime.compose_and_run for full schema.
    """
    dlrt = _import("dl_runtime")
    rels = [s.strip() for s in (output_relations or "").split(",") if s.strip()]
    if not rels:
        return {
            "status": "error",
            "souffle_stderr": "output_relations must list at least one "
                              "relation (e.g. 'MyResult')",
            "souffle_stdout": "",
            "rule_text_with_line_numbers": "",
            "elapsed_seconds": 0.0,
        }
    extra: dict = {}
    if extra_inputs_json:
        try:
            extra = json.loads(extra_inputs_json)
        except (json.JSONDecodeError, ValueError):
            return {
                "status": "error",
                "souffle_stderr": (f"extra_inputs_json is not valid JSON: "
                                   f"{extra_inputs_json[:200]}"),
                "souffle_stdout": "",
                "rule_text_with_line_numbers": "",
                "elapsed_seconds": 0.0,
            }
    fdir = facts_dir or str(FACTS_DIR)
    return dlrt.compose_and_run(
        rule_text=rule_text,
        facts_dir=fdir,
        output_relations=rels,
        timeout_seconds=timeout_seconds,
        extra_inputs=extra or None,
    )


def tool_list_datalog_files() -> dict:
    """List available Datalog rule files and fact files with their schemas.

    Returns:
        Dict with rule files (with sizes) and fact files (with row counts and columns).
    """
    _fs = _import("fact_schema")
    SCHEMA_DOCS = _fs.SCHEMA_DOCS
    RELATION_SCHEMA = _fs.RELATION_SCHEMA

    file_columns = {}
    for kind_str, cols in SCHEMA_DOCS.items():
        schema = RELATION_SCHEMA.get(kind_str)
        if schema:
            file_columns[schema[0]] = cols

    rules = []
    for f in sorted(RULES_DIR.glob("*.dl")):
        rules.append({"name": f.name, "size_bytes": f.stat().st_size})

    facts = []
    for f in sorted(FACTS_DIR.glob("*.facts")):
        lines = f.read_text().strip().count('\n') + 1 if f.stat().st_size > 0 else 0
        entry = {"name": f.name, "rows": lines}
        if f.name in file_columns:
            entry["columns"] = file_columns[f.name]
        facts.append(entry)

    return {"rules": rules, "facts": facts}


# =============================================================================
# Tool: Read a rule, fact, or output file
# =============================================================================
def tool_read_file(file_path: str) -> dict:
    """Read contents of a rule file, fact file, or output file.

    Args:
        file_path: Path relative to project dir (e.g., "rules/interproc.dl",
                   "output/TaintedSink.csv", "facts/Call.facts").
    """
    p = Path(file_path)
    if not p.is_absolute():
        p = PROJECT_DIR / p

    if not p.exists():
        return {"error": f"File not found: {p}"}

    # If a directory is given, return its listing instead of crashing
    # (the agent often probes the eval_dir to discover what's there).
    if p.is_dir():
        try:
            entries = sorted(p.iterdir())
        except Exception as e:
            return {"error": f"Cannot list directory {p}: {e}"}
        return {
            "path": str(p), "is_directory": True,
            "entries": [
                {"name": e.name,
                 "is_dir": e.is_dir(),
                 "size": (e.stat().st_size if e.is_file() else None)}
                for e in entries
            ],
            "hint": (f"{p} is a directory. To read a file inside, "
                     f"call tool_read_file with the full path "
                     f"(e.g., '{p}/<filename>')."),
        }

    try:
        content = p.read_text()
    except UnicodeDecodeError:
        return {"error": f"{p} is not text-readable (binary file?)"}
    except Exception as e:
        return {"error": f"Cannot read {p}: {e}"}
    lines = content.split('\n')
    total_lines = len(lines)

    # Cap content returned to prevent context overflow
    max_lines = MAX_SOURCE_LINES_RETURN
    if total_lines > max_lines:
        content = '\n'.join(lines[:max_lines])
        return {
            "path": str(p), "size_bytes": p.stat().st_size,
            "total_lines": total_lines, "showing": max_lines,
            "content": content,
            "truncated": True,
            "hint": f"Showing first {max_lines} of {total_lines} lines. "
                    f"Full file at: {p}",
        }
    return {"path": str(p), "size_bytes": p.stat().st_size,
            "total_lines": total_lines, "content": content}


# =============================================================================
# Tool: Generate source/sink annotations
# =============================================================================

_BUILTIN_SINKS = [
    ("memcpy", 0, "buffer_overflow_dst"),
    ("memcpy", 2, "buffer_overflow_size"),
    ("memmove", 0, "buffer_overflow_dst"),
    ("memmove", 2, "buffer_overflow_size"),
    ("strcpy", 0, "buffer_overflow_dst"),
    ("strncpy", 0, "buffer_overflow_dst"),
    ("strcat", 0, "buffer_overflow_dst"),
    ("sprintf", 0, "format_buffer_overflow"),
    ("snprintf", 0, "format_buffer_overflow"),
    ("system", 0, "command_injection"),
    ("execve", 0, "command_injection"),
    ("free", 0, "double_free"),
]

_BUILTIN_SOURCES = [
    ("read", "external"),
    ("recv", "external"),
    ("recvfrom", "external"),
    ("fread", "external"),
    ("fgets", "external"),
    ("gets", "external"),
    ("getenv", "external"),
    ("getline", "external"),
    ("scanf", "external"),
    ("recvmsg", "external"),
]


def tool_generate_annotations(
    extra_sources: list[dict] = None,
    extra_sinks: list[dict] = None,
) -> dict:
    """Generate DangerousSink.facts and TaintSourceFunc.facts from built-in catalogs.

    These fact files are used by interproc.dl for taint sink/source detection.
    Extend the catalogs with project-specific entries.

    Args:
        extra_sources: Optional list of {"func": str, "category": str}.
        extra_sinks: Optional list of {"func": str, "arg_idx": int, "risk": str}.

    Returns:
        Dict with counts of sink and source facts written.
    """
    FACTS_DIR.mkdir(parents=True, exist_ok=True)

    sink_rows = set()
    for func, idx, risk in _BUILTIN_SINKS:
        sink_rows.add((func, str(idx), risk))
    if extra_sinks:
        for s in extra_sinks:
            sink_rows.add((s["func"], str(s["arg_idx"]), s["risk"]))

    sink_path = FACTS_DIR / "DangerousSink.facts"
    with open(sink_path, 'w') as fp:
        for row in sorted(sink_rows):
            fp.write('\t'.join(row) + '\n')

    source_rows = set()
    for func, cat in _BUILTIN_SOURCES:
        source_rows.add((func, cat))
    if extra_sources:
        for s in extra_sources:
            source_rows.add((s["func"], s["category"]))

    source_path = FACTS_DIR / "TaintSourceFunc.facts"
    with open(source_path, 'w') as fp:
        for row in sorted(source_rows):
            fp.write('\t'.join(row) + '\n')

    return {
        "sinks": len(sink_rows),
        "sources": len(source_rows),
        "sink_path": str(sink_path),
        "source_path": str(source_path),
    }


# =============================================================================
# Tool: Generate CFG / basic-block facts from tree-sitter
# =============================================================================
def tool_generate_cfg(
    project_dir: str,
    function_names: list[str] = None,
    extensions: str = ".c",
) -> dict:
    """Compute CFGEdge / BlockHead / CFGBlockEdge / OpaqueCallSite facts
    deterministically from the C AST.

    Replaces LLM-emitted CFGEdge for the bulk of mechanical control flow.
    The LLM still resolves opaque sites (control-flow macros, longjmp,
    inline asm) by reading OpaqueCallSite.facts during extraction.

    Args:
        project_dir: Path to the source code directory.
        function_names: If provided, restrict CFG generation to these
                        functions. Otherwise process all functions in scope.
        extensions: Comma-separated file extensions (default: ".c").

    Returns:
        Dict with row counts per generated fact relation.
    """
    _generate = _import("tree_sitter_cfg").generate_cfg_facts_for_project
    ext_tuple = tuple(e.strip() if e.startswith(".") else f".{e.strip()}"
                      for e in extensions.split(","))
    return _generate(
        project_dir,
        func_names=function_names,
        facts_dir=FACTS_DIR,
        extensions=ext_tuple,
    )


# =============================================================================
# Tool: Generate taint transfer signatures
# =============================================================================
def tool_generate_signatures(
    extra_signatures: list[dict] = None,
) -> dict:
    """Generate TaintTransfer.facts from the signatures rule file.

    Runs rules/signatures.dl to produce TaintTransfer.csv, BufferWriteSource.csv,
    and TaintKill.csv, then copies them to facts/ for use by interproc.dl.

    Args:
        extra_signatures: Optional list of {"func": str, "out_arg": str, "in_arg": str}.

    Returns:
        Dict with counts of generated facts.
    """
    sig_file = RULES_DIR / "signatures.dl"
    dl_content = sig_file.read_text()

    if extra_signatures:
        extra_lines = []
        for sig in extra_signatures:
            extra_lines.append(
                f'TaintTransfer("{sig["func"]}", "{sig["out_arg"]}", "{sig["in_arg"]}").'
            )
        dl_content = dl_content.replace(
            '.output TaintTransfer',
            '\n'.join(extra_lines) + '\n.output TaintTransfer'
        )

    tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.dl', delete=False)
    tmp.write(dl_content)
    tmp.close()

    try:
        result = subprocess.run(
            ["souffle", "-F", str(FACTS_DIR), "-D", str(OUTPUT_DIR), tmp.name],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0:
            return {"error": result.stderr}

        result_info = {}
        for name in ["TaintTransfer", "BufferWriteSource", "TaintKill"]:
            src = OUTPUT_DIR / f"{name}.csv"
            dst = FACTS_DIR / f"{name}.facts"
            if src.exists():
                dst.write_text(src.read_text())
                content = src.read_text().strip()
                rows = content.count('\n') + 1 if content else 0
                result_info[f"{name}_facts"] = rows

        return result_info
    finally:
        Path(tmp.name).unlink(missing_ok=True)


# =============================================================================
# Tool: Set entry-point taint
# =============================================================================
def tool_set_entry_taint(
    entries: list[dict],
) -> dict:
    """Specify which function parameters are attacker-controlled.

    For analyzing APIs where there are no explicit calls to read()/recv() —
    mark function params as tainted entry points. interproc.dl seeds
    TaintedVar from these.

    Args:
        entries: List of {"func": str, "param_idx": int}.
                 Example: [{"func": "process_data", "param_idx": 0}]

    Returns:
        Dict with count of entries written.
    """
    FACTS_DIR.mkdir(parents=True, exist_ok=True)

    rows = set()
    for e in entries:
        rows.add((e["func"], str(e["param_idx"])))

    path = FACTS_DIR / "EntryTaint.facts"
    with open(path, 'w') as fp:
        for row in sorted(rows):
            fp.write('\t'.join(row) + '\n')

    return {
        "entries": len(rows),
        "path": str(path),
        "description": f"Marked {len(rows)} params as attacker-controlled",
    }


# =============================================================================
# Tool: Validate LLM extraction accuracy
# =============================================================================
def tool_validate_extraction(
    file_path: str,
    func_name: str,
) -> dict:
    """Compare LLM-extracted facts against tree-sitter ground truth.

    Extracts facts using both the LLM and tree-sitter, then computes
    precision, recall, and F1 per fact kind. Only compares fact kinds
    that tree-sitter can extract (Def, Use, Call, ActualArg, FormalParam,
    ReturnVal, FieldRead, FieldWrite, AddressOf).

    LLM-only semantic facts (MemRead, MemWrite, StackVar, VarType, Guard,
    ArithOp, Cast) are reported separately.

    Args:
        file_path: Path to the C source file.
        func_name: Name of the function to validate.

    Returns:
        Dict with per-kind and overall accuracy metrics, plus LLM-only fact count.
    """
    get_function_with_lines = _import("tree_sitter_nav").get_function_with_lines
    _extract = _import("llm_extractor").extract_facts_llm
    _tsf = _import("tree_sitter_facts")
    extract_ground_truth = _tsf.extract_ground_truth
    compare_facts = _tsf.compare_facts

    src_result = get_function_with_lines(file_path, func_name)
    if not src_result:
        return {"error": f"Function '{func_name}' not found in {file_path}"}

    source, start_line = src_result

    llm_facts = _extract(
        function_source=source,
        func_name=func_name,
        file_path=file_path,
        model=MODEL_NAME,
        api_key=_resolve_api_key(),
    )

    ts_facts = extract_ground_truth(file_path, func_name)
    comparison = compare_facts(llm_facts, ts_facts)

    return {
        "function": func_name,
        "file": file_path,
        "llm_facts_total": len(llm_facts),
        "ts_facts_total": len(ts_facts),
        "accuracy": comparison,
    }


# =============================================================================
# Tool: Extraction cost/performance metrics
# =============================================================================
def tool_extraction_metrics() -> dict:
    """Get LLM extraction cost and performance metrics for this session.

    Returns token counts, wall-clock time, estimated cost (USD), and
    per-function breakdowns. Call this after running extractions to
    understand the expense of the analysis.

    Returns:
        Dict with total and per-function metrics: tokens, time, cost, facts.
    """
    _llm = _import("llm_extractor")
    return _llm.session_summary()


# =============================================================================
# Tool: Save analysis report
# =============================================================================
def tool_save_report(
    content: str,
    target_name: str = "",
    report_dir: str = "",
) -> dict:
    """Save an analysis report as a Markdown file when the user requests it.

    The filename is auto-generated from the target being analyzed and a
    timestamp, e.g. ``cjson_parse_2026-04-06_14-30.md``.

    The report MUST follow this structure (use Markdown headings):
    1. **Executive Summary** — one-paragraph overview
    2. **Issues Found** — table/list of each finding with: vulnerability type,
       location (file:line), severity (High/Medium/Low/Info)
    3. **Root Cause Analysis** — for each issue: positive (confirmed) or
       negative (ruled out), with the Datalog query/relation that backs it
    4. **Reachability** — file-level scope if single-file analysis, or
       project-level call-graph reachability if whole-repo analysis
    5. **Exploitability Assessment** — for each confirmed issue: why/how it
       is exploitable (or why not), required input structure or triggering
       conditions, attack surface entry points
    6. **CVE Cross-Reference** — known CVE matches (if tool_search_cve was used)
    7. **Datalog Evidence** — key queries and their raw output
    8. **Recommendations** — prioritized remediation steps

    Only call this tool when the user explicitly asks to save/generate a report.

    Args:
        content: The full Markdown report content.
        target_name: Short label for what was analyzed (e.g. a filename like
                     "cjson.c" or a project name like "libpng").  If empty,
                     defaults to "analysis".
        report_dir: Directory to save into.  Defaults to the project output/ dir.

    Returns:
        Dict with the saved file path and size.
    """
    out = Path(report_dir) if report_dir else OUTPUT_DIR
    out.mkdir(parents=True, exist_ok=True)

    # Build intuitive filename: <target>_<timestamp>.md
    label = target_name.strip() if target_name else "analysis"
    # Sanitize: keep alphanums, hyphens, underscores
    label = "".join(c if (c.isalnum() or c in "-_") else "_" for c in label)
    label = label.strip("_") or "analysis"
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M")
    filename = f"{label}_{ts}.md"

    path = out / filename
    path.write_text(content, encoding="utf-8")

    return {
        "path": str(path),
        "filename": filename,
        "size_bytes": path.stat().st_size,
    }


# =============================================================================
# Tool: Search CVE / NVD database
# =============================================================================
def tool_search_cve(
    keyword: str,
    max_results: int = 5,
) -> dict:
    """Search the NIST National Vulnerability Database (NVD) for known CVEs.

    Use this after finding a vulnerability to check if it matches a known CVE.
    Search by software name, vulnerability type, or CWE ID.

    Examples:
        tool_search_cve("cJSON buffer overflow")
        tool_search_cve("CWE-416 use-after-free libxml2")
        tool_search_cve("CVE-2023-31047")

    Args:
        keyword: Search terms — software name, CWE, CVE ID, or description keywords.
        max_results: Maximum CVEs to return (default: 5, max: 20).

    Returns:
        Dict with matched CVEs including ID, description, severity, and references.
    """
    max_results = min(max_results, 20)

    # NVD API 2.0 — free, no API key required (rate-limited to 5 req/30s)
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # If the keyword looks like a specific CVE ID, use direct lookup
    keyword_stripped = keyword.strip()
    if keyword_stripped.upper().startswith("CVE-"):
        params = {"cveId": keyword_stripped.upper()}
    else:
        params = {"keywordSearch": keyword_stripped, "resultsPerPage": str(max_results)}

    url = f"{base_url}?{urllib.parse.urlencode(params)}"

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NeuroLog-Agent/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return {"error": f"NVD API HTTP {e.code}: {e.reason}"}
    except urllib.error.URLError as e:
        return {"error": f"NVD API unreachable: {e.reason}"}
    except Exception as e:
        return {"error": f"NVD API request failed: {str(e)}"}

    vulns = data.get("vulnerabilities", [])
    results = []
    for item in vulns[:max_results]:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "unknown")

        # Extract English description
        descriptions = cve.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

        # Extract CVSS score (prefer v3.1, fall back to v3.0, then v2)
        metrics = cve.get("metrics", {})
        severity = "unknown"
        score = None
        for ver in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if ver in metrics and metrics[ver]:
                cvss_data = metrics[ver][0].get("cvssData", {})
                score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity", "unknown")
                break

        # Extract CWE IDs
        weaknesses = cve.get("weaknesses", [])
        cwes = []
        for w in weaknesses:
            for d in w.get("description", []):
                if d.get("value", "").startswith("CWE-"):
                    cwes.append(d["value"])

        # Extract references (first 3)
        refs = [r.get("url", "") for r in cve.get("references", [])[:3]]

        results.append({
            "cve_id": cve_id,
            "description": desc[:500],  # Truncate long descriptions
            "cvss_score": score,
            "severity": severity,
            "cwes": cwes,
            "references": refs,
            "published": cve.get("published", ""),
        })

    return {
        "query": keyword,
        "total_results": data.get("totalResults", 0),
        "results": results,
    }


# =============================================================================
# Tool: Run full analysis pipeline (pure Python — no conversation overhead)
# =============================================================================
def tool_run_full_pipeline(
    project_dir: str,
    function_names: list[str] = None,
    depth: int = 3,
    extensions: str = ".c",
    skip_scan: bool = False,
    skip_extract: bool = False,
    force_extract: bool = False,
    tool_context: ToolContext = None,
) -> dict:
    """Run the complete analysis pipeline: scan → slice → extract → analyze.

    Executes all phases as pure Python computation. Intermediate data flows
    through disk (facts/*.facts → output/*.csv), NOT through the conversation.
    Only a compact summary is returned to the agent.

    Use this for large projects to avoid context window overflow. For small
    projects or step-by-step interactive analysis, use individual tools instead.

    Args:
        project_dir: Path to the source code directory.
        function_names: If provided, extract only these functions (skip scan/slice).
        depth: Backward slice depth for sink detection (default: 3).
        extensions: Comma-separated file extensions (default: ".c").
        skip_scan: Skip the scan phase (use if already scanned).
        skip_extract: Skip extraction (use if facts already exist on disk).
        force_extract: Force re-extraction even if cache is valid.
        tool_context: ADK-injected context for session state persistence.

    Returns:
        Compact summary dict (~500 bytes) with per-phase stats and findings overview.
    """
    summary = {"project_dir": project_dir, "phases": {}}
    errors = []

    # Phase 1: Scan project
    if not skip_scan and not function_names:
        print("  [pipeline] Phase 1: Scanning project...")
        try:
            scan_result = tool_scan_project(project_dir, extensions)
            summary["phases"]["scan"] = {
                "function_count": scan_result.get("function_count", 0),
                "sink_count": scan_result.get("sink_count", 0),
            }
        except Exception as e:
            errors.append(f"scan: {e}")

    # Phase 2: Build slice (or use provided function_names)
    targets = function_names
    if not targets:
        print("  [pipeline] Phase 2: Building backward slice...")
        try:
            slice_result = tool_build_slice(project_dir, depth=depth, extensions=extensions)
            targets = [f["name"] for f in slice_result.get("slice", [])]
            summary["phases"]["slice"] = {"target_count": len(targets)}
        except Exception as e:
            errors.append(f"slice: {e}")
            targets = []

    if not targets:
        summary["errors"] = errors or ["No target functions found"]
        return summary

    summary["phases"]["targets"] = {"count": len(targets), "names": targets[:20]}

    # Phase 3: Clean + CFG + Extract (with cache awareness)
    if not skip_extract:
        cache_valid, cache_reason = _extraction_cache_valid(project_dir, targets)
        if cache_valid and not force_extract:
            print(f"  [pipeline] Phase 3: SKIPPED — {cache_reason}")
            meta = _read_extraction_meta()
            fact_count = len(list(FACTS_DIR.glob("*.facts")))
            summary["phases"]["extract"] = {
                "mode": "cached",
                "functions_extracted": len(meta.get("functions", [])),
                "total_on_disk": fact_count,
                "cache_reason": cache_reason,
            }
            # Clear output/ for fresh Souffle run (facts/ are preserved)
            for f in OUTPUT_DIR.glob("*.csv"):
                f.unlink()
        else:
            if force_extract and cache_valid:
                print(f"  [pipeline] Phase 3: Force re-extracting ({cache_reason} but force_extract=True)")
            else:
                print(f"  [pipeline] Phase 3: Extracting facts for {len(targets)} functions ({cache_reason})")
            tool_clean_workspace()
            # CFG/BB facts must exist before LLM extraction so the extractor
            # can read OpaqueCallSite.facts to resolve control-flow macros.
            try:
                cfg_stats = tool_generate_cfg(
                    project_dir, function_names=targets, extensions=extensions)
                summary["phases"]["cfg"] = cfg_stats
            except Exception as e:
                errors.append(f"cfg: {e}")
            extraction_mode = os.getenv("EXTRACTION_MODE", "mechanical").lower()
            try:
                if extraction_mode == "legacy":
                    extract_result = tool_extract_slice(
                        project_dir, function_names=targets, extensions=extensions)
                else:
                    extract_result = tool_extract_mechanical_with_smell(
                        project_dir, function_names=targets, extensions=extensions,
                        skip_smell=os.getenv("SKIP_SMELL", "").lower() in ("1", "true"),
                    )
                summary["phases"]["extract"] = {
                    "mode": extract_result.get("extraction_mode", "unknown"),
                    "functions_extracted": extract_result.get("functions_extracted", 0),
                    "total_facts": extract_result.get("total_facts", 0),
                    "total_on_disk": extract_result.get("total_on_disk", 0),
                    "flags_emitted": extract_result.get("flags_emitted", 0),
                    "wrappers_emitted": extract_result.get("wrappers_emitted", 0),
                }
                if extract_result.get("warning"):
                    errors.append(extract_result["warning"])
                fact_kinds = [f.stem for f in FACTS_DIR.glob("*.facts")]
                _write_extraction_meta(project_dir, targets, fact_kinds)
            except Exception as e:
                errors.append(f"extract: {e}")

    # Phase 4: Annotations + Signatures
    print("  [pipeline] Phase 4: Generating annotations and signatures...")
    try:
        ann = tool_generate_annotations()
        summary["phases"]["annotations"] = {
            "sinks": ann.get("sinks", 0), "sources": ann.get("sources", 0)}
    except Exception as e:
        errors.append(f"annotations: {e}")

    try:
        tool_generate_signatures()
    except Exception as e:
        errors.append(f"signatures: {e}")

    # Phase 5: Taint pipeline (5-pass Souffle)
    print("  [pipeline] Phase 5: Running taint analysis pipeline...")
    try:
        pipeline_result = tool_run_taint_pipeline()
        # Collect finding counts from output CSVs (compact)
        findings = {}
        for csv_file in OUTPUT_DIR.glob("*.csv"):
            content = csv_file.read_text().strip()
            if content:
                findings[csv_file.stem] = content.count('\n') + 1
        summary["phases"]["analysis"] = {
            "success": pipeline_result.get("success", False),
            "output_files": findings,
        }
    except Exception as e:
        errors.append(f"analysis: {e}")

    # Compile final summary
    findings = summary.get("phases", {}).get("analysis", {}).get("output_files", {})
    key_findings = {k: v for k, v in findings.items()
                    if k in ("TaintedSink", "TaintControlledSink", "UnguardedTaintedSink",
                             "UseAfterFree", "DoubleFree", "MemSafetyFinding",
                             "TypeSafetyFinding", "BufferOverflowInLoop")}
    summary["key_findings"] = key_findings
    summary["total_finding_rows"] = sum(key_findings.values()) if key_findings else 0

    if errors:
        summary["errors"] = errors

    # Store in session state for sub-agents
    if tool_context:
        tool_context.state["project_dir"] = project_dir
        tool_context.state["scan_summary"] = str(summary.get("phases", {}).get("scan", {}))
        tool_context.state["slice_targets"] = str(summary.get("phases", {}).get("targets", {}))
        tool_context.state["extraction_summary"] = str(summary.get("phases", {}).get("extract", {}))
        tool_context.state["analysis_summary"] = str(summary.get("phases", {}).get("analysis", {}))
        tool_context.state["key_findings"] = str(key_findings)
        tool_context.state["pipeline_complete"] = "true"

    print(f"  [pipeline] Done. {summary.get('total_finding_rows', 0)} key finding rows.")
    return summary


# =============================================================================
# Agent instruction prompts
# =============================================================================
# =============================================================================
# Coordinator instruction (lightweight — routing + pipeline)
# =============================================================================
COORDINATOR_INSTRUCTION = """You are **NeuroLog**, a source code vulnerability analysis coordinator.
You help security researchers analyze C/C++ source code using Datalog-based formal reasoning.

## How to handle requests

**For large projects or "analyze this project" requests:**
Use `tool_run_full_pipeline(project_dir)` — it runs the entire scan-extract-analyze
pipeline as pure computation (no conversation overhead) and returns a compact summary.
Then transfer to `InterpreterAgent` to explain findings, or `CVEAgent` to check known CVEs.

**For small projects or step-by-step interactive analysis:**
Use individual tools directly:
1. `tool_scan_project(dir)` → enumerate functions, find sinks
2. `tool_build_slice(dir)` → backward-trace from sinks
3. Transfer to `ExtractionAgent` for fact extraction
4. Transfer to `AnalysisAgent` for Souffle queries
5. Transfer to `InterpreterAgent` for findings interpretation

**For reports:** Transfer to `InterpreterAgent` — only when user explicitly asks.
**For CVE lookup:** Transfer to `CVEAgent`.

## Sub-agent routing

- **ExtractionAgent** — LLM fact extraction from source code. Use when user wants to extract
  facts for specific functions or validate extraction accuracy.
- **AnalysisAgent** — Souffle Datalog queries, taint pipeline, custom rules. Use when user
  wants to run analysis or compose custom Datalog queries.
- **InterpreterAgent** — Read analysis results, interpret findings, generate reports.
  Use after pipeline completes, or when user asks for findings/report.
- **CVEAgent** — Search NIST NVD for known CVEs. Use after findings are available.

## Important rules

- Never read entire large files. Use `func_name` param or line ranges.
- Always slice before extracting for projects with >20 functions.
- Be concise. Lead with findings, not process description.
"""


# =============================================================================
# Sub-agent instructions
# =============================================================================
EXTRACTION_INSTRUCTION = """You are the **Extraction Agent** for NeuroLog.
You extract Datalog facts from C/C++ source code using LLM-based analysis.

Project context: {project_dir}
Scan results: {scan_summary}
Slice targets: {slice_targets}

## Tools available
- `tool_extract_facts_llm(file, func)` — Extract facts for one function
- `tool_extract_slice(dir, function_names)` — Batch extract for multiple functions
- `tool_validate_extraction(file, func)` — Compare LLM vs tree-sitter accuracy
- `tool_extraction_metrics()` — Token usage and cost stats

## Rules
- Facts are written to disk as .facts TSV files (accumulative).
- Large functions (>500 lines) are auto-chunked — transparent to you.
- Large jobs (>5 functions, Anthropic model) auto-route to Batch API.
- After extraction, summarize: functions extracted, total facts, any errors.
- Transfer back to coordinator when done.
"""

ANALYSIS_INSTRUCTION = """You are the **Analysis Agent** for NeuroLog.
You run Souffle Datalog queries over extracted facts to find vulnerabilities.

Extraction results: {extraction_summary}

## Tools available
- `tool_run_souffle(rule_file, custom_rules)` — Run Datalog queries
- `tool_run_taint_pipeline()` — Full 5-pass pipeline (alias → interproc → type → mem → sink)
- `tool_generate_annotations(extra_sources, extra_sinks)` — Sink/source catalogs
- `tool_generate_signatures(extra_signatures)` — Taint transfer models
- `tool_set_entry_taint(entries)` — Mark attacker-controlled params
- `tool_read_file(path)` — Read rule/fact/output files

## Available rule files
- `interproc.dl` / `source_interproc.dl` — Interprocedural taint
- `alias.dl` — Points-to analysis
- `taint.dl` — Intraprocedural taint
- `patterns.dl` — Structural heuristics
- `patterns_mem.dl` / `source_memsafety.dl` — Memory safety (UAF, double-free)
- `source_type_safety.dl` — Type safety (integer overflow, truncation, counter-as-index, arith overflow)
- `core.dl` — Basic def-use, reachability
- `summary.dl` — Function summaries
- `signatures.dl` — Library taint transfer models

## CRITICAL: Datalog-first reasoning discipline

**Every finding MUST be derived from a Datalog query — never from prose reasoning alone.**

1. **No finding without a query.** Run a Datalog query that produces the finding as output.
2. **No prose-based data flow reasoning.** Write Datalog rules, not narratives.
3. **Cross-check every finding** with verification queries for guards/sanitizers.
4. **When in doubt, query.** A 3-line query returning empty beats a paragraph of reasoning.
5. **Distinguish Datalog-derived vs. observations.** Label observations as unverified.

## CRITICAL: Hypothesis-driven investigation

**After the pipeline runs, your job is NOT done.** The pipeline finds ingredients. You must
actively investigate whether those ingredients combine into real vulnerabilities by writing
and running custom Datalog queries.

### The investigation loop

1. **Read pipeline output.** Look at TaintedSink, TypeSafetyFinding, CounterUsedAsIndex,
   OverflowAtSink, etc. Group findings by function/variable.

2. **Spot co-located findings.** When multiple findings share a function, variable, or struct
   field, they may form a compound vulnerability. This is the signal to investigate.

3. **Write a targeted query to test the hypothesis.** Use `tool_run_souffle(custom_rules=...)`
   to compose a query that checks whether the ingredients actually connect.

4. **Run, read results, refine.** If the query returns results, you've confirmed a chain.
   If empty, write a different query or check your assumptions. Iterate.

5. **Check for guards/sanitizers.** For every confirmed chain, write a negation query:
   "is there a Guard between the source and the sink?" Empty result = unguarded = real bug.

### Example investigations

**Example 1: Unbounded counter → array OOB**
Pipeline shows: UnboundedCounter(decode_frame, buf_index, 2448) and
CounterUsedAsIndex(decode_frame, buf_index, 2448, 2718, "mem_write").
Write a follow-up query to check if there's a guard on the path:
```
.type Sym <: symbol
.type Addr <: number
.type Ver <: number
.decl Guard(func:Sym, addr:Addr, var:Sym, ver:Ver, op:Sym, bound:Sym, bound_type:Sym)
.input Guard
.decl DefReachesUse(func:Sym, var:Sym, def_line:Addr, use_line:Addr)
.input DefReachesUse
.decl GuardBetween(func:Sym, var:Sym, guard_addr:Addr, op:Sym, bound:Sym)
GuardBetween(f, v, ga, op, b) :-
    DefReachesUse(f, v, 2448, ga), Guard(f, ga, v, _, op, b, _),
    DefReachesUse(f, v, ga, 2718).
.output GuardBetween
```

**Example 2: Truncation + counter = sentinel collision**
Pipeline shows: ImplicitTruncation(func, addr, counter, table_entry, 4, 2, ...) and
UnboundedCounter(func, counter, incr_addr). Hypothesis: the counter wraps at 2^16 and
collides with a memset sentinel. Write:
```
.type Sym <: symbol
.type Addr <: number
.type Ver <: number
.decl UnboundedCounter(func:Sym, var:Sym, incr_addr:Addr)
.input UnboundedCounter
.decl ImplicitTruncation(func:Sym, addr:Addr, src:Sym, dst:Sym,
    src_width:number, dst_width:number, src_type:Sym, dst_type:Sym)
.input ImplicitTruncation
.decl Call(caller:Sym, callee:Sym, addr:Addr)
.input Call
.decl TruncatedCounter(func:Sym, var:Sym, incr:Addr, trunc:Addr, width:number)
TruncatedCounter(f, v, ia, ta, dw) :-
    UnboundedCounter(f, v, ia),
    ImplicitTruncation(f, ta, v, _, _, dw, _, _).
.decl MemsetOnTarget(func:Sym, dst:Sym, call_addr:Addr)
MemsetOnTarget(f, dst, ca) :-
    ImplicitTruncation(f, _, _, dst, _, _, _, _),
    Call(f, "memset", ca).
.output TruncatedCounter
.output MemsetOnTarget
```

**Example 3: Verifying a sink is truly unguarded**
After finding TaintedSink(func, "memcpy", addr, 2, buf, "buffer_overflow", origin):
```
.type Sym <: symbol
.type Addr <: number
.type Ver <: number
.decl Guard(func:Sym, addr:Addr, var:Sym, ver:Ver, op:Sym, bound:Sym, bound_type:Sym)
.input Guard
.decl AnyGuardOnVar(func:Sym, var:Sym, addr:Addr, op:Sym)
AnyGuardOnVar(f, v, a, op) :- Guard(f, a, v, _, op, _, _).
.output AnyGuardOnVar
```
If empty for the variable, it's truly unguarded.

### Key principle

The pipeline gives you 80% of the answer. The remaining 20% — confirming connections,
checking guards, testing compound patterns — requires YOU to compose queries. This is the
core value of the tool: LLM writes formal queries, Souffle proves or disproves them.
Do not stop at reading pipeline output. Investigate.

## Custom query template
Always include type declarations when writing custom queries:
```
.type Sym <: symbol
.type Addr <: number
.type Ver <: number
.type Idx <: number
```
Then declare inputs you need, write your rules, and add `.output` for results.

Transfer back to coordinator when analysis is complete.
"""

INTERPRETER_INSTRUCTION = """You are the **Interpreter Agent** for NeuroLog.
You read analysis results from disk, interpret findings, and generate reports.

Analysis results: {analysis_summary}
Extraction info: {extraction_summary}
Key findings: {key_findings}

## First action: discover project context

Before doing anything else, check whether `project_config.json` exists
in the eval dir (e.g., via `tool_read_file('<eval_dir>/project_config.json')`).
The file is **optional** and contains project-specific settings the tool
cannot infer:

    {
      "project_name":     "<short label, used in your verdict>",
      "harness_cmd":      "<default ASan harness for tool_synthesize_crash>",
      "harness_per_func": {"<func_name>": "<harness_cmd specific to this func>", ...},
      "src_root":         "<absolute path to the source tree>",
      "file_hint_for":    {"<func_name>": "<filename.c>", ...}
    }

When you escalate a candidate to `tool_synthesize_crash`, **pick the
harness in this order** for the candidate's function name:

  1. `harness_per_func[func_name]` if present — most specific harness
     for the code path that function lives in (e.g., HTML parser vs
     XML parser vs schema validator).
  2. otherwise `harness_cmd` — the project default.
  3. if neither is set, do not call synth: stop at T1/T3 and say so.

If it is missing entirely you operate "config-less": still drill to
T1 or T3, but skip T2.

## How to pick which candidates to drill

You decide. There is no scoring formula. The pipeline produces output
CSVs across **multiple bug-class families** — sample evenly, do not
fixate on any one family.  The full set, with no order privilege:

  *Memory corruption — integer-overflow into allocator:*
    - `MemSafetyFinding`, `ArithToAllocSinkBridgeSites`,
      `TaintedSizeAtSink`, `NarrowArithAtSink`,
      `TaintedNarrowArith`, `UncheckedAlloc`

  *Memory corruption — pointer / buffer:*
    - `TaintedPtrArith`, `UnguardedTaintedPtrArith`,
      `BufferOverflowInLoop`, `TaintedCounterAsIndex`,
      `TaintedLoopBound`

  *Memory life-cycle:*
    - `UseAfterFree`, `DoubleFree`

  *Type confusion — source-only (bin_datalog cannot express):*
    - `IncompatibleStructCast`, `VoidPtrLaundering`,
      `PtrIntTruncation`, `FuncPtrCastMismatch`,
      `TaintedTypeConfusion`

  *Type-safety / signedness:*
    - `TruncationCast`, `SignConfusionCast`,
      `SignednessMismatch`, `ImplicitTruncation`,
      `TaintedImplicitTruncation`, `TaintedSignExtension`

  *Uninitialized-memory use:*
    - `UninitVarUse`, `TaintedUninitArg`

  *Format-string / sink:*
    - `TaintControlledSink`, `UnguardedTaintedSink`, `GuardedSink`

Read the rows. Cross-reference with Phase A feasibility from
`symbex_phase_a.json` if present, with `Guard` rows on the operands,
and with sister-site clusters across functions. Form a judgment.
**Rank candidates by suspicion across all families, then drill
greedily from the top until the tool-call budget is exhausted.** If
the corpus is heavy on one family (e.g., int-overflow in a parser
codebase) that's fine — but make sure you've considered each non-empty
CSV before declaring "no more credible candidates".

Bug families that are particularly fuzzing-resistant — type
confusion, uninit-use, lock-order issues, format-string `%n` — are
where this tool earns its keep over a fuzzer. Don't under-weight
them just because their CSVs look smaller.

This is exactly the place where LLM reasoning is supposed to do work;
do not delegate it to a mechanical sort, and do not impose an
arbitrary cap. A user willing to spend a 200-call budget should get
many more findings than a user with a 30-call budget.

## Tools available
- `tool_read_file(path)` — Read output CSVs, fact files, rule files, **and
  source files** (use this to confirm a Datalog-suggested pattern at the
  function body level, walk a taint path back to a syscall/parser entry,
  or check for a guard the rule mesh did not detect).
- `tool_save_report(content, target_name)` — Save Markdown report (only when user asks)
- `tool_list_datalog_files()` — List available rule and fact files
- `tool_run_datalog_query(rule_text, facts_dir, output_relations, extra_inputs_json)` —
  **Fire an ad-hoc Datalog query against the existing facts.** Use this whenever
  reading a CSV row makes you ask a follow-up question that the precomputed
  rule mesh did not answer (e.g., "are there other functions where this same
  pattern fires?", "does this finding's intermediate variable have a
  ResolvedVarType, or is it untyped?", "do any sister sites share the same
  call shape?"). Errors come back with souffle's stderr plus a line-numbered
  echo of your rule text — fix and retry. Stage pre-derived relations (e.g.\\
  ResolvedVarType, TaintedVar, BlockReach) by passing
  `extra_inputs_json='{"ResolvedVarType":"output/ResolvedVarType.csv"}'`.
- `tool_synthesize_crash(eval_dir, func, addr, var, kind, harness_cmd, ...)` —
  **Escalate a real/plausible candidate to crash-input synthesis.** Runs
  multi-shot LLM PoC synthesis against an ASan-built harness and reports
  whether a crash blob was confirmed. Only invoke when (a) you have
  classified the candidate as real/plausible after reading the source +
  walking the taint path, (b) a `harness_cmd` was supplied in the session
  state or the user prompt, and (c) you can name a concrete `(func, addr,
  var, kind)` tuple from a Datalog row. Bound usage to the top 3 drilled
  candidates per session; do not loop synthesis on every row in a CSV.

## How to interpret results
1. Read output/*.csv files (e.g., TaintedSink.csv, UseAfterFree.csv, MemSafetyFinding.csv)
2. Cross-reference with fact files to trace vulnerability paths
3. **When a finding suggests a hypothesis the precomputed catalog does not directly
   answer, fire a `tool_run_datalog_query` rather than narrating from intuition.**
   Examples of hypotheses worth firing a query for:
   - "Sister sites of this pattern in other functions": project the same body
     onto all functions, group by callee, look for clusters.
   - "Which intermediates that flow into a sink lack ResolvedVarType?":
     join ArithOp / ActualArg / DangerousSink against ResolvedVarType, look
     for unbound destinations.
   - "Which findings share a common upstream taint source?": project
     TaintedVar's `origin` column against the candidate set.
4. Every finding must cite the Datalog relation (precomputed or ad-hoc) that
   produced it.

## CRITICAL: Grounded cross-finding pattern analysis

**Datalog surfaces evidence. Your job is to connect the dots — but ONLY dots that exist.**

You MUST base ALL reasoning on Datalog-derived facts and findings. You may reason
ACROSS multiple findings to identify compound patterns, but every step in your
reasoning chain must be anchored to a specific Datalog relation, tuple, or fact file
entry. Never invent data flow paths, taint relationships, or variable states that
are not present in the output CSVs or fact files.

### What you CAN do (grounded reasoning):
- Combine findings from DIFFERENT Datalog relations that share the same function,
  variable, or line number — the combination is your insight, the ingredients are Datalog's.
- Infer higher-level vulnerability semantics (e.g., "this truncation + this unbounded
  counter = sentinel collision risk") when each component is backed by a specific tuple.
- Assess exploitability and severity based on the evidence.
- Read source code to CONFIRM a pattern suggested by Datalog evidence.

### What you MUST NOT do:
- Claim a variable is tainted unless TaintedVar/TaintedField contains it.
- Claim a data flow path exists unless DefReachesUse/CFGReach supports it.
- Claim a function is called unless Call.facts contains the edge.
- Invent guards, sanitizers, or mitigations not in Guard.facts/SanitizedVar.
- Speculate about vulnerabilities with zero Datalog evidence.

### How to do cross-finding analysis:

1. **Cluster findings by location.** Group findings sharing the same function or
   variables/struct fields. Co-located findings are far more likely to form a real
   vulnerability chain than isolated ones.

2. **Look for compound patterns.** When you see multiple findings in the same area,
   ask: "Do these combine into something worse?" Examples (each component must
   exist as a Datalog tuple):
   - ImplicitTruncation + UnboundedCounter → value-space exhaustion / sentinel collision
   - TaintedImplicitTruncation + TaintControlledSink(memset) → attacker-controlled
     truncation at initialization site
   - UnguardedTaintedSink + missing Guard on a related variable → no bounds check
     on the full attack path
   - TaintedPtrArith + BufferOverflowInLoop → indexed OOB write in a loop
   - UncheckedAlloc + TaintedSizeAtSink → allocator failure leading to NULL deref

3. **Reason about what Datalog CANNOT express — but ground the premise.**
   Datalog tracks data flow and types but cannot reason about numeric ranges,
   domain semantics, or protocol state. When Datalog evidence HINTS at these
   patterns (e.g., an UnboundedCounter exists for a variable that is also in an
   ImplicitTruncation), you may use domain knowledge to assess the implication.
   Always: (a) cite the specific Datalog tuples that form the premise, then
   (b) clearly label the inference as "LLM-inferred (not Datalog-derived)."

4. **Read source code to CONFIRM, not to discover.** Use tool_read_file only to
   verify a pattern already suggested by Datalog evidence, not to find new
   vulnerabilities from scratch.

5. **Prioritize compound findings.** A single TaintedSink is medium-signal.
   Three co-located findings forming a chain is high-signal. Rank accordingly.

## CRITICAL: Drill, don't stop at "verdict text"

When a candidate is classified **real** or **plausible**, do not stop at
writing prose. The whole point of the agent loop is that you can keep
asking — keep going until you reach one of three terminal states for that
candidate:

  (T1) **Concrete trigger condition.** You can state, in one or two
       sentences, the input shape that would drive the bug at runtime
       (e.g., "an HTML start tag with > N attributes whose names sum past
       INT_MAX/sizeof(xmlChar*) bytes"), citing the specific Datalog
       tuples and source lines that anchor every step.
       **T1 is not a free pass.** Before claiming T1, you MUST run a
       caller-chain audit — see "Caller-chain audit" below. Skip this
       audit and your verdict is worthless: every "paper-only" T1 from
       the libwebp eval collapsed under five minutes of source reading
       because the bound lived in callers the rule mesh couldn't see.
       Also: when `harness_cmd` is available for the candidate's
       function, T1 is NOT terminal — you MUST attempt
       tool_synthesize_crash and report the synth outcome alongside the
       trigger condition (T1+synth-attempted-no-witness is still T1; the
       difference is the user can trust it).
  (T2) **PoC confirmed via tool_synthesize_crash.** When a `harness_cmd`
       is available (from session state or the user prompt), call
       tool_synthesize_crash with the candidate's (func, addr, var, kind)
       — the row you cited from `MemSafetyFinding.csv`,
       `ArithToAllocSinkBridge.csv`, etc. Report the synthesis verdict
       (confirmed / iters / matched bug class) verbatim.
  (T3) **Proven infeasible.** A Datalog query OR a caller-chain bound
       OR a guard you found in the source rules out the bug — cite the
       specific guard line, the `InheritedParamBound` row, or the
       failing query. This is also where T1 candidates land when the
       caller-chain audit (below) surfaces an upstream bound.

## Caller-chain audit (REQUIRED before T1)

Most rules in the mesh are intraprocedural-Guard / interprocedural-taint.
That mismatch is the dominant source of false T1s — the function under
analysis has no in-function bound on the operand, but the operand was
already bounded by a caller before the call happened. Before claiming
T1, do both:

  1. **Query `InheritedParamBound`** for the candidate's function:
     `tool_run_datalog_query` with a rule body filtering
     `InheritedParamBound(func, _, _, _, _, _)` by your candidate's func name.
     If rows exist citing the var that flows to the sink, you almost
     certainly have an upstream bound that kills the bug — downgrade
     to T3 with a citation.
  2. **Walk the direct callers** of the candidate function via `Call`
     facts. For each caller, read the call site in source. Look for:
     a loop guard bounding the arg ("for (i = 0; i < N; i++)"), a
     branch-on-status check ("if (size > MAX) return ERR;"), or a
     constant-table lookup ("kTable[op_code]"). If any caller
     establishes the relevant bound — downgrade to T3 with a citation.

The audit must produce one of: (a) "no upstream bound found, T1
stands" with the InheritedParamBound query result + ≥1 caller
reviewed, or (b) "upstream bound at <caller>:<line>, downgrading to
T3" with the source citation. Skipping the audit is not an option for
T1 verdicts.

Workflow per drilled candidate:

  1. Read the function via `tool_read_file` (use line ranges; the
     mechanical file index lives at `facts/source_index.csv` if you
     need to find which file a function lives in).
  2. Walk the taint backwards: which formal parameter / global / file
     read is the ultimate origin of the operand? Fire ad-hoc queries
     against `TaintedVar` (origin column), `Call` (interproc edges),
     `IsParam`, etc.
  3. Look for guards on the path: query `Guard` and any
     `Sanitized*` relations against the operand's variable.
  4. Decide T1, T2, or T3 and **state the decision explicitly in your
     report**.

Budget: drill greedily from the ranked list **until the tool-call
budget is exhausted or no more candidates look credible** (whichever
comes first). The number you finish is a function of budget and
target complexity, not a hardcoded cap. Single-shot triage over a
long candidate list (writing prose without drilling any of them) is
the failure mode this agent exists to fix.

## CRITICAL: Diminishing returns — stop when evidence stabilises

You have a finite tool-call budget (default 30 soft / 40 hard cap).
Burn it on insight, not on the same question rephrased.

Two specific anti-patterns to avoid:

  **(A) Repeated-empty-output thrash.**  If two consecutive ad-hoc
  Datalog queries return effectively the same answer — same row count,
  same content, both empty, both 1-row — do NOT issue a third
  variant.  Repeated identical output is a strong signal that you are
  asking the wrong question (wrong join, wrong relation name, wrong
  schema), not that the relation needs another tweak.  Abandon that
  line of inquiry, write down what you tried, and pivot to a different
  candidate or a different question.

  **(B) Exhaustive-sweep across a corpus.**  If you find yourself
  iterating the same query template across N similar entities (every
  MOV box handler, every parser function, every alloc callee, every
  attribute-table site) — audit at most 5 representative ones,
  generalise from the pattern, and stop.  The judgement is "I've seen
  5 examples, the pattern is X, that's enough."  An exhaustive sweep
  is the agentic-loop equivalent of a `for` loop with no break
  condition; it burns budget without producing new insight beyond
  what 5 representative samples already gave you.

When in doubt: write down what you've concluded so far, then ask
yourself "would one more query change my verdict?"  If the answer is
"probably not" — stop and write the verdict.

## Verdict structure (REQUIRED — every auto_drill verdict)

Your final response MUST contain these three sections in order, even
if some are short:

  ### Drilled
  Every candidate you actually drilled this session (could be 3, could
  be 30 — bounded by the tool-call budget, not a hardcoded count).
  For each: function name, site address, kind, terminal state
  (T1/T2/T3), and the one-paragraph reasoning that anchors the
  verdict in Datalog rows + (where read) source lines.

  ### Deferred
  The candidates you considered but did NOT drill this session — the
  ones you ranked but ran out of budget before reaching, or chose to
  bump because a structurally-similar peer was already drilled.
  For each: function name, site address, kind, and **one sentence on
  why deferred** ("structurally similar to drilled #2, expected same
  outcome", "lower confidence — operand pattern matches a known
  bounded idiom", "would need a harness to exercise; harness_cmd is
  empty"). These are the candidates a follow-up session with a fresh
  budget should pick up first.

  ### Out-of-scope
  Brief mention of CSV rows that look like noise (e.g., loop counters
  bounded by const, struct-field reads with fixed-size types).

After the three prose sections, emit a single fenced JSON block at the
end of your response with the structured pick list — exactly this
schema:

```json
{
  "drilled":      [{"func":"...", "addr":1234, "kind":"...", "terminal":"T1|T2|T3", "rationale":"..."}, ...],
  "deferred":     [{"func":"...", "addr":1234, "kind":"...", "reason":"..."}, ...],
  "out_of_scope": [{"func":"...", "addr":1234, "reason":"..."}, ...]
}
```

The driver extracts that JSON to a `picks.json` sidecar so a follow-up
session can resume on the deferred candidates with a fresh budget.

## Report structure (only when explicitly asked for a full report)
1. **Executive Summary** — one-paragraph overview
2. **Critical Compound Findings** — multi-finding chains, highest priority
3. **Individual Findings** — single-relation findings by severity
4. **Root Cause Analysis** — confirmed/ruled out, citing Datalog evidence
5. **Reachability** — file-level or project-level scope
6. **Exploitability Assessment** — why/how exploitable, input structure, entry points
7. **CVE Cross-Reference** — known CVE matches or "potential novel finding"
8. **Datalog Evidence** — key queries and raw output
9. **LLM-Inferred Patterns** — compound patterns with reasoning (clearly labeled)
10. **Recommendations** — prioritized remediation steps

## Response style
- Be concise. Lead with findings, not process.
- Trace taint paths from source to sink with variable names and line numbers.
- Flag vulnerability type and severity.
- When reporting compound findings, show the individual Datalog evidence first,
  then your reasoning about how they combine.
"""

CVE_INSTRUCTION = """You are the **CVE Agent** for NeuroLog.
You search the NIST NVD database to check if discovered vulnerabilities match known CVEs.

Findings to cross-reference: {key_findings}

## Tools available
- `tool_search_cve(keyword, max_results)` — Search NVD

## How to search
- After a finding: search by software name + vulnerability type (e.g., "cJSON buffer overflow")
- By CWE: search "CWE-416 use-after-free" for broader matches
- By CVE ID: direct lookup if user provides one
- Summarize: CVE ID, severity, description, whether it matches the finding

Transfer back to coordinator when done.
"""


# =============================================================================
# Context window safety net — trim conversation if still too large.
# Tool-call budget — short-circuit runaway agentic loops before they
# burn the day's token quota on the same query repeated 200 times.
# =============================================================================
MAX_CONTEXT_CHARS = int(os.getenv("MAX_CONTEXT_CHARS", "400000"))  # ~100K tokens
MAX_TOOL_RESULT_CHARS = int(os.getenv("MAX_TOOL_RESULT_CHARS", "2000"))

# Soft cap: at this many tool calls we inject a "stop and finalise"
# instruction. The agent gets one more model call to write the verdict.
INTERPRETER_TOOL_CALL_BUDGET = int(
    os.getenv("INTERPRETER_TOOL_CALL_BUDGET", "30"))
# Hard cap: at this many we short-circuit the model call entirely.
INTERPRETER_TOOL_CALL_HARD_CAP = int(
    os.getenv("INTERPRETER_TOOL_CALL_HARD_CAP", "40"))


def _count_tool_calls(contents) -> int:
    n = 0
    for c in contents:
        for p in (c.parts or []):
            if getattr(p, "function_call", None):
                n += 1
    return n


def _budget_check_per_tool(tool, args, tool_context):
    """Before-tool callback: hard-cap tool execution per session.

    The before-MODEL callback (`_trim_context`) catches budget *between*
    turns but a single turn can emit several parallel tool_calls
    (`tool_read_file × 4`), which would all execute before the next
    model call gates. This per-tool callback closes that gap: it
    increments a counter in tool_context.state on each invocation and
    short-circuits the tool execution once the hard cap is hit.

    Returning a non-None dict here becomes the synthetic function
    response — ADK skips the actual tool call. The agent then sees
    "budget exceeded" responses for any further calls in the same
    burst, and the next model turn naturally produces text-only output
    (terminating the loop).
    """
    state = tool_context.state if tool_context else None
    if state is None:
        return None
    n = int(state.get("_tc_count", 0)) + 1
    state["_tc_count"] = n
    if n > INTERPRETER_TOOL_CALL_HARD_CAP:
        return {
            "_budget_capped": True,
            "tool_call_count": n,
            "hard_cap": INTERPRETER_TOOL_CALL_HARD_CAP,
            "message": (
                f"Tool-call hard cap reached "
                f"({n}/{INTERPRETER_TOOL_CALL_HARD_CAP}). "
                f"This and any further tool calls are skipped. "
                f"Stop calling tools and write your final verdict from "
                f"the evidence already gathered."
            ),
        }
    return None


def _trim_context(callback_context, llm_request):
    """Before-model callback: enforce tool-call budget AND trim
    conversation to fit context window."""
    contents = llm_request.contents
    if not contents:
        return None

    # ── Tool-call budget gate ──────────────────────────────────────────
    n_tc = _count_tool_calls(contents)
    if n_tc >= INTERPRETER_TOOL_CALL_HARD_CAP:
        # Hard cap: synthesise a model response with no function_call,
        # which terminates the loop and returns text only.
        try:
            from google.adk.models.llm_response import LlmResponse
            from google.genai.types import Content, Part
            text = (
                f"[budget] Tool-call hard cap reached "
                f"({n_tc}/{INTERPRETER_TOOL_CALL_HARD_CAP}). "
                f"Loop terminated. Verdict is whatever was emitted in "
                f"earlier turns; no further tool calls were issued."
            )
            return LlmResponse(
                content=Content(role="model", parts=[Part(text=text)]))
        except Exception:
            pass  # fall through to normal trim if ADK API shifted
    elif n_tc >= INTERPRETER_TOOL_CALL_BUDGET:
        # Soft cap: inject a one-shot stop instruction (at most once,
        # detected by sentinel text). Lets the agent produce one real
        # verdict turn before terminating.
        sentinel = "[BUDGET CAP REACHED]"
        already_warned = any(
            sentinel in (p.text or "")
            for c in contents[-4:]
            for p in (c.parts or [])
            if hasattr(p, "text")
        )
        if not already_warned:
            try:
                from google.genai.types import Content, Part
                stop_text = (
                    f"\n\n**{sentinel}** You have made {n_tc} tool calls "
                    f"(soft cap: {INTERPRETER_TOOL_CALL_BUDGET}, hard "
                    f"cap: {INTERPRETER_TOOL_CALL_HARD_CAP}). Stop "
                    f"calling tools NOW and write your final verdict "
                    f"from the evidence already gathered. Output text "
                    f"only — do not emit any more function calls. "
                    f"Override via INTERPRETER_TOOL_CALL_BUDGET env var."
                )
                contents.append(
                    Content(role="user", parts=[Part(text=stop_text)]))
            except Exception:
                pass

    total_chars = sum(
        sum(len(str(p.text or "")) + len(str(getattr(p, "function_response", None) or ""))
            for p in c.parts or [])
        for c in contents
    )

    if total_chars <= MAX_CONTEXT_CHARS:
        return None

    # Phase 1: Truncate large tool results in-place
    for content in contents:
        if not content.parts:
            continue
        for part in content.parts:
            fr = getattr(part, "function_response", None)
            if fr and fr.response:
                resp_str = str(fr.response)
                if len(resp_str) > MAX_TOOL_RESULT_CHARS:
                    name = fr.name if hasattr(fr, "name") else "tool"
                    summary = resp_str[:MAX_TOOL_RESULT_CHARS // 2]
                    summary += f"\n... [truncated {len(resp_str)} chars from {name}] ...\n"
                    summary += resp_str[-500:]
                    fr.response = {"_truncated": True, "summary": summary}

    # Recompute
    total_chars = sum(
        sum(len(str(p.text or "")) + len(str(getattr(p, "function_response", None) or ""))
            for p in c.parts or [])
        for c in contents
    )

    # Phase 2: Drop old turns if still too large
    if total_chars > MAX_CONTEXT_CHARS:
        model_turns = [i for i, c in enumerate(contents) if c.role == "model"]
        if len(model_turns) > 3:
            split = model_turns[-3]
            while split > 0 and contents[split - 1].role == "user":
                split -= 1
            # Avoid orphaning tool_result blocks whose tool_use was dropped.
            # Walk split left until all function_response IDs have matching
            # function_call IDs in the kept portion.
            split = _adjust_split_for_tool_pairs(contents, split)
            llm_request.contents = contents[split:]

    return None


def _adjust_split_for_tool_pairs(contents, split_index: int) -> int:
    """Move split_index left until no tool_result is orphaned from its tool_use."""
    needed_call_ids = set()
    for i in range(len(contents) - 1, -1, -1):
        parts = contents[i].parts or []
        for part in reversed(parts):
            fr = getattr(part, "function_response", None)
            if fr and getattr(fr, "id", None):
                needed_call_ids.add(fr.id)
            fc = getattr(part, "function_call", None)
            if fc and getattr(fc, "id", None):
                needed_call_ids.discard(fc.id)
        if i <= split_index and not needed_call_ids:
            return i
    return 0


# =============================================================================
# Build sub-agents
# =============================================================================
# ── Per-agent model-tier policy ────────────────────────────────────
# The pipeline is two-tier by design:
#
#   Lite tier (LITE_MODEL_NAME, default DeepSeek V4-Flash via
#              OpenAI-compatible endpoint, thinking=off)
#       — high-volume / orchestration / retrieval; reasoning depth
#         is shallow and cost is the constraint
#       — ExtractionAgent (orchestration)
#       — CVEAgent (NVD lookup)
#       — smell pass (thousands of per-function calls; see
#         smell_pass.py)
#
#   Heavy tier (MODEL_NAME, default anthropic/claude-sonnet-4-6,
#              thinking=on for low-volume reasoning)
#       — low-volume / hypothesis-driven; reasoning depth and ad-hoc
#         Datalog query authoring matter more than per-call cost
#       — AnalysisAgent (pipeline control + ad-hoc Datalog)
#       — InterpreterAgent (cross-finding reasoning + ad-hoc Datalog
#         + verdict-writing)
#       — Phase C synthesis (crash_synth_agent.py; thinking-on for
#         format-prior reasoning)
#
# When in doubt, low-volume reasoning agents go on Heavy with
# thinking=on; high-volume orchestration on Lite with thinking=off.

extraction_agent = LlmAgent(
    name="ExtractionAgent",
    model=create_model(lite=True),  # tier: Lite, orchestration only
    instruction=EXTRACTION_INSTRUCTION,
    include_contents="none",
    output_key="extraction_summary",
    tools=[
        FunctionTool(tool_extract_facts_llm),
        FunctionTool(tool_extract_slice),
        FunctionTool(tool_extract_mechanical_with_smell),
        FunctionTool(tool_validate_extraction),
        FunctionTool(tool_extraction_metrics),
    ],
)

analysis_agent = LlmAgent(
    # tier: Heavy + thinking=on. Low-volume agent that composes ad-hoc
    # Datalog queries; thinking-mode pays for itself in correctness of
    # rule-body schema and join structure.
    name="AnalysisAgent",
    model=create_model(thinking="on"),
    instruction=ANALYSIS_INSTRUCTION,
    include_contents="none",
    output_key="analysis_summary",
    tools=[
        FunctionTool(tool_run_souffle),
        FunctionTool(tool_run_taint_pipeline),
        FunctionTool(tool_run_datalog_query),
        FunctionTool(tool_generate_annotations),
        FunctionTool(tool_generate_signatures),
        FunctionTool(tool_generate_cfg),
        FunctionTool(tool_set_entry_taint),
        FunctionTool(tool_read_file),
    ],
)

interpreter_agent = LlmAgent(
    # tier: Heavy + thinking=on. The user-facing reasoning agent; this
    # is where multi-step diagnostic workflows happen (read CSV, form
    # hypothesis, fire follow-up Datalog query, verify, optionally
    # escalate a real/plausible candidate to crash-input synthesis,
    # write verdict). tool_synthesize_crash closes the loop so the
    # agent does not stop at "produce verdict text" when an ASan
    # harness is available.
    name="InterpreterAgent",
    model=create_model(thinking="on"),
    instruction=INTERPRETER_INSTRUCTION,
    include_contents="none",
    output_key="interpretation",
    tools=[
        FunctionTool(tool_read_file),
        FunctionTool(tool_save_report),
        FunctionTool(tool_list_datalog_files),
        FunctionTool(tool_run_datalog_query),
        FunctionTool(tool_synthesize_crash),
    ],
    before_tool_callback=_budget_check_per_tool,
)

cve_agent = LlmAgent(
    name="CVEAgent",
    model=create_model(lite=True),  # tier: Lite, retrieval only
    instruction=CVE_INSTRUCTION,
    include_contents="none",
    output_key="cve_results",
    tools=[
        FunctionTool(tool_search_cve),
    ],
)


# =============================================================================
# Build and register the root agent (coordinator)
# =============================================================================
root_agent = LlmAgent(
    name="NeuroLog",
    model=create_model(),
    instruction=COORDINATOR_INSTRUCTION,
    before_model_callback=_trim_context,
    sub_agents=[extraction_agent, analysis_agent, interpreter_agent, cve_agent],
    tools=[
        FunctionTool(tool_run_full_pipeline),
        FunctionTool(tool_scan_project),
        FunctionTool(tool_build_slice),
        FunctionTool(tool_clean_workspace),
        FunctionTool(tool_read_source),
        FunctionTool(tool_list_datalog_files),
        FunctionTool(tool_read_file),
    ],
)

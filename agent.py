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


def _resolve_api_key():
    """Pick the right API key based on MODEL_NAME prefix."""
    explicit = os.getenv("API_KEY")
    if explicit:
        return explicit
    if MODEL_NAME.startswith("anthropic/"):
        return os.getenv("ANTHROPIC_API_KEY")
    if MODEL_NAME.startswith("openai/"):
        return os.getenv("OPENAI_API_KEY")
    if MODEL_NAME.startswith("gemini/") or MODEL_NAME.startswith("google/"):
        return os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
    return os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY")


def _use_batch_api() -> bool:
    """Check if batch API can be used (Anthropic model + SDK available)."""
    if not MODEL_NAME.startswith("anthropic/"):
        return False
    try:
        import anthropic  # noqa: F401
        return True
    except ImportError:
        return False


def create_model(lite: bool = False):
    """Create a LiteLLM model instance.

    Args:
        lite: If True, use LITE_MODEL_NAME (cheaper, for routing/extraction).
              If False, use MODEL_NAME (full model, for reasoning/interpretation).
    """
    name = LITE_MODEL_NAME if lite else MODEL_NAME
    return LiteLlm(model=name, api_key=_resolve_api_key())


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

    requests = prepare_batch_requests(func_sources)
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

    content = p.read_text()
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
        req = urllib.request.Request(url, headers={"User-Agent": "SourceCodeQL-Agent/1.0"})
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

    # Phase 3: Clean + Extract
    if not skip_extract:
        print(f"  [pipeline] Phase 3: Extracting facts for {len(targets)} functions...")
        tool_clean_workspace()
        try:
            extract_result = tool_extract_slice(
                project_dir, function_names=targets, extensions=extensions)
            summary["phases"]["extract"] = {
                "mode": extract_result.get("extraction_mode", "unknown"),
                "functions_extracted": extract_result.get("functions_extracted", 0),
                "total_facts": extract_result.get("total_facts", 0),
                "total_on_disk": extract_result.get("total_on_disk", 0),
            }
            if extract_result.get("warning"):
                errors.append(extract_result["warning"])
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
COORDINATOR_INSTRUCTION = """You are **SourceCodeQL**, a source code vulnerability analysis coordinator.
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
EXTRACTION_INSTRUCTION = """You are the **Extraction Agent** for SourceCodeQL.
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

ANALYSIS_INSTRUCTION = """You are the **Analysis Agent** for SourceCodeQL.
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
- `source_type_safety.dl` — Type safety (integer overflow, truncation)
- `core.dl` — Basic def-use, reachability
- `summary.dl` — Function summaries
- `signatures.dl` — Library taint transfer models

## Custom queries
Compose with `tool_run_souffle(custom_rules=...)`:
```
.type Sym <: symbol
.type Addr <: unsigned
.decl Call(caller: Sym, callee: Sym, addr: Addr)
.input Call
.decl CallerOfFree(func: Sym)
CallerOfFree(f) :- Call(f, "free", _).
.output CallerOfFree
```

## CRITICAL: Datalog-first reasoning discipline

**Every finding MUST be derived from a Datalog query — never from prose reasoning alone.**

1. **No finding without a query.** Run a Datalog query that produces the finding as output.
2. **No prose-based data flow reasoning.** Write Datalog rules, not narratives.
3. **Cross-check every finding** with verification queries for guards/sanitizers.
4. **When in doubt, query.** A 3-line query returning empty beats a paragraph of reasoning.
5. **Distinguish Datalog-derived vs. observations.** Label observations as unverified.

Transfer back to coordinator when analysis is complete.
"""

INTERPRETER_INSTRUCTION = """You are the **Interpreter Agent** for SourceCodeQL.
You read analysis results from disk, interpret findings, and generate reports.

Analysis results: {analysis_summary}
Extraction info: {extraction_summary}
Key findings: {key_findings}

## Tools available
- `tool_read_file(path)` — Read output CSVs, fact files, rule files
- `tool_save_report(content, target_name)` — Save Markdown report (only when user asks)
- `tool_list_datalog_files()` — List available files

## How to interpret results
1. Read output/*.csv files (e.g., TaintedSink.csv, UseAfterFree.csv, MemSafetyFinding.csv)
2. Cross-reference with fact files to trace vulnerability paths
3. Every finding must cite the Datalog relation that produced it

## Report structure (when asked to save/generate a report)
1. **Executive Summary** — one-paragraph overview
2. **Issues Found** — vulnerability type, location (file:line), severity
3. **Root Cause Analysis** — confirmed/ruled out, citing Datalog evidence
4. **Reachability** — file-level or project-level scope
5. **Exploitability Assessment** — why/how exploitable, input structure, entry points
6. **CVE Cross-Reference** — known CVE matches or "potential novel finding"
7. **Datalog Evidence** — key queries and raw output
8. **Recommendations** — prioritized remediation steps

## Response style
- Be concise. Lead with findings, not process.
- Trace taint paths from source to sink with variable names and line numbers.
- Flag vulnerability type and severity.
"""

CVE_INSTRUCTION = """You are the **CVE Agent** for SourceCodeQL.
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
# Context window safety net — trim conversation if still too large
# =============================================================================
MAX_CONTEXT_CHARS = int(os.getenv("MAX_CONTEXT_CHARS", "400000"))  # ~100K tokens
MAX_TOOL_RESULT_CHARS = int(os.getenv("MAX_TOOL_RESULT_CHARS", "2000"))


def _trim_context(callback_context, llm_request):
    """Before-model callback: trim conversation to fit context window."""
    contents = llm_request.contents
    if not contents:
        return None

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
extraction_agent = LlmAgent(
    name="ExtractionAgent",
    model=create_model(lite=True),
    instruction=EXTRACTION_INSTRUCTION,
    include_contents="none",
    output_key="extraction_summary",
    tools=[
        FunctionTool(tool_extract_facts_llm),
        FunctionTool(tool_extract_slice),
        FunctionTool(tool_validate_extraction),
        FunctionTool(tool_extraction_metrics),
    ],
)

analysis_agent = LlmAgent(
    name="AnalysisAgent",
    model=create_model(),
    instruction=ANALYSIS_INSTRUCTION,
    include_contents="none",
    output_key="analysis_summary",
    tools=[
        FunctionTool(tool_run_souffle),
        FunctionTool(tool_run_taint_pipeline),
        FunctionTool(tool_generate_annotations),
        FunctionTool(tool_generate_signatures),
        FunctionTool(tool_set_entry_taint),
        FunctionTool(tool_read_file),
    ],
)

interpreter_agent = LlmAgent(
    name="InterpreterAgent",
    model=create_model(),
    instruction=INTERPRETER_INSTRUCTION,
    include_contents="none",
    output_key="interpretation",
    tools=[
        FunctionTool(tool_read_file),
        FunctionTool(tool_save_report),
        FunctionTool(tool_list_datalog_files),
    ],
)

cve_agent = LlmAgent(
    name="CVEAgent",
    model=create_model(lite=True),
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
    name="SourceCodeQL",
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

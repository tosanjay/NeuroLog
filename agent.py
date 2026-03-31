# File: agent.py
# LLM-Datalog-QL — Datalog-powered source code analysis agent
# LLM extracts facts from C/C++ source, tree-sitter navigates, Souffle reasons.

import os
import sys
import subprocess
import tempfile
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
from google.adk.tools import FunctionTool
from google.adk.models.lite_llm import LiteLlm

load_dotenv(override=True)

# =============================================================================
# Configuration
# =============================================================================
MODEL_NAME = os.getenv("MODEL_NAME", "anthropic/claude-sonnet-4-6")

# Smart extraction routing: use batch API for jobs larger than this threshold
BATCH_THRESHOLD = int(os.getenv("BATCH_THRESHOLD", "5"))

PROJECT_DIR = Path(__file__).parent
RULES_DIR = PROJECT_DIR / "rules"
FACTS_DIR = PROJECT_DIR / "facts"
OUTPUT_DIR = PROJECT_DIR / "output"


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


def create_model():
    return LiteLlm(model=MODEL_NAME, api_key=_resolve_api_key())


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
    start = max(0, start_line - 1) if start_line > 0 else 0
    end = end_line if end_line > 0 else len(lines)
    selected = lines[start:end]

    numbered = []
    for i, line in enumerate(selected):
        numbered.append(f"{start + i + 1:4d}| {line}")

    return {"source": '\n'.join(numbered), "start_line": start + 1,
            "end_line": start + len(selected), "file": file_path}


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
    result_dict = {
        "extraction_mode": mode,
        "functions_extracted": len([r for r in results if "facts" in r]),
        "total_facts": len(all_facts),
        "per_function": results,
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
        try:
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
    return {"path": str(p), "size_bytes": p.stat().st_size, "content": content}


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
# Agent instruction prompt
# =============================================================================
AGENT_INSTRUCTION = """You are **SourceCodeQL**, an interactive source code analysis co-pilot.
You help security researchers analyze C/C++ source code using Datalog queries
over facts extracted directly from source code by an LLM — no compilation required.

## Your capabilities

1. **Project scanning** (tree-sitter, no compilation) — Enumerate functions, build
   call graphs, find dangerous sinks, backward-slice to identify analysis targets.

2. **LLM fact extraction** — Extract Datalog facts (Def, Use, Call, MemRead, MemWrite,
   Guard, Cast, StackVar, VarType, etc.) from C functions using the LLM. The LLM
   reads source code directly — no AST, no CFG, no SSA compiler needed. Facts are
   written as .facts TSV files for Souffle.
   - **Smart routing**: Single functions extract instantly (synchronous). Large slice
     jobs (>5 functions) automatically use the Anthropic Batch API for 50% cost
     reduction and zero rate-limit pressure. This is transparent to the user.

3. **Souffle Datalog engine** — Run pre-built or custom Datalog queries:
   - `interproc.dl` — 1-CFA context-sensitive interprocedural taint analysis
   - `taint.dl` — Intraprocedural taint tracking
   - `alias.dl` — Andersen-style points-to analysis
   - `patterns.dl` — Structural vulnerability heuristics (unsafe strcpy, gets)
   - `patterns_mem.dl` — Memory safety: UAF, double-free, unchecked malloc
   - `core.dl` — Basic def-use and reachability queries
   - `summary.dl` — Function summary computation
   - `signatures.dl` — Library function taint transfer models
   - Custom `.dl` programs composed on the fly

4. **Taint analysis** — Two-pass pipeline: alias analysis → interprocedural taint.
   Tracks attacker-controlled data from entry points through function calls to sinks.

5. **Validation** — Compare LLM-extracted facts against tree-sitter ground truth
   to measure extraction accuracy per fact kind.

## Fact schema reference

| Relation | Columns | Source |
|----------|---------|--------|
| Def | func, var, ver, addr | LLM |
| Use | func, var, ver, addr | LLM |
| Call | caller, callee, addr | LLM |
| ActualArg | call_addr, arg_idx, param, var, ver | LLM |
| ReturnVal | func, var, ver | LLM |
| FormalParam | func, var, idx | LLM |
| MemRead | func, addr, base, offset, size | LLM (semantic) |
| MemWrite | func, addr, target, mem_in, mem_out | LLM (semantic) |
| FieldRead | func, addr, base, field | LLM |
| FieldWrite | func, addr, base, field, mem_in, mem_out | LLM |
| AddressOf | func, var, ver, target | LLM |
| CFGEdge | func, from_addr, to_addr | LLM |
| Guard | func, addr, var, ver, op, bound, bound_type | LLM (semantic) |
| ArithOp | func, addr, dst, dst_ver, op, src, src_ver, operand | LLM |
| Cast | func, addr, dst, dst_ver, src, src_ver, kind, src_width, dst_width, src_type, dst_type | LLM (semantic) |
| StackVar | func, var, offset, size | LLM (semantic) |
| VarType | func, var, type_name, width, signedness | LLM (semantic) |
| DangerousSink | func, arg_idx, risk | Generated |
| TaintSourceFunc | name, category | Generated |
| EntryTaint | func, param_idx | User-specified |

Addresses are source **line numbers** (not hex). SSA ver=0 (flow-insensitive MVP).

"LLM (semantic)" marks facts that only the LLM can extract — they require understanding
code semantics beyond what a parser can provide (type sizes, library function behavior,
pointer semantics).

## Recommended workflow

1. **Scan project** — `tool_scan_project(project_dir)` to enumerate functions and find sinks.
2. **Build slice** — `tool_build_slice(project_dir)` to backward-trace from sinks.
3. **Clean workspace** — `tool_clean_workspace()` to start fresh.
4. **Extract facts** — `tool_extract_slice(project_dir)` for the full slice, or
   `tool_extract_facts_llm(file, func)` for individual functions.
5. **Generate annotations** — `tool_generate_annotations()` for sink/source catalogs.
6. **Generate signatures** — `tool_generate_signatures()` for taint transfer models.
7. **Set entry taint** — `tool_set_entry_taint(entries)` to mark attack surface.
8. **Run analysis** — `tool_run_taint_pipeline()` for full interprocedural taint, or
   `tool_run_souffle(rule_file)` for specific analyses.
9. **Interpret results** — Read output CSVs and explain findings.

## Writing custom Datalog queries

Compose custom queries with `tool_run_souffle(custom_rules=...)`:
```
.type Sym <: symbol
.type Addr <: unsigned
.decl Call(caller: Sym, callee: Sym, addr: Addr)
.input Call
.decl CallerOfMemcpy(func: Sym)
CallerOfMemcpy(f) :- Call(f, "memcpy", _).
.output CallerOfMemcpy
```

## CRITICAL: Datalog-first reasoning discipline

**Every finding you report MUST be derived from a Datalog query — never from prose reasoning alone.**

This is the core principle of neuro-symbolic analysis: the LLM perceives (extracts facts),
Datalog reasons (derives conclusions). You must NOT reason about data flow, control flow,
reachability, or vulnerability conditions in your head — that is Datalog's job.

### Rules:

1. **No finding without a query.** Before reporting any finding (vulnerability, taint path,
   safety issue), you MUST have run a Datalog query that produces the finding as output.
   If you suspect something is vulnerable, write a Datalog rule to test it — don't assert
   it from prose reasoning.

2. **No prose-based data flow reasoning.** Do NOT trace taint paths, reachability, or
   def-use chains by reading code and reasoning narratively. Instead:
   - Write a custom Datalog query that encodes the property you want to check
   - Run it via `tool_run_souffle(custom_rules=...)`
   - Report what the query produces (or doesn't produce)

3. **Cross-check every finding.** Before finalizing a finding, write a verification query
   that checks whether guards, sanitizers, or contradictions invalidate it. Specifically:
   - If you claim "X flows to Y", there must be a `TaintedVar` or `DefReachesUse` tuple
   - If you claim "no guard protects this", there must be no `GuardedSink` tuple
   - If you claim "integer overflow at line N", compose the `Guard` facts at that point
     to check whether preconditions are actually reachable

4. **When in doubt, query.** If you're unsure whether a property holds, the answer is
   always to write a Datalog query — never to reason about it in prose. A 3-line custom
   query that returns empty is more trustworthy than a paragraph of plausible reasoning.

5. **Distinguish Datalog-derived vs. observations.** When you do make an observation from
   reading code (e.g., "this function uses malloc"), clearly label it as an observation
   and state that formal verification requires running a query. Never present observations
   as verified findings.

### Why this matters:

The LLM is good at pattern-matching and generating plausible narratives. It is NOT reliable
for formal reasoning about program properties — that's exactly why we have Datalog. If you
bypass Datalog and reason in prose, you will produce findings that sound correct but may be
wrong (e.g., missing a guard that blocks a taint path). The whole point of this tool is that
Datalog catches what prose reasoning misses.

## Response style

- Be concise. Lead with findings, not process.
- When showing taint paths, trace from source to sink with variable names and line numbers.
- Every finding must cite the Datalog query or relation that produced it.
- Flag vulnerability type and severity.
- When asked about a function, extract and analyze it before answering.
"""


# =============================================================================
# Build and register the root agent
# =============================================================================
root_agent = LlmAgent(
    name="SourceCodeQL",
    model=create_model(),
    instruction=AGENT_INSTRUCTION,
    tools=[
        FunctionTool(tool_clean_workspace),
        FunctionTool(tool_scan_project),
        FunctionTool(tool_build_slice),
        FunctionTool(tool_read_source),
        FunctionTool(tool_extract_facts_llm),
        FunctionTool(tool_extract_slice),
        FunctionTool(tool_run_souffle),
        FunctionTool(tool_run_taint_pipeline),
        FunctionTool(tool_list_datalog_files),
        FunctionTool(tool_read_file),
        FunctionTool(tool_generate_annotations),
        FunctionTool(tool_generate_signatures),
        FunctionTool(tool_set_entry_taint),
        FunctionTool(tool_validate_extraction),
        FunctionTool(tool_extraction_metrics),
    ],
)

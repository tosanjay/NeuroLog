#!/usr/bin/env python3
"""Run DatalogLLM pipeline on cJSON v1.7.17 parse-chain functions."""

import shutil
import sys
import tempfile
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

from batch_extractor import _load_env, prepare_batch_requests, submit_batch, poll_batch, retrieve_results
from tree_sitter_nav import enumerate_functions, get_function_with_lines
from fact_schema import write_facts
from souffle_runner import run_taint_pipeline

# Load environment
_load_env()

CJSON_SOURCE = Path("/tmp/cjson_test/cJSON.c")
FACTS_DIR = PROJECT_ROOT / "eval" / "results" / "cjson_work" / "cJSON" / "facts"
OUTPUT_DIR = PROJECT_ROOT / "eval" / "results" / "cjson_work" / "cJSON" / "output"

INCLUDE = {
    'cJSON_Parse', 'cJSON_ParseWithLength', 'cJSON_ParseWithOpts', 'cJSON_ParseWithLengthOpts',
    'parse_value', 'parse_string', 'parse_number', 'parse_array', 'parse_object',
    'parse_hex4', 'utf16_literal_to_utf8', 'buffer_skip_whitespace', 'skip_utf8_bom',
    'get_decimal_point', 'case_insensitive_strcmp',
    'ensure', 'cJSON_strdup', 'cJSON_New_Item', 'cJSON_Delete',
    'internal_malloc', 'internal_free', 'internal_realloc',
    'cJSON_Minify', 'minify_string', 'skip_oneline_comment', 'skip_multiline_comment',
}


def step1_enumerate():
    """Enumerate functions via tree-sitter, filter to INCLUDE set."""
    print("=" * 60)
    print("STEP 1: Enumerate and filter functions")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_file = Path(tmpdir) / "cJSON.c"
        shutil.copy2(CJSON_SOURCE, tmp_file)
        all_funcs = enumerate_functions(tmpdir)

    print(f"  Total functions in cJSON.c: {len(all_funcs)}")

    filtered = [f for f in all_funcs if f.name in INCLUDE]
    found_names = {f.name for f in filtered}
    missing = INCLUDE - found_names
    if missing:
        print(f"  [WARN] Functions not found: {missing}")
    print(f"  Filtered to {len(filtered)} parse-chain functions")
    for f in filtered:
        print(f"    {f.name} (L{f.start_line}-{f.end_line})")

    return filtered


def step2_extract(filtered_funcs):
    """Extract facts via Anthropic batch API."""
    print("\n" + "=" * 60)
    print("STEP 2: Extract Datalog facts via batch API")
    print("=" * 60)

    func_sources = []
    for fi in filtered_funcs:
        result = get_function_with_lines(str(CJSON_SOURCE), fi.name)
        if result:
            numbered_source, start_line = result
            func_sources.append({
                "name": fi.name,
                "source": numbered_source,
                "file_path": "file_0.c",  # anonymized!
                "file_stem": "cJSON",
            })
        else:
            print(f"  [WARN] Could not extract source for {fi.name}")

    print(f"  Prepared {len(func_sources)} function sources (anonymized as file_0.c)")

    # Submit batch
    requests = prepare_batch_requests(func_sources)
    batch_id = submit_batch(requests)
    print(f"  Batch ID: {batch_id}")

    # Poll until done
    print("  Polling for completion...")
    status = poll_batch(batch_id, poll_interval=10, timeout=600)
    print(f"  Status: {status}")

    if status.get("status") != "ended":
        print(f"  [ERROR] Batch did not complete: {status}")
        sys.exit(1)

    if status.get("errored", 0) > 0:
        print(f"  [WARN] {status['errored']} requests errored")

    # Retrieve results
    print("  Retrieving results...")
    results_by_file = retrieve_results(batch_id)

    # Write facts
    all_facts = []
    for file_stem, facts in results_by_file.items():
        all_facts.extend(facts)
        print(f"    {file_stem}: {len(facts)} facts")

    # Clear stale facts
    for f in FACTS_DIR.glob("*.facts"):
        f.unlink()

    stats = write_facts(all_facts, str(FACTS_DIR))
    print(f"\n  Facts written to {FACTS_DIR}:")
    for filename, count in sorted(stats.items()):
        print(f"    {filename}: {count} rows")

    return all_facts


def step3_annotations():
    """Write DangerousSink.facts, TaintSourceFunc.facts, EntryTaint.facts."""
    print("\n" + "=" * 60)
    print("STEP 3: Generate annotation facts")
    print("=" * 60)

    # DangerousSink.facts: func\targ_idx\trisk (3 columns per schema.dl)
    dangerous_sinks = [
        ("malloc", "0", "alloc"), ("calloc", "0", "alloc"), ("calloc", "1", "alloc"),
        ("realloc", "1", "alloc"), ("memcpy", "2", "overflow"), ("memmove", "2", "overflow"),
        ("free", "0", "uaf"), ("strcpy", "1", "overflow"), ("strncpy", "2", "overflow"),
        ("sprintf", "1", "overflow"), ("system", "0", "exec"), ("strcat", "1", "overflow"),
        ("strncat", "1", "overflow"), ("printf", "0", "format"), ("fprintf", "1", "format"),
    ]
    sink_path = FACTS_DIR / "DangerousSink.facts"
    with open(sink_path, 'w') as f:
        for callee, idx, risk in dangerous_sinks:
            f.write(f"{callee}\t{idx}\t{risk}\n")
    print(f"  DangerousSink.facts: {len(dangerous_sinks)} entries")

    # TaintSourceFunc.facts: name\tcategory (2 columns per schema.dl)
    taint_sources = [
        ("read", "io"), ("recv", "network"), ("recvfrom", "network"),
        ("fgets", "io"), ("fread", "io"), ("gets", "io"),
        ("scanf", "io"), ("sscanf", "io"), ("fscanf", "io"),
        ("getenv", "env"), ("getchar", "io"), ("fgetc", "io"), ("getc", "io"),
    ]
    src_path = FACTS_DIR / "TaintSourceFunc.facts"
    with open(src_path, 'w') as f:
        for func, cat in taint_sources:
            f.write(f"{func}\t{cat}\n")
    print(f"  TaintSourceFunc.facts: {len(taint_sources)} entries")

    # EntryTaint.facts: func\tparam_idx
    entry_path = FACTS_DIR / "EntryTaint.facts"
    with open(entry_path, 'w') as f:
        f.write("cJSON_ParseWithLengthOpts\t0\n")
    print(f"  EntryTaint.facts: 1 entry (cJSON_ParseWithLengthOpts param 0)")


def step4_souffle():
    """Run Souffle taint pipeline."""
    print("\n" + "=" * 60)
    print("STEP 4: Run Souffle pipeline")
    print("=" * 60)

    result = run_taint_pipeline(
        facts_dir=str(FACTS_DIR),
        output_dir=str(OUTPUT_DIR),
        source_mode=True,
    )

    if not result["success"]:
        print(f"  [ERROR] Souffle pipeline failed: {result.get('error', result.get('stderr', 'unknown'))}")
        # Don't exit — still try to report partial results
    else:
        print("  Pipeline completed successfully")

    return result


def step5_report(result):
    """Print summary of all output CSV files."""
    print("\n" + "=" * 60)
    print("STEP 5: Vulnerability Analysis Results")
    print("=" * 60)

    # Key findings to highlight
    KEY_FILES = [
        "TaintedSink.csv", "TaintedVar.csv",
        "TypeSafetyFinding.csv", "MemSafetyFinding.csv",
        "UnguardedTaintedSink.csv", "TaintedSizeAtSink.csv",
        "UncheckedAlloc.csv", "AllocCopyMismatch.csv",
        "BufferOverflowInLoop.csv",
    ]

    outputs = result.get("outputs", {})
    stats = result.get("stats", {})

    # Summary table
    print("\n  Output summary:")
    print(f"  {'File':<35s} {'Rows':>6s}")
    print(f"  {'-'*35} {'-'*6}")
    for name in sorted(outputs.keys()):
        rows = stats.get(name, "?")
        marker = " <<<" if name in KEY_FILES else ""
        print(f"  {name:<35s} {rows:>6}{marker}")

    # Print full contents of all non-empty CSVs
    print("\n" + "=" * 60)
    print("FULL OUTPUT OF ALL NON-EMPTY CSV FILES")
    print("=" * 60)

    for name in sorted(outputs.keys()):
        content = outputs[name]
        if content.strip():
            rows = len(content.strip().split('\n'))
            print(f"\n--- {name} ({rows} rows) ---")
            print(content)

    # Also check output dir for any files not in the result dict
    for csv_file in sorted(OUTPUT_DIR.glob("*.csv")):
        if csv_file.name not in outputs:
            content = csv_file.read_text().strip()
            if content:
                rows = len(content.split('\n'))
                print(f"\n--- {csv_file.name} ({rows} rows) [from disk] ---")
                print(content)


if __name__ == "__main__":
    # Check if facts already extracted (skip expensive batch API call)
    existing_facts = list(FACTS_DIR.glob("Def.facts"))
    if existing_facts and (FACTS_DIR / "Def.facts").stat().st_size > 0:
        print("Facts already exist, skipping steps 1-2 (batch extraction)")
        print(f"  Facts dir: {FACTS_DIR}")
        for f in sorted(FACTS_DIR.glob("*.facts")):
            if f.stat().st_size > 0:
                rows = len(f.read_text().strip().split('\n'))
                print(f"    {f.name}: {rows} rows")
    else:
        filtered = step1_enumerate()
        facts = step2_extract(filtered)
    step3_annotations()
    result = step4_souffle()
    step5_report(result)

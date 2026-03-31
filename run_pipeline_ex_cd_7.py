#!/usr/bin/env python3
"""Full pipeline test on ex_cd_7.c with metrics."""

import sys, os, time, json

# Setup paths
PROJECT_DIR = "/media/sanjay/f574986f-8197-4e72-a69d-87ddf200a6a9/sanjay/research/tii/tii24/repos/dev-claude/LLM_Datalog_QL"
sys.path.insert(0, PROJECT_DIR)
os.chdir(PROJECT_DIR)

from llm_extractor import extract_facts_llm, get_session_metrics, reset_session_metrics, session_summary
from fact_schema import write_facts, ALL_FACT_FILES
from souffle_runner import run_souffle, run_taint_pipeline
from tree_sitter_nav import enumerate_functions, get_function_source, get_function_with_lines
from pathlib import Path

FACTS_DIR = Path(PROJECT_DIR) / "facts"
OUTPUT_DIR = Path(PROJECT_DIR) / "output"
TEST_FILE = Path(PROJECT_DIR) / "tests/samples/ex_cd_7.c"

# Functions to extract
FUNCTIONS = [
    "handle_finalize_event",
    "handle_cleanup_event", 
    "handle_process_event",
    "handle_allocate_event",
    "parse_event_type",
    "dispatch_event",
    "read_event_file",
    "main",
]

# Ensure output dirs exist
FACTS_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)

# Create all empty .facts files (prevents Souffle errors)
for fname in ALL_FACT_FILES:
    (FACTS_DIR / fname).touch()

reset_session_metrics()
pipeline_start = time.time()

# ── Step 1: Extract facts for each function ─────────────────────────────
print("=" * 60)
print("STEP 1: LLM Fact Extraction")
print("=" * 60)

all_facts = []
for func_name in FUNCTIONS:
    result = get_function_with_lines(str(TEST_FILE), func_name)
    if not result:
        print(f"  [SKIP] {func_name}: source not found")
        continue

    numbered_src, start_line = result
    lines = numbered_src.strip().count('\n') + 1
    print(f"\n  Extracting: {func_name} ({lines} lines, starting at L{start_line})...")

    t0 = time.time()
    facts = extract_facts_llm(numbered_src, func_name, str(TEST_FILE))
    t1 = time.time()

    print(f"    → {len(facts)} facts in {t1-t0:.1f}s")
    all_facts.extend(facts)

# Write all facts
print(f"\n  Total facts extracted: {len(all_facts)}")
written = write_facts(all_facts, str(FACTS_DIR))
print(f"  Facts written to disk: {written}")

extraction_time = time.time() - pipeline_start

# ── Step 2: Set up taint sources / sinks / entry taint ──────────────────
print("\n" + "=" * 60)
print("STEP 2: Configure Taint Analysis")
print("=" * 60)

# Write TaintSourceFunc.facts — alias.dl expects 2 columns (name, category)
taint_sources = [
    ("read", "fd_read"), ("recv", "network"), ("fread", "file_read"),
    ("fgets", "file_read"), ("getenv", "environment"), ("scanf", "stdin"),
    ("fgetc", "file_read"), ("getchar", "stdin"), ("gets", "stdin"),
]
with open(FACTS_DIR / "TaintSourceFunc.facts", "w") as f:
    for name, cat in taint_sources:
        f.write(f"{name}\t{cat}\n")
print(f"  TaintSourceFunc: {len(taint_sources)} functions")

# Write DangerousSink.facts
sinks = [
    ("memcpy", "2", "buffer_overflow"),
    ("memcpy", "1", "buffer_overflow"),
    ("memmove", "2", "buffer_overflow"),
    ("memset", "2", "buffer_overflow"),
    ("strcpy", "1", "buffer_overflow"),
    ("strncpy", "2", "buffer_overflow"),
    ("sprintf", "2", "format_string"),
    ("system", "0", "command_injection"),
    ("free", "0", "double_free"),
    ("strcat", "0", "buffer_overflow"),
    ("strcat", "1", "buffer_overflow"),
]
with open(FACTS_DIR / "DangerousSink.facts", "w") as f:
    for s in sinks:
        f.write("\t".join(s) + "\n")
print(f"  DangerousSink: {len(sinks)} entries")

# Write EntryTaint.facts — source_interproc.dl expects (func, param_idx)
# read_event_file(filename) — param 0 is the filename from argv
# But the real taint source is fgets inside it, which source_interproc.dl
# handles via TaintSourceFunc. So mark main's argv (param 1) as entry.
with open(FACTS_DIR / "EntryTaint.facts", "w") as f:
    f.write("main\t1\n")  # argv is param index 1
print("  EntryTaint: main/argv (param_idx=1)")

# ── Step 3: Run Souffle analysis ────────────────────────────────────────
print("\n" + "=" * 60)
print("STEP 3: Souffle Analysis")
print("=" * 60)

souffle_start = time.time()

# 3a: patterns_mem.dl (memory safety)
print("\n  Running patterns_mem.dl...")
r = run_souffle("patterns_mem.dl")
if r["success"]:
    for name, rows in sorted(r["stats"].items()):
        print(f"    {name}: {rows} rows")
else:
    print(f"    FAILED: {r.get('stderr', r.get('error', ''))[:200]}")

# 3b: source_taint.dl (intraprocedural taint with reaching defs)
print("\n  Running source_taint.dl...")
r = run_souffle("source_taint.dl")
if r["success"]:
    for name, rows in sorted(r["stats"].items()):
        print(f"    {name}: {rows} rows")
else:
    print(f"    FAILED: {r.get('stderr', r.get('error', ''))[:500]}")

# 3c: Full taint pipeline (alias → source_interproc.dl)
print("\n  Running taint pipeline (alias → source_interproc)...")
r = run_taint_pipeline()
if r["success"]:
    for name, rows in sorted(r["stats"].items()):
        print(f"    {name}: {rows} rows")
else:
    print(f"    FAILED: {r.get('stderr', r.get('error', ''))[:500]}")

souffle_time = time.time() - souffle_start
total_time = time.time() - pipeline_start

# ── Step 4: Key results ─────────────────────────────────────────────────
print("\n" + "=" * 60)
print("STEP 4: Key Findings")
print("=" * 60)

for csv_name in ["TaintedSink.csv", "TaintControlledSink.csv", "DoubleFree.csv", 
                  "UseAfterFreeRisk.csv", "NullAfterFree.csv"]:
    path = OUTPUT_DIR / csv_name
    if path.exists():
        content = path.read_text().strip()
        if content:
            lines = content.split('\n')
            print(f"\n  {csv_name} ({len(lines)} rows):")
            for line in lines[:15]:
                print(f"    {line}")
            if len(lines) > 15:
                print(f"    ... ({len(lines)-15} more)")
        else:
            print(f"\n  {csv_name}: (empty)")
    else:
        print(f"\n  {csv_name}: (not produced)")

# ── Step 5: Metrics ─────────────────────────────────────────────────────
print("\n" + "=" * 60)
print("STEP 5: Metrics")
print("=" * 60)

metrics = get_session_metrics()
total_prompt = sum(m.prompt_tokens for m in metrics)
total_completion = sum(m.completion_tokens for m in metrics)
total_tokens = sum(m.total_tokens for m in metrics)
total_cost = sum(m.estimated_cost_usd for m in metrics)
retries = sum(1 for m in metrics if m.retried)

print(f"\n  Functions extracted:  {len(metrics)}")
print(f"  Total facts:         {len(all_facts)}")
print(f"  LLM calls:           {len(metrics)} (retries: {retries})")
print(f"  Prompt tokens:       {total_prompt:,}")
print(f"  Completion tokens:   {total_completion:,}")
print(f"  Total tokens:        {total_tokens:,}")
print(f"  Estimated cost:      ${total_cost:.4f}")
print(f"  Extraction time:     {extraction_time:.1f}s")
print(f"  Souffle time:        {souffle_time:.1f}s")
print(f"  Total pipeline time: {total_time:.1f}s")

print("\n  Per-function breakdown:")
print(f"  {'Function':<30s} {'Lines':>5s} {'Facts':>5s} {'Tokens':>7s} {'Time':>6s} {'Cost':>8s}")
print(f"  {'-'*30} {'-'*5} {'-'*5} {'-'*7} {'-'*6} {'-'*8}")
for m in metrics:
    print(f"  {m.func_name:<30s} {m.source_lines:>5d} {m.facts_extracted:>5d} {m.total_tokens:>7,d} {m.wall_time_s:>5.1f}s ${m.estimated_cost_usd:>.4f}")

# ── Step 6: Fact file stats ─────────────────────────────────────────────
print("\n  Fact files written:")
for f in sorted(FACTS_DIR.glob("*.facts")):
    content = f.read_text().strip()
    if content:
        rows = len(content.split('\n'))
        print(f"    {f.name:<25s} {rows:>5d} rows")


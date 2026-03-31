#!/usr/bin/env python3
"""Extract facts for cJSON_Utils.c CVE-2025-57052 attack chain functions."""

import os
import sys
import re
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent))

from llm_extractor import extract_facts_llm, ExtractionMetrics
from fact_schema import write_facts

SOURCE_FILE = "/tmp/cjson_test/cJSON_Utils.c"
FACTS_DIR = Path(__file__).parent / "eval/results/cjson_work/cJSON/facts"

# Functions in the CVE-2025-57052 attack chain
TARGET_FUNCTIONS = [
    "decode_array_index_from_pointer",  # The buggy function
    "get_array_item",                    # Uses the index for OOB access
    "get_item_from_pointer",             # Calls decode + get_array_item
    "detach_path",                       # Entry point using the chain
    "apply_patch",                       # Main entry point from external input
]


def extract_function_source(file_path: str, func_name: str) -> str | None:
    """Extract function source with line numbers from C file."""
    with open(file_path) as f:
        lines = f.readlines()

    # Find function start
    func_pattern = re.compile(rf'\b{re.escape(func_name)}\s*\(')
    start_line = None
    for i, line in enumerate(lines):
        if func_pattern.search(line):
            # Check it's a definition (not just a call) - look for { on same or next lines
            for j in range(max(0, i-2), min(len(lines), i+5)):
                if '{' in lines[j]:
                    start_line = i
                    break
            if start_line is not None:
                break

    if start_line is None:
        print(f"  [SKIP] Function '{func_name}' not found")
        return None

    # Find matching closing brace
    brace_count = 0
    end_line = start_line
    found_open = False
    for i in range(start_line, len(lines)):
        for ch in lines[i]:
            if ch == '{':
                brace_count += 1
                found_open = True
            elif ch == '}':
                brace_count -= 1
        if found_open and brace_count == 0:
            end_line = i
            break

    # Extract with line numbers
    numbered = []
    for i in range(start_line, end_line + 1):
        numbered.append(f"{i+1}\t{lines[i].rstrip()}")

    return "\n".join(numbered)


def main():
    total_facts = []
    total_cost = 0.0
    total_time = 0.0

    for func_name in TARGET_FUNCTIONS:
        print(f"\nExtracting: {func_name}")
        source = extract_function_source(SOURCE_FILE, func_name)
        if source is None:
            continue

        lines = source.count('\n') + 1
        print(f"  {lines} lines")

        facts = extract_facts_llm(
            function_source=source,
            func_name=func_name,
            file_path="file_0.c",  # anonymized
        )

        print(f"  → {len(facts)} facts extracted")
        total_facts.extend(facts)

    # Append to existing facts using write_facts (handles schema correctly)
    print(f"\nTotal: {len(total_facts)} new facts")
    print(f"Appending to {FACTS_DIR}")

    stats = write_facts(total_facts, FACTS_DIR, append=True)
    for filename, count in sorted(stats.items()):
        print(f"  {filename}: {count} total rows")

    # Add entry taint for the public API entry points
    entry_taint_file = FACTS_DIR / "EntryTaint.facts"
    with open(entry_taint_file, 'a') as f:
        # apply_patch receives external JSON patch data
        f.write("apply_patch\t1\n")  # patch parameter (cJSON from external)
        # get_item_from_pointer receives external pointer string
        f.write("get_item_from_pointer\t1\n")  # pointer param
    print("  EntryTaint: +2 entries (apply_patch:patch, get_item_from_pointer:pointer)")

    # Add DangerousSink for array access functions (OOB pattern)
    # get_array_item takes an index that can cause OOB
    dangerous_sink_file = FACTS_DIR / "DangerousSink.facts"
    with open(dangerous_sink_file, 'a') as f:
        f.write("get_array_item\t1\toob_access\n")
        f.write("detach_item_from_array\t1\toob_access\n")
        f.write("insert_item_in_array\t1\toob_access\n")
    print("  DangerousSink: +3 entries (array index functions)")


if __name__ == "__main__":
    main()

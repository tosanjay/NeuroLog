"""
Souffle Runner — Execute Datalog queries via souffle subprocess.

Adapted from bin_datalog's agent.py tool_run_souffle().
"""

import os
import subprocess
import tempfile
from pathlib import Path

RULES_DIR = Path(__file__).parent / "rules"
DEFAULT_FACTS_DIR = Path(__file__).parent / "facts"
DEFAULT_OUTPUT_DIR = Path(__file__).parent / "output"


def run_souffle(
    rule_file: str | None = None,
    custom_rules: str | None = None,
    facts_dir: str | Path | None = None,
    output_dir: str | Path | None = None,
    timeout: int = 60,
) -> dict:
    """Run a Souffle Datalog query.

    Args:
        rule_file: Name of a .dl file in rules/ (e.g., "taint.dl").
        custom_rules: Inline Datalog rules (alternative to rule_file).
        facts_dir: Directory containing .facts TSV files.
        output_dir: Directory for .csv output files.
        timeout: Subprocess timeout in seconds.

    Returns:
        Dict with keys: success, outputs (dict of filename → content),
        stdout, stderr, stats.
    """
    facts_dir = Path(facts_dir or DEFAULT_FACTS_DIR)
    output_dir = Path(output_dir or DEFAULT_OUTPUT_DIR)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Clear stale output files
    for f in output_dir.glob("*.csv"):
        f.unlink()

    # Determine rule file path
    if custom_rules:
        tmp = tempfile.NamedTemporaryFile(
            mode='w', suffix='.dl', dir=str(RULES_DIR), delete=False
        )
        tmp.write(custom_rules)
        tmp.close()
        rule_path = tmp.name
    elif rule_file:
        rule_path = str(RULES_DIR / rule_file)
        if not os.path.exists(rule_path):
            return {
                "success": False,
                "error": f"Rule file not found: {rule_path}",
                "outputs": {},
            }
    else:
        return {
            "success": False,
            "error": "Either rule_file or custom_rules must be provided",
            "outputs": {},
        }

    cmd = ["souffle", "-F", str(facts_dir), "-D", str(output_dir), rule_path]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": f"Souffle timed out after {timeout}s",
            "outputs": {},
        }
    except FileNotFoundError:
        return {
            "success": False,
            "error": "souffle not found. Is Souffle installed?",
            "outputs": {},
        }
    finally:
        if custom_rules and os.path.exists(rule_path):
            os.unlink(rule_path)

    # Collect outputs
    # Cap content returned to caller to prevent ADK context overflow.
    # Full results remain on disk in output/*.csv.
    MAX_OUTPUT_LINES = int(os.environ.get("MAX_SOUFFLE_OUTPUT_LINES", "50"))

    outputs = {}
    stats = {}
    for csv_file in sorted(output_dir.glob("*.csv")):
        content = csv_file.read_text().strip()
        if content:
            lines = content.split('\n')
            stats[csv_file.name] = len(lines)
            if len(lines) > MAX_OUTPUT_LINES:
                truncated = '\n'.join(lines[:MAX_OUTPUT_LINES])
                outputs[csv_file.name] = (
                    f"{truncated}\n... ({len(lines) - MAX_OUTPUT_LINES} more rows, "
                    f"see {csv_file} for full output)"
                )
            else:
                outputs[csv_file.name] = content

    success = result.returncode == 0

    # Recycle outputs to facts/ for subsequent queries
    _recycle_outputs_to_facts(output_dir, facts_dir)

    return {
        "success": success,
        "outputs": outputs,
        "stats": stats,
        "stdout": result.stdout.strip() if result.stdout else "",
        "stderr": result.stderr.strip() if result.stderr else "",
    }


def _recycle_outputs_to_facts(output_dir: Path, facts_dir: Path):
    """Copy key Souffle outputs (.csv) back to facts/ (.facts) so subsequent
    queries can consume them as input relations.

    This avoids the confusion where results live in output/ but a follow-up
    custom query expects them in facts/.
    """
    # Relations that downstream queries commonly need as input
    RECYCLE = [
        "TaintedVar", "TaintedSink", "TaintControlledSink",
        "TaintedBuffer", "TaintedField", "TaintSummary",
        "PointsTo", "DefReachesUse", "CFGReach",
        "GuardedSink", "SanitizedVar",
        "TaintGuardedCall", "TaintReachableFunc",
        "TypeSafetyFinding", "TaintedTruncation",
        "TaintedSignExtension", "TaintedWidthMismatchAtSink",
        "MemSafetyFinding", "UnguardedTaintedSink",
        "TaintedPtrArith", "BufferOverflowInLoop",
        "AllocCopyMismatch", "TaintedSizeAtSink",
        "UncheckedAlloc",
        "UseAfterFree", "UnguardedUAF",
        "DoubleFree", "UnguardedDoubleFree",
    ]
    copied = []
    for name in RECYCLE:
        csv = output_dir / f"{name}.csv"
        facts_file = facts_dir / f"{name}.facts"
        if csv.exists():
            content = csv.read_text()
            if content.strip():
                facts_file.write_text(content)
                copied.append(name)
            elif not facts_file.exists():
                facts_file.touch()  # empty but present for downstream
        elif not facts_file.exists():
            facts_file.touch()  # ensure downstream passes can open it
    if copied:
        print(f"    → Recycled to facts/: {', '.join(copied)}")


def run_taint_pipeline(
    facts_dir: str | Path | None = None,
    output_dir: str | Path | None = None,
    timeout: int = 60,
    source_mode: bool = True,
) -> dict:
    """Two-pass taint pipeline: alias → interprocedural taint.

    Args:
        source_mode: If True, use source_interproc.dl (reaching-definitions
                     based, for source code). If False, use original
                     interproc.dl (SSA-based, for binary analysis).

    Pass 1: Run alias.dl to get PointsTo.csv
    Pass 2: Copy PointsTo.csv → PointsTo.facts, then run interproc rules.
    """
    facts_dir = Path(facts_dir or DEFAULT_FACTS_DIR)
    output_dir = Path(output_dir or DEFAULT_OUTPUT_DIR)

    interproc_file = "source_interproc.dl" if source_mode else "interproc.dl"

    # Pass 1: Alias analysis
    print("  Pass 1: Running alias.dl...")
    result1 = run_souffle("alias.dl", facts_dir=facts_dir, output_dir=output_dir, timeout=timeout)
    if not result1["success"]:
        return {"success": False, "error": f"Pass 1 (alias) failed: {result1.get('stderr', '')}", "outputs": {}}

    # Copy PointsTo.csv → PointsTo.facts
    points_to_csv = output_dir / "PointsTo.csv"
    points_to_facts = facts_dir / "PointsTo.facts"
    if points_to_csv.exists():
        content = points_to_csv.read_text()
        points_to_facts.write_text(content)
        print(f"    → PointsTo: {len(content.strip().splitlines())} tuples")
    else:
        print("    → No PointsTo results (empty)")
        points_to_facts.touch()

    # Pass 2: Interprocedural taint (source-aware or SSA-based)
    print(f"  Pass 2: Running {interproc_file}...")
    result2 = run_souffle(interproc_file, facts_dir=facts_dir, output_dir=output_dir, timeout=timeout)

    # Copy key outputs back to facts/ so subsequent queries can use them as input
    _recycle_outputs_to_facts(output_dir, facts_dir)

    # Pass 3: Type safety analysis (consumes TaintedVar + DefReachesUse from Pass 2)
    # Only run in source mode — binary analysis uses inttype.dl separately
    result3 = {"outputs": {}, "stats": {}}
    if source_mode:
        type_safety_file = RULES_DIR / "source_type_safety.dl"
        if type_safety_file.exists():
            print("  Pass 3: Running source_type_safety.dl...")
            result3 = run_souffle("source_type_safety.dl", facts_dir=facts_dir,
                                  output_dir=output_dir, timeout=timeout)
            if not result3["success"]:
                print(f"    [WARN] Pass 3 (type_safety) failed: {result3.get('stderr', '')[:200]}")
            _recycle_outputs_to_facts(output_dir, facts_dir)

    # Pass 4: Memory safety analysis (consumes TaintedVar, TaintedSink,
    # GuardedSink, DefReachesUse from Pass 2)
    result4 = {"outputs": {}, "stats": {}}
    if source_mode:
        memsafety_file = RULES_DIR / "source_memsafety.dl"
        if memsafety_file.exists():
            print("  Pass 4: Running source_memsafety.dl...")
            result4 = run_souffle("source_memsafety.dl", facts_dir=facts_dir,
                                  output_dir=output_dir, timeout=timeout)
            if not result4["success"]:
                print(f"    [WARN] Pass 4 (memsafety) failed: {result4.get('stderr', '')[:200]}")
            _recycle_outputs_to_facts(output_dir, facts_dir)

    # Pass 5: Sink post-pass — recomputes TaintedSink from recycled facts
    # to catch sinks that the fixpoint computation in Pass 2 misses
    result5 = {"outputs": {}, "stats": {}}
    if source_mode:
        sink_pass_file = RULES_DIR / "source_sink_pass.dl"
        if sink_pass_file.exists():
            print("  Pass 5: Running source_sink_pass.dl...")
            result5 = run_souffle("source_sink_pass.dl", facts_dir=facts_dir,
                                  output_dir=output_dir, timeout=timeout)
            if not result5["success"]:
                print(f"    [WARN] Pass 5 (sink_pass) failed: {result5.get('stderr', '')[:200]}")
            _recycle_outputs_to_facts(output_dir, facts_dir)

    # Merge outputs from all passes
    all_outputs = {**result1.get("outputs", {}), **result2.get("outputs", {}),
                   **result3.get("outputs", {}), **result4.get("outputs", {}),
                   **result5.get("outputs", {})}
    all_stats = {**result1.get("stats", {}), **result2.get("stats", {}),
                 **result3.get("stats", {}), **result4.get("stats", {}),
                 **result5.get("stats", {})}

    return {
        "success": result2["success"],
        "outputs": all_outputs,
        "stats": all_stats,
        "stderr": result2.get("stderr", ""),
    }


def list_rule_files() -> list[dict]:
    """List available Datalog rule files."""
    rules = []
    for dl_file in sorted(RULES_DIR.glob("*.dl")):
        # Read first comment line as description
        desc = ""
        try:
            with open(dl_file) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("//"):
                        desc = line.lstrip("/ ").strip()
                        break
                    elif line and not line.startswith("/*"):
                        break
        except Exception:
            pass
        rules.append({"file": dl_file.name, "description": desc})
    return rules


# ── CLI ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python souffle_runner.py <rule_file.dl> [facts_dir] [output_dir]")
        print("\nAvailable rules:")
        for r in list_rule_files():
            print(f"  {r['file']:30s} {r['description']}")
        sys.exit(1)

    rule_file = sys.argv[1]
    facts_dir = sys.argv[2] if len(sys.argv) > 2 else None
    output_dir = sys.argv[3] if len(sys.argv) > 3 else None

    if rule_file == "pipeline":
        result = run_taint_pipeline(facts_dir=facts_dir, output_dir=output_dir)
    else:
        result = run_souffle(rule_file=rule_file, facts_dir=facts_dir, output_dir=output_dir)

    if result["success"]:
        print(f"\nSouffle completed successfully.")
        if result["outputs"]:
            for name, content in sorted(result["outputs"].items()):
                rows = len(content.strip().split('\n')) if content.strip() else 0
                print(f"\n--- {name} ({rows} rows) ---")
                # Show first 20 rows
                lines = content.strip().split('\n')
                for line in lines[:20]:
                    print(f"  {line}")
                if len(lines) > 20:
                    print(f"  ... ({len(lines) - 20} more rows)")
        else:
            print("  (no output produced)")
    else:
        print(f"\nSouffle FAILED:")
        print(f"  {result.get('error', result.get('stderr', 'Unknown error'))}")

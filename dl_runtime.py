"""On-demand Datalog runtime — execute LLM-authored rules against an
existing facts directory at reasoning time.

Companion to `souffle_runner.py`, which runs the precomputed five-pass
rule mesh from `rules/`. This module accepts arbitrary Datalog source
from the agent layer (typically the InterpreterAgent or AnalysisAgent),
runs it via souffle against an existing facts directory, and returns
either parsed output relations OR a structured error record the agent
can use to fix its rule and retry.

The error-feedback loop is the whole point of having this. LLM-authored
Datalog will frequently miss arity, types, or `.input` declarations on
the first try; the agent reads `souffle_stderr` plus the line-numbered
source we hand back, fixes it, and resubmits. This is what turns
NeuroLog from a batch pipeline into an interactive analysis tool: the
agent sees a finding, hypothesises a follow-up question, fires a
narrowly-scoped query against the same facts, and grounds its verdict
in the result.

Design choices:
  * `souffle_stderr` is passed through verbatim (capped at 16 KB only
    as a safety against runaway error cascades; truncation is signalled
    in the response).
  * The submitted rule text is returned with `<line> | ` markers so the
    agent can match `<file>:<line>:<col>` errors directly to its source
    without having to re-count.
  * Output rows per relation are capped at 500 to avoid blowing the
    LLM's context with a runaway query — `truncated=true` flags this so
    the agent can re-run with a tighter filter.
  * Inlined souffle command construction; no dependency on the rest of
    the pipeline. The sibling project's `dl_runtime.py` depended on
    `pipeline.souffle_cmd()`; this version is standalone so the agent
    layer can import it without dragging in the full pipeline.
"""

from __future__ import annotations

import csv
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

try:
    from audit_log import log_step as _audit_log_step  # type: ignore
except ImportError:
    def _audit_log_step(*args, **kwargs):  # noqa: D401
        return None


_SOUFFLE_BIN = os.environ.get("SOUFFLE_BIN", "souffle")
_STDERR_CAP_BYTES = 16 * 1024
_STDOUT_CAP_BYTES = 8 * 1024
_OUTPUT_ROW_CAP = 500


def _line_number_source(text: str) -> str:
    """Prepend `<line> | ` markers so souffle's <file>:<line>:<col>
    error messages align with what the agent sees."""
    lines = text.splitlines() or [""]
    width = len(str(len(lines)))
    return "\n".join(
        f"{i + 1:>{width}} | {line}" for i, line in enumerate(lines)
    )


def _read_csv(p: Path) -> list[list[str]]:
    if not p.exists() or p.stat().st_size == 0:
        return []
    with open(p, newline="") as f:
        return [row for row in csv.reader(f, delimiter="\t") if row]


def _cap(s: str, n: int) -> tuple[str, bool]:
    """Cap string at n bytes (UTF-8). Returns (capped, was_truncated)."""
    if len(s) <= n:
        return s, False
    return s[:n] + f"\n[...truncated {len(s) - n} more bytes]", True


def _souffle_cmd(rule_file: Path, facts_dir: Path, out_dir: Path,
                  jobs: str = "auto") -> list[str]:
    """Build the souffle invocation. Mirrors `souffle_runner.py`'s
    `subprocess.run` call (`-F facts -D output rule.dl`) so any
    behavioural assumption that holds for the batch pipeline holds
    here as well."""
    cmd = [_SOUFFLE_BIN, "-F", str(facts_dir), "-D", str(out_dir)]
    if jobs:
        cmd.extend(["-j", jobs])
    cmd.append(str(rule_file))
    return cmd


def compose_and_run(
    rule_text: str,
    facts_dir: str | Path,
    output_relations: list[str],
    timeout_seconds: int = 60,
    jobs: str = "auto",
    extra_inputs: dict[str, str | Path] | None = None,
) -> dict:
    """Author + execute Datalog `rule_text` against `facts_dir`.

    Args:
        rule_text: Full .dl source. The author MUST declare every
                   input relation it consumes via `.decl X(...)`
                   followed by `.input X` — souffle does not auto-bind
                   to facts/. Likewise, every relation listed in
                   `output_relations` must have a corresponding
                   `.output Foo` directive.
        facts_dir: Directory containing the existing .facts files.
        output_relations: Names of derived relations to read back.
        timeout_seconds: Per-query timeout (default 60s — small,
                         because triage queries should be narrowly
                         scoped).
        jobs: Souffle `-j` argument (default "auto").
        extra_inputs: Optional mapping
                   `{relation_name: path_to_csv_or_facts}` for staging
                   pre-derived relations (e.g.\\ `ResolvedVarType`,
                   `TaintedVar`, `BlockReach`) from a previous batch
                   pipeline run as additional `.input` sources. The
                   files are TSV in both cases; the runtime copies
                   each one into the working facts dir as
                   `<relation>.facts`. Without this, the agent would
                   have to re-derive precomputed relations every
                   ad-hoc query, which on libxml2-class facts is
                   expensive (and error-prone for the LLM).

    Returns one of these structured dicts (always includes the
    `status` key):

      * status="ok":
          {"status": "ok",
           "outputs": {rel: {"rows": [[...]], "row_count": N,
                             "truncated": bool}, ...},
           "elapsed_seconds": float}

      * status="error":
          {"status": "error",
           "souffle_stderr": str,            # full stderr (capped)
           "souffle_stdout": str,            # may also be informative
           "rule_text_with_line_numbers": str,  # `1 | .decl ...`
           "elapsed_seconds": float,
           "stderr_truncated": bool}         # absent if not truncated

      * status="timeout":
          {"status": "timeout",
           "timeout_seconds": int,
           "elapsed_seconds": float}

      * status="no_outputs":  (souffle ran cleanly but produced no
        non-empty CSVs for the requested output relations — usually a
        sign the rule body never matched any facts)
          {"status": "no_outputs",
           "souffle_stderr": str,
           "elapsed_seconds": float,
           "outputs": {rel: {...empty rows...}}}
    """
    fdir = Path(facts_dir)
    if not fdir.exists():
        return {
            "status": "error",
            "souffle_stderr": f"facts_dir does not exist: {fdir}",
            "souffle_stdout": "",
            "rule_text_with_line_numbers": _line_number_source(rule_text),
            "elapsed_seconds": 0.0,
        }
    if shutil.which(_SOUFFLE_BIN) is None:
        return {
            "status": "error",
            "souffle_stderr": f"souffle binary not found: {_SOUFFLE_BIN}",
            "souffle_stdout": "",
            "rule_text_with_line_numbers": _line_number_source(rule_text),
            "elapsed_seconds": 0.0,
        }

    t0 = time.time()

    with tempfile.TemporaryDirectory(prefix="dl_runtime_") as td:
        td_p = Path(td)
        rule_file = td_p / "query.dl"
        rule_file.write_text(rule_text)
        out_dir = td_p / "out"
        out_dir.mkdir()

        # If the caller asked us to stage extra inputs (typically
        # pre-derived relations from a previous pipeline run), copy
        # the original facts dir into a working dir first, then drop
        # each extra in alongside as `<relation>.facts`. We never
        # mutate the caller's facts_dir.
        active_facts_dir = fdir
        if extra_inputs:
            # Symlink the existing facts (read-only from souffle's
            # POV) and copy the extras. Avoids the disk-copy cost of
            # the whole facts dir on libxml2-class corpora while
            # still letting us drop new inputs in alongside.
            staged = td_p / "facts"
            staged.mkdir()
            for entry in fdir.iterdir():
                if entry.is_file():
                    try:
                        os.symlink(entry.resolve(), staged / entry.name)
                    except OSError:
                        shutil.copy2(entry, staged / entry.name)
            for rel, src in extra_inputs.items():
                src_p = Path(src)
                if src_p.exists():
                    shutil.copy2(src_p, staged / f"{rel}.facts")
            active_facts_dir = staged

        cmd = _souffle_cmd(rule_file, active_facts_dir, out_dir, jobs=jobs)

        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            return {
                "status": "timeout",
                "timeout_seconds": timeout_seconds,
                "elapsed_seconds": time.time() - t0,
            }

        elapsed = time.time() - t0
        stderr_capped, stderr_trunc = _cap(r.stderr or "", _STDERR_CAP_BYTES)
        stdout_capped, _ = _cap(r.stdout or "", _STDOUT_CAP_BYTES)

        if r.returncode != 0:
            err_first = (r.stderr or "").splitlines()[:1]
            err_first = err_first[0] if err_first else ""
            _audit_log_step("agent", "datalog_query",
                            ",".join(output_relations),
                            f"status=error elapsed={elapsed:.3f}s "
                            f"err={err_first[:120]}")
            result = {
                "status": "error",
                "souffle_stderr": stderr_capped,
                "souffle_stdout": stdout_capped,
                "rule_text_with_line_numbers": _line_number_source(rule_text),
                "elapsed_seconds": elapsed,
            }
            if stderr_trunc:
                result["stderr_truncated"] = True
            return result

        outputs: dict = {}
        any_nonempty = False
        for rel in output_relations:
            csv_path = out_dir / f"{rel}.csv"
            rows = _read_csv(csv_path)
            if rows:
                any_nonempty = True
            truncated = len(rows) > _OUTPUT_ROW_CAP
            if truncated:
                rows = rows[:_OUTPUT_ROW_CAP]
            outputs[rel] = {
                "rows": rows,
                "row_count": len(rows),
                "truncated": truncated,
            }

        rel_summary = " ".join(f"{r}={outputs[r]['row_count']}"
                                for r in output_relations)
        if not any_nonempty:
            _audit_log_step("agent", "datalog_query",
                            ",".join(output_relations),
                            f"status=no_outputs elapsed={elapsed:.3f}s "
                            f"{rel_summary}")
            return {
                "status": "no_outputs",
                "souffle_stderr": stderr_capped,
                "elapsed_seconds": elapsed,
                "outputs": outputs,
            }

        _audit_log_step("agent", "datalog_query",
                        ",".join(output_relations),
                        f"status=ok elapsed={elapsed:.3f}s {rel_summary}")
        return {
            "status": "ok",
            "outputs": outputs,
            "elapsed_seconds": elapsed,
        }

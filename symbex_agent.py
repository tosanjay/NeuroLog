"""
Symbex Agent — on-demand Z3 verification of Datalog findings.

Phase A: intra-procedural. The agent receives a Datalog finding (function,
addr, var, kind), encodes the def-use chain + path guards as a Z3 formula,
and asserts the bug condition. SAT → feasible (likely true positive);
UNSAT → infeasible (false positive ruled out by guards); UNKNOWN → Z3
timeout or unsupported pattern.

This module is intended as an ADK sub-agent the InterpreterAgent can hand
findings to before promoting them in the report. It can also be driven
standalone via the `tool_check_finding_feasibility` and
`tool_batch_check_findings` functions.
"""

from __future__ import annotations

import csv
import dataclasses
import json
import os
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool

from symbex_config import SymbexConfig
from symbex_encoder import (
    BUG_CONDITION_BUILDERS,
    FactStore,
    Finding,
    FunctionEncoder,
    SymbexResult,
)
from summary_pass import derive_summaries, write_summaries

try:
    from audit_log import log_step as _audit_log_step  # type: ignore
except ImportError:
    def _audit_log_step(*args, **kwargs):  # noqa: D401
        return None


# ── Worker globals (Phase D parallelism) ────────────────────────────────────
# Set by `_worker_init` once per child process. Keeping the FactStore at
# module scope avoids re-loading hundreds of MB of facts per finding —
# the dominant cost on libxml2-scale codebases. Z3 contexts are not
# fork-safe, so encoders are still created per finding inside the worker.

_WORKER_STORE: Optional[FactStore] = None
_WORKER_CFG: Optional[SymbexConfig] = None


def _worker_init(facts_dir: str, cfg_dict: dict) -> None:
    """Initializer for ProcessPoolExecutor children: load facts once."""
    global _WORKER_STORE, _WORKER_CFG
    _WORKER_STORE = FactStore.load(facts_dir)
    _WORKER_CFG = SymbexConfig(**cfg_dict)


def _worker_check(rel: str, kind: str, func: str, addr: int,
                   var: str) -> dict:
    """Per-finding worker. Builds an encoder against the pre-loaded
    FactStore (module global), runs `check()`, returns a result dict."""
    finding = Finding(func=func, addr=int(addr), var=var, kind=kind)
    enc = FunctionEncoder(_WORKER_STORE, finding, _WORKER_CFG)
    r = enc.check()
    return {
        "relation": rel, "func": func, "addr": int(addr), "var": var,
        "kind": kind, "verdict": r.verdict, "model": r.model_str,
        "elapsed_ms": r.elapsed_ms,
    }


def _worker_check_chunk(chunk: list[tuple]) -> list[dict]:
    """Process a chunk of findings in one worker call.

    IPC-amortizing batch worker: serializing one tuple per future is
    high-overhead at <10 ms/finding. With ~50–100 findings per chunk
    the FactStore + Z3 import is amortized; throughput on libxml2-
    class codebases scales near-linearly with worker count."""
    out: list[dict] = []
    for (rel, kind, func, addr, var) in chunk:
        try:
            out.append(_worker_check(rel, kind, func, addr, var))
        except Exception:  # noqa: BLE001 — preserve robustness
            continue
    return out


def _enumerate_findings(out_dir: Path, selected: list[str], limit: int):
    """Yield (rel, kind, func, addr, var) tuples from CSV files."""
    for rel in selected:
        if rel not in CSV_TO_KIND:
            continue
        kind, fcol, acol, vcol = CSV_TO_KIND[rel]
        path = out_dir / rel
        if not path.exists():
            continue
        with path.open() as fp:
            for i, row in enumerate(csv.reader(fp, delimiter="\t")):
                if limit and i >= limit:
                    break
                if not row or len(row) <= max(fcol, acol, vcol):
                    continue
                try:
                    addr = int(row[acol])
                except (ValueError, IndexError):
                    continue
                yield rel, kind, row[fcol], addr, row[vcol]


# ── CSV → finding-kind dispatch ─────────────────────────────────────────────
# Maps the Datalog output CSV name to the bug-class key used in
# symbex_encoder.BUG_CONDITION_BUILDERS, plus the column indices that
# identify the (func, addr, var) tuple. Unsupported relations are skipped.
CSV_TO_KIND: dict[str, tuple[str, int, int, int]] = {
    # csv_basename: (kind, func_col, addr_col, var_col)
    "NarrowArithAtSink.csv":     ("narrow_arith_at_sink",     0, 1, 3),
    "SignedArgAtSink.csv":       ("signed_arg_at_sink",       0, 1, 3),
    "ImplicitTruncation.csv":    ("truncation_cast",          0, 1, 3),
    "PotentialArithOverflow.csv":("potential_arith_overflow", 0, 1, 2),
    "OverflowAtSink.csv":        ("potential_arith_overflow", 0, 1, 3),
    "TaintedUnboundedCounter.csv":("unbounded_counter_at_sink", 0, 1, 2),
    "CounterUsedAsIndex.csv":    ("unbounded_counter_at_sink",0, 1, 2),
}


# ── Tools ───────────────────────────────────────────────────────────────────

def tool_check_finding_feasibility(
    facts_dir: str,
    func: str,
    addr: int,
    var: str,
    kind: str = "narrow_arith_at_sink",
    extra_json: str = "",
) -> dict:
    """Verify a single Datalog finding with Z3.

    Args:
      facts_dir: path to the facts/ directory of the project.
      func: function name where the finding was raised.
      addr: bug-site source line number.
      var: primary variable name involved in the finding.
      kind: bug-class key (one of `BUG_CONDITION_BUILDERS`). Defaults to
            `narrow_arith_at_sink`.
      extra_json: optional JSON for class-specific knobs (e.g.
            `{"sentinel": 65535}` for unbounded_counter_at_sink, or
            `{"narrow_bits": 8}` for truncation_cast).

    Returns:
      A dict with verdict / reason / model summary, ready to surface in a
      report alongside the Datalog finding.
    """
    extra: dict = {}
    if extra_json:
        try:
            extra = json.loads(extra_json)
        except (json.JSONDecodeError, ValueError):
            extra = {}
    if kind not in BUG_CONDITION_BUILDERS:
        return {
            "verdict": "unknown",
            "reason": f"unsupported bug class: {kind}. Supported: "
                      f"{sorted(BUG_CONDITION_BUILDERS)}",
            "func": func, "addr": addr, "var": var, "kind": kind,
        }

    cfg = SymbexConfig.from_env()
    store = FactStore.load(facts_dir)
    finding = Finding(func=func, addr=int(addr), var=var, kind=kind, extra=extra)
    enc = FunctionEncoder(store, finding, cfg)
    result = enc.check()
    return {
        "verdict": result.verdict,
        "reason": result.reason,
        "model": result.model_str,
        "elapsed_ms": result.elapsed_ms,
        "func": func, "addr": addr, "var": var, "kind": kind,
    }


def tool_batch_check_findings(
    facts_dir: str,
    output_dir: str,
    relations: str = "",
    limit: int = 0,
    parallel: bool = False,
    n_workers: int = 0,
) -> dict:
    """Run symbex on every finding in selected output CSVs.

    Args:
      facts_dir: path to the facts/ directory.
      output_dir: path to the output/ directory holding Datalog *.csv.
      relations: comma-separated list of CSV basenames to check (e.g.
            `NarrowArithAtSink.csv,SignedArgAtSink.csv`). Empty → all
            supported relations present in `output_dir`.
      limit: cap per-relation row count (0 = no cap; useful for triage).

    Returns:
      Summary: counts (feasible/infeasible/unknown) per relation + a
      flat list of feasible findings, each with verdict + model. Reports
      should highlight the feasible set first and list infeasible
      findings as filtered out by the verifier.
    """
    out_dir = Path(output_dir)
    if not out_dir.exists():
        return {"error": f"output_dir does not exist: {output_dir}"}
    cfg = SymbexConfig.from_env()

    selected = (relations.split(",") if relations else
                [n for n in CSV_TO_KIND if (out_dir / n).exists()])
    selected = [s.strip() for s in selected if s.strip()]

    # Track per-relation buckets independent of execution mode so the
    # serial / parallel branches can share the same accumulator.
    buckets: dict[str, dict] = {
        rel: {"feasible": 0, "infeasible": 0, "unknown": 0, "errors": 0}
        for rel in selected if rel in CSV_TO_KIND
    }
    feasible_rows: list[dict] = []
    t0 = time.monotonic()

    findings_iter = list(_enumerate_findings(out_dir, selected, limit))

    if parallel and findings_iter:
        n = n_workers if n_workers > 0 else max(1, (os.cpu_count() or 4) - 1)
        cfg_dict = dataclasses.asdict(cfg)
        # Aim for ~4 chunks per worker so stragglers don't dominate;
        # at least 16 findings per chunk to amortize IPC.
        n_chunks = max(n, min(4 * n, max(1, len(findings_iter) // 16)))
        chunk_size = max(1, (len(findings_iter) + n_chunks - 1) // n_chunks)
        chunks = [findings_iter[i:i + chunk_size]
                  for i in range(0, len(findings_iter), chunk_size)]
        with ProcessPoolExecutor(max_workers=n,
                                  initializer=_worker_init,
                                  initargs=(facts_dir, cfg_dict)) as pool:
            futs = [pool.submit(_worker_check_chunk, chunk)
                    for chunk in chunks]
            for fut in as_completed(futs):
                try:
                    results = fut.result()
                except Exception:  # noqa: BLE001 — preserve robustness
                    continue
                for res in results:
                    rel = res["relation"]
                    if res["verdict"] == "feasible":
                        buckets[rel]["feasible"] += 1
                        feasible_rows.append({k: res[k] for k in (
                            "relation", "func", "addr", "var", "kind",
                            "model", "elapsed_ms")})
                    elif res["verdict"] == "infeasible":
                        buckets[rel]["infeasible"] += 1
                    else:
                        buckets[rel]["unknown"] += 1
    else:
        store = FactStore.load(facts_dir)
        for rel, kind, func, addr, var in findings_iter:
            finding = Finding(func=func, addr=addr, var=var, kind=kind)
            enc = FunctionEncoder(store, finding, cfg)
            r = enc.check()
            if r.verdict == "feasible":
                buckets[rel]["feasible"] += 1
                feasible_rows.append({
                    "relation": rel, "func": func, "addr": addr,
                    "var": var, "kind": kind, "model": r.model_str,
                    "elapsed_ms": r.elapsed_ms,
                })
            elif r.verdict == "infeasible":
                buckets[rel]["infeasible"] += 1
            else:
                buckets[rel]["unknown"] += 1

    # Carry forward error counts for relations that exist but had no
    # rows / unsupported entries (kept for parity with legacy reports).
    summary: dict[str, dict] = {}
    for rel in selected:
        if rel not in CSV_TO_KIND:
            summary[rel] = {"error": "unsupported relation"}
            continue
        path = out_dir / rel
        if not path.exists():
            summary[rel] = {"error": "file not found"}
            continue
        b = buckets[rel]
        # CSV row enumeration in `_enumerate_findings` silently drops
        # malformed rows; recount errors here for parity.
        n_rows = 0
        with path.open() as fp:
            for i, row in enumerate(csv.reader(fp, delimiter="\t")):
                if limit and i >= limit:
                    break
                n_rows += 1
        b["errors"] = max(0, n_rows -
                           (b["feasible"] + b["infeasible"] + b["unknown"]))
        summary[rel] = b
    elapsed_s = round(time.monotonic() - t0, 3)
    n_feas = sum(b.get("feasible", 0) for b in buckets.values())
    n_inf  = sum(b.get("infeasible", 0) for b in buckets.values())
    n_unk  = sum(b.get("unknown", 0) for b in buckets.values())
    label = "phase_b" if (Path(facts_dir) / "summaries.json").exists() \
            else "phase_a"
    _audit_log_step("symbex", "batch_check", label,
                    f"findings={len(findings_iter)} feasible={n_feas} "
                    f"infeasible={n_inf} unknown={n_unk} "
                    f"elapsed={elapsed_s}s parallel={bool(parallel)}")
    return {
        "summary": summary,
        "feasible": feasible_rows,
        "supported_relations": sorted(CSV_TO_KIND),
        "elapsed_s": elapsed_s,
        "parallel": bool(parallel),
        "n_findings": len(findings_iter),
    }


def tool_list_supported_classes() -> dict:
    """Return the list of bug classes the symbex encoder can verify."""
    return {
        "kinds": sorted(BUG_CONDITION_BUILDERS),
        "relations": {k: v[0] for k, v in CSV_TO_KIND.items()},
    }


def tool_compute_function_summaries(facts_dir: str) -> dict:
    """Compute Phase-B function summaries (return-value bounds) and
    write them to `<facts_dir>/summaries.json`. Subsequent symbex calls
    on the same `facts_dir` automatically pick the summaries up.

    Returns counts grouped by summary `kind` so the Interpreter can see
    how much extra precision the catalog + heuristics provide.
    """
    fdir = Path(facts_dir)
    if not fdir.exists():
        return {"error": f"facts_dir does not exist: {facts_dir}"}
    store = FactStore.load(fdir)
    summaries = derive_summaries(store)
    out = write_summaries(summaries, fdir)
    by_kind: dict[str, int] = {}
    for s in summaries.values():
        by_kind[s.kind] = by_kind.get(s.kind, 0) + 1
    return {
        "wrote": str(out),
        "total": len(summaries),
        "by_kind": by_kind,
    }


# ── Agent definition ────────────────────────────────────────────────────────

SYMBEX_INSTRUCTION = """You are the **Symbex Agent** for NeuroLog.

Your job: verify Datalog findings with a Z3 SMT solver before they are
promoted in the final report. The Datalog rule mesh has high recall but
imperfect precision — your verdicts let the Interpreter prioritise truly
reachable findings and demote false positives that path conditions
exclude.

Inputs you may receive:
- A specific finding tuple (func, addr, var, kind) the Interpreter wants
  to verify before reporting it.
- A request to batch-verify all findings in a relation (or all relations).

## Tools

- `tool_compute_function_summaries(facts_dir)` — derive Phase-B return-value
  summaries and write them to `summaries.json`. Run this ONCE per
  facts_dir before batch verification; the encoder picks summaries up
  automatically. Re-run when facts change.
- `tool_check_finding_feasibility(facts_dir, func, addr, var, kind, extra_json)`
  — verify ONE finding. Returns verdict + Z3 model (when feasible).
- `tool_batch_check_findings(facts_dir, output_dir, relations, limit)`
  — sweep selected relations. Returns counts + the list of feasible
    findings. Use `relations=""` to check every supported relation.
- `tool_list_supported_classes()` — list bug classes you can verify.

## Verdict semantics (READ CAREFULLY)

- **feasible**: Z3 found a satisfying assignment. The bug condition CAN
  hold under SOME input on SOME path through the function — strong
  evidence for true positive. Include the model in the report.
- **infeasible**: Z3 proved UNSAT. Path guards rule out the bug
  condition for every input — strong evidence for false positive. The
  finding should be filtered or footnoted, not promoted.
- **unknown**: Z3 timed out, hit a non-linear theory, or the encoder
  could not model the relevant pattern (call summaries unavailable in
  Phase A). Treat as inconclusive — do not use as evidence either way.

## Limitations (state these honestly when relevant)

- Phase B-1 summaries are coarse: catalog covers libc + ffmpeg/libav
  bitstream/io/allocator/validator helpers, plus a type-range
  heuristic for declared narrow returns. Functions outside the catalog
  fall back to free-symbolic returns (Phase A behaviour). Run
  `tool_compute_function_summaries` BEFORE batch verification — it's a
  no-op if no summaries.json yet exists.
- Path guards over-approximate: only `if (cond) return/goto cleanup`
  patterns (`GuardEarlyReturn`) are asserted as path conditions. A
  guarded `if (cond) sink(...)` may be missed and the verdict may
  read `feasible` even though the sink is locally guarded.
- Loop unrolling capped at config (default 4); deeper invariants are
  approximated.
- No depth-bounded inlining yet: a callee whose summary is unknown but
  whose definition exists in the fact set is not yet inlined. That
  comes in Phase B-2.

## Output discipline

When the Interpreter sends a single finding: respond with a compact
JSON-flavoured summary including verdict, reason, model (if feasible),
and elapsed_ms.

When the Interpreter requests batch verification: report the per-relation
counts AND the full list of feasible findings (these are the candidates
the report should retain). Do not fabricate verdicts — quote the tool
output verbatim.
"""


def make_symbex_agent(create_model):
    """Factory — accepts the project's `create_model` so the agent uses
    the same model wiring as its siblings."""
    return LlmAgent(
        name="SymbexAgent",
        model=create_model(lite=True),
        instruction=SYMBEX_INSTRUCTION,
        include_contents="none",
        output_key="symbex_summary",
        tools=[
            FunctionTool(tool_check_finding_feasibility),
            FunctionTool(tool_batch_check_findings),
            FunctionTool(tool_list_supported_classes),
            FunctionTool(tool_compute_function_summaries),
        ],
    )


# ── CLI driver (for offline batch sweeps without ADK) ──────────────────────

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python symbex_agent.py <facts_dir> <output_dir> "
              "[relations] [limit]")
        print()
        print(f"Supported relations: {sorted(CSV_TO_KIND)}")
        sys.exit(1)
    facts_dir = sys.argv[1]
    output_dir = sys.argv[2]
    relations = sys.argv[3] if len(sys.argv) >= 4 else ""
    limit = int(sys.argv[4]) if len(sys.argv) >= 5 else 0
    res = tool_batch_check_findings(facts_dir, output_dir, relations, limit)
    print(json.dumps(res, indent=2, default=str))

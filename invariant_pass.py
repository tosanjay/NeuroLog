"""
Phase E2 — Likely range invariant extractor.

Adapted from Sahoo et al., ASPLOS'13 §2.1 (likely range invariants):
run an ASan-built harness on a small set of "good" inputs (typically
8–16), observe per-(func, addr, var) value ranges, and emit them as
`LikelyRangeInvariant.facts`. Downstream consumers (symbex encoder,
Datalog rules) treat these as observed bounds — values outside this
range have not been seen during normal operation, which is a signal
about programmer intent.

Mechanism: GDB tracepoints (no recompilation needed). For each
finding's `(file, addr, var)` we set a breakpoint that runs a tiny
Python `commands` block: silently `parse_and_eval(var)`, log the
value, continue. Aggregate across all seed runs.

Pragma: this is the simplest credible mechanism. PIN/DynamoRIO would
be lower-overhead but heavier engineering. GDB tracepoints are
acceptable for prototype scale (low hundreds of breakpoints, < 1KLoC
seeds, ~minutes total wall).

CLI:
    python invariant_pass.py <eval_dir> <harness> <corpus_dir> \
        --src <stb_vorbis.c> [--seeds N] [--per-bp-cap N] [--timeout S]

Output:
    <eval_dir>/facts/LikelyRangeInvariant.facts
        TSV: func  var  addr  lo  hi  n_obs
    <eval_dir>/invariant_observations.json
        Per-tuple full observation log (for ablation / debugging)
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path


# Same set of relations symbex understands; we only extract invariants
# at sites that the symbex encoder will actually consult.
SYMBEX_RELATIONS = {
    "NarrowArithAtSink.csv":     3,
    "SignedArgAtSink.csv":       3,
    "ImplicitTruncation.csv":    3,
    "PotentialArithOverflow.csv":2,
    "OverflowAtSink.csv":        3,
    "TaintedUnboundedCounter.csv":2,
    "CounterUsedAsIndex.csv":    2,
    "TruncationCast.csv":        3,
    "UnboundedCounter.csv":      2,
}


@dataclass
class Tracepoint:
    func: str
    addr: int                    # source line
    var: str                     # GDB-evaluable variable expression
    file_basename: str           # e.g. "stb_vorbis.c" — passed to break <file>:<line>


# ── Tracepoint discovery ────────────────────────────────────────────────────

def discover_tracepoints(output_dir: Path, src_basename: str,
                          func_file_map: dict[str, str] | None = None
                          ) -> list[Tracepoint]:
    """Read the symbex-supported finding CSVs; build a unique
    (func, addr, var) tracepoint set.

    `func_file_map`: optional {func_name: source_relpath} for projects
    spanning multiple files (e.g. ffmpeg). When present, each tp's
    file_basename is set to `basename(func_file_map[func])`; falls
    back to `src_basename` for unmapped functions."""
    func_file_map = func_file_map or {}
    seen: set[tuple[str, int, str]] = set()
    out: list[Tracepoint] = []
    for rel, vc in SYMBEX_RELATIONS.items():
        p = output_dir / rel
        if not p.exists() or p.stat().st_size == 0:
            continue
        for row in csv.reader(p.open(), delimiter="\t"):
            if not row or len(row) <= vc:
                continue
            try:
                func, addr, var = row[0], int(row[1]), row[vc].strip()
            except (ValueError, IndexError):
                continue
            if not var or not _is_gdb_safe_expr(var):
                continue
            key = (func, addr, var)
            if key in seen:
                continue
            seen.add(key)
            fbn = func_file_map.get(func)
            fbn = os.path.basename(fbn) if fbn else src_basename
            out.append(Tracepoint(func, addr, var, fbn))
    return out


def load_func_file_map(eval_dir: Path) -> dict[str, str]:
    """Best-effort lookup: read per_function_report.json if present."""
    p = eval_dir / "per_function_report.json"
    if not p.exists():
        return {}
    try:
        rows = json.load(p.open())
    except (OSError, json.JSONDecodeError):
        return {}
    out: dict[str, str] = {}
    for r in rows:
        name = r.get("name")
        f = r.get("file")
        if name and f:
            out[name] = f
    return out


_GDB_SAFE_RE = re.compile(r"^[A-Za-z_][\w\->\[\].]*$")


def _is_gdb_safe_expr(s: str) -> bool:
    """Allow simple identifiers and field/index expressions; reject
    arbitrary C operators that would confuse GDB."""
    return bool(_GDB_SAFE_RE.match(s)) and len(s) <= 80


# ── GDB script generation ──────────────────────────────────────────────────

GDB_PRELUDE = """\
set pagination off
set logging overwrite on
set print elements 0
set print pretty off
set confirm off
set breakpoint pending on
"""


def render_gdb_script(tps: list[Tracepoint], out_log: Path,
                       per_bp_cap: int = 200) -> str:
    """Generate the GDB batch script.

    At each unique (file, line) seen in any finding, set a single
    breakpoint that — via a Python `commands` block — enumerates ALL
    locals visible in the current frame and emits one `INV|...` line
    per integer-valued local. We use real source names (not the LLM
    extractor's synthetic names) and rely on the symbex consumer to
    do approximate matching by (func, line)."""
    parts = [GDB_PRELUDE]
    parts.append(f"set logging file {out_log}\n")
    parts.append("set logging redirect on\n")
    parts.append("set logging enabled on\n")
    by_loc: dict[tuple[str, int], list[Tracepoint]] = defaultdict(list)
    for tp in tps:
        by_loc[(tp.file_basename, tp.addr)].append(tp)
    for i, ((fbn, addr), group) in enumerate(sorted(by_loc.items())):
        # Collect all distinct functions associated with this line —
        # usually one, but defensive in case of inlined / overloaded.
        funcs = sorted({tp.func for tp in group})
        parts.append(f"break {fbn}:{addr}\n")
        parts.append("commands\n")
        parts.append("silent\n")
        parts.append("python\n")
        parts.append(f"_HITS_{i} = globals().get('_HITS_{i}', 0) + 1\n")
        parts.append(f"globals()['_HITS_{i}'] = _HITS_{i}\n")
        parts.append(f"if _HITS_{i} <= {per_bp_cap}:\n")
        parts.append(f"    _funcs = {funcs!r}\n")
        parts.append(f"    _addr = {addr}\n")
        parts.append("    try:\n"
                     "        _frame = gdb.selected_frame()\n"
                     "        _func_name = _frame.name() or ''\n"
                     "        if _func_name in _funcs:\n"
                     "            _block = _frame.block()\n"
                     "            _seen = set()\n"
                     "            while _block is not None:\n"
                     "                for _sym in _block:\n"
                     "                    if not _sym.is_variable: continue\n"
                     "                    _name = _sym.name\n"
                     "                    if _name in _seen: continue\n"
                     "                    _seen.add(_name)\n"
                     "                    try:\n"
                     "                        _val = _frame.read_var(_sym)\n"
                     "                        _i = int(_val)\n"
                     "                        print(f'INV|{_func_name}|{_addr}|{_name}|{_i}', flush=True)\n"
                     "                    except (gdb.error, ValueError, OverflowError, TypeError):\n"
                     "                        pass\n"
                     "                if _block.function: break\n"
                     "                _block = _block.superblock\n"
                     "    except (gdb.error, AttributeError):\n"
                     "        pass\n")
        parts.append("end\n")
        parts.append("continue\n")
        parts.append("end\n\n")
    parts.append("run\n")
    parts.append("quit\n")
    return "".join(parts)


# ── GDB execution ──────────────────────────────────────────────────────────

_INV_LINE_RE = re.compile(r"^INV\|([^|]+)\|(\d+)\|([^|]+)\|(-?\d+)$")


def run_gdb_on_seed(harness: Path, gdb_script: str, seed: Path,
                     timeout_s: float = 30.0) -> str:
    """Run GDB in batch on a single seed; return concatenated stdout +
    log file contents (the script redirects to a log)."""
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        log_path = td_path / "inv.log"
        # Substitute the log path into the script (rendered with a
        # placeholder by the caller).
        script = gdb_script.replace("{LOG_PATH}", str(log_path))
        script_path = td_path / "script.gdb"
        script_path.write_text(script)
        env = os.environ.copy()
        # Disable LSan and ASan abort: LSan does not work under ptrace.
        env["LSAN_OPTIONS"] = "detect_leaks=0"
        env["ASAN_OPTIONS"] = (
            "abort_on_error=0:exitcode=77:detect_leaks=0:" +
            env.get("ASAN_OPTIONS", "")).rstrip(":")
        try:
            p = subprocess.run(
                ["gdb", "-batch", "-x", str(script_path),
                 "--args", str(harness), str(seed)],
                capture_output=True, timeout=timeout_s, env=env)
        except subprocess.TimeoutExpired:
            return ""
        log = ""
        if log_path.exists():
            log = log_path.read_text(errors="replace")
        return log + "\n" + p.stdout.decode("latin1", "replace")


def parse_observations(stdout: str
                        ) -> dict[tuple[str, int, str], list[int]]:
    out: dict[tuple[str, int, str], list[int]] = defaultdict(list)
    for line in stdout.splitlines():
        m = _INV_LINE_RE.match(line.strip())
        if not m:
            continue
        func, addr_s, var, val_s = m.group(1), m.group(2), m.group(3), m.group(4)
        try:
            out[(func, int(addr_s), var)].append(int(val_s))
        except ValueError:
            continue
    return out


# ── Aggregation ────────────────────────────────────────────────────────────

@dataclass
class Invariant:
    func: str
    addr: int
    var: str
    lo: int
    hi: int
    n_obs: int

    def to_facts_row(self) -> str:
        return (f"{self.func}\t{self.var}\t{self.addr}\t"
                f"{self.lo}\t{self.hi}\t{self.n_obs}")


def aggregate(observations: dict[tuple[str, int, str], list[int]]
               ) -> list[Invariant]:
    out: list[Invariant] = []
    for (func, addr, var), values in observations.items():
        if not values:
            continue
        out.append(Invariant(func=func, addr=addr, var=var,
                              lo=min(values), hi=max(values),
                              n_obs=len(values)))
    out.sort(key=lambda inv: (inv.func, inv.addr, inv.var))
    return out


# ── Top-level orchestration ────────────────────────────────────────────────

def collect_invariants(eval_dir: Path, harness: Path, corpus_dir: Path,
                        src_basename: str, n_seeds: int = 8,
                        per_bp_cap: int = 200, timeout_s: float = 30.0,
                        verbose: bool = True) -> tuple[list[Invariant], dict]:
    output_dir = eval_dir / "output"
    facts_dir = eval_dir / "facts"
    facts_dir.mkdir(parents=True, exist_ok=True)

    func_file_map = load_func_file_map(eval_dir)
    tps = discover_tracepoints(output_dir, src_basename, func_file_map)
    if verbose and func_file_map:
        n_mapped = sum(1 for tp in tps if tp.file_basename != src_basename)
        print(f"[invariant] func→file map: {len(func_file_map)} entries, "
              f"{n_mapped}/{len(tps)} tps file-resolved.")
    if verbose:
        print(f"[invariant] {len(tps)} unique tracepoints across "
              f"{len(SYMBEX_RELATIONS)} relations.")
    if not tps:
        return [], {"reason": "no tracepoints"}

    seeds = sorted([p for p in corpus_dir.iterdir() if p.is_file()])[:n_seeds]
    if verbose:
        print(f"[invariant] running on {len(seeds)} seeds.")
    if not seeds:
        return [], {"reason": "empty corpus"}

    # `{LOG_PATH}` is a literal placeholder substituted per-seed by
    # `run_gdb_on_seed` (each seed gets its own temp dir).
    script = render_gdb_script(tps, Path("{LOG_PATH}"),
                                 per_bp_cap=per_bp_cap)

    aggregated: dict[tuple[str, int, str], list[int]] = defaultdict(list)
    per_seed_obs: list[dict] = []
    for i, seed in enumerate(seeds):
        if verbose:
            print(f"[invariant]   seed {i+1}/{len(seeds)}: {seed.name}")
        out = run_gdb_on_seed(harness, script, seed, timeout_s=timeout_s)
        obs = parse_observations(out)
        for k, v in obs.items():
            aggregated[k].extend(v)
        per_seed_obs.append({
            "seed": seed.name,
            "tracepoints_hit": len(obs),
            "total_observations": sum(len(v) for v in obs.values()),
        })

    invariants = aggregate(aggregated)
    if verbose:
        print(f"[invariant] derived {len(invariants)} invariants from "
              f"{sum(s['total_observations'] for s in per_seed_obs)} observations.")

    facts_path = facts_dir / "LikelyRangeInvariant.facts"
    facts_path.write_text(
        "\n".join(inv.to_facts_row() for inv in invariants) + "\n"
        if invariants else "")
    obs_path = eval_dir / "invariant_observations.json"
    obs_path.write_text(json.dumps({
        "n_tracepoints": len(tps),
        "n_seeds": len(seeds),
        "per_seed": per_seed_obs,
        "invariants": [{"func": inv.func, "var": inv.var, "addr": inv.addr,
                         "lo": inv.lo, "hi": inv.hi, "n_obs": inv.n_obs}
                        for inv in invariants],
    }, indent=2))
    return invariants, {
        "n_tracepoints": len(tps),
        "n_seeds": len(seeds),
        "n_invariants": len(invariants),
        "facts_path": str(facts_path),
        "obs_path": str(obs_path),
    }


# ── CLI ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("eval_dir")
    ap.add_argument("harness")
    ap.add_argument("corpus_dir")
    ap.add_argument("--src-basename", default="",
                     help="Source basename for break commands "
                          "(e.g. 'stb_vorbis.c'). If empty, infer from facts.")
    ap.add_argument("--seeds", type=int, default=8)
    ap.add_argument("--per-bp-cap", type=int, default=200)
    ap.add_argument("--timeout", type=float, default=30.0)
    args = ap.parse_args()

    eval_dir = Path(args.eval_dir)
    harness = Path(args.harness)
    corpus_dir = Path(args.corpus_dir)
    src_basename = args.src_basename or "stb_vorbis.c"

    invs, meta = collect_invariants(
        eval_dir=eval_dir, harness=harness, corpus_dir=corpus_dir,
        src_basename=src_basename, n_seeds=args.seeds,
        per_bp_cap=args.per_bp_cap, timeout_s=args.timeout)
    print()
    print("=" * 60)
    print(f"Wrote   : {meta.get('facts_path')}")
    print(f"Obs log : {meta.get('obs_path')}")
    print(f"Stats   : {meta}")
    if invs:
        print()
        print("Top 10 (narrowest range):")
        for inv in sorted(invs, key=lambda i: i.hi - i.lo)[:10]:
            print(f"  {inv.func:30s} L{inv.addr:5d}  {inv.var:20s}  "
                  f"[{inv.lo}, {inv.hi}]  n={inv.n_obs}")

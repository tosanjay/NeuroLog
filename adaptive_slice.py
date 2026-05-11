"""
Phase E4 — Adaptive σ-doubling for backward-slice depth.

Adapted from Kasikci et al. SOSP'15 (Gist) §3.2.1 Adaptive Slice
Tracking, repurposed for our static setting: instead of doubling the
runtime tracking window σ until we find the root cause, we double the
**static-slicing depth** σ until adding more depth no longer adds
meaningful candidate findings. The goal is the same — pick the
*smallest* slice that captures the bug-relevant code, avoiding both
over-tight (miss) and over-wide (extraction cost).

Two modes:

  - `progression` (offline): given a project directory and a sink list,
    compute |slice(σ)| for σ ∈ {2, 4, 6, 8, …} and emit a recommendation
    via diminishing-returns. No pipeline runs; just call-graph BFS over
    tree_sitter_nav. Cheap (seconds).

  - `full` (online — to be wired in by the eval runner): run the full
    pipeline at each σ in increasing order, terminate when symbex-
    feasible count grows by < ε between successive σ values. Re-uses
    extracted facts incrementally so cost is bounded by the converged σ.

Tier-don't-drop: the LARGER σ's findings remain available as a
secondary tier (full set) even if the recommended σ is smaller. The
"recommended σ" is a curation hint, not a filter.

CLI:
    python adaptive_slice.py <project_dir> [--sinks malloc,memcpy,...]
                               [--sigmas 2,4,6,8] [--out adapt.json]
"""
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Optional

from tree_sitter_nav import (
    FuncInfo, build_call_graph, enumerate_functions,
    find_dangerous_sinks, slice_from_sinks,
)


# ── Default sink catalog (matches the eval runner) ─────────────────────────
DEFAULT_SINK_FUNCS = [
    # libc
    "malloc", "calloc", "realloc",
    "memcpy", "memmove", "memset",
    "strcpy", "strncpy", "strcat", "strncat",
    "snprintf", "vsnprintf",
    # ffmpeg / libav
    "av_malloc", "av_mallocz", "av_realloc", "av_calloc",
    "av_fast_realloc", "av_fast_malloc", "av_memcpy_backptr",
    # stb internal
    "setup_malloc", "setup_temp_malloc",
]


# ── Sigma progression ──────────────────────────────────────────────────────

@dataclass
class SigmaPoint:
    sigma: int
    n_funcs: int
    n_files: int
    n_new_funcs: int                 # functions added since previous σ
    func_names: list[str] = field(default_factory=list)

    def to_jsonable(self) -> dict:
        d = asdict(self)
        # File names live in `func_names`; keep the list compact in JSON.
        return d


def compute_progression(project_dir: str | Path,
                          sink_funcs: list[str],
                          sigmas: list[int]) -> list[SigmaPoint]:
    """Compute |slice(σ)| for each σ in `sigmas` (sorted ascending).
    Returns a list of SigmaPoint with new-functions-vs-previous diff."""
    sigmas = sorted(sigmas)
    pts: list[SigmaPoint] = []
    prev_set: set[str] = set()
    for s in sigmas:
        sliced = slice_from_sinks(str(project_dir), sink_functions=sink_funcs,
                                    depth=s)
        names = sorted({f.name for f in sliced})
        n_files = len({f.file_path for f in sliced})
        cur_set = set(names)
        new = sorted(cur_set - prev_set)
        pts.append(SigmaPoint(sigma=s, n_funcs=len(cur_set),
                                n_files=n_files,
                                n_new_funcs=len(new),
                                func_names=names))
        prev_set = cur_set
    return pts


# ── Recommendation ─────────────────────────────────────────────────────────

@dataclass
class SigmaRecommendation:
    chosen_sigma: int
    rationale: str
    saturation_ratio: float          # |slice(chosen)| / |slice(max σ)|
    progression: list[SigmaPoint]


def recommend_sigma(progression: list[SigmaPoint],
                     diminish_threshold: float = 0.05,
                     min_funcs: int = 50,
                     max_funcs: int = 800) -> SigmaRecommendation:
    """Pick σ by diminishing-returns, bounded by sanity thresholds.

    Stop conditions (first match wins):
      1. The slice size has grown by < `diminish_threshold` since the
         previous σ — adding more depth isn't pulling in new functions.
      2. The slice size exceeds `max_funcs` — extraction would cost too
         much, return previous σ.
      3. Otherwise keep growing.
    Always pick at least the smallest σ that crosses `min_funcs` (we
    don't want to under-extract).

    The maximum σ in the progression is the upper bound.
    """
    if not progression:
        return SigmaRecommendation(0, "empty progression", 0.0, [])
    max_pt = progression[-1]
    if max_pt.n_funcs == 0:
        return SigmaRecommendation(progression[0].sigma,
                                     "no functions in slice — sinks not in project?",
                                     0.0, progression)

    # Walk the progression, looking for the first σ where:
    #  - we have at least min_funcs in the slice
    #  - the next σ adds < diminish_threshold more
    chosen: Optional[int] = None
    rationale = ""
    for i, pt in enumerate(progression):
        if pt.n_funcs > max_funcs:
            # over-extraction territory — fall back to previous
            if i > 0:
                chosen = progression[i - 1].sigma
                rationale = (f"σ={pt.sigma} crossed max_funcs={max_funcs}; "
                             f"recommending previous σ.")
            else:
                chosen = pt.sigma
                rationale = (f"σ={pt.sigma} already over max_funcs; using it "
                             f"anyway since it's the smallest available.")
            break
        if i + 1 < len(progression) and pt.n_funcs >= min_funcs:
            nxt = progression[i + 1]
            growth = ((nxt.n_funcs - pt.n_funcs) /
                       max(pt.n_funcs, 1))
            if growth < diminish_threshold:
                chosen = pt.sigma
                rationale = (f"slice growth from σ={pt.sigma} to σ={nxt.sigma} "
                             f"is {growth:.1%} (< {diminish_threshold:.0%}); "
                             f"diminishing returns.")
                break

    if chosen is None:
        chosen = max_pt.sigma
        rationale = (f"slice still growing at σ={max_pt.sigma} "
                     f"(haven't saturated); use the largest σ provided "
                     f"or extend the search range.")

    chosen_pt = next(p for p in progression if p.sigma == chosen)
    saturation = chosen_pt.n_funcs / max(max_pt.n_funcs, 1)
    return SigmaRecommendation(chosen_sigma=chosen, rationale=rationale,
                                 saturation_ratio=saturation,
                                 progression=progression)


# ── Pretty printing ────────────────────────────────────────────────────────

def render_progression(rec: SigmaRecommendation) -> str:
    lines = [f"σ-doubling progression",
              "",
              f"{'σ':>3}  {'|slice|':>8}  {'files':>6}  {'+new':>6}",
              f"{'-'*3}  {'-'*8}  {'-'*6}  {'-'*6}"]
    for pt in rec.progression:
        lines.append(f"{pt.sigma:>3}  {pt.n_funcs:>8}  {pt.n_files:>6}  "
                      f"{pt.n_new_funcs:>+6}")
    lines.append("")
    lines.append(f"Recommended σ : {rec.chosen_sigma}")
    lines.append(f"Saturation    : {rec.saturation_ratio:.1%} of "
                  f"σ={rec.progression[-1].sigma} slice")
    lines.append(f"Rationale     : {rec.rationale}")
    return "\n".join(lines)


# ── CLI ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("project_dir")
    ap.add_argument("--sinks", default="",
                     help="Comma-separated sink functions. Empty → "
                          "default catalog.")
    ap.add_argument("--sigmas", default="2,4,6,8")
    ap.add_argument("--diminish-threshold", type=float, default=0.05)
    ap.add_argument("--min-funcs", type=int, default=50)
    ap.add_argument("--max-funcs", type=int, default=800)
    ap.add_argument("--out", default="",
                     help="JSON output path (default: stdout summary only)")
    args = ap.parse_args()

    sinks = ([s.strip() for s in args.sinks.split(",") if s.strip()]
              if args.sinks else DEFAULT_SINK_FUNCS)
    sigmas = [int(s) for s in args.sigmas.split(",")]

    print(f"[adaptive_slice] project: {args.project_dir}")
    print(f"[adaptive_slice] sinks  : {len(sinks)} ({sinks[:8]}…)")
    print(f"[adaptive_slice] σ list : {sigmas}")
    print()

    progression = compute_progression(args.project_dir, sinks, sigmas)
    rec = recommend_sigma(progression,
                            diminish_threshold=args.diminish_threshold,
                            min_funcs=args.min_funcs,
                            max_funcs=args.max_funcs)
    print(render_progression(rec))

    if args.out:
        out_path = Path(args.out)
        # Truncate the func_names list to keep JSON readable; full
        # `func_names` lives in the per-σ slice if needed.
        progression_jsonable = []
        for pt in rec.progression:
            d = pt.to_jsonable()
            d["func_names_preview"] = d["func_names"][:30]
            d["func_names_total"] = len(d["func_names"])
            del d["func_names"]
            progression_jsonable.append(d)
        out_path.write_text(json.dumps({
            "chosen_sigma": rec.chosen_sigma,
            "rationale": rec.rationale,
            "saturation_ratio": rec.saturation_ratio,
            "progression": progression_jsonable,
            "params": {"diminish_threshold": args.diminish_threshold,
                        "min_funcs": args.min_funcs,
                        "max_funcs": args.max_funcs,
                        "sigmas": sigmas, "sinks": sinks},
            # Full slice at the chosen σ — what the runner consumes.
            "chosen_slice": next(
                (p.func_names for p in rec.progression
                 if p.sigma == rec.chosen_sigma), []),
        }, indent=2))
        print(f"\n[adaptive_slice] wrote {out_path}")

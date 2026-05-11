"""
Phase E1 — Dependence filtering of symbex-feasible findings.

Adapted from Sahoo et al., ASPLOS'13 §2.3 dependence filtering: when
multiple findings are *symptoms* of a single upstream root cause
propagating along the same data-flow chain, only the upstream finding
is the candidate root cause; the downstream ones are co-located
symptoms.

Tier, don't drop. The output is a two-tier list:

  - feasible_root_cause      (top tier — to surface in the headline)
  - feasible_downstream_symptom (second tier — preserved with a
                                 back-pointer to the nearest upstream root)

Algorithm (per function):

  1. Collect all feasible findings F whose `func == this function`.
  2. Build a forward def-use graph over (var, addr) nodes:
       - DefReachesUse(func, v, def_addr, use_addr) →
           edge (v, def_addr) → (v, use_addr)
       - ArithOp(func, addr, dst, _, src, _, _) →
           edge (src, addr) → (dst, addr)
       - Cast(func, addr, dst, _, src, _, ...) → same
  3. Compute transitive closure.
  4. Two findings A, B in the same function form a directed edge A→B
     when (B.var, B.addr) ∈ reachable_from(A.var, A.addr).
  5. Within each weakly-connected cluster:
       - "roots" = findings with no incoming dependency edge from any
                    other finding in the cluster.
       - everything else = downstream symptoms; their `upstream_root` is
                    the nearest reachable root (BFS).

Cross-function symptoms are NOT clustered yet (interprocedural
extension is a follow-up).
"""
from __future__ import annotations

import csv
import json
from collections import defaultdict, deque
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Optional


# ── Inputs (mirrors symbex_agent's CSV_TO_KIND) ────────────────────────────
CSV_RELATIONS = [
    "NarrowArithAtSink.csv", "SignedArgAtSink.csv",
    "ImplicitTruncation.csv", "PotentialArithOverflow.csv",
    "OverflowAtSink.csv", "TaintedUnboundedCounter.csv",
    "CounterUsedAsIndex.csv",
]
# Column index of the variable in each CSV.
CSV_VAR_COL = {
    "NarrowArithAtSink.csv": 3, "SignedArgAtSink.csv": 3,
    "ImplicitTruncation.csv": 3, "PotentialArithOverflow.csv": 2,
    "OverflowAtSink.csv": 3, "TaintedUnboundedCounter.csv": 2,
    "CounterUsedAsIndex.csv": 2,
}


@dataclass(frozen=True)
class FindingKey:
    relation: str
    func: str
    addr: int
    var: str

    def to_jsonable(self) -> dict:
        return asdict(self)


@dataclass
class FilteredFinding:
    key: FindingKey
    tier: str                                   # "root" | "symptom"
    upstream_root: Optional[FindingKey] = None  # set iff tier == "symptom"
    cluster_id: int = -1


# ── Graph construction ────────────────────────────────────────────────────

def _read_facts(path: Path) -> list[list[str]]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    rows: list[list[str]] = []
    for line in path.read_text(errors="replace").splitlines():
        if line:
            rows.append(line.split("\t"))
    return rows


def _build_forward_graph_per_func(facts_dir: Path
                                    ) -> dict[str, dict[tuple[str, int],
                                                          set[tuple[str, int]]]]:
    """func → adjacency dict of (var, addr) → set of forward-reachable
    (var, addr) one-step neighbours."""
    g: dict[str, dict[tuple[str, int], set[tuple[str, int]]]] = defaultdict(
        lambda: defaultdict(set))

    # DefReachesUse: same var, addr-to-addr.
    for row in _read_facts(facts_dir / "DefReachesUse.facts"):
        if len(row) < 4:
            continue
        try:
            func, var = row[0], row[1]
            d, u = int(row[2]), int(row[3])
        except (ValueError, IndexError):
            continue
        g[func][(var, d)].add((var, u))

    # ArithOp: at the same addr, src is read and dst is written.
    for row in _read_facts(facts_dir / "ArithOp.facts"):
        if len(row) < 7:
            continue
        try:
            func, addr, dst, src = row[0], int(row[1]), row[2], row[4]
        except (ValueError, IndexError):
            continue
        if not src or not dst:
            continue
        g[func][(src, addr)].add((dst, addr))

    # Cast: same — src @addr → dst @addr.
    for row in _read_facts(facts_dir / "Cast.facts"):
        if len(row) < 5:
            continue
        try:
            func, addr, dst, src = row[0], int(row[1]), row[2], row[3]
        except (ValueError, IndexError):
            continue
        if not src or not dst:
            continue
        g[func][(src, addr)].add((dst, addr))

    return g


def _bfs_reach(start: tuple[str, int],
                adj: dict[tuple[str, int], set[tuple[str, int]]],
                budget: int = 4096) -> set[tuple[str, int]]:
    """Forward-reachable set from `start`. Bounded for safety."""
    seen: set[tuple[str, int]] = {start}
    queue: deque[tuple[str, int]] = deque([start])
    while queue and len(seen) < budget:
        n = queue.popleft()
        for nxt in adj.get(n, ()):
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    return seen


# ── Inputs: feasible findings from CSV outputs ─────────────────────────────

def load_feasible_findings(output_dir: Path) -> list[FindingKey]:
    """Load every Datalog finding from the symbex-supported relations,
    treating rows without a Phase-B-infeasible verdict as candidates.

    For dependence filtering, we work over ALL findings in those
    relations — the symbex verdict is consulted later when we render
    the final tiers (so an infeasible finding will not appear at all).
    """
    found: list[FindingKey] = []
    for rel in CSV_RELATIONS:
        p = output_dir / rel
        if not p.exists() or p.stat().st_size == 0:
            continue
        vc = CSV_VAR_COL[rel]
        for row in csv.reader(p.open(), delimiter="\t"):
            if not row or len(row) <= vc:
                continue
            try:
                func, addr = row[0], int(row[1])
                var = row[vc]
            except (ValueError, IndexError):
                continue
            found.append(FindingKey(rel, func, addr, var))
    return found


def load_phase_b_feasible(eval_dir: Path) -> set[tuple[str, str, int, str]]:
    """Set of feasible (relation, func, addr, var) tuples from Phase B."""
    p = eval_dir / "symbex_phase_b.json"
    if not p.exists():
        return set()
    data = json.loads(p.read_text())
    out = set()
    for f in data.get("feasible", []):
        try:
            out.add((f["relation"], f["func"], int(f["addr"]), f["var"]))
        except (KeyError, ValueError):
            continue
    return out


# ── Main filter ────────────────────────────────────────────────────────────

def filter_dependences(eval_dir: str | Path,
                        budget: int = 4096) -> dict:
    eval_path = Path(eval_dir)
    facts_dir = eval_path / "facts"
    output_dir = eval_path / "output"

    findings_all = load_feasible_findings(output_dir)
    feasible_keys = load_phase_b_feasible(eval_path)
    # Restrict to Phase-B feasible only and dedupe (CSVs occasionally
    # have duplicate rows for the same (rel, func, addr, var) tuple).
    findings = sorted({f for f in findings_all
                if (f.relation, f.func, f.addr, f.var) in feasible_keys},
                key=lambda f: (f.func, f.addr, f.relation, f.var))

    forward = _build_forward_graph_per_func(facts_dir)

    # Group by function.
    by_func: dict[str, list[FindingKey]] = defaultdict(list)
    for f in findings:
        by_func[f.func].append(f)

    all_filtered: list[FilteredFinding] = []
    cluster_seq = 0

    for func, fs in by_func.items():
        adj = forward.get(func, {})
        if not fs:
            continue

        # Forward-reachability from each finding's (var, addr).
        reach: dict[FindingKey, set[tuple[str, int]]] = {
            f: _bfs_reach((f.var, f.addr), adj, budget=budget) for f in fs}

        # A → B iff B's (var, addr) is in A's reach.
        succ: dict[FindingKey, set[FindingKey]] = defaultdict(set)
        pred: dict[FindingKey, set[FindingKey]] = defaultdict(set)
        keyset = set(fs)
        for a in fs:
            for b in fs:
                if a == b:
                    continue
                if (b.var, b.addr) in reach[a]:
                    succ[a].add(b)
                    pred[b].add(a)

        # Build undirected component structure for clustering.
        seen: set[FindingKey] = set()
        for f in fs:
            if f in seen:
                continue
            comp: set[FindingKey] = set()
            queue = deque([f])
            while queue:
                n = queue.popleft()
                if n in comp:
                    continue
                comp.add(n)
                queue.extend(succ.get(n, ()))
                queue.extend(pred.get(n, ()))
            seen |= comp

            cluster_seq += 1
            roots = [n for n in comp if not pred.get(n)]
            # Strongly connected -> all roots = all members in cycle.
            if not roots:
                roots = sorted(comp, key=lambda k: (k.addr, k.relation))[:1]
            root_set = set(roots)

            for n in comp:
                if n in root_set:
                    all_filtered.append(FilteredFinding(
                        key=n, tier="root",
                        upstream_root=None, cluster_id=cluster_seq))
                else:
                    # Nearest upstream root via BFS over `pred`.
                    nearest = _nearest_root(n, pred, root_set)
                    all_filtered.append(FilteredFinding(
                        key=n, tier="symptom",
                        upstream_root=nearest, cluster_id=cluster_seq))

    # Sort: by function then addr for stable diff.
    all_filtered.sort(key=lambda f: (f.key.func, f.key.addr,
                                       f.key.relation, f.key.var))
    return {
        "input_feasible_count": len(findings),
        "root_count": sum(1 for f in all_filtered if f.tier == "root"),
        "symptom_count": sum(1 for f in all_filtered if f.tier == "symptom"),
        "cluster_count": cluster_seq,
        "by_function_summary": _by_function_summary(all_filtered),
        "tiered": [_to_jsonable(f) for f in all_filtered],
    }


def _nearest_root(node: FindingKey,
                  pred: dict[FindingKey, set[FindingKey]],
                  roots: set[FindingKey]) -> Optional[FindingKey]:
    """BFS along predecessor edges; return the first root encountered."""
    seen: set[FindingKey] = {node}
    queue = deque([node])
    while queue:
        n = queue.popleft()
        for p in pred.get(n, ()):
            if p in roots:
                return p
            if p not in seen:
                seen.add(p)
                queue.append(p)
    return None


def _by_function_summary(filt: list[FilteredFinding]) -> dict[str, dict]:
    out: dict[str, dict] = defaultdict(lambda: {"roots": 0, "symptoms": 0,
                                                  "clusters": set()})
    for f in filt:
        out[f.key.func]["roots" if f.tier == "root" else "symptoms"] += 1
        out[f.key.func]["clusters"].add(f.cluster_id)
    return {fn: {"roots": d["roots"], "symptoms": d["symptoms"],
                  "cluster_count": len(d["clusters"])}
            for fn, d in out.items()}


def _to_jsonable(f: FilteredFinding) -> dict:
    d = {"key": f.key.to_jsonable(), "tier": f.tier,
         "cluster_id": f.cluster_id}
    if f.upstream_root is not None:
        d["upstream_root"] = f.upstream_root.to_jsonable()
    return d


# ── CLI ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python dependence_filter.py <eval_dir> [out.json]")
        sys.exit(1)
    eval_dir = sys.argv[1]
    out_path = (Path(sys.argv[2]) if len(sys.argv) >= 3
                else Path(eval_dir) / "dependence_filter.json")
    res = filter_dependences(eval_dir)
    out_path.write_text(json.dumps(res, indent=2, default=str))
    print(f"Input feasible : {res['input_feasible_count']}")
    print(f"Roots          : {res['root_count']}")
    print(f"Symptoms       : {res['symptom_count']}  "
          f"(reduction: "
          f"{100 * res['symptom_count'] / max(res['input_feasible_count'], 1):.1f}%)")
    print(f"Clusters       : {res['cluster_count']}")
    print(f"Wrote          : {out_path}")
    # Top 5 most-clustered functions.
    by_func = res["by_function_summary"]
    if by_func:
        ranked = sorted(by_func.items(),
                         key=lambda kv: -(kv[1]["roots"] + kv[1]["symptoms"]))
        print()
        print("Functions with the most clustered findings:")
        for fn, s in ranked[:5]:
            print(f"  {fn:40s} roots={s['roots']:3d}  symptoms={s['symptoms']:3d}  "
                  f"clusters={s['cluster_count']}")

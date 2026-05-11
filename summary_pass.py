"""
Summary Pass — derive lightweight per-function summaries for the symbex encoder.

Phase B-1 implementation: scan Datalog facts for each function and emit a
compact summary capturing what the encoder needs to know at a Call site:

  - ret_bounds: signed/unsigned (lo, hi) interval the return value lies in
  - ret_signed: whether the bounds are signed-int interpretations
  - arg_writes: per-arg-index value bounds for output-pointer parameters
  - kind:       one of "validator" | "narrow_returner" | "identity" |
                "constant" | "stdlib" | "unknown"

The encoder reads summaries.json from the facts directory and constrains
free symbolic returns at Call sites accordingly. With summaries in place,
callees that always return small/non-negative values stop manufacturing
"feasible" verdicts for findings whose bug condition relies on extreme
return values.

Phase B-1 is conservative: when in doubt, emit no summary (caller sees a
free symbolic return, same as Phase A). Phase B-2 will widen with depth-
bounded inlining and field-write summaries.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Optional

from symbex_encoder import FactStore, _PRIMITIVE_BITS


# ── Catalog: stdlib + ffmpeg/libav patterns we know cold ────────────────────
# Keys are callee names. Values are FuncSummary dicts (subset of fields).
KNOWN_CALLEE_SUMMARIES: dict[str, dict] = {
    # libc string/length returners — always non-negative size_t.
    "strlen":       {"ret_bounds": (0, 1 << 31), "ret_signed": False, "kind": "stdlib"},
    "strnlen":      {"ret_bounds": (0, 1 << 31), "ret_signed": False, "kind": "stdlib"},
    "wcslen":       {"ret_bounds": (0, 1 << 31), "ret_signed": False, "kind": "stdlib"},
    # Allocators: pointer-typed return; encoder treats pointers via free
    # symbolic anyway, but recording the kind lets us tag it.
    "malloc":       {"kind": "allocator"},
    "calloc":       {"kind": "allocator"},
    "realloc":      {"kind": "allocator"},
    "av_malloc":    {"kind": "allocator"},
    "av_mallocz":   {"kind": "allocator"},
    "av_calloc":    {"kind": "allocator"},
    "av_realloc":   {"kind": "allocator"},
    # Validators returning 0/1 or 0/-error.
    "av_image_check_size":   {"ret_bounds": (-(1<<31), 0), "ret_signed": True, "kind": "validator"},
    "av_image_check_size2":  {"ret_bounds": (-(1<<31), 0), "ret_signed": True, "kind": "validator"},
    # min/max — bounded by inputs; Phase B-1 conservatively returns int range.
    "FFMIN": {"kind": "min_max"},
    "FFMAX": {"kind": "min_max"},
    "FFABS": {"ret_bounds": (0, (1 << 31) - 1), "ret_signed": True, "kind": "abs"},
    # Bitstream readers — return non-negative count of bits read; <= 32 in
    # practice for fixed-width readers.
    "get_bits":   {"ret_bounds": (0, (1 << 32) - 1), "ret_signed": False, "kind": "bitstream"},
    "get_bits1":  {"ret_bounds": (0, 1), "ret_signed": False, "kind": "bitstream"},
    "get_ue_golomb":     {"ret_bounds": (0, (1 << 31) - 1), "ret_signed": False, "kind": "bitstream"},
    "get_ue_golomb_31":  {"ret_bounds": (0, 31), "ret_signed": False, "kind": "bitstream"},
    "get_se_golomb":     {"ret_bounds": (-(1 << 30), (1 << 30) - 1), "ret_signed": True, "kind": "bitstream"},
    # I/O return-non-negative-or-negative-errno
    "avio_r8":      {"ret_bounds": (0, 255), "ret_signed": False, "kind": "io"},
    "avio_rb16":    {"ret_bounds": (0, 0xFFFF), "ret_signed": False, "kind": "io"},
    "avio_rb24":    {"ret_bounds": (0, 0xFFFFFF), "ret_signed": False, "kind": "io"},
    "avio_rl16":    {"ret_bounds": (0, 0xFFFF), "ret_signed": False, "kind": "io"},
    "avio_rl24":    {"ret_bounds": (0, 0xFFFFFF), "ret_signed": False, "kind": "io"},
}


@dataclass
class FuncSummary:
    func: str
    kind: str = "unknown"           # see module docstring
    ret_bounds: Optional[tuple[int, int]] = None
    ret_signed: bool = True
    ret_const: Optional[int] = None  # if function always returns this constant
    arg_writes: list[dict] = field(default_factory=list)

    def to_jsonable(self) -> dict:
        d = asdict(self)
        if d["ret_bounds"] is not None:
            d["ret_bounds"] = list(d["ret_bounds"])
        return d


# ── Heuristics ──────────────────────────────────────────────────────────────

def _type_range(type_name: str, sign_hint: str) -> Optional[tuple[int, int]]:
    bits = _PRIMITIVE_BITS.get(type_name)
    if not bits:
        return None
    if sign_hint == "unsigned" or type_name.startswith(("uint", "unsigned", "size_t")):
        return (0, (1 << bits) - 1)
    return (-(1 << (bits - 1)), (1 << (bits - 1)) - 1)


def _all_returns_constant(store: FactStore, func: str) -> Optional[int]:
    """If every ReturnVal of `func` is a Def-via-constant-assignment, return
    the constant when there's exactly one. Conservative: if any return
    var has no obvious constant def, returns None."""
    return_vars = [r[0] for r in store.uses.get(func, []) if False]  # placeholder
    rets = [v for (v, _ver, _addr) in [(r, 0, 0) for r in []]]  # placeholder
    # The actual ReturnVal facts aren't loaded into FactStore in Phase A —
    # we need to read them here. Phase B-1: read directly from disk.
    rv_path = store.facts_dir / "ReturnVal.facts"
    if not rv_path.exists():
        return None
    return_vars = []
    for line in rv_path.read_text().splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0] == func:
            return_vars.append(parts[1])
    if not return_vars:
        return None
    # For each return var, look at the latest Def in the function and
    # check if there's a one-operand ArithOp with a literal that could
    # encode `return 0;`. Phase B-1 only catches the literal-return case
    # by inspecting Guard.facts and ArithOp.facts is overkill — instead,
    # we just check whether the var itself is a known return-of-literal
    # pattern by looking for it in NO Def AT ALL (function signature
    # `return 0;` doesn't always show up as a Def).
    # Pragmatic: if there's exactly one return var AND it has zero Defs
    # in the function, the LLM/mechanical extractor probably saw a bare
    # `return CONSTANT` that didn't materialise as a Def — but we can't
    # tell which constant. Skip this case in Phase B-1.
    return None


def _return_var_type_bounds(store: FactStore, func: str) -> Optional[tuple[int, int, bool]]:
    """If all ReturnVal vars share a narrow declared type, return
    (lo, hi, signed). Otherwise None."""
    rv_path = store.facts_dir / "ReturnVal.facts"
    if not rv_path.exists():
        return None
    return_vars = [parts[1] for parts in
                   (line.split("\t") for line in rv_path.read_text().splitlines())
                   if len(parts) >= 2 and parts[0] == func]
    if not return_vars:
        return None
    bounds: Optional[tuple[int, int]] = None
    signed: Optional[bool] = None
    vts = store.vartype.get(func, {})
    for v in return_vars:
        vt = vts.get(v)
        if vt is None:
            return None
        type_name, _width, sign = vt
        rng = _type_range(type_name, sign)
        if rng is None:
            return None
        if bounds is None:
            bounds = rng
            signed = (sign == "signed") or type_name.startswith(("int", "long", "short", "char", "signed"))
        else:
            # Widen the union conservatively.
            if rng != bounds:
                bounds = (min(bounds[0], rng[0]), max(bounds[1], rng[1]))
    return (bounds[0], bounds[1], bool(signed)) if bounds else None


# ── Main entry ─────────────────────────────────────────────────────────────

def derive_summaries(store: FactStore) -> dict[str, FuncSummary]:
    summaries: dict[str, FuncSummary] = {}

    # 1) Catalog injection — known external callees.
    for name, sd in KNOWN_CALLEE_SUMMARIES.items():
        rb = sd.get("ret_bounds")
        summaries[name] = FuncSummary(
            func=name,
            kind=sd.get("kind", "stdlib"),
            ret_bounds=tuple(rb) if rb else None,
            ret_signed=sd.get("ret_signed", True),
        )

    # 2) Per-defined-function heuristics.
    funcs: set[str] = set()
    funcs.update(store.defs.keys())
    funcs.update(store.formal.keys())
    funcs.update(f for (f, _) in store.calls.items())

    for func in sorted(funcs):
        if func in summaries:
            continue  # catalog wins
        s = FuncSummary(func=func)

        # Type-derived return bounds.
        type_bounds = _return_var_type_bounds(store, func)
        if type_bounds is not None:
            lo, hi, signed = type_bounds
            s.ret_bounds = (lo, hi)
            s.ret_signed = signed
            s.kind = "narrow_returner"

        if s.kind != "unknown" or s.ret_bounds is not None:
            summaries[func] = s

    return summaries


def write_summaries(summaries: dict[str, FuncSummary], facts_dir: Path) -> Path:
    out = facts_dir / "summaries.json"
    payload = {name: s.to_jsonable() for name, s in summaries.items()}
    out.write_text(json.dumps(payload, indent=2))
    return out


def load_summaries(facts_dir: Path) -> dict[str, FuncSummary]:
    path = facts_dir / "summaries.json"
    if not path.exists():
        return {}
    raw = json.loads(path.read_text())
    out: dict[str, FuncSummary] = {}
    for name, d in raw.items():
        rb = d.get("ret_bounds")
        out[name] = FuncSummary(
            func=d["func"],
            kind=d.get("kind", "unknown"),
            ret_bounds=tuple(rb) if rb else None,
            ret_signed=d.get("ret_signed", True),
            ret_const=d.get("ret_const"),
            arg_writes=d.get("arg_writes", []),
        )
    return out


# ── CLI driver ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python summary_pass.py <facts_dir>")
        sys.exit(1)
    fdir = Path(sys.argv[1])
    store = FactStore.load(fdir)
    summaries = derive_summaries(store)
    out = write_summaries(summaries, fdir)
    by_kind: dict[str, int] = {}
    for s in summaries.values():
        by_kind[s.kind] = by_kind.get(s.kind, 0) + 1
    print(f"Wrote {len(summaries)} summaries to {out}")
    for k in sorted(by_kind):
        print(f"  {k}: {by_kind[k]}")

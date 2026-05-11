"""
Symbex Encoder — Datalog facts → Z3 bit-vector model for one finding.

Given a Datalog finding (e.g., a row from UnguardedDangerousCast.csv) and
the surrounding fact set, build a Z3 query that asserts:
    1. All Defs / ArithOps / Casts along the def-use chain.
    2. All Guards reachable on the CFG path from function entry to the
       finding site (path conditions).
    3. A bug-condition specific to the finding's class.
Then ask Z3 if the conjunction is satisfiable. SAT means the finding is
*reachable* under some attacker input → genuine. UNSAT means a guard
along the path rules it out → false positive.

Phase A is intra-procedural: callees become free symbolic return values
constrained by their declared return type. Phase B will swap in cached
function summaries and do bounded-depth lazy inference.
"""

from __future__ import annotations

import csv
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import z3

from symbex_config import SymbexConfig


# ── Fact store ───────────────────────────────────────────────────────────────

@dataclass
class FactStore:
    """Loads Datalog facts from a directory and indexes them by function.

    All access is by `func` so encoding one finding only touches the
    relevant function's facts (cheap even on large fact sets).
    """
    facts_dir: Path
    defs:       dict[str, list[tuple]] = field(default_factory=dict)  # func → [(var, ver, addr)]
    uses:       dict[str, list[tuple]] = field(default_factory=dict)
    arith:      dict[str, list[tuple]] = field(default_factory=dict)
    casts:      dict[str, list[tuple]] = field(default_factory=dict)
    guards:     dict[str, list[tuple]] = field(default_factory=dict)
    cfgedges:   dict[str, list[tuple]] = field(default_factory=dict)  # func → [(from, to)]
    formal:     dict[str, list[tuple]] = field(default_factory=dict)  # func → [(var, idx)]
    calls:      dict[str, list[tuple]] = field(default_factory=dict)  # func → [(callee, addr)]
    actualarg:  dict[str, list[tuple]] = field(default_factory=dict)  # func → [(call_addr, idx, param, var, ver)]
    fieldread:  dict[str, list[tuple]] = field(default_factory=dict)  # func → [(addr, base, field)]
    returnvals: dict[str, list[tuple]] = field(default_factory=dict)  # func → [(var, ver)]
    vartype:    dict[str, dict[str, tuple]] = field(default_factory=dict)  # func → {var: (type_name, width, sign)}
    # Globals
    bounded_field: set[str] = field(default_factory=set)
    early_return: dict[str, set[int]] = field(default_factory=dict)  # func → {addrs}
    taint_sources: set[str] = field(default_factory=set)
    # Phase B: per-callee return-value summaries. Keyed by callee name.
    summaries: dict[str, dict] = field(default_factory=dict)
    # Phase E2: likely range invariants observed dynamically on
    # corpus seeds. Keyed by (func, addr), value is list of
    # (var, lo, hi, n_obs) — multiple locals can be in scope at a line.
    likely_invariants: dict[tuple[str, int],
                              list[tuple[str, int, int, int]]] = field(default_factory=dict)

    @classmethod
    def load(cls, facts_dir: str | Path) -> "FactStore":
        s = cls(facts_dir=Path(facts_dir))
        s._load_per_func("Def.facts", s.defs, lambda r: (r[0], (r[1], _i(r[2]), _i(r[3]))))
        s._load_per_func("Use.facts", s.uses, lambda r: (r[0], (r[1], _i(r[2]), _i(r[3]))))
        s._load_per_func("ArithOp.facts", s.arith,
            lambda r: (r[0], (_i(r[1]), r[2], _i(r[3]), r[4], r[5], _i(r[6]), r[7])))
        s._load_per_func("Cast.facts", s.casts,
            lambda r: (r[0], (_i(r[1]), r[2], _i(r[3]), r[4], _i(r[5]), r[6], _i(r[7]), _i(r[8]), r[9], r[10])))
        s._load_per_func("Guard.facts", s.guards,
            lambda r: (r[0], (_i(r[1]), r[2], _i(r[3]), r[4], r[5], r[6])))
        s._load_per_func("CFGEdge.facts", s.cfgedges,
            lambda r: (r[0], (_i(r[1]), _i(r[2]))))
        s._load_per_func("FormalParam.facts", s.formal,
            lambda r: (r[0], (r[1], _i(r[2]))))
        s._load_per_func("Call.facts", s.calls,
            lambda r: (r[0], (r[1], _i(r[2]))))

        # ActualArg key is call_addr, but we want it accessible per function;
        # we index by caller via a sweep over Call.
        actualarg_by_call_addr: dict[int, list[tuple]] = {}
        for row in s._read_rows("ActualArg.facts"):
            ca = _i(row[0])
            actualarg_by_call_addr.setdefault(ca, []).append(
                (ca, _i(row[1]), row[2], row[3], _i(row[4])))
        for func, calls in s.calls.items():
            for callee, addr in calls:
                if addr in actualarg_by_call_addr:
                    s.actualarg.setdefault(func, []).extend(actualarg_by_call_addr[addr])

        s._load_per_func("FieldRead.facts", s.fieldread,
            lambda r: (r[0], (_i(r[1]), r[2], r[3])))

        s._load_per_func("ReturnVal.facts", s.returnvals,
            lambda r: (r[0], (r[1], _i(r[2]))))

        for row in s._read_rows("VarType.facts"):
            if len(row) < 5:
                continue
            func, var, type_name, width_s, sign = row[0], row[1], row[2], row[3], row[4]
            try:
                width = int(width_s)
            except ValueError:
                width = 0
            s.vartype.setdefault(func, {})[var] = (type_name, width, sign)

        for row in s._read_rows("BoundedField.facts"):
            if row:
                s.bounded_field.add(row[0])

        for row in s._read_rows("GuardEarlyReturn.facts"):
            if len(row) < 2:
                continue
            s.early_return.setdefault(row[0], set()).add(_i(row[1]))

        for row in s._read_rows("TaintSourceFunc.facts"):
            if row:
                s.taint_sources.add(row[0])

        # Phase B: load summaries.json if present.
        summary_path = s.facts_dir / "summaries.json"
        if summary_path.exists():
            try:
                import json
                s.summaries = json.loads(summary_path.read_text())
            except (json.JSONDecodeError, ValueError):
                s.summaries = {}

        # Phase E2: load likely range invariants from
        # LikelyRangeInvariant.facts (TSV: func, var, addr, lo, hi, n_obs).
        for row in s._read_rows("LikelyRangeInvariant.facts"):
            if len(row) < 6:
                continue
            try:
                func, var = row[0], row[1]
                addr, lo, hi, nobs = (int(row[2]), int(row[3]),
                                       int(row[4]), int(row[5]))
            except (ValueError, IndexError):
                continue
            s.likely_invariants.setdefault((func, addr), []).append(
                (var, lo, hi, nobs))
        return s

    def _load_per_func(self, fname: str, dest: dict, mapper):
        for row in self._read_rows(fname):
            try:
                key, val = mapper(row)
            except (IndexError, ValueError):
                continue
            dest.setdefault(key, []).append(val)

    def _read_rows(self, fname: str):
        path = self.facts_dir / fname
        if not path.exists() or path.stat().st_size == 0:
            return
        with path.open() as fp:
            for line in fp:
                line = line.rstrip("\n")
                if not line:
                    continue
                yield line.split("\t")


def _i(s) -> int:
    try:
        return int(s)
    except (ValueError, TypeError):
        return 0


# ── Encoder ─────────────────────────────────────────────────────────────────

# Sentinel mapping for unknown / unrecognised C types — fall back to default int.
_PRIMITIVE_BITS = {
    "char": 8, "signed char": 8, "unsigned char": 8,
    "short": 16, "unsigned short": 16,
    "int": 32, "unsigned int": 32, "unsigned": 32, "signed": 32,
    "long": 64, "unsigned long": 64, "long long": 64, "unsigned long long": 64,
    "size_t": 64, "ssize_t": 64, "ptrdiff_t": 64,
    "int8_t": 8, "uint8_t": 8,
    "int16_t": 16, "uint16_t": 16,
    "int32_t": 32, "uint32_t": 32,
    "int64_t": 64, "uint64_t": 64,
    "intptr_t": 64, "uintptr_t": 64,
    "off_t": 64, "_Bool": 1, "bool": 1,
}


def _bits_for_type(type_name: str, sign: str, width_bytes: int,
                    default: int) -> tuple[int, bool]:
    """Return (bit-width, signed). Type-name lookup first, then width
    bytes × 8, then default."""
    if type_name in _PRIMITIVE_BITS:
        bits = _PRIMITIVE_BITS[type_name]
    elif width_bytes and width_bytes > 0:
        bits = width_bytes * 8
    else:
        bits = default
    is_signed = (sign == "signed")
    return bits, is_signed


@dataclass
class Finding:
    """A Datalog finding to verify."""
    func: str
    addr: int           # bug site line
    var: str            # primary variable involved
    kind: str           # one of cfg.enabled_bug_classes
    extra: dict = field(default_factory=dict)


@dataclass
class SymbexResult:
    finding: Finding
    verdict: str        # "feasible" | "infeasible" | "unknown"
    reason: str = ""
    model_str: str = ""
    elapsed_ms: int = 0


# ── Bug condition builders ──────────────────────────────────────────────────
# Each builder takes (encoder, finding, var_z3) and returns a Z3 BoolRef that,
# when added to the model, asserts the bug occurs.

def _bc_narrow_arith_at_sink(enc: "FunctionEncoder", finding: Finding,
                              var_z3: z3.BitVecRef) -> z3.BoolRef:
    # Signed `int` flowing into memset/memcpy size argument. Bug if value
    # is negative (interpreted as huge size_t at the call) OR exceeds a
    # plausible buffer max. Z3's default `<` on BitVec is signed.
    bits = var_z3.size()
    return var_z3 < z3.BitVecVal(0, bits)


def _bc_signed_arg_at_sink(enc, finding, var_z3):
    return _bc_narrow_arith_at_sink(enc, finding, var_z3)


def _bc_unbounded_counter_at_sink(enc, finding, var_z3):
    # Counter exceeds INT16_MAX (65535) — sentinel-collision class. The
    # actual sentinel value can be passed via finding.extra['sentinel'].
    sentinel = int(finding.extra.get("sentinel", 0xFFFF))
    bits = var_z3.size()
    return z3.UGE(var_z3, z3.BitVecVal(sentinel, bits))


def _bc_truncation_cast(enc, finding, var_z3):
    # Truncation loses data: var ≠ extend(truncate(var, narrow), wide).
    narrow_bits = int(finding.extra.get("narrow_bits", 8))
    bits = var_z3.size()
    if narrow_bits >= bits:
        return z3.BoolVal(False)
    truncated = z3.Extract(narrow_bits - 1, 0, var_z3)
    extended = z3.SignExt(bits - narrow_bits, truncated)
    return var_z3 != extended


def _bc_unguarded_dangerous_cast(enc, finding, var_z3):
    return _bc_truncation_cast(enc, finding, var_z3)


def _bc_potential_arith_overflow(enc, finding, var_z3):
    # Signed-int arithmetic produces a value outside int range. After
    # bit-vector wrap, this manifests as the signed value being beyond
    # ±2^(bits-1). With our BitVec width matching the source type, we
    # instead check that *some interpretation* of var has wrapped: the
    # unsigned reading of var is in the "would-have-been-overflow" range.
    bits = var_z3.size()
    half = z3.BitVecVal(1 << (bits - 1), bits)
    # var as unsigned ≥ 2^(bits-1) iff signed view is negative (overflow
    # of a positive signed sum).
    return z3.UGE(var_z3, half)


def _bc_sentinel_collision(enc, finding, var_z3):
    sentinel = int(finding.extra.get("sentinel", 0xFFFF))
    bits = var_z3.size()
    return var_z3 == z3.BitVecVal(sentinel, bits)


BUG_CONDITION_BUILDERS = {
    "narrow_arith_at_sink": _bc_narrow_arith_at_sink,
    "signed_arg_at_sink": _bc_signed_arg_at_sink,
    "unguarded_dangerous_cast": _bc_unguarded_dangerous_cast,
    "truncation_cast": _bc_truncation_cast,
    "unbounded_counter_at_sink": _bc_unbounded_counter_at_sink,
    "potential_arith_overflow": _bc_potential_arith_overflow,
    "sentinel_collision": _bc_sentinel_collision,
}


# Z3 op mapping from ArithOp's `op` field.
_Z3_BIN_OP = {
    "add": lambda a, b: a + b,
    "sub": lambda a, b: a - b,
    "mul": lambda a, b: a * b,
    "div": lambda a, b: a / b,
    "mod": lambda a, b: a % b,
    "lsl": lambda a, b: a << b,
    "lsr": lambda a, b: z3.LShR(a, b),
    "and": lambda a, b: a & b,
    "or":  lambda a, b: a | b,
    "xor": lambda a, b: a ^ b,
}


_Z3_CMP_OP = {
    # Default <, <=, >, >= on BitVec are SIGNED in Z3's Python API.
    "<":  lambda a, b: a < b,
    "<=": lambda a, b: a <= b,
    ">":  lambda a, b: a > b,
    ">=": lambda a, b: a >= b,
    "==": lambda a, b: a == b,
    "!=": lambda a, b: a != b,
    "unsigned_lt": lambda a, b: z3.ULT(a, b),
    "unsigned_le": lambda a, b: z3.ULE(a, b),
    "unsigned_gt": lambda a, b: z3.UGT(a, b),
    "unsigned_ge": lambda a, b: z3.UGE(a, b),
}


class FunctionEncoder:
    """Encodes one function's def-use chain reachable to a finding's
    `var` at a given `addr`. Phase B-2: depth-bounded inter-procedural
    inlining via a `_func_stack` (active function context) and
    `_param_bindings` (caller-actual values bound to callee formals).
    All fact lookups go through `_cur_func()` so the same logic encodes
    the caller body and inlined callee bodies uniformly."""

    # Sentinel "after everything" address used when encoding a callee's
    # ReturnVal: we want the latest def of the return var in the callee.
    _EXIT_ADDR = 10 ** 9

    def __init__(self, store: FactStore, finding: Finding,
                 cfg: SymbexConfig):
        self.store = store
        self.finding = finding
        self.cfg = cfg
        self.solver = z3.Solver()
        self.solver.set("timeout", int(cfg.z3_timeout_s * 1000))
        # Symbols are keyed by (func, var, def_addr) so that an inlined
        # callee's local `i` cannot collide with the caller's `i`.
        self.symbols: dict[tuple[str, str, int], z3.BitVecRef] = {}
        # Pending guards we'd assert on top.
        self._asserted_addrs: set[int] = set()
        # Phase B-2: function context stack.
        self._func_stack: list[str] = [finding.func]
        # Per-frame: param_name → caller's z3 BitVecRef bound to that param.
        self._param_bindings: list[dict[str, z3.BitVecRef]] = [{}]
        # Inlined call-stack to detect recursion; entries are (callee, depth).
        self._inline_stack: list[str] = []

    def _cur_func(self) -> str:
        return self._func_stack[-1]

    # --- Type lookup ---
    def _bits_for_var(self, var: str) -> tuple[int, bool]:
        vt = self.store.vartype.get(self._cur_func(), {}).get(var)
        if vt is None:
            return self.cfg.default_int_bits, True
        type_name, width, sign = vt
        return _bits_for_type(type_name, sign, width, self.cfg.default_int_bits)

    # --- Symbol creation ---
    def sym(self, var: str, def_addr: int) -> z3.BitVecRef:
        func = self._cur_func()
        key = (func, var, def_addr)
        s = self.symbols.get(key)
        if s is None:
            bits, _signed = self._bits_for_var(var)
            s = z3.BitVec(f"{func}__{var}_{def_addr}", bits)
            self.symbols[key] = s
        return s

    # --- Find the def reaching a given (var, use_addr) within the
    #     function. Phase A: pick the latest Def line ≤ use_addr that
    #     has a CFG path to use_addr. If none, var is a free symbolic
    #     input (function param, global, etc.).
    def _resolve_def(self, var: str, use_addr: int,
                      strict_before: bool = False) -> Optional[int]:
        defs = self.store.defs.get(self._cur_func(), [])
        if strict_before:
            candidates = [a for (v, _ver, a) in defs
                          if v == var and a < use_addr]
        else:
            candidates = [a for (v, _ver, a) in defs
                          if v == var and a <= use_addr]
        if not candidates:
            return None
        return max(candidates)

    # --- Encode one variable's value at a use site by walking back the
    #     def chain. Returns the Z3 expression bound to var@use_addr.
    #
    #     `strict_before`: when set, we look for a Def line *strictly
    #     less than* use_addr — required when encoding the RHS operands
    #     of a Def itself (e.g. `x = x + 1`: the RHS `x` reads the
    #     pre-increment value, not the def at this same line).
    def encode_var(self, var: str, use_addr: int,
                   visited: Optional[set] = None,
                   strict_before: bool = False) -> z3.BitVecRef:
        if visited is None:
            visited = set()
        # Phase B-2: include current function in the visited key so the
        # same `var` name in different inlined frames doesn't short-circuit.
        key = (self._cur_func(), var, use_addr, strict_before)
        if key in visited:
            return self.sym(var, use_addr)
        visited.add(key)

        def_addr = self._resolve_def(var, use_addr, strict_before)
        if def_addr is None:
            # Phase B-2: when encoding a callee body, a "var with no def"
            # is most often a formal parameter — return the caller's
            # bound actual value if we have one.
            binding = self._param_bindings[-1].get(var)
            if binding is not None:
                bits, _ = self._bits_for_var(var)
                return self._align(binding, bits)
            # Unbound: treat as free input. Constrained only by type range.
            # If we're resolving in strict_before mode (RHS of a def at use_addr),
            # the symbol must be DISTINCT from sym(var, use_addr) (which is the
            # LHS of that def) — otherwise `x = x + 1` collapses to `x == x + 1`.
            if strict_before:
                return self.sym(var, -use_addr - 1)
            return self.sym(var, use_addr)

        out = self.sym(var, def_addr)

        # Phase E2 — constrain `out` with observed likely-invariant
        # bounds at this program point. Applied once here so every
        # subsequent path (ArithOp / Cast / Call / FieldRead / fallback)
        # accumulates constraints on top of the bounded symbol.
        if self.cfg.use_likely_invariants:
            self._apply_likely_invariant(out, var, def_addr)

        # Look for an ArithOp at this Def addr defining `var`.
        for (a, dst, _dv, op, src, _sv, operand) in self.store.arith.get(
                self._cur_func(), []):
            if a != def_addr or dst != var:
                continue
            arith_fn = _Z3_BIN_OP.get(op)
            if arith_fn is None:
                continue
            # RHS operands must read the value BEFORE this def — strict_before.
            src_z3 = self.encode_var(src, def_addr, visited,
                                     strict_before=True) if src else None
            operand_z3 = self._encode_operand(operand, def_addr, visited)
            if src_z3 is None and operand_z3 is None:
                continue
            if src_z3 is None:
                src_z3 = z3.BitVecVal(0, out.size())
            if operand_z3 is None:
                operand_z3 = z3.BitVecVal(0, out.size())
            # Width-align operands to match `out`.
            src_z3 = self._align(src_z3, out.size())
            operand_z3 = self._align(operand_z3, out.size())
            self.solver.add(out == arith_fn(src_z3, operand_z3))
            return out

        # Look for a Cast at this Def addr defining `var`.
        for (a, dst, _dv, src, _sv, kind, sw, dw, st, dt) in self.store.casts.get(
                self._cur_func(), []):
            if a != def_addr or dst != var:
                continue
            src_z3 = self.encode_var(src, def_addr, visited,
                                     strict_before=True) if src else None
            if src_z3 is None:
                continue
            target_bits = out.size()
            self.solver.add(out == self._apply_cast(src_z3, kind, target_bits))
            return out

        # Look for a Call at this addr that returns `var` (Def via call
        # return). Phase B-2 priority: (1) inline the callee body if we
        # have its facts and there's depth budget; (2) apply catalog
        # summary; (3) fall back to free symbolic.
        for (callee, ca) in self.store.calls.get(self._cur_func(), []):
            if ca != def_addr:
                continue
            # If callee is a known taint source AND config says so, leave
            # `out` free (already a fresh BitVec) regardless of summary.
            if (self.cfg.taint_sources_are_free
                    and callee in self.store.taint_sources):
                return out
            inlined = self._try_inline_callee(callee, ca, out.size())
            if inlined is not None:
                self.solver.add(out == self._align(inlined, out.size()))
            else:
                self._apply_callee_summary(out, callee)
            return out

        # Look for a FieldRead at this addr — if the field is BoundedField,
        # constrain `out` with whatever bounds we have. Without explicit
        # bounds in BoundedField.facts, just leave free (typed range).
        for (a, base, fld) in self.store.fieldread.get(self._cur_func(), []):
            if a != def_addr:
                continue
            if fld in self.store.bounded_field:
                # Phase A: BoundedField is a single-column relation, no
                # numeric bounds. Treat as "non-negative, ≤ small".
                # Realistic: spec-bounded fields are typically small ints.
                bits = out.size()
                # 16 bits is a generous default for spec-validated fields.
                self.solver.add(z3.UGE(out, z3.BitVecVal(0, bits)))
                self.solver.add(z3.ULE(out, z3.BitVecVal(0xFFFF, bits)))
            return out

        # Couldn't resolve via known patterns; leave as free symbolic
        # (already constrained by likely-invariant on the path above).
        return out

    def _apply_likely_invariant(self, out: z3.BitVecRef, var: str,
                                  addr: int) -> None:
        """Phase E2 — constrain `out` by observed likely-invariant ranges.

        Two-tier match — both *sound* (same variable name in the same
        function is reliably the same variable in single-TU C):

          (1) exact (func, addr, var)        — tightest
          (2) function-scope name match       — widest observed range for
                                                `var` name anywhere in this
                                                function (compiler line-
                                                folding makes (func, addr)
                                                unreliable in -O0+; same-
                                                name-same-function is
                                                consistently the same local)

        We deliberately do NOT use a (func, addr, *) widest-range
        fallback when the variable name is synthetic / has no observed
        match: that risks suppressing the very findings where the
        bug-relevant variable is exactly something the seed corpus
        never exercised (e.g., attacker-controlled lengths). Tier-don't-
        drop at the symbex-verdict level handles those: the
        no-invariant baseline keeps them top-tier.
        """
        func = self._cur_func()
        # Tier 1: exact (func, addr, var).
        invs_at = self.store.likely_invariants.get((func, addr), [])
        for (n, lo, hi, _) in invs_at:
            if n == var:
                self._add_range(out, lo, hi)
                return
        # Tier 2: function-scope widest range for the same name.
        widest_lo: Optional[int] = None
        widest_hi: Optional[int] = None
        for (f2, _a), invs in self.store.likely_invariants.items():
            if f2 != func:
                continue
            for (n, lo, hi, _) in invs:
                if n == var:
                    widest_lo = lo if widest_lo is None else min(widest_lo, lo)
                    widest_hi = hi if widest_hi is None else max(widest_hi, hi)
        if widest_lo is not None and widest_hi is not None:
            self._add_range(out, widest_lo, widest_hi)

    def _add_range(self, out: z3.BitVecRef, lo: int, hi: int) -> None:
        bits = out.size()
        type_lo = -(1 << (bits - 1))
        type_hi = (1 << (bits - 1)) - 1
        lo = max(lo, type_lo)
        hi = min(hi, type_hi)
        if lo > hi:
            return
        self.solver.add(out >= z3.BitVecVal(lo, bits))
        self.solver.add(out <= z3.BitVecVal(hi, bits))

    def _try_inline_callee(self, callee: str, call_addr: int,
                            target_bits: int) -> Optional[z3.BitVecRef]:
        """Phase B-2: encode the callee body and return its return value.

        Returns None when:
          - depth budget is exhausted,
          - the callee has no facts in the store (external — let summary handle it),
          - the callee has no recorded ReturnVal (void function),
          - the callee is on the inline stack (recursion).
        """
        depth = len(self._inline_stack)
        if depth >= self.cfg.max_call_depth:
            return None
        if callee in self._inline_stack:
            return None
        # Need callee facts. We require at least Def + ReturnVal to make
        # inlining meaningful; otherwise we can't pin down what the
        # function actually returns.
        if (callee not in self.store.defs and
                callee not in self.store.returnvals):
            return None
        ret_vars = self.store.returnvals.get(callee, [])
        if not ret_vars:
            return None

        # Bind callee's formals to caller's actuals at this call site.
        bindings = self._collect_arg_bindings(callee, call_addr)

        # Push callee frame.
        self._func_stack.append(callee)
        self._param_bindings.append(bindings)
        self._inline_stack.append(callee)
        try:
            # Encode each ReturnVal candidate; OR them with a fresh witness
            # symbol the caller binds to. For Phase B-2 simplicity, take
            # the most-recently-defined return var (largest def addr) — the
            # "happy path" return — to avoid blow-up from N-way disjunction.
            best_var: Optional[str] = None
            best_def: int = -1
            defs = self.store.defs.get(callee, [])
            for (rv, _ver) in ret_vars:
                # Latest def of rv in callee.
                cands = [a for (v, _v2, a) in defs if v == rv]
                latest = max(cands) if cands else 0
                if latest > best_def:
                    best_def = latest
                    best_var = rv
            if best_var is None:
                return None
            return self.encode_var(best_var, self._EXIT_ADDR)
        finally:
            self._func_stack.pop()
            self._param_bindings.pop()
            self._inline_stack.pop()

    def _collect_arg_bindings(self, callee: str, call_addr: int
                                ) -> dict[str, z3.BitVecRef]:
        """For a call site at `call_addr` in the *current* function, look
        up the actuals being passed and resolve each to a Z3 expr in the
        caller's context. Then map idx → callee's formal-param name."""
        actuals: dict[int, z3.BitVecRef] = {}
        for (ca, idx, _param, var, _ver) in self.store.actualarg.get(
                self._cur_func(), []):
            if ca != call_addr:
                continue
            try:
                z = self.encode_var(var, call_addr, strict_before=True)
                actuals[idx] = z
            except Exception:
                continue
        bindings: dict[str, z3.BitVecRef] = {}
        for (fp_name, idx) in self.store.formal.get(callee, []):
            if idx in actuals:
                bindings[fp_name] = actuals[idx]
        return bindings

    def _apply_callee_summary(self, out: z3.BitVecRef, callee: str) -> None:
        """Phase B-1: constrain `out` (a callee's return value) using a
        summary derived in summary_pass.py. If no summary is available,
        do nothing — `out` stays free symbolic, matching Phase A."""
        s = self.store.summaries.get(callee)
        if not s:
            return
        rb = s.get("ret_bounds")
        if not rb or len(rb) != 2:
            return
        lo, hi = int(rb[0]), int(rb[1])
        bits = out.size()
        signed = bool(s.get("ret_signed", True))
        # Clip lo/hi to the BitVec width to avoid Z3 value-out-of-range
        # crashes for cases where the summary is wider than the call's
        # local var (e.g., size_t summary feeding into an int variable).
        if signed:
            type_lo = -(1 << (bits - 1))
            type_hi = (1 << (bits - 1)) - 1
            lo = max(lo, type_lo)
            hi = min(hi, type_hi)
            if lo > hi:
                return
            self.solver.add(out >= z3.BitVecVal(lo, bits))
            self.solver.add(out <= z3.BitVecVal(hi, bits))
        else:
            type_hi = (1 << bits) - 1
            lo = max(lo, 0)
            hi = min(hi, type_hi)
            if lo > hi:
                return
            self.solver.add(z3.UGE(out, z3.BitVecVal(lo, bits)))
            self.solver.add(z3.ULE(out, z3.BitVecVal(hi, bits)))

    def _encode_operand(self, operand: str, def_addr: int,
                         visited: set) -> Optional[z3.BitVecRef]:
        """An ArithOp's `operand` is a string — could be a constant, an
        identifier, or a field expression. Best-effort decode. RHS-side,
        so identifiers resolve via strict_before=True."""
        s = (operand or "").strip()
        if not s:
            return None
        try:
            return z3.BitVecVal(int(s, 0), self.cfg.default_int_bits)
        except (ValueError, TypeError):
            pass
        if s.isidentifier():
            return self.encode_var(s, def_addr, visited,
                                   strict_before=True)
        return z3.BitVec(f"_tmp_{abs(hash(s))%(1<<24):x}_{def_addr}",
                          self.cfg.default_int_bits)

    @staticmethod
    def _align(expr: z3.BitVecRef, target_bits: int) -> z3.BitVecRef:
        cur = expr.size()
        if cur == target_bits:
            return expr
        if cur < target_bits:
            return z3.SignExt(target_bits - cur, expr)
        return z3.Extract(target_bits - 1, 0, expr)

    @staticmethod
    def _apply_cast(src: z3.BitVecRef, kind: str, target_bits: int):
        cur = src.size()
        if cur == target_bits:
            return src
        if kind == "truncate" or cur > target_bits:
            return z3.Extract(target_bits - 1, 0, src)
        if kind == "sign_extend":
            return z3.SignExt(target_bits - cur, src)
        if kind == "zero_extend":
            return z3.ZeroExt(target_bits - cur, src)
        # reinterpret / unknown: pad with zero.
        return z3.ZeroExt(target_bits - cur, src) if cur < target_bits else \
               z3.Extract(target_bits - 1, 0, src)

    # --- Path conditions ---
    def encode_path_guards(self, target_addr: int):
        """Add Guard constraints for every guard whose addr ≤ target on
        the same function, and whose CFG path reaches target. Phase A
        approximation: include ALL guards in the function with addr <
        target (over-approximation; loses path-sensitivity but is
        sound: stronger guards make the formula more constrained).

        For each Guard(var, op, bound): the THEN branch fires when the
        condition is true; if THEN terminates the function (early return),
        then control reaches `target` only when the condition is FALSE.
        We assert the negation of the guard condition.

        For non-early-return guards: we leave them out (over-approximation).
        """
        early = self.store.early_return.get(self.finding.func, set())
        for (ga, var, _ver, op, bound, _bt) in self.store.guards.get(
                self.finding.func, []):
            if ga >= target_addr:
                continue
            if ga not in early:
                continue
            if op not in _Z3_CMP_OP:
                continue
            var_z3 = self.encode_var(var, ga)
            bound_z3 = self._encode_bound(bound, ga, var_z3.size())
            if bound_z3 is None:
                continue
            bound_z3 = self._align(bound_z3, var_z3.size())
            cond = _Z3_CMP_OP[op](var_z3, bound_z3)
            self.solver.add(z3.Not(cond))

    def _encode_bound(self, bound: str, addr: int,
                       target_bits: int) -> Optional[z3.BitVecRef]:
        s = (bound or "").strip()
        if not s:
            return None
        # NULL → 0
        if s in ("NULL", "0"):
            return z3.BitVecVal(0, target_bits)
        try:
            return z3.BitVecVal(int(s, 0), target_bits)
        except (ValueError, TypeError):
            pass
        if s.isidentifier():
            return self.encode_var(s, addr)
        return None

    # --- Top-level: build the model + ask Z3 ---
    def check(self) -> SymbexResult:
        t0 = time.monotonic()
        bug_builder = BUG_CONDITION_BUILDERS.get(self.finding.kind)
        if bug_builder is None:
            return SymbexResult(self.finding, "unknown",
                                f"unsupported bug class: {self.finding.kind}",
                                elapsed_ms=int((time.monotonic()-t0)*1000))

        try:
            var_z3 = self.encode_var(self.finding.var, self.finding.addr)
            self.encode_path_guards(self.finding.addr)
            bug_assert = bug_builder(self, self.finding, var_z3)
            self.solver.add(bug_assert)

            chk = self.solver.check()
            elapsed_ms = int((time.monotonic() - t0) * 1000)

            if chk == z3.sat:
                m = self.solver.model()
                # Compact model dump: name → numeric value.
                kv = []
                for d in m.decls():
                    try:
                        kv.append(f"{d.name()}={m[d]}")
                    except Exception:
                        pass
                return SymbexResult(self.finding, "feasible",
                                    "Z3 produced a satisfying assignment",
                                    "; ".join(sorted(kv)[:15]),
                                    elapsed_ms)
            if chk == z3.unsat:
                return SymbexResult(self.finding, "infeasible",
                                    "Z3 proved no input satisfies the bug "
                                    "condition under the path guards",
                                    "", elapsed_ms)
            return SymbexResult(self.finding, "unknown",
                                "Z3 returned `unknown` (timeout or "
                                "incomplete theory)",
                                "", elapsed_ms)
        except Exception as e:
            return SymbexResult(self.finding, "unknown",
                                f"encoder error: {type(e).__name__}: {e}",
                                "",
                                int((time.monotonic()-t0)*1000))


# ── Convenience entry point ────────────────────────────────────────────────

def check_finding(facts_dir: str | Path, finding: Finding,
                   cfg: Optional[SymbexConfig] = None) -> SymbexResult:
    cfg = cfg or SymbexConfig.from_env()
    store = FactStore.load(facts_dir)
    enc = FunctionEncoder(store, finding, cfg)
    return enc.check()


# ── CLI smoke test ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys, json
    if len(sys.argv) < 5:
        print("Usage: python symbex_encoder.py <facts_dir> <func> <addr> <var> [kind] [extra_json]")
        print()
        print("kind defaults to 'narrow_arith_at_sink'.")
        sys.exit(1)
    facts_dir = sys.argv[1]
    func = sys.argv[2]
    addr = int(sys.argv[3])
    var = sys.argv[4]
    kind = sys.argv[5] if len(sys.argv) >= 6 else "narrow_arith_at_sink"
    extra = json.loads(sys.argv[6]) if len(sys.argv) >= 7 else {}

    finding = Finding(func=func, addr=addr, var=var, kind=kind, extra=extra)
    result = check_finding(facts_dir, finding)
    print(f"Verdict: {result.verdict}")
    print(f"Reason : {result.reason}")
    print(f"Elapsed: {result.elapsed_ms} ms")
    if result.model_str:
        print(f"Model  : {result.model_str}")

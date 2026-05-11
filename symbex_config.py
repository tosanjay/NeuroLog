"""
Symbolic-execution / SMT-verification knobs.

The symbex sub-agent encodes a Datalog finding's def-use chain plus path
guards into a Z3 query. The knobs here control how deep the encoder
explores and how long Z3 is allowed to think. Override via env vars or
by passing a custom SymbexConfig to the encoder.

Defaults are conservative — designed for sub-second verification on
small/medium codebases. For deep parser/codec slices you may want
higher depth + longer timeouts; bump via env at run time.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class SymbexConfig:
    # Maximum nesting depth for inter-procedural call encoding. When the
    # encoder hits a callee at depth ≥ max_call_depth, it falls back to
    # the function's summary (if cached) or a free-symbolic return value
    # constrained only by its declared return type.
    max_call_depth: int = 3

    # Per-finding Z3 wall-clock timeout (seconds). On timeout the verdict
    # is `unknown` rather than `feasible` / `infeasible`. Set higher for
    # complex codecs / deep call chains.
    z3_timeout_s: float = 5.0

    # Loop unrolling depth. When the encoder sees a CFG cycle, it unrolls
    # up to `loop_unroll` iterations of the body explicitly; beyond that
    # the loop's modified vars become unconstrained within their type
    # ranges. 4 is enough for "off-by-one" / bound-check patterns; bump
    # for deeper loop-carried dependencies.
    loop_unroll: int = 4

    # SMT integer width default (when VarType is unknown). C ints on the
    # target platforms are typically 32 bits.
    default_int_bits: int = 32

    # Treat any Use whose def comes from a known TaintSourceFunc as a
    # free input variable. If False, taint sources are concrete-zero
    # (overly optimistic; useful for sanity testing only).
    taint_sources_are_free: bool = True

    # When the encoder cannot find a Def for a Use (function param,
    # global, opaque), introduce a free variable constrained only by the
    # variable's declared type range.
    free_unbound_uses: bool = True

    # Fall back to assuming "callee returns any value of its declared
    # return type" when a callee has no summary AND we're at max depth.
    # If False, encoder returns `unknown` for findings depending on such
    # callees.
    free_return_at_depth_limit: bool = True

    # Path-condition cap: how many CFG nodes deep we're willing to walk
    # backward from the bug site collecting guards. Beyond this we just
    # stop adding constraints. Larger = stronger verdicts but slower.
    max_path_nodes: int = 200

    # Per-encoded-finding total wall-clock budget (Python encoder + Z3).
    # Hard kill above this. Includes Z3 timeout above as a sub-budget.
    per_finding_total_budget_s: float = 15.0

    # Phase E2: when True, constrain the symbolic value of a (var, addr)
    # by the union of observed likely-invariant ranges at that program
    # point. Off by default so Phase B verdicts stay reproducible; the
    # tiered re-run sets this to True to compute the second tier.
    use_likely_invariants: bool = False

    # Bug classes the encoder knows how to model. Each maps to a
    # bug-condition assertion in Z3. Add new keys + handlers in
    # symbex_encoder.BUG_CONDITION_BUILDERS to extend.
    enabled_bug_classes: tuple = (
        "narrow_arith_at_sink",
        "unguarded_dangerous_cast",
        "truncation_cast",
        "unbounded_counter_at_sink",
        "potential_arith_overflow",
        "signed_arg_at_sink",
        "sentinel_collision",
    )

    @classmethod
    def from_env(cls) -> "SymbexConfig":
        """Build config from environment variables. Any subset can be set;
        unset values fall back to dataclass defaults.

        Env contract:
          SYMBEX_MAX_CALL_DEPTH       (int)
          SYMBEX_Z3_TIMEOUT_S         (float)
          SYMBEX_LOOP_UNROLL          (int)
          SYMBEX_DEFAULT_INT_BITS     (int)
          SYMBEX_TAINT_SOURCES_FREE   (truthy/falsy: 1/0/true/false/on/off)
          SYMBEX_FREE_UNBOUND_USES    (same)
          SYMBEX_FREE_RETURN_AT_LIMIT (same)
          SYMBEX_MAX_PATH_NODES       (int)
          SYMBEX_PER_FINDING_BUDGET_S (float)
          SYMBEX_ENABLED_BUG_CLASSES  (comma-separated)
        """
        def _b(name: str, default: bool) -> bool:
            v = os.getenv(name)
            if v is None:
                return default
            return v.strip().lower() in ("1", "true", "yes", "on")

        cfg = cls()
        if v := os.getenv("SYMBEX_MAX_CALL_DEPTH"):
            cfg.max_call_depth = int(v)
        if v := os.getenv("SYMBEX_Z3_TIMEOUT_S"):
            cfg.z3_timeout_s = float(v)
        if v := os.getenv("SYMBEX_LOOP_UNROLL"):
            cfg.loop_unroll = int(v)
        if v := os.getenv("SYMBEX_DEFAULT_INT_BITS"):
            cfg.default_int_bits = int(v)
        cfg.taint_sources_are_free = _b("SYMBEX_TAINT_SOURCES_FREE",
                                         cfg.taint_sources_are_free)
        cfg.free_unbound_uses = _b("SYMBEX_FREE_UNBOUND_USES",
                                    cfg.free_unbound_uses)
        cfg.free_return_at_depth_limit = _b("SYMBEX_FREE_RETURN_AT_LIMIT",
                                             cfg.free_return_at_depth_limit)
        if v := os.getenv("SYMBEX_MAX_PATH_NODES"):
            cfg.max_path_nodes = int(v)
        if v := os.getenv("SYMBEX_PER_FINDING_BUDGET_S"):
            cfg.per_finding_total_budget_s = float(v)
        cfg.use_likely_invariants = _b("SYMBEX_USE_LIKELY_INVARIANTS",
                                        cfg.use_likely_invariants)
        if v := os.getenv("SYMBEX_ENABLED_BUG_CLASSES"):
            cfg.enabled_bug_classes = tuple(
                c.strip() for c in v.split(",") if c.strip())
        return cfg

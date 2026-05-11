# External Review: Datalog/Souffle Rule Sets (Souffle 2.5)

Date: 2026-04-10
Reviewer: Expert Prof. Dr. Mr. Datalog
Scope: LLM_Datalog_QL/rules/*.dl

## 1) Executive Summary

The rule ecosystem is ambitious and well-structured for source and binary analysis, but it currently has several schema-contract mismatches and precision hazards that can significantly impact correctness, false positives, and maintainability.

The highest-priority issues to fix first are:

1. Relation schema drift across files (TaintSourceFunc and ActualArg).
2. Over-broad global variable taint inference.
3. Expression substring matching for field/argument propagation.
4. Guard checks that are not tied to control/data reachability at the sink/cast site.

## 2) Critical Findings (Severity Ordered)

### High 1: TaintSourceFunc schema drift

- 2-arity declaration in:
  - rules/schema.dl:60
  - rules/alias.dl:30
- 1-arity declaration in:
  - rules/taint.dl:45
  - rules/source_interproc.dl:172

Risk:
- Hard to compose rule files in one Souffle program.
- Breakage risk in shared fact contracts and include-based assembly.

### High 2: ActualArg schema mismatch between source passes

- Core source analysis expects:
  - ActualArg(call_addr, arg_idx, param, var, ver)
  - rules/source_interproc.dl:27
- Sink post-pass expects:
  - ActualArg(ca, idx, name, expr, indirect)
  - rules/source_sink_pass.dl:12

Risk:
- Recycled facts can be misinterpreted.
- Missed sinks and wrong sink matches.

### High 3: Global taint inference from symbol-name reuse

- rules/source_interproc.dl:655
- rules/source_interproc.dl:662

Current behavior:
- Any same variable name across functions can be inferred as global.

Risk:
- Severe over-tainting and cross-function contamination.
- Common local names (i, len, buf) become pseudo-globals.

### High 4: contains-based field/arg propagation

- rules/source_interproc.dl:421
- rules/source_interproc.dl:448

Risk:
- High false positive rate due to substring collisions.
- Poor semantic precision for expression handling.

### Medium-High 5: Guard checks not tied to sink reachability

- rules/source_memsafety.dl:388

Current behavior:
- Any guard on the size var can suppress unguarded finding.

Risk:
- Guard-after-sink or irrelevant guard can hide true positives.

### Medium-High 6: GuardedBeforeCast logic too weak

- rules/source_type_safety.dl:313

Current behavior:
- Uses loose CFGEdge/line-order style hints.

Risk:
- Unrelated guards may suppress dangerous cast findings.

### Medium 7: Alias load/store semantics are fragile

- rules/alias.dl:58
- rules/alias.dl:61

Risk:
- Imprecise object/value association.
- Noisy points-to and taint-through-alias behavior.

### Medium 8: Recursion cost hotspots

- rules/core.dl:54, 82
- rules/summary.dl:74
- rules/interproc.dl:84
- rules/source_core.dl:99

Risk:
- Join explosion on large fact sets.

## 3) Structured Rubric Scores (1 low, 5 high)

Dimensions:

1. Correctness and soundness confidence
2. Precision and false-positive control
3. Performance and scalability
4. Maintainability and schema clarity

Scores:

- source_interproc.dl: 3.0 / 2.5 / 3.0 / 3.0
- source_memsafety.dl: 3.5 / 3.0 / 3.5 / 3.5
- source_type_safety.dl: 3.5 / 3.0 / 3.0 / 4.0
- source_taint.dl: 3.0 / 3.0 / 3.0 / 3.5
- alias.dl: 2.5 / 2.5 / 3.0 / 3.0
- interproc.dl: 3.0 / 3.0 / 2.5 / 3.0
- taint.dl: 3.0 / 2.5 / 3.5 / 3.5
- core.dl and summary.dl: 3.5 / 3.5 / 2.5 / 4.0
- patterns.dl: 4.0 / 2.5 / 4.5 / 4.0
- patterns_mem.dl: 2.5 / 2.0 / 4.5 / 3.5
- signatures.dl and type_knowledge.dl: 4.5 / 4.0 / 4.5 / 4.0

## 4) Concrete Patch Plan (Souffle 2.5 Compatible)

The following replacement snippets are designed to be practical, incremental, and low-risk.

---

### Patch A: Unify TaintSourceFunc contract

Target files:

- rules/schema.dl
- rules/source_interproc.dl
- rules/taint.dl
- rules/source_taint.dl
- rules/alias.dl

Canonical declaration:

	.decl TaintSourceFunc(name: Sym, category: Sym)

Add compatibility view for files that currently expect 1-arity:

	.decl TaintSourceName(name: Sym)
	TaintSourceName(n) :- TaintSourceFunc(n, _).

Then replace rules of form:

	TaintSourceFunc(callee)

with:

	TaintSourceName(callee)

or directly:

	TaintSourceFunc(callee, _)

---

### Patch B: Unify ActualArg and split expression metadata

Target files:

- rules/source_interproc.dl
- rules/source_sink_pass.dl
- rules/debug_sink.dl

Canonical relation:

	.decl ActualArg(call_addr: Addr, arg_idx: Idx, param: Sym, var: Sym, ver: Ver)

If expression text/indirection is needed, add separate relation:

	.decl ActualArgExpr(call_addr: Addr, arg_idx: Idx, expr: Sym, indirect: Idx)
	.input ActualArgExpr

Then update sink pass to read both relations explicitly instead of overloading ActualArg.

---

### Patch C: Replace name-based global inference

Target file:

- rules/source_interproc.dl

Add extractor-provided relation:

	.decl GlobalDecl(var: Sym, object_id: Sym)
	.input GlobalDecl

Replace current GlobalVar derivation with:

	.decl GlobalVar(var: Sym, object_id: Sym)
	GlobalVar(v, oid) :- GlobalDecl(v, oid).

Tainted global becomes object-based:

	.decl TaintedGlobalObj(object_id: Sym, origin: Sym)
	TaintedGlobalObj(oid, origin) :-
		GlobalVar(v, oid),
		TaintedVar(_, v, _, origin, _).

Propagation from global object to function-local symbol:

	TaintedVar(f, v, d, origin, 0) :-
		GlobalVar(v, oid),
		TaintedGlobalObj(oid, origin),
		Def(f, v, _, d).

If extractor changes are not yet available, add a temporary guardrail fallback:

	.decl FuncLocalVar(func: Sym, var: Sym)
	FuncLocalVar(f, v) :- FormalParam(f, v, _).
	FuncLocalVar(f, v) :- Def(f, v, _, _), !GlobalDecl(v, _).

and avoid cross-function promotion without GlobalDecl.

---

### Patch D: Remove contains heuristics for field interproc propagation

Target file:

- rules/source_interproc.dl

Current risky pattern:

	contains(base, arg_expr)

Replace with extractor relation:

	.decl ArgExprUsesVar(call_addr: Addr, arg_idx: Idx, var: Sym)
	.input ArgExprUsesVar

Then use precise membership:

	TaintedField(callee, param, field, origin, ca) :-
		TaintedField(caller, base, field, origin, _),
		Call(caller, callee, ca),
		ArgExprUsesVar(ca, idx, base),
		FormalParam(callee, param, idx).

---

### Patch E: Strengthen guardedness for tainted-size sinks

Target file:

- rules/source_memsafety.dl

Replace broad negation:

	!Guard(f, _, sv, _, _, _, _)

with reachability-aware guard check:

	.decl EffectiveGuardForSize(func: Sym, guard_addr: Addr, call_addr: Addr, var: Sym)
	EffectiveGuardForSize(f, ga, ca, sv) :-
		Guard(f, ga, sv, _, _, _, _),
		CFGReach(f, ga, ca).

	UnguardedTaintedSize(f, ca, callee, sv, idx, origin) :-
		TaintedSizeAtSink(f, ca, callee, sv, idx, origin),
		!EffectiveGuardForSize(f, _, ca, sv).

Optional strengthening using dataflow:

	EffectiveGuardForSize(f, ga, ca, sv) :-
		Guard(f, ga, sv, _, _, _, _),
		DefReachesUse(f, sv, d, ga),
		DefReachesUse(f, sv, d, ca),
		CFGReach(f, ga, ca).

---

### Patch F: Replace GuardedBeforeCast with dataflow-aware guard

Target file:

- rules/source_type_safety.dl

New relation:

	.decl GuardedCastSource(func: Sym, cast_addr: Addr, src: Sym)
	GuardedCastSource(f, ca, src) :-
		Cast(f, ca, _, _, src, _, _, _, _, _, _),
		Guard(f, ga, src, _, _, _, _),
		DefReachesUse(f, src, d, ga),
		DefReachesUse(f, src, d, ca),
		CFGReach(f, ga, ca).

Use this in UnguardedDangerousCast:

	...
	!GuardedCastSource(f, a, src).

---

### Patch G: Tighten alias load/store modeling

Target file:

- rules/alias.dl

Introduce explicit store-value link from extractor or synthetic relation:

	.decl StoreValue(func: Sym, store_addr: Addr, value_var: Sym, value_ver: Ver)
	.input StoreValue

Refined load rule sketch:

	PointsTo(f, load_dst, load_dver, obj) :-
		MemRead(f, load_addr, load_ptr, _, _),
		Def(f, load_dst, load_dver, load_addr),
		PointsTo(f, load_ptr, _, mem_obj),
		MemWrite(f, store_addr, store_ptr, _, _),
		PointsTo(f, store_ptr, _, mem_obj),
		StoreValue(f, store_addr, store_val, store_vver),
		PointsTo(f, store_val, store_vver, obj).

This avoids conflating symbol-name identity with object identity.

## 5) Suggested Implementation Order

1. Patch A and Patch B first (schema contracts).
2. Patch C and Patch D second (major precision wins).
3. Patch E and Patch F third (guard correctness).
4. Patch G fourth (alias precision).
5. Profile recursive relations and optimize hotspots after semantic fixes.

## 6) Validation Checklist (Souffle 2.5)

For each patch stage:

1. Compile: no relation declaration conflicts.
2. Sanity: relation cardinalities stay within expected range.
3. Regression set:
   - At least one known positive survives.
   - Known benign examples do not increase false positives.
4. Performance:
   - Track runtime and peak memory on the same fact corpus.

## 7) Notes

- This review emphasizes logic quality and composability.
- Runtime-grounded tuning should be done after schema unification.

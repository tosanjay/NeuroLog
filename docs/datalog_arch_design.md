# Datalog Architecture & Design

This document describes the architecture of NeuroLog: how facts are extracted from C source code using an LLM, the Datalog fact schema, the analysis rule files, and the multi-pass Souffle pipeline.

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [LLM-Based Fact Extraction from C Source (Core Innovation)](#2-llm-based-fact-extraction-from-c-source)
3. [Fact Schema (19 Types)](#3-fact-schema)
4. [Analysis Pipeline (5 Passes)](#4-analysis-pipeline)
5. [Datalog Rule Files](#5-datalog-rule-files)
6. [Key Datalog Relations and Rules](#6-key-datalog-relations-and-rules)
7. [Defensive Rules for LLM Imprecision](#7-defensive-rules-for-llm-imprecision)
8. [Lessons Learned](#8-lessons-learned)
9. [Comparison with Traditional Approaches](#9-comparison-with-traditional-approaches)
10. [TODO / Future Work](#10-todo--future-work)

---

## 1. Architecture Overview

NeuroLog is a three-stage pipeline:

```
Stage 1: tree-sitter (fast, free)
  ├── Enumerate all functions in a project
  ├── Build call graph
  ├── Find dangerous sinks (memcpy, strcpy, malloc, free, printf, system, ...)
  └── Backward slice from sinks → targeted function set

Stage 2: LLM (expensive, targeted — only on the slice)
  └── For each function in the slice:
      ├── Send function source (with line numbers) to Claude
      ├── LLM extracts structured Datalog facts
      └── Facts written as TSV to .facts files

Stage 3: Souffle Datalog (formal reasoning, sub-second)
  ├── Pass 1: Alias analysis (Andersen-style points-to)
  ├── Pass 2: Interprocedural taint (reaching defs + 1-CFA)
  ├── Pass 3: Type safety (signedness, truncation, width mismatch)
  ├── Pass 4: Memory safety (BOIL, tainted alloc size, ptr arithmetic)
  └── Pass 5: Sink post-pass (recomputes TaintedSink from materialized facts)
```

**Key design principle**: Use tree-sitter (free) to identify which functions matter, then use the LLM (expensive) only on the targeted subset. For a typical project, backward slicing reduces the function set by 50-80%.

---

## 2. LLM-Based Fact Extraction from C Source

This is the core innovation of the project and the primary differentiator from traditional tools like CodeQL, DOOP, and Joern.

### 2.1 The Problem

Traditional static analysis requires:
1. A **complete build environment** (compiler, headers, libraries, build system)
2. **Compilation** to produce an intermediate representation (AST → CFG → SSA)
3. A **fact extractor** that walks the IR and emits Datalog facts

This is a significant barrier. Legacy code may not compile. Partial codebases lack headers. Cross-platform projects need platform-specific toolchains. Build systems break.

### 2.2 The Solution: LLM as Semantic Compiler

We replace steps 1-3 with a single LLM call. The LLM reads raw C source code and extracts the same structured facts that a compiler-based extractor would produce:

```
Traditional:    source → compiler → IR → fact extractor → Datalog facts
NeuroLog: source → LLM prompt → Datalog facts
```

The LLM understands C semantics without needing headers or a build system. It can resolve:
- Type information (signedness, width) from declarations
- Output parameter conventions (`fgets` writes into `buf`, `scanf` writes into `&x`)
- Struct field access patterns (`ptr->field`)
- Implicit type conversions (`int` to `size_t`)
- Macro expansions (conceptually, even if the macro body isn't visible)

### 2.3 The Extraction Prompt

The extraction prompt ([`prompts/fact_extraction.md`](../prompts/fact_extraction.md)) is 233 lines and serves as a precise specification. Key sections:

**Context framing**: The prompt tells the LLM it is part of a vulnerability detection pipeline and explains what the downstream Datalog rules will compute (taint analysis, integer overflow, type confusion, buffer overflow, UAF). This context helps the LLM prioritize which facts matter.

**Schema definition**: Each of the 19 fact types is specified with column names, types, and emit conditions. For example:

```
### Def — Variable definition (assignment, declaration with init, output parameter)
Columns: `var` (string), `ver` (int, always 0)
Emit when: a variable is assigned a value, declared with initialization,
receives a return value from a call, OR is passed as an output parameter
to a function that writes into it.
```

**Critical patterns**: The prompt emphasizes facts that are commonly missed and break analysis:
- **Output parameter Defs**: `fgets(buf, n, stream)` must emit `Def(buf)` — the most common source of missing taint propagation
- **CFGEdge completeness**: Every sequential line pair and every branch/loop edge must be emitted — missing edges break reaching definitions
- **Formal parameter Defs**: Parameters are initial definitions that must reach their uses

**Soundness constraint**: "Only emit facts that are directly grounded in the source code. A false fact is worse than a missing one." This prevents the LLM from hallucinating vulnerabilities.

**Worked example**: A complete 21-line C function with all expected facts shown, demonstrating the output parameter pattern, CFGEdge completeness, and all 19 fact types.

### 2.4 The Extraction Function

```python
def extract_facts_llm(
    function_source: str,   # C source with line numbers
    func_name: str,         # Function name
    file_path: str,         # File path (for fact records)
    model: str = None,      # LLM model (default: Claude Sonnet)
) -> list[Fact]
```

The function:
1. Adds line numbers to source if not present
2. Estimates `max_tokens` based on function size (8K–32K)
3. Calls `litellm.completion()` with the extraction prompt as system message
4. Parses the JSON response into `Fact` objects
5. Retries once if 0 facts extracted (for functions >20 lines)
6. Returns structured facts with metrics (tokens, cost, time)

**Async variant**: `extract_facts_llm_async()` supports parallel extraction with semaphore-based concurrency control and exponential backoff for rate limits.

**Batch mode**: `batch_extractor.py` wraps the Anthropic Message Batches API to submit all functions in one batch. This achieves 8x speedup and 50% cost reduction.

### 2.5 Example: What the LLM Extracts

Given this C function:

```c
10| int read_and_copy(const char *filename) {
11|     FILE *file;
12|     char buf[256];
13|     char dest[64];
14|     file = fopen(filename, "r");
15|     if (!file) return -1;
16|     fgets(buf, sizeof(buf), file);
17|     strcpy(dest, buf);
18|     printf("Got: %s\n", dest);
19|     fclose(file);
20|     return 0;
21| }
```

The LLM produces ~43 facts including:

| Kind | Addr | Key Fields | Why It Matters |
|------|------|------------|----------------|
| `FormalParam` | 10 | var=filename, idx=0 | Declares entry point for interprocedural taint |
| `Def` | 10 | var=filename | Parameter is an initial definition |
| `CFGEdge` | 10→14, 14→15, ..., 19→20 | Sequential flow | Reaching definitions need complete CFG |
| `StackVar` | 12 | var=buf, size=256 | Buffer size for overflow detection |
| `VarType` | 12 | var=buf, type=char[256], signed=unsigned | Type info for signedness analysis |
| `Call` | 16 | callee=fgets | Function call site |
| **`Def`** | **16** | **var=buf** | **Output parameter — `fgets` writes into `buf`** |
| `ActualArg` | 16 | idx=0, var=buf | Argument mapping for interprocedural taint |
| `Guard` | 15 | var=file, op="==", bound="0" | NULL check — guards subsequent code |
| `MemWrite` | 17 | target=dest | `strcpy` writes through pointer |

The **Def at line 16 for `buf`** is the critical extraction. Without it, the Datalog engine cannot establish that `fgets` taints `buf`, and the entire taint chain to `strcpy` breaks.

### 2.6 Quality and Accuracy

From the Phase 3A evaluation (20 files, 90 functions, 4,355 facts):

| Metric | Value |
|--------|-------|
| Avg facts per function | 48.4 |
| Avg cost per function | $0.052 |
| File-level taint recall vs Joern | 92.3% |
| Sink-level F1 vs Joern | 68.3% |

The LLM extraction is not perfect. Common issues:
- Missing CFGEdge facts (especially loop back-edges)
- Missing output parameter Defs for less-common functions
- Vocabulary mismatch (LLM emits `"<"` but rules expect `"lt"` for Guard operators)

These are compensated by **defensive Datalog rules** (see Section 7).

### 2.7 Why Not Just Use tree-sitter?

tree-sitter can extract some facts (Def, Use, Call, ActualArg) from the AST. We implemented `tree_sitter_facts.py` as a baseline. But tree-sitter cannot extract:

- **Output parameter Defs**: Requires knowing function semantics (`fgets` writes into arg0)
- **VarType signedness**: Requires understanding C type semantics
- **Guard semantics**: Requires understanding comparison operators and their bounds
- **CFGEdge**: Requires control flow analysis beyond pure syntax
- **Implicit casts**: Requires type inference

The LLM fills this semantic gap — it understands C conventions, library function behavior, and implicit operations that pure syntax analysis misses.

---

## 3. Fact Schema

The schema defines 19 fact types, shared with the binary analysis sibling project (`bin_datalog`). In the source-code context, addresses are source line numbers (not hex addresses) and SSA version is always 0 (flow-insensitive).

### 3.1 Core Data Flow Facts

| Fact | Columns | Description |
|------|---------|-------------|
| **Def** | func, var, ver, addr | Variable definition (assignment, output param, return value) |
| **Use** | func, var, ver, addr | Variable read |
| **PhiSource** | func, var, def_ver, src_var, src_ver | SSA phi merge (binary only; not used in source mode) |
| **ReturnVal** | func, var, ver | Return statement value |

### 3.2 Call Graph Facts

| Fact | Columns | Description |
|------|---------|-------------|
| **Call** | caller, callee, addr | Function call |
| **ActualArg** | call_addr, arg_idx, param, var, ver | Argument passed to call |
| **FormalParam** | func, var, idx | Function parameter declaration |

### 3.3 Memory & Pointer Facts

| Fact | Columns | Description |
|------|---------|-------------|
| **MemRead** | func, addr, base, offset, size | Pointer dereference read (`*ptr`, `ptr[i]`) |
| **MemWrite** | func, addr, target, mem_in, mem_out | Pointer dereference write |
| **AddressOf** | func, var, ver, target | `&variable` expression |
| **FieldRead** | func, addr, base, field | Struct field read (`obj.field`, `ptr->field`) |
| **FieldWrite** | func, addr, base, field, mem_in, mem_out | Struct field write |

### 3.4 Control Flow Facts

| Fact | Columns | Description |
|------|---------|-------------|
| **CFGEdge** | func, from_addr, to_addr | Control flow edge (sequential, branch, loop) |
| **Jump** | func, addr, expr | Branch/jump expression |
| **Guard** | func, addr, var, ver, op, bound, bound_type | Conditional check (if/while/for) |

### 3.5 Type & Arithmetic Facts

| Fact | Columns | Description |
|------|---------|-------------|
| **ArithOp** | func, addr, dst_var, dst_ver, op, src_var, src_ver, operand | Arithmetic operation |
| **Cast** | func, addr, dst, dst_ver, src, src_ver, kind, src_width, dst_width, src_type, dst_type | Type cast |
| **StackVar** | func, addr, var, offset, size | Local variable with size |
| **VarType** | func, addr, var, type_name, width, signedness | Variable type info |

### 3.6 Fact File Format

Facts are stored as tab-separated `.facts` files, one per relation:

```
# Def.facts
read_and_copy	filename	0	10
read_and_copy	file	0	14
read_and_copy	buf	0	16
```

The `fact_schema.py` module defines the `FactKind` enum, `Fact` dataclass, and `write_facts()` function that handles TSV serialization.

---

## 4. Analysis Pipeline

The `souffle_runner.py` module orchestrates a 5-pass Souffle pipeline:

### Pass 1: Alias Analysis (`alias.dl`)

Andersen-style points-to analysis. Computes `PointsTo(func, var, ver, obj)` — which abstract objects each pointer may point to.

**Input**: Def, AddressOf, MemWrite, Call, ActualArg, FormalParam
**Output**: `PointsTo.csv` → recycled to `PointsTo.facts`

### Pass 2: Interprocedural Taint (`source_interproc.dl`)

The main analysis pass. Computes reaching definitions, intraprocedural and interprocedural taint propagation with 1-CFA context sensitivity.

**Input**: All 19 fact types + PointsTo + EntryTaint + DangerousSink + library signatures
**Output**: TaintedVar, TaintedSink, TaintedField, TaintedBuffer, DefReachesUse, GuardedSink, TaintGuardedCall, TaintReachableFunc, and more

### Pass 3: Type Safety (`source_type_safety.dl`)

Detects signed/unsigned confusion, truncation casts, width mismatches at dangerous sinks, and tainted cast chains.

**Input**: Cast, VarType, TaintedVar, DefReachesUse (from Pass 2)
**Output**: TypeSafetyFinding, SignednessMismatch, TruncationCast, TaintedSignednessMismatch

### Pass 4: Memory Safety (`source_memsafety.dl`)

Detects buffer overflow in loops (BOIL), tainted pointer arithmetic, alloc-copy size mismatch, and unchecked allocations.

**Input**: TaintedVar, TaintedSink, GuardedSink, DefReachesUse (from Pass 2)
**Output**: MemSafetyFinding, BufferOverflowInLoop, TaintedSizeAtSink, TaintedPtrArith, AllocCopyMismatch

### Pass 5: Sink Post-Pass (`source_sink_pass.dl`)

Recomputes TaintedSink from the materialized (recycled) facts. This catches sinks that the fixpoint computation in Pass 2 misses due to Souffle's evaluation ordering with string operations in recursive rules.

**Input**: TaintedVar.facts, DefReachesUse.facts, Call.facts, ActualArg.facts, DangerousSink.facts, SanitizedVar.facts
**Output**: TaintedSink, UnguardedTaintedSink

### Fact Recycling

After each pass, key output `.csv` files are copied back to the facts directory as `.facts` files. This allows subsequent passes to consume results from earlier passes as input relations.

---

## 5. Datalog Rule Files

### Source-Level Rules (used in the pipeline)

| File | Lines | Purpose |
|------|-------|---------|
| `source_interproc.dl` | 677 | Full interprocedural taint: reaching defs, 1-CFA taint propagation, TaintedSink, defensive inference |
| `source_memsafety.dl` | 409 | Memory safety: BOIL, tainted alloc size, ptr arith, alloc-copy mismatch |
| `source_type_safety.dl` | 383 | Type safety: signedness, truncation, width mismatch |
| `source_core.dl` | 116 | Core reaching definitions (standalone version) |
| `source_taint.dl` | 232 | Intraprocedural taint (standalone version) |
| `source_sink_pass.dl` | 65 | Post-pass TaintedSink recomputation |
| `alias.dl` | 121 | Andersen-style points-to analysis |

### Binary-Level Rules (from sibling `bin_datalog` project)

| File | Lines | Purpose |
|------|-------|---------|
| `core.dl` | 101 | SSA-based def-use chains |
| `taint.dl` | 160 | SSA-based taint tracking |
| `interproc.dl` | 318 | SSA-based interprocedural taint |
| `patterns.dl` | 47 | Structural vulnerability patterns |
| `patterns_mem.dl` | 126 | UAF, double-free, format string patterns |
| `summary.dl` | 135 | Per-function taint summaries |

### Support Files

| File | Lines | Purpose |
|------|-------|---------|
| `schema.dl` | 100 | Shared type/relation declarations |
| `signatures.dl` | 187 | Library function taint-transfer models |
| `type_knowledge.dl` | 201 | C type semantics knowledge base |

---

## 6. Key Datalog Relations and Rules

### 6.1 Reaching Definitions

The foundation of the analysis. Unlike binary analysis (which uses SSA versions), source-level analysis uses `(var, def_line)` pairs:

```prolog
% A definition reaches out of its own line
ReachesOut(f, v, d, d) :- Def(f, v, _, d).

% Propagate through CFG edges, killed by redefinition
ReachesOut(f, v, d, n) :-
    ReachesIn(f, v, d, n),
    !Kills(f, v, n).

ReachesIn(f, v, d, n) :-
    ReachesOut(f, v, d, pred),
    CFGEdge(f, pred, n).

% Def at line d reaches use at line u
DefReachesUse(f, v, d, u) :-
    ReachesIn(f, v, d, u),
    Use(f, v, _, u).
```

This correctly handles sanitization: if a variable is redefined between its tainted definition and its use, taint is killed.

### 6.2 TaintedVar (1-CFA Context-Sensitive)

```prolog
TaintedVar(func, var, def_line, origin, ctx)
```

Taint propagation rules:
- **Rule 1**: External sources (`fgets`, `recv`, `scanf`, etc.) introduce taint
- **Rule 2**: Intraprocedural propagation (assignment, self-assignment) gated by DefReachesUse
- **Rule 3**: Pointer/buffer propagation (AddressOf, MemWrite)
- **Rule 4**: Field propagation (FieldRead from tainted struct taints destination)
- **Rule 5**: Interprocedural caller→callee (actual args become tainted formal params)
- **Rule 6**: Interprocedural callee→caller (FuncModifiesParam side effects, return values)
- **Rule 7**: Entry-point taint (user-specified API surface)

### 6.3 TaintedSink

```prolog
TaintedSink(caller, callee, ca, idx, v, risk, origin) :-
    TaintedVar(caller, v, v_def, origin, _),
    DefReachesUse(caller, v, v_def, ca),
    Call(caller, callee, ca),
    ActualArg(ca, idx, _, v, _),
    DangerousSink(callee, idx, risk),
    !SanitizedVar(caller, v, v_def, _, _).
```

A tainted variable reaches a dangerous sink if:
1. The variable is tainted (`TaintedVar`)
2. Its tainted definition reaches the call site (`DefReachesUse`)
3. It's passed as an argument at that call site (`ActualArg`)
4. The callee has a dangerous parameter at that index (`DangerousSink`)
5. The variable was not sanitized between def and use (`!SanitizedVar`)

### 6.4 GuardedSink and SanitizedVar

```prolog
GuardedSink(f, callee, ca, gv, op, val) :-
    Call(f, callee, ca),
    Guard(f, g, gv, _, op, val, _),
    CFGReach(f, g, ca),
    (DangerousSink(callee, _, _) ; contains("free", callee) ; ...).
```

A sink is guarded if there's a Guard condition between the function entry and the call site in the CFG. This reduces false positives for code that properly validates input.

### 6.5 BufferOverflowInLoop (BOIL)

```prolog
BufferOverflowInLoop(f, loop_line, tainted_bound, write_addr, write_kind, origin) :-
    TaintedLoopBound(f, loop_line, tainted_bound, _, _, origin),
    MemWrite(f, write_addr, target, _, _),
    CFGReach(f, loop_line, write_addr),
    CFGReach(f, write_addr, loop_line).  % back-edge proves it's in the loop
```

Detects the classic pattern: a tainted variable controls a loop bound, and a buffer write occurs inside that loop body.

---

## 7. Defensive Rules for LLM Imprecision

Because the LLM is not a perfect fact extractor, the Datalog rules include defensive logic that compensates for common extraction errors.

### 7.1 Defensive Def Inference

The LLM sometimes misses `Def` for output parameters. The rules infer these:

```prolog
% If callee is a known taint source, all actual args get a Def
Def(caller, v, 0, ca) :-
    Call(caller, callee, ca),
    TaintSourceFunc(callee),
    ActualArg(ca, _, _, v, _).

% If callee writes to a parameter (multiple Defs or MemWrite), propagate Def to caller
FuncModifiesParam(f, idx) :- FormalParam(f, p, idx), MemWrite(f, _, p, _, _).

Def(caller, v, 0, ca) :-
    Call(caller, callee, ca),
    FuncModifiesParam(callee, idx),
    ActualArg(ca, idx, _, v, _).
```

### 7.2 Expression-Argument Matching

The LLM sometimes uses expressions as `ActualArg` values (e.g., `&buffer` instead of `buffer`). Rules handle this:

```prolog
% Address-of pattern: match &base to TaintedField base
TaintedField(callee, param, field, origin, ca) :-
    TaintedField(caller, base, field, origin, _),
    Call(caller, callee, ca),
    ActualArg(ca, idx, _, arg_expr, _),
    arg_expr = cat("&", base),
    FormalParam(callee, param, idx).

% Substring match: if base appears in the argument expression
TaintedField(callee, param, field, origin, ca) :-
    TaintedField(caller, base, field, origin, _),
    Call(caller, callee, ca),
    ActualArg(ca, idx, _, arg_expr, _),
    contains(base, arg_expr),
    arg_expr != base,
    strlen(base) > 1,
    FormalParam(callee, param, idx).
```

### 7.3 Operator Vocabulary Normalization

The LLM sometimes emits `"<"` where rules expect `"lt"`, or `"var"` instead of `"variable"`. Rules accept both:

```prolog
TaintedLoopBound(f, addr, tv, gv, op, origin) :-
    TaintedVar(f, tv, tv_def, origin, _),
    Guard(f, addr, gv, _, op, _, bound_type),
    (op = "lt" ; op = "<" ; op = "le" ; op = "<=" ; op = "ne" ; op = "!="),
    (bound_type = "variable" ; bound_type = "var"),
    ...
```

### 7.4 Function-Pointer Indirection

Real code uses function pointers for allocation (`hooks->allocate` instead of `malloc`). Rules use substring matching:

```prolog
TaintedSink(caller, callee, ca, idx, v, "alloc", origin) :-
    TaintedVar(caller, v, v_def, origin, _),
    DefReachesUse(caller, v, v_def, ca),
    Call(caller, callee, ca),
    ActualArg(ca, idx, _, v, _),
    (contains("allocate", callee) ; contains("malloc", callee)),
    idx = 0.
```

### 7.5 Macro/Body-less Callee Pass-Through

C macros have no function body, so `FormalParam` is empty. Rules pass taint through:

```prolog
TaintedVar(f, dv, ca, origin, ctx) :-
    TaintedField(f, base, _field, origin, ctx),
    Call(f, callee, ca),
    ActualArg(ca, _, _, base, _),
    !FormalParam(callee, _, _),   % callee has no body (macro/inline)
    Def(f, dv, _, ca).
```

---

## 8. Lessons Learned

### 8.1 CFGEdge is the Most Critical Fact

Without complete CFGEdge facts, reaching definitions break down and taint cannot propagate between lines. The LLM prompt heavily emphasizes CFGEdge completeness, and the evaluation showed that most analysis failures trace back to missing edges.

### 8.2 Output Parameter Defs are the Second Most Critical

The pattern `fgets(buf, n, stream)` must produce `Def(buf)`. Missing this single fact breaks the entire taint chain from external input to the buffer. The prompt includes 12 examples of this pattern, and defensive rules infer it when the LLM misses it.

### 8.3 Souffle Stratification Matters

Souffle evaluates rules in strata determined by negation dependencies. Rules using `cat()` string operations in recursive relations (like TaintedVar) can produce tuples that aren't visible to downstream relations (like TaintedSink) in the same fixpoint. The solution: a post-pass (Pass 5) that recomputes sinks from materialized facts.

### 8.4 Vocabulary Mismatch is Silent

When the LLM emits `"<"` but a rule expects `"lt"`, there is no error — the join simply produces no results. These silent failures are the hardest to debug. The solution: accept both forms in disjunctions.

### 8.5 Batch API Changes the Economics

Sequential LLM extraction is 15x slower than Joern. The Anthropic Batch API reduces this to 1.9x slower at 50% cost reduction. For large codebases, batch processing time is bounded by Anthropic's ~1 hour SLA regardless of size.

---

## 9. Comparison with Traditional Approaches

### 9.1 vs. CodeQL (GitHub)

CodeQL requires compilation via a custom database creation step (`codeql database create`). It uses a proprietary query language (QL) that is more expressive than Datalog but less amenable to formal reasoning. NeuroLog trades the compilation requirement for LLM cost, and uses standard Souffle Datalog (open-source, well-understood semantics).

### 9.2 vs. DOOP (Research)

DOOP is the gold standard for Datalog-based points-to analysis of Java programs. It uses Souffle (or LogicBlox) and has hundreds of meticulously crafted Datalog rules. However, it requires a compiled Java bytecode input. Our approach is analogous — Datalog rules over extracted facts — but targets C/C++ and replaces bytecode analysis with LLM extraction.

Reference: Bravenboer & Smaragdakis, "Strictly Declarative Specification of Sophisticated Points-to Analyses" (OOPSLA 2009)

### 9.3 vs. Joern

Joern is the closest comparison point. It uses fuzzy parsing (no compilation required) to build a Code Property Graph (CPG), then supports queries over the PDG for taint reachability. Our Phase 3A evaluation shows 100% agreement with Joern on overlapping analysis scope (interprocedural data taint). Joern additionally handles UAF lifecycle analysis; we additionally detect tainted allocation sizes.

### 9.4 vs. GrammaTech Datalog Disassembly

Flores-Montoya & Schulte (2020) use Datalog for binary disassembly and analysis — a different problem (binary → facts) but the same paradigm (facts + Datalog rules = analysis). Their work demonstrates that Datalog scales to production binary analysis. Our contribution is showing that an LLM can serve as the "fact extractor" from source code.

### 9.5 vs. Semgrep / Infer

Semgrep is pattern-matching without formal dataflow; it finds syntactic patterns but not interprocedural taint. Infer (Facebook) uses abstract interpretation with bi-abduction — more precise for memory safety but requires compilation. NeuroLog sits between these: more formal than Semgrep, more accessible than Infer.

### 9.6 vs. Cyclone/CCured (Historical)

Cyclone and CCured took the approach of safe C dialects or runtime instrumentation. They require source modification or recompilation. Our approach is purely static and non-invasive — it analyzes code as-is, without requiring any changes or even the ability to compile.

---

## 10. TODO / Future Work

### 10.1 C++ Language Support

The pipeline currently targets **C**. C++ source files will parse and produce facts, but several C++ constructs cause the analysis to degrade or miss vulnerabilities entirely. These are listed from highest to lowest impact:

#### Virtual Dispatch & Polymorphism

**Problem**: `obj->method()` emits `Call(caller, "method", addr)`, but the Datalog engine cannot resolve which concrete override is called. The interprocedural taint chain breaks at every virtual call.

```cpp
class Handler { public: virtual void process(char* buf, int len) = 0; };
class VulnHandler : public Handler {
    void process(char* buf, int len) override { memcpy(local, buf, len); }
};
void dispatch(Handler* h, char* input, int size) {
    h->process(input, size);  // Which process()? Analysis doesn't know.
}
```

**Required work**:
- New fact types: `VTableEntry(class, method_name, concrete_func)`, `Inherits(derived, base)`
- Resolve `Call` targets using class hierarchy analysis (CHA) or rapid type analysis (RTA)
- Extend `source_interproc.dl` with virtual dispatch resolution rules
- Switch tree-sitter parser from `tree-sitter-c` to `tree-sitter-cpp`

#### Templates

**Problem**: `sizeof(T)` stays as a string literal in ArithOp facts. No tracking of template instantiation, so type-dependent size calculations are symbolic.

```cpp
template<typename T>
void copy(T* dst, T* src, size_t n) {
    memcpy(dst, src, n * sizeof(T));  // sizeof(T) = ? at analysis time
}
copy<int>(d, s, count);  // sizeof(int) = 4 — but this is lost
```

**Required work**:
- New fact type: `TemplateInstantiation(template_func, concrete_func, type_param, concrete_type)`
- LLM prompt extension to resolve template parameters at call sites
- Type knowledge rules to substitute `sizeof(T)` with concrete values

#### Exceptions (try/catch/throw)

**Problem**: No CFGEdge for exception control flow. Reaching definitions analysis doesn't know that `throw` can skip code or jump to catch blocks. Cleanup code in destructors is invisible.

```cpp
try {
    Buffer buf(tainted_size);   // Constructor may throw
    memcpy(buf.data, src, n);   // Reachable? Analysis doesn't know.
} catch (std::bad_alloc& e) {
    // Exception edge not in CFGEdge
}
```

**Required work**:
- CFGEdge edges for throw→catch and try-body→finally
- LLM prompt extension to emit exception control flow
- Guard rules for catch blocks that sanitize exception state

#### RAII & Destructors

**Problem**: Implicit destructor calls at scope exit are invisible. `std::unique_ptr` auto-deletion, `fclose()` in RAII wrappers, `free()` in custom allocators — none emit Call facts.

```cpp
{
    std::unique_ptr<char[]> buf(new char[size]);
    read(fd, buf.get(), size);
}  // Implicit delete[] here — no Call fact emitted
```

**Required work**:
- New fact type: `ImplicitCall(func, addr, callee, kind)` with kind = "destructor"
- LLM must recognize scope exits and emit destructor Call facts
- Extend UAF/double-free rules to account for implicit cleanup

#### Operator Overloading

**Problem**: `operator[]` is parsed as a function call, not a MemWrite. Buffer access semantics are lost. `operator=` hides memcpy/strcpy inside.

```cpp
class String {
    char buf[256];
    String& operator=(const char* s) { strcpy(buf, s); return *this; }
};
String s;
s = tainted_input;  // operator= calls strcpy internally — invisible
```

**Required work**:
- Map `operator[]` to MemRead/MemWrite in extraction
- Map `operator=` with known-dangerous implementations to MemWrite + DangerousSink
- LLM prompt extension for operator overload semantics

#### Lambdas & Closures

**Problem**: Lambda bodies are not extracted as separate functions. Capture semantics (by-value vs by-reference) are not modeled. If a lambda captures a tainted variable and is passed to a callback, taint is lost.

**Required work**:
- Extract lambda bodies as anonymous functions with FormalParam for captures
- New fact type: `LambdaCapture(lambda_func, var, capture_kind)` (value/reference)
- Taint propagation rules for capture→lambda-body

#### Move Semantics

**Problem**: `std::move()` is parsed as a regular function call. Ownership transfer between `unique_ptr`, `shared_ptr`, or move constructors is not tracked.

**Required work**:
- Library signatures for `std::move`, `std::forward`
- Taint transfer rules for move constructors/assignment operators

#### STL Library Models

**Problem**: `std::string`, `std::vector`, `std::map`, `std::shared_ptr` have no taint-transfer models. `s.c_str()`, `v.data()`, `v[i]` are plain function calls with no special semantics.

**Required work**:
- `signatures.dl` entries for STL container methods:
  - `std::string::c_str()` → returns tainted pointer if string is tainted
  - `std::vector::operator[]` → MemRead with bounds check semantic
  - `std::vector::push_back()` → may reallocate (tainted size)
  - `std::shared_ptr::get()` → returns raw pointer

### 10.2 Analysis Precision Improvements

#### Path Sensitivity

Neither our analysis nor Joern reasons about infeasible paths. Both flag taint in code like:
```c
if (len < 0) { memcpy(dest, src, len); }  // Dead code on unsigned len
```

**Approach**: Predicated taint — track guard conditions along with taint state. If a guard contradicts the condition required for the sink to be reached, suppress the finding.

#### 2-CFA or Object-Sensitive Context

Current 1-CFA tracks one call site as context. For deep call chains or factory patterns, this loses precision. Upgrading to 2-CFA doubles context sensitivity; object-sensitive analysis (as in DOOP) would be more precise for OOP code.

#### UAF Lifecycle Analysis

Use-after-free requires tracking `alloc → free → use` temporal ordering, which is fundamentally different from data taint. This is the primary gap vs Joern's findings.

**Approach**: New Datalog rules over `Call(f, "free", addr)` and subsequent `Use(f, freed_var, ...)` with reaching-definition gating.

### 10.3 Scalability & Engineering

#### Incremental Analysis

Currently, every run re-extracts all functions. For large codebases, delta-based analysis would re-extract only changed functions and re-run Souffle incrementally.

**Approach**: Use git diff to identify changed functions, re-extract only those, merge with cached facts.

#### Whole-Program Analysis

Backward slicing limits analysis scope — taint entering through non-sliced functions is missed. A full call-graph traversal from all entry points would improve coverage at higher cost.

#### Macro Expansion

C macros are expanded before tree-sitter sees the source. `COPY(dst, src, n)` expanding to `memcpy(dst, src, n)` is invisible.

**Approach**: Preprocess with `gcc -E` to get expanded source, then analyze. Alternatively, add common macro patterns to the LLM prompt.

#### Concurrency

No modeling of thread safety, atomics, or data races. Shared mutable state accessed from multiple threads could mask or introduce vulnerabilities.

### 10.4 Broader Language Support

The architecture (LLM extraction → Datalog reasoning) is language-agnostic. The fact schema (Def, Use, Call, Guard, MemWrite, ...) applies to any imperative language. Extending to Java, Go, or Rust would require:
- Language-specific tree-sitter grammar
- Updated LLM extraction prompt with language-specific examples
- Language-specific library signatures
- Language-specific type knowledge rules

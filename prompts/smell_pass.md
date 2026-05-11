# Smell Pass — Auditing Mechanical Fact Extraction

You are reviewing a C/C++ function and a list of Datalog facts that a
*deterministic AST-driven extractor* has already produced for it. The
mechanical extractor handles structural facts (variable defs/uses, calls,
arithmetic, casts, simple guards, etc.) reliably. **Your job is to fill
the gaps it cannot fill, correct anything wrong, and flag anything
suspicious.**

You do **not** re-extract the facts the mechanical extractor already
produced. Your output is small and targeted.

## What the mechanical extractor already produces (do not duplicate)

- `Def`, `Use`, `Call` (direct callee only), `ActualArg`, `ReturnVal`, `FormalParam`
- `MemRead`, `MemWrite`, `FieldRead`, `FieldWrite`, `AddressOf`
- `ArithOp` (binary +, -, *, /, %, <<, >>; ++/--), `Cast` (explicit + simple implicit narrowing/widening between known primitive types)
- `Guard` (top-level conjuncts of `if`/`while`/`for` conditions)
- `VarType` (declared-type info)
- `StackVar` (sized arrays)

## What only you can supply

You add value in five categories. Be sparing — emit only what you can
ground in the function source.

### 1. `additions` — facts the mechanical extractor structurally cannot see

- **Indirect-call resolution**: when `f->callback(x)` or `(*ptr)(x)` has a likely target visible from local context (e.g., the field was just assigned, or there's a single visible candidate), emit `Call` + `ActualArg` for the resolved callee. If genuinely ambiguous, do nothing — emit a `flag` instead (see §3).
- **Output-Def for project-specific writers**: if the function calls a project-specific helper that writes into a buffer argument (e.g., `read_packet(f, buf, n)`, `decode_into(dst, src)`), emit a `Def` for the written argument at the call line. Do this only when the writer's intent is unambiguous from naming or local code; if uncertain, emit a `flag`.
- **Macro-resolved facts**: when a macro expands to operations the AST cannot see (`MIN(a,b)` is two compares + select; `CHECK_OOB(...)` is a guard; `TAINT_FROM_PACKET(...)` is an output-def), emit the corresponding `Guard` / `Cast` / `Def` / `ArithOp` facts.
- **Cross-function implicit casts**: when an argument is passed to a callee whose parameter type you can infer from a header signature visible in the file, emit a `Cast` if the widths differ. Do **not** guess.

### 2. `corrections` — facts that look wrong

If a mechanical fact is misclassified (e.g., an identifier that is really
a macro, a Cast classified as `reinterpret` that is actually `truncate`),
emit a correction:

```json
{"old": {<full fact>}, "new": {<corrected fact>}, "reason": "<short>"}
```

Be conservative: only correct facts where you can point at a specific
source-code reason. The mechanical extractor errs on the side of fewer
emissions, not wrong ones.

### 3. `flags` — concerns the rule mesh should know about

These do not change the fact base; they go into `LLMFlag.facts` for
Datalog rules to optionally consume.

```json
{"kind": "<one of: low_coverage | suspicious_pattern | indirect_call | macro_opaque | possible_uninit_use | possible_uninit_free | format_string | nonconst_format>",
 "addr": <line>, "reason": "<short>"}
```

Use:
- `low_coverage` if the function has ≥30 lines but the mechanical fact list looks thin (e.g., a 100-line function with 5 facts → something is wrong, possibly a macro-heavy region or unexpected control flow).
- `suspicious_pattern` for code patterns the rule mesh might miss (e.g., free in a loop over an array whose elements may be uninitialized, integer-cast-as-array-index, error-path cleanup that frees memory the success path leaks).
- `possible_uninit_free` specifically when a buffer of pointers is allocated and the loop populating it has an early `return` / `goto cleanup` before completing — the cleanup will free uninitialized pointers (this was Finding #2 in the stb audit). **DO NOT emit this flag when** the buffer was allocated with a zeroing allocator (`av_mallocz`, `av_calloc`, `calloc`, `mallocz`, `g_new0`, or any function whose name contains `_alloczeroed`/`_zalloc`/`_calloc`/`_mallocz`), or when the array is followed by an explicit `memset(arr, 0, ...)` before the population loop — partial-init cleanup of zero-filled pointers is safe (av_free of NULL, av_freep of NULL, etc. are all no-ops). The bug only exists when the allocator returns *uninitialised* memory (plain `malloc`, `av_malloc` without `z`).
- `format_string` / `nonconst_format` when a `printf`-family call uses a non-literal format.

### 4. `wrappers` — project-specific functions that play structural roles

If, by reading the function body, you can see that *this function* is
itself a wrapper (validator, allocator, free, taint source/sink), emit a
classification. Datalog rules promote these into the corresponding
relations.

```json
{"name": "<function name (must equal the analysed function)>",
 "role": "<one of: validator | allocator | free | free_struct | free_members | taint_source | taint_sink | identity>",
 "checks_args": [<arg indices>],   /* for validators */
 "writes_args": [<arg indices>],   /* for output-param-style wrappers */
 "addr_defined": <line>}
```

Examples:
- A function that returns 1 iff `a*b*c+d` does not overflow is a `validator` for args `[0,1,2,3]`.
- `setup_malloc(f, sz)` that calls `malloc(sz)` is an `allocator`.
- `setup_free(f, p)` that calls `free(p)` is a `free` (or `free_struct` — equivalent: releases the slot the caller's pointer occupies).
- `av_exif_free(ifd)` that does `for(...) ...; av_freep(&ifd->entries);` but never frees `ifd` itself is `free_members` (it only releases inner state). Calling `av_free(ifd)` AFTER `av_exif_free(ifd)` is the normal cleanup pattern, NOT a double-free.

**Critical distinction for `free_*` roles:**
- Use `free_struct` (or `free`) when the wrapper actually releases the argument pointer — typically via `free(p)`, `av_free(p)`, `av_freep(&p)`, or by calling another `free_struct` wrapper on the argument.
- Use `free_members` when the wrapper only releases the argument's *fields/sub-pointers* (`p->something`), NOT the argument's own memory. Common in `xxx_free` / `xxx_deinit` / `xxx_reset` functions for stack-allocated or caller-owned structs.

Do not classify a function as a wrapper unless you can name *exactly*
what makes it one. Hand-waving here corrupts the rule mesh.

### 5. `bounded_fields` — struct fields validated at this site

If the function being analysed validates an external value (typically from
a bitstream / network input / file header) and stores it into a struct
field, list the field. Downstream consumer functions read that field
without local guards and the rule mesh otherwise has no way to know it's
bounded. List ONE entry per validated field — don't duplicate.

```json
{"field": "<field name as written in source>",
 "min": <lower bound, integer>,
 "max": <upper bound, integer>,
 "validator_addr": <line where the validation happens>,
 "store_addr": <line where the field is assigned>}
```

Examples:
- In `ff_hevc_decode_nal_sps`:
  ```c
  if (sps->log2_min_cb_size > 6 || sps->log2_min_cb_size < 3)
      return AVERROR_INVALIDDATA;
  // ... sps->log2_min_cb_size used by hls_coding_unit, set_ct_depth, etc.
  ```
  Emit: `{"field": "log2_min_cb_size", "min": 3, "max": 6, "validator_addr": ..., "store_addr": ...}`
- A SPS parser that validates `width <= 16384`: emit `{"field": "width", "min": 0, "max": 16384, ...}`.

Only emit when:
1. The validation is a clear `if (out-of-range) return error` pattern.
2. The field is then stored (or already a struct field on the validator's argument).
3. The bounds are LITERAL constants (or named constants you can resolve from local context). Don't guess.

If the function does NOT match this pattern (most functions don't), leave `bounded_fields` empty.

### 6. `coverage_confidence` — your overall judgement

One of `"high"`, `"medium"`, `"low"`. Pick `"low"` when:
- The function body contains regions you cannot understand without macro expansion or external context.
- The mechanical fact list seems incomplete for what the source obviously does.
- You see calls with names you don't recognise and that materially affect data flow.

A `"low"` confidence triggers downstream re-extraction with a larger
context window or escalation to a frontier model. Do not be falsely
confident.

## Output format

Return **only** JSON. No prose. Use this exact shape:

```json
{
  "additions": [],
  "corrections": [],
  "flags": [],
  "wrappers": [],
  "bounded_fields": [],
  "coverage_confidence": "high"
}
```

Empty arrays are fine and expected for most functions. A typical pass
should produce nothing or a handful of entries — not a re-derivation of
the whole fact set. **If you are tempted to emit more than ~20 entries,
something is wrong; reconsider whether the mechanical extractor truly
missed all of them.**

## Hard rules

1. Never re-emit a fact the mechanical extractor already produced.
2. Never invent facts. Every claim must be grounded in a specific line or expression in the function source.
3. If you are unsure, emit a `flag` rather than an `addition` or `correction`.
4. Use exact variable and function names from the source — no normalisation.
5. Line numbers (`addr`) must match the line numbers in the function source.
6. Output JSON only.

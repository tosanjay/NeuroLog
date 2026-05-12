```
    _   _                      _
   | \ | | ___ _   _ _ __ ___ | |    ___   __ _
   |  \| |/ _ \ | | | '__/ _ \| |   / _ \ / _` |
   | |\  |  __/ |_| | | | (_) | |__| (_) | (_| |
   |_| \_|\___|\__,_|_|  \___/|_____\___/ \__, |
                                           |___/
   Neuro-Symbolic Static Analysis via Datalog

   Neuro  =  LLM perceives code, extracts semantic facts
   Log    =  Datalog reasons formally over those facts
```

# NeuroLog

> **🚧 This repository is the ADK-based prototype and is now frozen.**
> Active development has moved to **[neurolog-cli](https://github.com/tosanjay/neurolog-cli)**,
> a Claude Code / OpenClaude-native rewrite (MCP server + plugin +
> CLI, no ADK dependency). This repo remains as a runnable reference
> implementation of the rule mesh, prompts, and analysis methodology.

**Compilation-free static analysis for C/C++ using neuro-symbolic reasoning: LLM perception + Datalog logic.**

NeuroLog is a neuro-symbolic static analysis research prototype that extracts and reasons about program properties from C/C++ source code — without requiring compilation. The **neural** component (an LLM) reads raw source code and extracts structured Datalog facts representing data flow, control flow, type information, and function relationships; the **symbolic** component (Souffle Datalog) performs formal interprocedural reasoning over those facts.

The extracted fact base is general-purpose: the same facts support taint analysis, memory safety checks, type safety reasoning, crypto API misuse detection, and any other property expressible in Datalog. Users can write custom Datalog rules to query arbitrary program properties.

## Key Idea

Traditional static analysis tools require a complete build environment to produce an intermediate representation (AST, CFG, SSA). This is a significant barrier for analyzing legacy code, partial codebases, or projects with complex build systems.

**NeuroLog replaces the compiler frontend with an LLM.** The LLM reads C source directly and emits the same structured facts (Def, Use, Call, Guard, MemWrite, etc.) that a compiler-based extractor would produce. These facts feed into standard Datalog rules for interprocedural analysis — no compilation, no headers, no build system required.

Because the reasoning layer is Datalog, the analysis is **extensible by writing rules, not code**. Adding a new analysis (e.g., detecting insecure crypto API usage, checking resource leak patterns, or enforcing coding standards) requires only new `.dl` rule files — the fact extraction is reused as-is.

```
                          NEURAL                          SYMBOLIC
                    ┌─────────────────┐
   C source ───────►│  tree-sitter    │──── function list, call graph, sink detection
                    │  (fast, free)   │──── backward slice --> targeted function set
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
   targeted funcs ─►│  LLM (Claude)   │──── Datalog facts (Def, Use, Call, Guard,
                    │  (perception)   │     MemWrite, Cast, ArithOp, VarType, ...)
                    └────────┬────────┘
                             │              ┌──────────────────────────────────────┐
                    ┌────────▼────────┐     │  Data/control flow properties        │
   .facts files ───►│  Souffle        │────►│  Security (taint, memory, type)      │
                    │  (reasoning)    │     │  Custom queries (crypto, resources)  │
                    └─────────────────┘     └──────────────────────────────────────┘
```

## What Can You Analyze?

NeuroLog's fact base captures definitions, uses, calls, control flow edges, guards, memory operations, types, and casts for every function. This enables a range of analyses:

| Analysis Domain | Example Queries | Status |
|----------------|-----------------|--------|
| **Interprocedural taint** | Does user input reach `strcpy`? Does a network buffer flow to `system()`? | Implemented |
| **Memory safety** | Buffer overflow in loops, use-after-free, double-free, tainted allocation sizes | Implemented |
| **Type safety** | Signed/unsigned mismatches on tainted data, truncation casts, width mismatches | Implemented |
| **Crypto API misuse** | Does a hardcoded key reach `EVP_EncryptInit`? Is `ECB` mode used with AES? Is `rand()` used for key generation? | Planned |
| **Resource leaks** | Is a file descriptor opened but never closed on some path? | Planned |
| **Custom properties** | Any interprocedural data/control flow property expressible in Datalog | Write your own `.dl` rules |

### Note on LLM Model

All evaluation results were obtained using **Claude Sonnet 4.6** (`anthropic/claude-sonnet-4-6`). The quality of extracted facts — and therefore the accuracy of downstream analyses — depends on the LLM's ability to understand C code semantics. Results may vary with different models or model versions. The pipeline is model-agnostic via LiteLLM and can be configured to use any supported LLM (see `.env`), but we recommend using a frontier-class model for best results.

## Evaluation Results

### Phase 3A: Synthetic Benchmark (20 files, 90 functions)

Compared against **Joern** (a traditional CPG-based analysis tool) on 5 vulnerability categories:

| Metric | NeuroLog | Joern |
|--------|-------------|-------|
| File-level recall | 92.3% | 86.7% |
| Sink-level F1 | 63.4% | — |
| UAF/DoubleFree detection | Yes (intraprocedural) | Yes |
| Type safety findings | 147 across 20 files | — |
| Memory safety findings | 540 across 20 files | — |
| Compilation required | No | No |
| Cost per file | ~$0.12 (batch) | $0 (local) |
| Wall-clock (20 files) | 3.7 min (batch) | 2 min |

On overlapping analysis scope (interprocedural data taint), agreement is strong at the sink-type level. Disagreements are due to different analysis capabilities: we find tainted-size allocation sinks and type safety issues; Joern finds UAF lifecycle issues via PDG reachability. The 5-pass pipeline additionally detects use-after-free, double-free, buffer overflow in loops, and signedness mismatches.

Full report: [`eval/results/phase3a_evaluation_report.md`](eval/results/phase3a_evaluation_report.md)

### Real-World Validation: cJSON v1.7.17

Applied to the [cJSON](https://github.com/DaveGamble/cJSON) JSON parser (31 functions, ~2,500 LOC). The pipeline detects:

| CVE | Type | Detection |
|-----|------|-----------|
| **CVE-2023-53154** | Heap buffer over-read in `parse_string` | BufferOverflowInLoop at lines 830/844/882 |
| **CVE-2025-57052** | OOB array access in `cJSON_Utils.c` | TaintedSink: `get_array_item` with `oob_access` |
| CVE-2023-26819 | DoS in `parse_number` | TaintedLoopBound (partial — no explicit DoS category) |

The CVE-2025-57052 detection traces taint across 4 functions: `apply_patch` → `get_item_from_pointer` → `decode_array_index_from_pointer` (writes tainted index via output param) → `get_array_item` (OOB access with unchecked index).

Total cJSON analysis cost: ~$2.12

Full report: [`eval/results/cjson_evaluation_report.md`](eval/results/cjson_evaluation_report.md)

## Quick Start

### Prerequisites

- Python 3.11+
- [Souffle](https://souffle-lang.github.io/) Datalog compiler
- [Google ADK](https://google.github.io/adk-docs/) (`pip install google-adk`)
- tree-sitter + tree-sitter-c (`pip install tree-sitter tree-sitter-c`)
- LiteLLM (`pip install litellm`)
- An Anthropic API key:
  ```bash
  cp .env.example .env
  # Edit .env and add your ANTHROPIC_API_KEY
  ```

### Interactive Mode (Recommended)

NeuroLog includes a Google ADK agent that provides an interactive web UI. The agent orchestrates the full pipeline — scanning, fact extraction, Souffle analysis — through natural language:

```bash
# Launch the interactive web UI
uv run adk web

# Or via adk directly
adk web
```

Then open the browser at `http://localhost:8000` and select the **SourceCodeQL** agent. You can interact with it conversationally:

> "Scan /path/to/project and find dangerous sinks"
> "Extract facts for parse_string in cJSON.c"
> "Run the taint pipeline and show me the findings"

The agent uses a **multi-agent coordinator architecture** designed for large projects:

- **Coordinator** — routes requests, runs the full pipeline tool
- **ExtractionAgent** — LLM fact extraction (uses `LITE_MODEL_NAME` for cost efficiency)
- **AnalysisAgent** — Souffle Datalog queries and custom rule composition
- **InterpreterAgent** — reads results, interprets findings, generates reports
- **CVEAgent** — searches NIST NVD for known CVEs matching findings (uses `LITE_MODEL_NAME`)

For large projects, use `tool_run_full_pipeline(project_dir)` — it runs the entire scan-extract-analyze pipeline as pure computation and returns only a compact summary, avoiding context window overflow.

#### Cost Optimization

By default, all agents use `MODEL_NAME`. For significant cost savings, set `LITE_MODEL_NAME` in `.env` to use a cheaper model for sub-agents that don't need deep reasoning:

```bash
# In .env
MODEL_NAME="anthropic/claude-opus-4-6"          # For analysis & interpretation
LITE_MODEL_NAME="anthropic/claude-sonnet-4-6"    # For extraction routing & CVE lookup (~10x cheaper)
```

| Agent | Model Used | Why |
|-------|-----------|-----|
| Coordinator | `MODEL_NAME` | Needs to understand user intent and route |
| ExtractionAgent | `LITE_MODEL_NAME` | Orchestrates extraction calls, no deep reasoning |
| AnalysisAgent | `MODEL_NAME` | Composes Datalog queries, interprets formal results |
| InterpreterAgent | `MODEL_NAME` | Deep reasoning for vulnerability assessment |
| CVEAgent | `LITE_MODEL_NAME` | Calls NVD API and formats results |

### Command-Line Mode

Individual pipeline stages can also be run directly:

```bash
# 1. Scan a project: enumerate functions, find dangerous sinks, compute backward slice
python tree_sitter_nav.py <project_dir> sinks
python tree_sitter_nav.py <project_dir> slice

# 2. Extract Datalog facts for a function using LLM
python llm_extractor.py <file.c> <func_name> [output_dir]

# 3. Run the full Souffle analysis pipeline (alias → taint → type safety → memory safety → sink post-pass)
python souffle_runner.py pipeline [facts_dir] [output_dir]

# Or run individual passes
python souffle_runner.py alias.dl [facts_dir] [output_dir]
python souffle_runner.py source_interproc.dl [facts_dir] [output_dir]
```

### Example: Analyzing a Single File

```bash
# Extract facts for all functions in a file
python llm_extractor.py vulnerable.c process_input facts/
python llm_extractor.py vulnerable.c handle_request facts/

# Run the 5-pass pipeline
python souffle_runner.py pipeline facts/ output/

# Check results
cat output/TaintedSink.csv          # Tainted data reaching dangerous sinks
cat output/UnguardedTaintedSink.csv # Unguarded tainted sinks (highest priority)
cat output/MemSafetyFinding.csv     # Memory safety violations
cat output/TypeSafetyFinding.csv    # Type confusion findings
```

## Project Structure

| File | Purpose |
|------|---------|
| `agent.py` | Google ADK agent — interactive web UI for the full pipeline (`adk web`) |
| `tree_sitter_nav.py` | Project scanning, call graph, sink detection, backward slicing |
| `llm_extractor.py` | LLM-based Datalog fact extraction from C source |
| `batch_extractor.py` | Anthropic Batch API wrapper (8x faster, 50% cheaper) |
| `fact_schema.py` | Fact schema (19 types), Fact dataclass, TSV writer |
| `souffle_runner.py` | Souffle subprocess execution, 5-pass analysis pipeline |
| `tree_sitter_facts.py` | Ground truth extraction (tree-sitter only, for comparison) |
| `prompts/fact_extraction.md` | The LLM fact extraction prompt |
| `rules/*.dl` | Souffle Datalog rule files (17 files) |
| `eval/` | Phase 3A evaluation framework and results |

## Architecture & Design

For detailed documentation of the Datalog rule architecture, fact schema, LLM extraction methodology, and analysis passes, see:

**[`docs/datalog_arch_design.md`](docs/datalog_arch_design.md)**

This covers:
- The 19-type fact schema and how facts map to C language constructs
- How the LLM extracts facts directly from C source (the core innovation)
- The 5-pass Souffle analysis pipeline
- All Datalog rule files and their purposes
- Interprocedural taint propagation mechanics
- Defensive rules that compensate for LLM imprecision

## Built-in Analyses

### Security Properties (Implemented)

| Property | Datalog Relation | Description |
|----------|-----------------|-------------|
| Tainted sink | `TaintedSink` | Untrusted data reaches a dangerous function (strcpy, malloc, free, etc.) |
| Unguarded tainted sink | `UnguardedTaintedSink` | Tainted sink with no bounds check or NULL guard |
| Use-after-free | `UseAfterFree` | Pointer used after being passed to free/deallocate |
| Double-free | `DoubleFree` | Same pointer freed twice without reassignment |
| Buffer overflow in loop | `BufferOverflowInLoop` | Tainted loop bound with buffer write in body |
| Tainted allocation size | `TaintedSizeAtSink` | Tainted value used as allocation/copy size |
| Signedness mismatch | `TaintedSignednessMismatch` | Signed/unsigned conversion on tainted data |
| Truncation cast | `TruncationCast` | Narrowing cast that loses bits |
| Type safety finding | `TypeSafetyFinding` | Combined type confusion findings |
| Memory safety finding | `MemSafetyFinding` | Combined memory safety findings |

### Data/Control Flow Properties (Reusable Foundation)

| Relation | Description |
|----------|-------------|
| `TaintedVar` | Interprocedural taint propagation — tracks which variables carry untrusted data |
| `DefReachesUse` | Reaching definitions — which definition of a variable is live at a given use |
| `CFGReach` | Control flow reachability between program points |
| `PointsTo` | Pointer alias analysis |
| `TaintSummary` | Per-function taint transfer summaries (parameter → return/output) |

These relations are computed by the pipeline and available for custom downstream queries.

### Writing Custom Analyses

To add a new analysis, create a `.dl` file in `rules/` that reads from the fact base. For example, to detect hardcoded keys passed to crypto functions:

```prolog
// crypto_misuse.dl — detect hardcoded keys reaching encryption APIs
.decl DangerousCryptoSink(func: symbol, arg: number, risk: symbol)
.input DangerousCryptoSink

.decl HardcodedKeyAtCrypto(caller: symbol, callee: symbol, line: number, var: symbol)
.output HardcodedKeyAtCrypto

// Flag calls where a string literal or constant reaches a crypto key parameter
HardcodedKeyAtCrypto(f, callee, ca, var) :-
    Call(f, callee, ca),
    DangerousCryptoSink(callee, idx, _),
    ActualArg(ca, idx, _, var, _),
    Def(f, var, da, "const"),
    DefReachesUse(f, var, da, ca).
```

Then run: `python souffle_runner.py crypto_misuse.dl facts/ output/`

## Comparison with Related Tools

| Tool | Approach | Compilation | Language | Interprocedural | Cost |
|------|----------|-------------|----------|-----------------|------|
| **NeuroLog** | LLM extraction → Datalog | No | C/C++ | Yes (1-CFA) | ~$0.12/file |
| [CodeQL](https://codeql.github.com/) | Compiler-based extraction → QL | Yes | 10+ languages | Yes | Free (OSS) |
| [Joern](https://joern.io/) | Fuzzy parsing → CPG → Scala queries | No | C/C++, Java, ... | Yes | Free (OSS) |
| [DOOP](https://bitbucket.org/yanniss/doop/) | Compiler-based → Datalog (Soufflé/LogicBlox) | Yes | Java/Android | Yes (deep) | Free (research) |
| [Semgrep](https://semgrep.dev/) | Pattern matching on AST | No | 30+ languages | Limited | Free/Paid |
| [Infer](https://fbinfer.com/) | Abstract interpretation (bi-abduction) | Yes | C/C++, Java, ObjC | Yes | Free (OSS) |

**Key differentiator**: NeuroLog combines compilation-free analysis with formal Datalog-based interprocedural reasoning. CodeQL and DOOP require compilation; Joern and Semgrep don't use formal Datalog. The LLM serves as a "semantic compiler" that understands C without needing headers, build systems, or platform-specific toolchains. Because the reasoning layer is standard Datalog, users can write custom queries for any property — security, correctness, coding standards — without modifying the extraction pipeline.

## TODO / Known Limitations

### C++ Support

The current pipeline targets **C**. C++ codebases will parse and extract facts, but the analysis degrades on C++-specific constructs:

| Construct | Impact | Workaround |
|-----------|--------|------------|
| **Virtual dispatch** | Polymorphic calls unresolved — `obj->method()` doesn't connect to the concrete override | Analyze concrete classes directly |
| **Templates** | `sizeof(T)` stays symbolic; no instantiation tracking | Manually instantiate target types |
| **Exceptions** | No CFGEdge for throw/catch — reaching defs incomplete | Treat as C (misses exception paths) |
| **RAII / Destructors** | Implicit `free()`/`fclose()` in destructors invisible | Manually add DangerousSink for RAII wrappers |
| **Operator overloading** | `operator[]` is a Call, not MemWrite — buffer semantics lost | N/A |
| **Lambdas** | Capture semantics not modeled; closure taint lost | Extract lambda body as separate function |
| **Move semantics** | `std::move()` ownership transfer not tracked | N/A |
| **STL containers** | `std::string`, `std::vector` — no library-specific taint models | Add signatures.dl entries for STL |

See [`docs/datalog_arch_design.md` § TODO](docs/datalog_arch_design.md#10-todo--future-work) for the full roadmap.

### Analysis Limitations

- **No path sensitivity**: Both feasible and infeasible paths are analyzed (same as Joern). Taint paths in "fixed" code are still flagged.
- **Intraprocedural UAF only**: Use-after-free and double-free are detected within a single function. Interprocedural UAF (freed in callee, used in caller) is planned.
- **1-CFA context depth**: Deeply nested call chains (>1 indirect) lose precision. Upgrading to 2-CFA or object-sensitive analysis would help.
- **No whole-program analysis**: Backward slicing limits scope — taint entering through non-sliced functions is missed.
- **No incremental analysis**: Every run re-extracts and re-analyzes all functions.

## Authors

- **Sanjay Rawat**
- **Claude Code** (Opus 4.6) — Anthropic

## License

This project is licensed under the [Polyform Noncommercial 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0/) license. Free for research, education, and personal use. Commercial use requires a separate license.

## References

- [Souffle Datalog](https://souffle-lang.github.io/) — The Datalog engine used for analysis
- [DOOP](https://bitbucket.org/yanniss/doop/) — Points-to analysis for Java via Datalog (Smaragdakis & Balatsouras, 2015)
- [CodeQL](https://codeql.github.com/) — GitHub's semantic code analysis engine
- [Joern](https://joern.io/) — Code Property Graph analysis platform
- [bddbddb](http://bddbddb.sourceforge.net/) — BDD-based Datalog for program analysis (Whaley & Lam, 2004)
- [Datalog Disassembly](https://arxiv.org/abs/1906.03969) — GrammaTech's Datalog-based binary analysis (Flores-Montoya & Schulte, 2020)
- [tree-sitter](https://tree-sitter.github.io/) — Incremental parsing library

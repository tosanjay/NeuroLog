"""
Crash-input synthesizer.

Given a Phase-B-feasible finding (function, addr, var, kind) plus the
backing facts/output dirs, build a synthesis context: the def-use chain
back to taint-source byte readers, the Z3 SAT model, the source
snippet, and a file-format hint. Use the context to prompt a frontier
LLM for N candidate Python emitters, each producing a binary blob
intended to drive the program to the bug site.

Multi-shot: the orchestration loop in crash_synth_agent.py validates
each candidate against an ASan-built harness. On no-crash / wrong-bug
verdict, the loop loops with a refinement prompt that includes the
prior attempt(s) and what went wrong.
"""
from __future__ import annotations

import json
import os
import re
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from symbex_config import SymbexConfig
from symbex_encoder import FactStore, Finding, FunctionEncoder


# ── Context dataclass ───────────────────────────────────────────────────────

@dataclass
class TaintSourcePoint:
    """A single byte-reader call in the chain leading to the bug var."""
    func: str
    callee: str          # e.g. "avio_rb24" / "fread" / "get_bits"
    addr: int            # source line of the call
    bound_to: str        # variable that received the read

    def __str__(self) -> str:
        return f"{self.func}:{self.addr} {self.bound_to} = {self.callee}(...)"


@dataclass
class ChainStep:
    """One link in the def-use trace from taint-source → bug variable."""
    addr: int
    var: str
    op: str              # "def" | "arith:add" | "cast:truncate" | "call:foo" | ...
    detail: str = ""     # human-readable extra (e.g. "x = x + 1")


@dataclass
class SynthesisContext:
    finding: Finding
    z3_model: dict[str, int] = field(default_factory=dict)
    chain: list[ChainStep] = field(default_factory=list)
    taint_sources: list[TaintSourcePoint] = field(default_factory=list)
    source_snippet: str = ""              # function body around the bug site
    callee_sources: dict[str, str] = field(default_factory=dict)
    format_hint: str = "unknown"          # "vorbis" / "matroska" / "mp4" / ...
    bug_summary: str = ""                 # one-line description of the bug
    # Phase C extension — known-good scaffold to mutate (rather than
    # synthesize from scratch). When set, the prompt instructs the LLM
    # to keep this scaffold's structure intact and only mutate the
    # bug-relevant field(s). Mirrors COTTONTAIL's history-guided seed.
    scaffold_bytes: bytes = b""
    scaffold_path: str = ""               # provenance only (informational)

    def render_for_prompt(self) -> str:
        """Compact textual summary for the LLM prompt."""
        parts: list[str] = []
        parts.append(f"Bug class: {self.finding.kind}")
        parts.append(f"Site:      {self.finding.func}:{self.finding.addr}")
        parts.append(f"Trigger:   variable `{self.finding.var}` must satisfy "
                      f"the bug condition for `{self.finding.kind}`")
        if self.bug_summary:
            parts.append(f"Summary:   {self.bug_summary}")
        if self.z3_model:
            parts.append("\nZ3 SAT model (concrete values that satisfy the bug):")
            for name, val in sorted(self.z3_model.items()):
                # Big numbers also as hex.
                parts.append(f"  {name} = {val} (0x{val:x})")
        if self.taint_sources:
            parts.append("\nTaint-source byte reads on the def-use path "
                          "(file-bytes → variables):")
            for ts in self.taint_sources:
                parts.append(f"  {ts}")
        if self.chain:
            parts.append("\nDef-use chain from taint to bug site "
                          "(latest first):")
            for s in self.chain[:30]:
                d = f" — {s.detail}" if s.detail else ""
                parts.append(f"  L{s.addr}  {s.var}  [{s.op}]{d}")
        parts.append(f"\nFile-format hint: {self.format_hint}")
        if self.source_snippet:
            parts.append("\nSource (function around the bug site):")
            parts.append("```c")
            parts.append(self.source_snippet)
            parts.append("```")
        return "\n".join(parts)


# ── Format hint heuristics ─────────────────────────────────────────────────

_FORMAT_HINTS = [
    (re.compile(r"stb_vorbis|vorbis_decode|comment_list_length|setup_malloc"),
     "ogg-vorbis"),
    (re.compile(r"matroska|ebml|mka_|mkv_"),                  "matroska/ebml"),
    (re.compile(r"\bmov[_ ]|isom|mp4|qt_|stsd|moov|mdat|trak"), "mp4/mov"),
    (re.compile(r"avi_|riff"),                                "avi/riff"),
    (re.compile(r"mpegts|ff_mpegts|tspacket"),                "mpeg-ts"),
    # WebP/VP8L MUST come before jpeg/jfif — libwebp's BuildHuffmanTable
    # matches "huffman" lexically but is VP8L territory, not JPEG.
    (re.compile(r"webp|vp8l|vp8_|webpdecod|webppic"),         "webp/vp8l"),
    (re.compile(r"jpeg|jfif|\bsof\b|\bsos\b"),                "jpeg/jfif"),
    (re.compile(r"png_|stbi__png"),                           "png"),
    (re.compile(r"json|cJSON"),                               "json"),
    (re.compile(r"xml|libxml"),                               "xml"),
    (re.compile(r"webvtt|webrtc|cluster"),                    "webvtt-in-mkv"),
]


_SOURCE_FORMAT_HINTS = [
    (re.compile(r"OggS|stb_vorbis|vorbis_validate|VORBIS_packet|comment_list_length",
                re.IGNORECASE), "ogg-vorbis"),
    (re.compile(r"\bEBML\b|matroska|mka_|mkv_|track_number|cluster"), "matroska/ebml"),
    (re.compile(r"\bftyp\b|\bmoov\b|\bmdat\b|\btrak\b|stsd|isom"), "mp4/mov"),
    # libwebp uses RIFF too. Match WebP-specific markers BEFORE the
    # generic RIFF rule and BEFORE the jpeg/huffman rule (libwebp's
    # huffman_utils.c body contains the word "huffman" but the format
    # is VP8L, not JPEG).
    (re.compile(r"\bVP8L?\b|\bWEBP\b|VP8LDec|VP8LBuildHuffmanTable|WebPDecode"),
     "webp/vp8l"),
    (re.compile(r"\bRIFF\b|\bAVI \b|riff_tag"), "avi/riff"),
    (re.compile(r"mpegts|0x47\s*\)?\s*[/]+.*sync", re.IGNORECASE), "mpeg-ts"),
    (re.compile(r"0xFFD8|JFIF|sof_baseline", re.IGNORECASE), "jpeg/jfif"),
    (re.compile(r"\bIHDR\b|\bIDAT\b|\bIEND\b"), "png"),
]


def detect_format(func_name: str, source_snippet: str = "") -> str:
    fname = func_name.lower()
    for rx, name in _FORMAT_HINTS:
        if rx.search(fname):
            return name
    # Look at the source body too — many parser functions have generic
    # names (start_decoder, parse_packet) but the body has format magic.
    body = source_snippet[:4000]
    for rx, name in _SOURCE_FORMAT_HINTS:
        if rx.search(body):
            return name
    return "unknown-binary"


# ── Z3 model + chain extraction ─────────────────────────────────────────────

def _read_phase_b_model(eval_dir: Path, finding: Finding) -> dict[str, int]:
    """Pull a fresh Z3 model for this finding by re-running the encoder.
    Phase B (with summaries.json) — we want the model that actually
    constrains the inputs, not Phase A's looser one."""
    cfg = SymbexConfig.from_env()
    store = FactStore.load(eval_dir / "facts")
    enc = FunctionEncoder(store, finding, cfg)
    res = enc.check()
    model: dict[str, int] = {}
    if res.verdict != "feasible" or not res.model_str:
        return model
    for chunk in res.model_str.split(";"):
        chunk = chunk.strip()
        if "=" not in chunk:
            continue
        name, val = chunk.split("=", 1)
        try:
            model[name.strip()] = int(val.strip())
        except ValueError:
            try:
                model[name.strip()] = int(val.strip(), 16)
            except ValueError:
                continue
    return model


def _walk_chain(store: FactStore, finding: Finding,
                 max_steps: int = 30) -> tuple[list[ChainStep],
                                                list[TaintSourcePoint]]:
    """BFS backward from finding.var@finding.addr along Def/ArithOp/Cast/Call.
    Also follows plain assignments (no ArithOp/Cast/Call at the def line)
    by walking same-line Use edges — captures `x = y;` propagation."""
    func = finding.func
    chain: list[ChainStep] = []
    taint_sources_set: set[tuple[str, str, int, str]] = set()
    visited: set[tuple[str, int]] = set()
    queue: list[tuple[str, int]] = [(finding.var, finding.addr)]

    arith = store.arith.get(func, [])
    casts = store.casts.get(func, [])
    calls = store.calls.get(func, [])
    actualarg = store.actualarg.get(func, [])
    defs = store.defs.get(func, [])
    fieldread = store.fieldread.get(func, [])
    # Index Uses by addr so the plain-assignment fallback is O(1).
    uses_by_addr: dict[int, list[str]] = {}
    for (v, _ver, addr) in store.uses.get(func, []):
        uses_by_addr.setdefault(addr, []).append(v)

    while queue and len(chain) < max_steps:
        var, use_addr = queue.pop(0)
        if (var, use_addr) in visited:
            continue
        visited.add((var, use_addr))

        # Latest def of var at or before use_addr.
        cands = [a for (v, _, a) in defs if v == var and a <= use_addr]
        if not cands:
            chain.append(ChainStep(use_addr, var, "free",
                                    "no def in this function (param/global)"))
            continue
        def_addr = max(cands)

        # ArithOp?
        for (a, dst, _, op, src, _, operand) in arith:
            if a == def_addr and dst == var:
                chain.append(ChainStep(a, var, f"arith:{op}",
                                        f"{var} = {src} {op} {operand}"))
                queue.append((src, a))
                continue
        # Cast?
        for (a, dst, _, src, _, kind, sw, dw, st, dt) in casts:
            if a == def_addr and dst == var:
                chain.append(ChainStep(
                    a, var, f"cast:{kind}",
                    f"{var} = ({dt}){src}  // {sw}-byte → {dw}-byte"))
                queue.append((src, a))
                continue
        # Call return?
        for (callee, ca) in calls:
            if ca == def_addr:
                if callee in store.taint_sources:
                    taint_sources_set.add((func, callee, ca, var))
                    chain.append(ChainStep(
                        ca, var, f"call:{callee}",
                        f"{var} = {callee}(...)  // taint source"))
                else:
                    chain.append(ChainStep(
                        ca, var, f"call:{callee}",
                        f"{var} = {callee}(...)"))
                # Walk into actuals if this is a known taint source.
                for (act_ca, idx, _p, av, _v) in actualarg:
                    if act_ca == ca:
                        queue.append((av, ca))
                break
        # FieldRead?
        had_fieldread = False
        for (a, base, fld) in fieldread:
            if a == def_addr:
                chain.append(ChainStep(a, var, "fieldread",
                                        f"{var} = {base}->{fld}"))
                queue.append((base, a))
                had_fieldread = True
                break

        # Plain assignment fallback: if no ArithOp/Cast/Call/FieldRead
        # was found at this Def addr, treat any Use(s) at the same line
        # as the source(s) of the assignment. Captures `x = y;` and
        # similar propagations the structural-fact extractors don't tag.
        if not (any(a == def_addr and dst == var
                     for (a, dst, *_) in arith) or
                any(a == def_addr and dst == var
                     for (a, dst, *_) in casts) or
                any(ca == def_addr for (_, ca) in calls) or had_fieldread):
            for u in uses_by_addr.get(def_addr, []):
                if u != var:
                    chain.append(ChainStep(def_addr, var, "assign",
                                            f"{var} = {u}"))
                    queue.append((u, def_addr))
                    break  # only follow one source per assignment

    taint_sources = [TaintSourcePoint(*t) for t in sorted(taint_sources_set)]
    return chain, taint_sources


def _read_function_source(src_root: Path, func: str,
                            file_hint: Optional[str] = None) -> str:
    """Best-effort grep for the function definition. Falls back to empty
    if we can't locate the source. We return up to ~200 lines around the
    function header."""
    if file_hint:
        candidate = src_root / file_hint
        if candidate.exists():
            return _grep_function(candidate, func)
    # Fallback: scan a few common locations.
    import subprocess
    try:
        out = subprocess.run(
            ["grep", "-rln", f"^[a-zA-Z_*][^=;]*{func}\\s*(", str(src_root)],
            capture_output=True, timeout=20).stdout.decode()
        for line in out.splitlines()[:5]:
            p = Path(line.strip())
            if p.is_file():
                snippet = _grep_function(p, func)
                if snippet:
                    return snippet
    except Exception:
        pass
    return ""


def _grep_function(path: Path, func: str, max_lines: int = 200) -> str:
    text = path.read_text(errors="replace").splitlines()
    rx = re.compile(rf"^\s*[\w*\s]+\b{re.escape(func)}\s*\(")
    for i, line in enumerate(text):
        if rx.match(line):
            return "\n".join(text[i:i + max_lines])
    return ""


# ── Public API ─────────────────────────────────────────────────────────────

def build_context(eval_dir: str | Path, finding: Finding,
                    src_root: Optional[str | Path] = None,
                    file_hint: Optional[str] = None,
                    scaffold_path: Optional[str | Path] = None,
                    format_override: Optional[str] = None,
                    ) -> SynthesisContext:
    eval_path = Path(eval_dir)
    store = FactStore.load(eval_path / "facts")
    chain, taint_sources = _walk_chain(store, finding)
    model = _read_phase_b_model(eval_path, finding)

    snippet = ""
    if src_root:
        snippet = _read_function_source(Path(src_root), finding.func,
                                          file_hint=file_hint)

    fmt = format_override if format_override else detect_format(finding.func, snippet)
    summary = _bug_summary(finding)

    scaffold_bytes = b""
    scaffold_str = ""
    if scaffold_path:
        sp = Path(scaffold_path)
        if sp.exists():
            scaffold_bytes = sp.read_bytes()
            scaffold_str = str(sp)

    return SynthesisContext(
        finding=finding, z3_model=model, chain=chain,
        taint_sources=taint_sources, source_snippet=snippet,
        format_hint=fmt, bug_summary=summary,
        scaffold_bytes=scaffold_bytes, scaffold_path=scaffold_str,
    )


_BUG_SUMMARIES = {
    "narrow_arith_at_sink":
        "Signed-narrow value (e.g. int) reaches a size argument of a "
        "memory sink (memcpy/memset/malloc-family). If negative, the "
        "size is reinterpreted as a huge size_t.",
    "signed_arg_at_sink":
        "Signed integer argument flows into a sink expecting a size; "
        "negative values cause unintended large allocations or copies.",
    "truncation_cast":
        "Wider type is implicitly truncated to a narrower type without "
        "a cast or bounds check; the truncated value loses high bits.",
    "unbounded_counter_at_sink":
        "Counter incremented in a loop without an upper-bound guard; "
        "reaches a sink (often used as an index, size, or allocation).",
    "potential_arith_overflow":
        "Signed arithmetic on ≤32-bit operands without an overflow "
        "guard before reaching a memory sink.",
    "sentinel_collision":
        "Counter reaches the sentinel value used to initialize a buffer "
        "(typically via memset(-1)), making invalid entries look valid.",
    "unguarded_dangerous_cast":
        "Cast that reinterprets sign or width without any precondition.",
}


def _bug_summary(finding: Finding) -> str:
    return _BUG_SUMMARIES.get(finding.kind, finding.kind)


# ── Prompt builder ─────────────────────────────────────────────────────────

SYSTEM_PROMPT = textwrap.dedent("""
You are a security researcher generating a *crash-input* for an
ASan-instrumented C parser. You will be given the result of a static
analysis pipeline that has identified a feasible bug site, the SMT
solver's concrete witness values, the def-use chain from byte-readers
to the bug variable, and a snippet of the affected source.

Your task:
1. Reason about how to lay out the input bytes so that the parser walks
   the path the static analysis flagged AND the bug-trigger value (or a
   value that satisfies the bug condition) ends up in the trigger var.
2. Produce N=5 *distinct* candidate inputs, each as a self-contained
   Python script. Each script, when run, must write ONE byte sequence
   to stdout (use sys.stdout.buffer.write). DO NOT print to stdout
   anything else. Use struct.pack / bytes literals — be precise about
   endianness and sizes.
3. The candidates should explore different hypotheses about how to
   reach the bug condition (different field-value mixes, different
   parser-state setups). Don't emit five trivially-similar variants.

Output strictly the following JSON block (no prose outside it):

{
  "candidates": [
    {
      "rationale": "<one short sentence on what byte-sequence hypothesis this represents>",
      "python_emitter": "<a complete python3 script>"
    },
    ...
  ]
}

Constraints:
- Each python_emitter must be runnable as `python3 -c "<script>" > out.bin`.
- Do not call subprocess, network, or any IO besides sys.stdout.buffer.write.
- Each candidate must produce a non-empty blob.
- Stay under ~16KB per blob unless the format obviously needs more.
""").strip()


def _hex_view(blob: bytes, max_bytes: int = 1024) -> str:
    """Compact hex+ASCII dump (xxd-style) for the LLM. Truncates with a
    marker if blob exceeds max_bytes."""
    truncated = len(blob) > max_bytes
    show = blob[:max_bytes]
    lines = []
    for i in range(0, len(show), 16):
        chunk = show[i:i + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:08x}  {hexpart:<47}  |{ascii_part}|")
    if truncated:
        lines.append(f"... ({len(blob) - max_bytes} more bytes)")
    return "\n".join(lines)


_BUG_CONDITION_SPECS = {
    "narrow_arith_at_sink":
        "the trigger variable, interpreted as a SIGNED int, must be "
        "negative (i.e. high bit set). When passed to a sink expecting "
        "size_t, the kernel sees a huge unsigned value and ASan reports "
        "`allocation-size-too-big` or `heap-buffer-overflow`.",
    "signed_arg_at_sink":
        "the trigger variable, a signed integer, must reach a sink as "
        "a negative value (size argument reinterpreted as huge size_t).",
    "truncation_cast":
        "the trigger value's high bits, when truncated by an implicit "
        "narrowing cast, must differ from the full value — i.e., the "
        "value exceeds the range of the narrow type.",
    "unbounded_counter_at_sink":
        "the trigger counter must reach a sentinel-collision value "
        "(typically ≥ 2^16 = 65535, where memset(-1)-initialized "
        "16-bit slots collide with valid indices).",
    "potential_arith_overflow":
        "the trigger arithmetic (signed +/-/*) must produce a result "
        "whose signed bit changes — i.e. signed-wrap occurs.",
    "sentinel_collision":
        "the trigger value must equal a memset-fill sentinel (often "
        "0xFFFF or 0xFFFFFFFF).",
    "unguarded_dangerous_cast":
        "the cast source value must lie outside the destination type's "
        "range so the cast either truncates or sign-flips.",
}


def build_synthesis_prompt(ctx: SynthesisContext,
                           prior_attempts: Optional[list[dict]] = None,
                           n_candidates: int = 5) -> str:
    parts: list[str] = []

    # Phase C extension — when a scaffold is provided, lead with it.
    # Otherwise the LLM gets attention-drained by the static-analysis
    # evidence and ignores the scaffold at the bottom.
    if ctx.scaffold_bytes:
        parts.append("## YOUR PRIMARY TASK: mutate this scaffold "
                      "(don't regenerate)")
        parts.append("")
        parts.append(
            f"You have a {len(ctx.scaffold_bytes)}-byte known-good "
            f"{ctx.format_hint} input that already drives the parser "
            "to the bug site without crashing. Your job is to **mutate "
            "specific bytes** so the trigger value satisfies the bug "
            "condition.")
        parts.append("")
        parts.append("**Use this exact Python template** for each "
                      "candidate's `python_emitter`:")
        parts.append("")
        parts.append("```python")
        parts.append("import sys")
        parts.append(f"SCAFFOLD = bytes.fromhex(")
        # Split the hex into 16-byte chunks for readability.
        hex_str = ctx.scaffold_bytes.hex()
        for i in range(0, len(hex_str), 64):
            parts.append(f"    \"{hex_str[i:i+64]}\"")
        parts.append(")")
        parts.append("buf = bytearray(SCAFFOLD)")
        parts.append("# YOUR MUTATIONS HERE — typical patterns:")
        parts.append("#   buf[OFFSET] = 0xFF                        "
                      "# single-byte tweak")
        parts.append("#   buf[A:B] = bytes([0xff]*(B-A))            "
                      "# fill a span")
        parts.append("#   buf = buf[:A] + new_bytes + buf[B:]       "
                      "# replace span")
        parts.append("#   # if you grow/shrink any element, also UPDATE")
        parts.append("#   # the parent container's length VINT.")
        parts.append("sys.stdout.buffer.write(bytes(buf))")
        parts.append("```")
        parts.append("")
        parts.append("Hex view of the scaffold (offsets shown for "
                      "mutation targeting):")
        parts.append("```")
        parts.append(_hex_view(ctx.scaffold_bytes))
        parts.append("```")
        parts.append("")
        parts.append("**Diversify across candidates**: try mutating "
                      "different fields. Common high-value targets in "
                      "container formats: payload-size VINTs, the "
                      "byte right before a length-prefixed element, "
                      "the trigger field itself.")
        parts.append("")

    # Bug-condition spec (V_c, the user's terminology).
    bc_spec = _BUG_CONDITION_SPECS.get(ctx.finding.kind)
    if bc_spec:
        parts.append("## Target bug condition (V_c)")
        parts.append("")
        parts.append(bc_spec)
        parts.append("")

    parts.append("## Static-analysis evidence")
    parts.append("")
    parts.append(ctx.render_for_prompt())
    parts.append("")
    parts.append(f"## Generate {n_candidates} candidate crash inputs")
    if prior_attempts:
        # Surface the "unmutated scaffold" signal aggressively if any
        # prior attempt returned the seed bytes verbatim. This is a
        # known LLM-emitter failure mode (rationale-vs-mutation gap):
        # the model articulates the right mutation in prose but its
        # generated Python just `sys.stdout.buffer.write(scaffold)`s
        # without applying any of the mutations described.
        n_unmutated = sum(1 for a in prior_attempts
                          if a.get("verdict", {}).get("unmutated"))
        if n_unmutated:
            parts.append(
                f"\n## ⚠ CRITICAL: {n_unmutated} prior attempt(s) returned "
                f"the SCAFFOLD BYTES UNCHANGED.\n\n"
                f"Your Python `emit()` produced output BYTE-IDENTICAL to "
                f"the {len(ctx.scaffold_bytes)}-byte input scaffold. The "
                f"scaffold is a *known-good* seed — by definition it does "
                f"NOT crash the harness. If your emitter returns it "
                f"verbatim, you are guaranteed to produce a no-crash "
                f"verdict.\n\n"
                f"You MUST mutate. Concretely, your emitter must:\n"
                f"  1. Load the scaffold into a `bytearray` (mutable).\n"
                f"  2. Modify byte(s) at the offset(s) you identified "
                f"in your rationale — overwrite specific fields with "
                f"the operand-extreme values your Datalog evidence "
                f"says will trigger the bug (e.g., zero out a length, "
                f"set a count field to UINT32_MAX, flip a Huffman "
                f"code-length to be unbalanced).\n"
                f"  3. Write the *mutated* bytes — never `sys.stdout."
                f"buffer.write(scaffold)` without first calling "
                f"`buf[offset] = ...` or `buf.extend(...)` somewhere.\n\n"
                f"Self-check before emitting: 'Does my Python actually "
                f"call a write/assign on the bytearray, or am I just "
                f"echoing the input?' If you only echo, you have failed "
                f"the task. Emit different bytes this round."
            )
        # Phase E3 — rank prior attempts by parser-progress score, so
        # the LLM is shown the candidate that walked deepest into the
        # parser FIRST. This is a "failure predictor" hint a la Gist
        # SOSP'15 §3.3 (failing-vs-passing diff): the deepest no-crash
        # got farthest along the path that should crash; it's the
        # closest non-trivial mutation target.
        ranked = sorted(prior_attempts,
                          key=lambda a: -int(a.get("verdict", {}).get(
                              "parser_progress", 0)))
        best = ranked[:3]
        parts.append("\n## Prior attempts ranked by parser progress "
                       "(deepest first)")
        if any(int(a.get("verdict", {}).get("parser_progress", 0)) > 0
                 for a in best):
            parts.append(
                "\nThe candidate that walked deepest into the parser is "
                "your best mutation target — its byte structure is the "
                "closest to a real crash-triggering shape we have. "
                "Mutate near its trigger field first; only restructure "
                "the header bytes when shallower attempts suggest the "
                "parser bailed at a magic / VINT / length check.")
        for i, a in enumerate(best, 1):
            verdict = a.get("verdict", {})
            progress = int(verdict.get("parser_progress", 0))
            frames = verdict.get("parser_frames", []) or []
            parts.append(f"\n### Attempt rank #{i}  (parser_progress={progress}"
                          f", crashed={verdict.get('crashed')})")
            parts.append(f"Rationale: {a.get('rationale', '')}")
            parts.append(f"Top frame: {verdict.get('top_frame_func')} "
                          f"@ L{verdict.get('top_frame_line')}")
            if frames:
                parts.append(f"Parser path (first 8 distinct frames): "
                              f"{frames[:8]}")
            tail = verdict.get("stderr_tail") or ""
            if tail:
                parts.append("Stderr tail (last ~768 B):")
                parts.append("```")
                parts.append(tail[-768:])
                parts.append("```")
        parts.append(
            "\nUse this feedback to *change strategy*, not to repeat. "
            "If even the deepest attempt only saw <3 frames, the parser "
            "is rejecting at a header check — fix that first. If the "
            "deepest got many frames but no crash, vary the trigger "
            "value or the field that gates the bug-class condition.")
    parts.append("\nReturn the JSON block now.")
    return "\n".join(parts)

"""
Crash validator — runs an LLM-synthesized binary input against an
ASan-built harness and reports whether it crashed at the predicted bug
class / site.

The harness is any executable that takes a single positional file
argument (libFuzzer single-shot mode, custom CLI, ffmpeg -i, etc.) and
exits non-zero on ASan abort. We don't assume libFuzzer-specific
behaviour — just exit code and stderr.

ASan signatures we recognize:
  - "allocation-size-too-big"      — int-truncation / overflow → alloc
  - "heap-buffer-overflow"
  - "stack-buffer-overflow"
  - "global-buffer-overflow"
  - "use-after-free"
  - "double-free"
  - "stack-overflow"
  - "SEGV on unknown address"
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


_ASAN_BUG_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("allocation_size_too_big",
     re.compile(r"allocation-size-too-big|requested allocation size .+ exceeds maximum")),
    ("heap_buffer_overflow",  re.compile(r"heap-buffer-overflow")),
    ("heap_use_after_free",   re.compile(r"heap-use-after-free|use-after-free")),
    ("double_free",           re.compile(r"double-free|attempting double-free")),
    ("stack_buffer_overflow", re.compile(r"stack-buffer-overflow")),
    ("global_buffer_overflow",re.compile(r"global-buffer-overflow")),
    ("stack_overflow",        re.compile(r"stack-overflow")),
    ("segv",                  re.compile(r"SEGV on unknown address|signal 11")),
    ("ubsan_int_overflow",    re.compile(r"signed integer overflow|unsigned integer overflow")),
    ("ubsan_misaligned",      re.compile(r"runtime error: load of misaligned address")),
]

# Two frame formats:
#   #1 0x... in func file.c:line:col
#   #1 0x... in func file.c:line
_FRAME_RE = re.compile(
    r"^\s*#\d+\s+0x[0-9a-f]+\s+in\s+(\S+)\s+([^\s:]+):(\d+)(?::\d+)?",
    re.MULTILINE)


@dataclass
class ValidationResult:
    crashed: bool
    bug_class: Optional[str] = None         # one of the keys above, or None
    top_frame_func: Optional[str] = None    # "start_decoder"
    top_frame_file: Optional[str] = None    # "stb_vorbis.c"
    top_frame_line: Optional[int] = None    # 3664
    exit_code: int = 0
    stderr_tail: str = ""                   # last ~4KB of stderr for prompt feedback
    stdout_tail: str = ""
    # Phase E3 — parser-progress score: number of distinct user-frame
    # functions seen in ASan trace OR (when no ASan output) heuristic
    # over libFuzzer's "Running %s" output. Higher = the candidate
    # blob walked deeper into the parser.
    parser_progress: int = 0
    parser_frames: list[str] = field(default_factory=list)

    def matches(self, want_bug_class: Optional[str],
                 want_func: Optional[str] = None,
                 want_line: Optional[int] = None) -> bool:
        """Did the crash hit the predicted bug class + site?"""
        if not self.crashed:
            return False
        if want_bug_class and self.bug_class != want_bug_class:
            return False
        if want_func and self.top_frame_func != want_func:
            return False
        if want_line is not None and self.top_frame_line != want_line:
            return False
        return True


_RUNTIME_SUBSTR_SKIPS = (
    "asan_malloc", "asan_free", "fuzzer::", "compiler-rt",
    "__interceptor_", "__sanitizer_", "__libc_",
    "__GI_", "ubsan_", "lsan_",
)
_RUNTIME_EXACT_SKIPS = {
    "main", "_start",
    "malloc", "free", "calloc", "realloc",
    "memcpy", "memmove", "memset", "memcmp",
    "strcpy", "strncpy", "strlen", "strcmp", "strcat",
    "abort", "raise", "exit", "_exit", "__cxa_throw",
    "LLVMFuzzerTestOneInput", "LLVMFuzzerInitialize",
}


def parser_progress_score(stderr: str) -> tuple[int, list[str]]:
    """Phase E3 — return (n_distinct_user_frames, frame_funcs).

    Counts frame functions skipping runtime/sanitizer/harness frames.
    Higher score ⇒ the input walked deeper into the actual parser,
    suggesting structural validity is closer to a real crash-triggering
    shape. Returns (0, []) when there's no symbolised trace."""
    seen: list[str] = []
    distinct: set[str] = set()
    for m in _FRAME_RE.finditer(stderr):
        func = m.group(1)
        if func in _RUNTIME_EXACT_SKIPS:
            continue
        if any(s in func for s in _RUNTIME_SUBSTR_SKIPS):
            continue
        if func in distinct:
            continue
        distinct.add(func)
        seen.append(func)
    return len(seen), seen


def parse_asan_output(stderr: str) -> tuple[Optional[str], Optional[str],
                                              Optional[str], Optional[int]]:
    """Returns (bug_class, top_frame_func, top_frame_file, top_frame_line)."""
    bug_class = None
    for kind, rx in _ASAN_BUG_PATTERNS:
        if rx.search(stderr):
            bug_class = kind
            break

    top_func = top_file = None
    top_line: Optional[int] = None
    # Walk frame by frame; pick the FIRST non-runtime frame
    # (skip asan_malloc_linux, fuzzer::Fuzzer::, libc_start_call_main, etc.)
    runtime_skips = ("asan_malloc", "asan_free", "fuzzer::", "compiler-rt",
                     "__interceptor_", "__sanitizer_", "__libc_", "main")
    for m in _FRAME_RE.finditer(stderr):
        func, fname, line = m.group(1), m.group(2), int(m.group(3))
        if any(s in func for s in runtime_skips):
            continue
        if "compiler-rt" in fname or "/sysdeps/" in fname:
            continue
        top_func, top_file, top_line = func, fname, line
        break
    return bug_class, top_func, top_file, top_line


def run_harness(blob: bytes, harness_cmd: list[str], timeout_s: float = 10.0,
                 use_libfuzzer_mode: bool = False) -> ValidationResult:
    """Write `blob` to a temp file and run `harness_cmd <tempfile>`.

    `harness_cmd` is a list whose final argument will be the path to the
    blob file. If the harness is libFuzzer-built, set
    use_libfuzzer_mode=True and we'll invoke it as
    `<harness> <tempfile>` which puts libFuzzer into single-shot mode.
    """
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as fp:
        fp.write(blob)
        blob_path = Path(fp.name)
    try:
        cmd = list(harness_cmd) + [str(blob_path)]
        # Inherit the parent env so llvm-symbolizer is on PATH and
        # libraries resolve. We only override ASAN_OPTIONS so that a
        # non-zero exit (rather than abort signal) lands in `returncode`.
        env = os.environ.copy()
        env["ASAN_OPTIONS"] = (env.get("ASAN_OPTIONS", "")
            + ":abort_on_error=0:exitcode=77:detect_leaks=0").lstrip(":")
        # If llvm-symbolizer isn't on PATH, hint ASan at a common location.
        if not shutil.which("llvm-symbolizer") and not env.get("ASAN_SYMBOLIZER_PATH"):
            for candidate in ("/usr/bin/llvm-symbolizer",
                              "/usr/local/bin/llvm-symbolizer"):
                if Path(candidate).exists():
                    env["ASAN_SYMBOLIZER_PATH"] = candidate
                    break
        try:
            p = subprocess.run(cmd, capture_output=True, timeout=timeout_s,
                                env=env)
        except subprocess.TimeoutExpired as e:
            return ValidationResult(
                crashed=False, exit_code=-9,
                stderr_tail=(e.stderr or b"").decode("latin1", "replace")[-4096:])
        stderr_full = p.stderr.decode("latin1", "replace")
        stdout_full = p.stdout.decode("latin1", "replace")
        bug_class, func, fname, line = parse_asan_output(stderr_full)
        progress, frames = parser_progress_score(stderr_full)
        crashed = bug_class is not None or p.returncode in (77, -6, -11, 134)
        return ValidationResult(
            crashed=crashed, bug_class=bug_class,
            top_frame_func=func, top_frame_file=fname, top_frame_line=line,
            exit_code=p.returncode,
            stderr_tail=stderr_full[-4096:],
            stdout_tail=stdout_full[-1024:],
            parser_progress=progress,
            parser_frames=frames,
        )
    finally:
        try:
            blob_path.unlink()
        except OSError:
            pass


# ── CLI ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python crash_validator.py <blob_or_-> <harness> [args...]")
        print("If blob is '-', reads stdin.")
        sys.exit(1)
    blob_arg = sys.argv[1]
    blob = (sys.stdin.buffer.read() if blob_arg == "-"
            else Path(blob_arg).read_bytes())
    harness = sys.argv[2:]
    r = run_harness(blob, harness)
    print(f"crashed     : {r.crashed}")
    print(f"bug_class   : {r.bug_class}")
    print(f"top_frame   : {r.top_frame_func} @ {r.top_frame_file}:{r.top_frame_line}")
    print(f"exit_code   : {r.exit_code}")
    print(f"stderr_tail :")
    print(r.stderr_tail[-1500:])

"""Per-scan audit log — one line per pipeline step.

Design goals:

  * Opt-in. The pipeline only writes to the audit log when the env
    var `NEUROLOG_AUDIT_LOG` is set to a path. Default: silent.
    This keeps interactive ADK sessions (where the line-noise would
    be unhelpful) clean by default.

  * Single source of truth. Every component that performs a
    user-visible step (mech extract per file, smell pass per
    function, souffle per output relation, agent ad-hoc query,
    symbex finding-batch, Phase C candidate emission, etc.) calls
    `log_step(...)` here. The line format is fixed; downstream
    tools can parse it.

  * Cheap. One file open per step, one line append, no flushing
    semantics beyond what `open(...,'a')` gives.

  * Threadsafe. Wraps the append in a module-level lock so
    parallel callers (smell pass at 15-way concurrency, symbex
    Phase D at N-way process pool) do not interleave bytes inside
    a single line.

Line format (tab-separated):

    <ISO-8601 UTC timestamp>\\t<phase>\\t<action>\\t<target>\\t<detail>

  phase   — coarse pipeline stage tag, e.g. "phase 1", "phase 6",
            "agent", "symbex_a", "phase_c"
  action  — what was done, e.g. "mech_extract", "smell_call",
            "souffle_pass", "datalog_query", "z3_check",
            "synth_candidate"
  target  — the object the step acted on (a file path, a function
            name, a rule file, a relation name, …)
  detail  — free-text key=value summary, kept short:
            "fns=44 facts=1498", "rows=300 truncated=False",
            "verdict=feasible elapsed=4ms", etc.

Example:

    2026-05-10T08:30:31Z\\tphase 2\\tsmell_call\\ttree.c:xmlBuildQName\\tadded=0 corrected=0 flags=0 elapsed=2.3s
    2026-05-10T08:55:31Z\\tphase 6\\tsouffle_output\\tArithToAllocSinkBridge\\trows=181
    2026-05-10T09:12:08Z\\tagent\\tdatalog_query\\tQNameArith\\tstatus=ok rows=10 elapsed=0.013s

Usage:

    from audit_log import log_step, set_audit_path
    set_audit_path("eval/results/libxml2_full/audit.log")  # optional
    log_step("phase 6", "souffle_output", "TaintedNarrowArith", "rows=0")
"""

from __future__ import annotations

import datetime
import os
import threading
from pathlib import Path
from typing import Optional


_LOCK = threading.Lock()
_DEFAULT_ENV_VAR = "NEUROLOG_AUDIT_LOG"


def _audit_path() -> Optional[Path]:
    """Return the active audit-log path, or None if logging is off."""
    p = os.environ.get(_DEFAULT_ENV_VAR, "").strip()
    return Path(p) if p else None


def set_audit_path(path: str | Path) -> None:
    """Programmatic equivalent of setting `$NEUROLOG_AUDIT_LOG`.

    Useful from runner scripts that want to tie the audit log to a
    per-eval-dir path without polluting the shell environment of
    callers higher up the stack."""
    os.environ[_DEFAULT_ENV_VAR] = str(path)


def clear_audit_path() -> None:
    os.environ.pop(_DEFAULT_ENV_VAR, None)


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _sanitize(s: str) -> str:
    """Strip newlines and tabs from a field so the line format
    remains parseable. Truncate at 240 chars to keep the audit log
    skimmable."""
    if s is None:
        return ""
    s = str(s).replace("\n", " ").replace("\r", " ").replace("\t", " ")
    if len(s) > 240:
        s = s[:237] + "..."
    return s


def log_step(phase: str, action: str, target: str = "",
              detail: str = "") -> None:
    """Append one line to the audit log if active; no-op otherwise.

    Args:
        phase:  coarse pipeline stage tag (e.g. "phase 6", "agent")
        action: short verb describing the step (e.g. "souffle_output",
                "datalog_query")
        target: what the step acted on (function name, file, relation)
        detail: free-text key=value summary; kept short
    """
    p = _audit_path()
    if p is None:
        return
    line = "\t".join((
        _now_iso(),
        _sanitize(phase),
        _sanitize(action),
        _sanitize(target),
        _sanitize(detail),
    )) + "\n"
    with _LOCK:
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            with p.open("a") as fp:
                fp.write(line)
        except OSError:
            # Intentionally swallowed: an audit-log write failure
            # must never break the pipeline. The user can re-enable
            # logging by fixing the path; the run continues.
            pass


def log_header(run_label: str, **kv: str) -> None:
    """Emit a banner line plus key=value metadata at the start of a
    run. Convention: phase="meta", action="run_start"."""
    detail = " ".join(f"{k}={_sanitize(v)}" for k, v in kv.items())
    log_step("meta", "run_start", run_label, detail)


def log_run_end(run_label: str, **kv: str) -> None:
    """Closing banner with summary stats. Pair with log_header."""
    detail = " ".join(f"{k}={_sanitize(v)}" for k, v in kv.items())
    log_step("meta", "run_end", run_label, detail)

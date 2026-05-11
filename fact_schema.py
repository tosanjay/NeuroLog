"""
Fact Schema — Data structures and TSV writer for Datalog facts.

Adapted from bin_datalog's mlil_parser.py (FactKind, Fact) and
fact_writer.py (RELATION_SCHEMA, write_facts). The schema is identical
so that bin_datalog's Souffle rule files work unchanged.

Key difference from bin_datalog: addresses are source line numbers (not
hex instruction addresses), and SSA versions default to 0 (flow-insensitive
MVP).
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class FactKind(Enum):
    DEF = "Def"
    USE = "Use"
    CALL = "Call"
    ACTUAL_ARG = "ActualArg"
    RETURN_VAL = "ReturnVal"
    PHI_SOURCE = "PhiSource"
    MEM_READ = "MemRead"
    MEM_WRITE = "MemWrite"
    ADDRESS_OF = "AddressOf"
    CFG_EDGE = "CFGEdge"
    FIELD_READ = "FieldRead"
    FIELD_WRITE = "FieldWrite"
    JUMP = "Jump"
    FORMAL_PARAM = "FormalParam"
    STACK_VAR = "StackVar"
    GUARD = "Guard"
    ARITH_OP = "ArithOp"
    CAST = "Cast"
    VAR_TYPE = "VarType"
    VAR_WIDTH = "VarWidth"  # legacy alias — maps to VarType
    GUARD_EARLY_RETURN = "GuardEarlyReturn"
    VALIDATING_CAST = "ValidatingCast"


@dataclass
class Fact:
    kind: FactKind
    func: str
    addr: int                           # source line number
    fields: dict = field(default_factory=dict)

    def __repr__(self):
        fstr = ", ".join(f"{k}={v}" for k, v in self.fields.items())
        return f"{self.kind.value}({self.func}, L{self.addr}, {fstr})"


# ── Relation schema: maps FactKind → (filename, column_extractor) ──────────

def _g(f, key, default=""):
    """Get a field value with fallback, converting to string."""
    return str(f.fields.get(key, default))


# Keyed by string (kind.value) to avoid enum identity issues when the
# module is imported under two names (e.g. 'fact_schema' vs
# 'LLM_Datalog_QL.fact_schema' in ADK web mode).
RELATION_SCHEMA = {
    "Def": ("Def.facts", lambda f: (
        f.func, _g(f, "var"), _g(f, "ver", 0), str(f.addr)
    )),
    "Use": ("Use.facts", lambda f: (
        f.func, _g(f, "var"), _g(f, "ver", 0), str(f.addr)
    )),
    "Call": ("Call.facts", lambda f: (
        f.func, _g(f, "callee"), str(f.addr)
    )),
    "ActualArg": ("ActualArg.facts", lambda f: (
        str(f.addr), _g(f, "arg_idx", 0),
        _g(f, "param", "arg0"), _g(f, "var"), _g(f, "ver", 0)
    )),
    "ReturnVal": ("ReturnVal.facts", lambda f: (
        f.func, _g(f, "var"), _g(f, "ver", 0)
    )),
    "PhiSource": ("PhiSource.facts", lambda f: (
        f.func, _g(f, "var"), _g(f, "def_ver", 0),
        _g(f, "src_var"), _g(f, "src_ver", 0)
    )),
    "MemRead": ("MemRead.facts", lambda f: (
        f.func, str(f.addr), _g(f, "base"),
        _g(f, "offset", "0"), _g(f, "size", "?")
    )),
    "MemWrite": ("MemWrite.facts", lambda f: (
        f.func, str(f.addr), _g(f, "target"),
        _g(f, "mem_in", 0), _g(f, "mem_out", 0)
    )),
    "FieldRead": ("FieldRead.facts", lambda f: (
        f.func, str(f.addr), _g(f, "base"), _g(f, "field")
    )),
    "FieldWrite": ("FieldWrite.facts", lambda f: (
        f.func, str(f.addr), _g(f, "base"), _g(f, "field"),
        _g(f, "mem_in", 0), _g(f, "mem_out", 0)
    )),
    "AddressOf": ("AddressOf.facts", lambda f: (
        f.func, _g(f, "var"), _g(f, "ver", 0), _g(f, "target", "anonymous")
    )),
    "CFGEdge": ("CFGEdge.facts", lambda f: (
        f.func, str(f.addr), _g(f, "to_addr", 0)
    )),
    "Jump": ("Jump.facts", lambda f: (
        f.func, str(f.addr), _g(f, "expr")
    )),
    "FormalParam": ("FormalParam.facts", lambda f: (
        f.func, _g(f, "var"), _g(f, "idx", 0)
    )),
    "StackVar": ("StackVar.facts", lambda f: (
        f.func, _g(f, "var"), _g(f, "offset", 0), _g(f, "size", 0)
    )),
    "Guard": ("Guard.facts", lambda f: (
        f.func, str(f.addr), _g(f, "var"), _g(f, "ver", 0),
        _g(f, "op"), _g(f, "bound"),
        _g(f, "bound_type", "unknown")
    )),
    "ArithOp": ("ArithOp.facts", lambda f: (
        f.func, str(f.addr), _g(f, "dst_var"), _g(f, "dst_ver", 0),
        _g(f, "op"), _g(f, "src_var"), _g(f, "src_ver", 0),
        _g(f, "operand")
    )),
    "Cast": ("Cast.facts", lambda f: (
        f.func, str(f.addr), _g(f, "dst"), _g(f, "dst_ver", 0),
        _g(f, "src"), _g(f, "src_ver", 0),
        _g(f, "kind", "unknown"), _g(f, "src_width", 0), _g(f, "dst_width", 0),
        _g(f, "src_type", "unknown"), _g(f, "dst_type", "unknown")
    )),
    "VarType": ("VarType.facts", lambda f: (
        f.func, _g(f, "var"), _g(f, "type_name", "unknown"),
        _g(f, "width", 0), _g(f, "signedness", "unknown")
    )),
    # Marks an `if (cond) { ... return ...; }` whose THEN branch is a
    # function-terminating block (return, goto cleanup, abort). Lets
    # rules credit `if (x >= LIMIT) return ERR` as a real upper bound
    # on x — distinct from `if (x >= LIMIT) av_log(...)` which only logs.
    "GuardEarlyReturn": ("GuardEarlyReturn.facts", lambda f: (
        f.func, str(f.addr)
    )),
    # Marks a cast that *is its own validator*: `if ((narrow_t)x != x)
    # return error;` — the cast at this addr is the bounds check on var.
    # Suppresses UnguardedDangerousCast / TruncationCast on x at this site
    # via the GuardedBeforeCast rule.
    "ValidatingCast": ("ValidatingCast.facts", lambda f: (
        f.func, str(f.addr), _g(f, "var")
    )),
    # `var = kTable[i]` lookup into a module-scope const table.
    # Used by source_interproc.dl::DerivedFromBounded to flag the loaded
    # value as "bounded by the table contents" — useful for filtering
    # FPs where extra_y_rows = kFilterExtraRows[op_code] looks unguarded
    # in the callee but the table only contains small literals.
    "ConstTableLookup": ("ConstTableLookup.facts", lambda f: (
        f.func, str(f.addr), _g(f, "var"), _g(f, "table")
    )),
    # Legacy: LLM may still emit "VarWidth" — write to VarType.facts with defaults
    "VarWidth": ("VarType.facts", lambda f: (
        f.func, _g(f, "var"), "unknown",
        _g(f, "width", 0), "unknown"
    )),
}

# All .facts files that Souffle rules may reference.
ALL_FACT_FILES = sorted(set(
    filename for filename, _ in RELATION_SCHEMA.values()
) | {
    "ArithOp.facts", "Cast.facts", "DangerousSink.facts", "EntryTaint.facts",
    "TaintSourceFunc.facts", "TaintTransfer.facts", "BufferWriteSource.facts",
    "PointsTo.facts", "StackVar.facts", "TaintKill.facts", "Guard.facts",
    "VarType.facts",
    # LLM smell-pass relations: created empty when no smell pass ran, so
    # Souffle .input declarations don't fail on missing files.
    "IsValidator.facts", "IsAllocator.facts", "IsFree.facts",
    "IsTaintSource.facts", "IsTaintSink.facts", "IsIdentity.facts",
    "IsValidatorArg.facts", "LLMFlag.facts",
    "GuardEarlyReturn.facts",
    "ValidatingCast.facts",
    "IsFreeMembers.facts",
    "ConstTableLookup.facts",
    # G9 function-pointer dispatch facts — emitted by funcptr_scanner.py.
    "FuncPtrAssign.facts",
    "IndirectCallSite.facts",
    # G8: spec-bounded struct fields (validated at parse time, used by
    # consumers without local guards). One-column relation: just the
    # field name; struct discrimination is approximate but acceptable
    # for the codecs we audit.
    "BoundedField.facts",
})

# Column names per kind (string-keyed, same reason as RELATION_SCHEMA).
SCHEMA_DOCS = {
    "Def": ["func", "var", "ver", "addr"],
    "Use": ["func", "var", "ver", "addr"],
    "Call": ["caller", "callee", "addr"],
    "ActualArg": ["call_addr", "arg_idx", "param", "var", "ver"],
    "ReturnVal": ["func", "var", "ver"],
    "PhiSource": ["func", "var", "def_ver", "src_var", "src_ver"],
    "MemRead": ["func", "addr", "base", "offset", "size"],
    "MemWrite": ["func", "addr", "target", "mem_in", "mem_out"],
    "FieldRead": ["func", "addr", "base", "field"],
    "FieldWrite": ["func", "addr", "base", "field", "mem_in", "mem_out"],
    "AddressOf": ["func", "var", "ver", "target"],
    "CFGEdge": ["func", "from_addr", "to_addr"],
    "Jump": ["func", "addr", "expr"],
    "FormalParam": ["func", "var", "idx"],
    "StackVar": ["func", "var", "offset", "size"],
    "Guard": ["func", "addr", "var", "ver", "op", "bound", "bound_type"],
    "ArithOp": ["func", "addr", "dst", "dst_ver", "op", "src", "src_ver", "operand"],
    "Cast": ["func", "addr", "dst", "dst_ver", "src", "src_ver", "kind", "src_width", "dst_width", "src_type", "dst_type"],
    "VarType": ["func", "var", "type_name", "width", "signedness"],
    "ConstTableLookup": ["func", "addr", "var", "table"],
}


# ── Fact writer ─────────────────────────────────────────────────────────────

def write_facts(
    facts: list[Fact],
    output_dir: str | Path,
    append: bool = False,
) -> dict[str, int]:
    """Write facts to TSV files in output_dir.

    Returns dict of filename → number of rows written.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    grouped: dict[FactKind, list[Fact]] = {}
    for f in facts:
        grouped.setdefault(f.kind, []).append(f)

    stats = {}
    for kind, kind_facts in grouped.items():
        schema = RELATION_SCHEMA.get(kind.value)
        if not schema:
            print(f"  [WARN] No schema for {kind.value}, skipping {len(kind_facts)} facts")
            continue

        filename, extractor = schema
        filepath = output_dir / filename

        rows = set()
        if append and filepath.exists():
            existing = filepath.read_text().strip()
            if existing:
                for line in existing.split('\n'):
                    rows.add(tuple(line.split('\t')))

        failed = 0
        for f in kind_facts:
            try:
                row = extractor(f)
                if row is not None:
                    # Sanitise: collapse embedded newlines/tabs/CR (which would
                    # break the TSV row format) and trim runs of whitespace.
                    row = tuple(
                        " ".join(str(c).replace("\t", " ").split())
                        for c in row
                    )
                    rows.add(row)
            except (KeyError, TypeError, ValueError) as e:
                failed += 1
                if failed <= 3:  # Only print first 3 warnings per kind
                    print(f"  [WARN] Failed to extract {kind.value} fact: {e} | fields={f.fields}")
        if failed:
            print(f"  [WARN] {kind.value}: {failed}/{len(kind_facts)} facts failed extraction")

        sorted_rows = sorted(rows)
        with open(filepath, 'w') as fp:
            for row in sorted_rows:
                fp.write('\t'.join(row) + '\n')

        stats[filename] = len(sorted_rows)

    # Create empty files for missing relations (prevents Souffle errors)
    for filename in ALL_FACT_FILES:
        filepath = output_dir / filename
        if not filepath.exists():
            filepath.touch()

    return stats

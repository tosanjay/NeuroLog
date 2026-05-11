"""
G9 — Function-pointer dispatch detection (tree-sitter, no LLM).

Scans every .c file in a project for two patterns that fan out indirect
control flow our regular Call.facts misses:

  (A) Static initializer table of function pointers:
        static const VP8PredFunc kPredTable[N] = { F1, F2, F3 };

  (B) Runtime table assignment inside an init function:
        VP8PredLuma4[0] = DC4_C;
        VP8PredLuma4[1] = TM4_C;

  (C) Indirect call site through a dispatched pointer:
        kPredTable[mode](dst);
        obj->callback(arg);

Emits two .facts files for source_interproc.dl:

  FuncPtrAssign(table, idx, target, file, line)
    — every observed (table, index, function) tuple from (A) or (B).
  IndirectCallSite(caller, addr, table)
    — every call expression whose callee shape is `table[expr](...)`.

A Souffle rule then synthesizes `Call(caller, target, addr)` edges by
joining these two — so downstream taint / interproc rules see indirect
dispatch as if it were a direct call (over-approximating: every table
entry is a possible target).

Usage:
    python funcptr_scanner.py <src_root> <facts_out_dir>
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

import tree_sitter_c as tsc
from tree_sitter import Language, Parser

C_LANGUAGE = Language(tsc.language())


@dataclass
class FuncPtrAssignRow:
    table: str
    idx: str
    target: str
    file: str
    line: int


@dataclass
class IndirectCallRow:
    caller: str
    addr: int
    table: str


def _text(node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _line(node) -> int:
    return node.start_point[0] + 1


def _walk(node):
    yield node
    for c in node.children:
        yield from _walk(c)


def _walk_funcdefs(root):
    if root.type == "function_definition":
        yield root
    for c in root.children:
        yield from _walk_funcdefs(c)


def _func_name(func_node, source: bytes) -> str:
    """Extract the name of a function_definition. Handles the common
    declarator shapes: identifier, function_declarator, pointer_declarator."""

    def _get(d):
        if d is None:
            return ""
        if d.type == "identifier":
            return _text(d, source)
        if d.type == "function_declarator":
            return _get(d.child_by_field_name("declarator"))
        if d.type == "pointer_declarator":
            for ch in d.children:
                n = _get(ch)
                if n:
                    return n
        return ""

    return _get(func_node.child_by_field_name("declarator"))


def enumerate_function_names(root, source: bytes) -> set[str]:
    """All function names defined in this translation unit."""
    names: set[str] = set()
    for fn in _walk_funcdefs(root):
        n = _func_name(fn, source)
        if n:
            names.add(n)
    return names


# ── Pattern (A): static-initializer dispatch tables ─────────────────────────

def _find_static_table_initializers(
    root, source: bytes, known_funcs: set[str], file_path: str
) -> list[FuncPtrAssignRow]:
    """Match top-level declarations whose initializer is `{ F1, F2, ... }`
    with at least one identifier that matches a known function name."""
    rows: list[FuncPtrAssignRow] = []
    for decl in root.children:
        if decl.type != "declaration":
            continue
        for child in decl.children:
            if child.type != "init_declarator":
                continue
            declarator = child.child_by_field_name("declarator")
            init = child.child_by_field_name("value")
            if declarator is None or init is None:
                continue
            # Walk down to the array_declarator's identifier name.
            table_name = _array_decl_name(declarator, source)
            if not table_name:
                continue
            if init.type != "initializer_list":
                continue
            idx = 0
            for entry in init.children:
                if entry.type in ("{", "}", ","):
                    continue
                # Strip any leading `(cast)` wrapper or `&` ref.
                tgt = _initializer_identifier(entry, source)
                if tgt and tgt in known_funcs:
                    rows.append(FuncPtrAssignRow(
                        table=table_name, idx=str(idx), target=tgt,
                        file=file_path, line=_line(entry),
                    ))
                idx += 1
    return rows


def _array_decl_name(declarator, source: bytes) -> str:
    """Get the table name from an array_declarator (possibly wrapped
    in pointer_declarator). Returns "" if not an array declarator."""
    cur = declarator
    while cur is not None:
        if cur.type == "array_declarator":
            inner = cur.child_by_field_name("declarator")
            return _text(inner, source) if inner else ""
        if cur.type == "pointer_declarator":
            cur = cur.child_by_field_name("declarator")
            continue
        return ""
    return ""


def _initializer_identifier(entry, source: bytes) -> str:
    """Best-effort extract identifier from an initializer entry,
    unwrapping common casts/refs. Returns "" if the entry is a literal
    or complex expression."""
    if entry.type == "identifier":
        return _text(entry, source)
    if entry.type == "pointer_expression":  # &func
        for c in entry.children:
            if c.type == "identifier":
                return _text(c, source)
    if entry.type == "cast_expression":  # (T*)func
        for c in entry.children:
            r = _initializer_identifier(c, source)
            if r:
                return r
    return ""


# ── Pattern (B): runtime table[idx] = Func; assignment ──────────────────────

def _find_runtime_assignments(
    root, source: bytes, known_funcs: set[str], file_path: str
) -> list[FuncPtrAssignRow]:
    """Match assignment_expressions where LHS is a subscript_expression
    and RHS is an identifier matching a known function name."""
    rows: list[FuncPtrAssignRow] = []
    for node in _walk(root):
        if node.type != "assignment_expression":
            continue
        lhs = node.child_by_field_name("left")
        rhs = node.child_by_field_name("right")
        if lhs is None or rhs is None:
            continue
        if lhs.type != "subscript_expression":
            continue
        # Extract `table` and `idx` from `table[idx]`.
        arg = lhs.child_by_field_name("argument")
        sub = lhs.child_by_field_name("index")
        if arg is None:
            continue
        table = _text(arg, source) if arg.type == "identifier" else ""
        if not table:
            continue
        idx_text = _text(sub, source) if sub is not None else "?"
        tgt = _initializer_identifier(rhs, source)
        if tgt and tgt in known_funcs:
            rows.append(FuncPtrAssignRow(
                table=table, idx=idx_text, target=tgt,
                file=file_path, line=_line(node),
            ))
    return rows


# ── Pattern (C): indirect call sites through dispatch tables ────────────────

def _find_indirect_call_sites(
    root, source: bytes, file_path: str
) -> list[IndirectCallRow]:
    """Match call_expression whose `function` field is a subscript
    expression — `table[idx](args)`. The caller field is the enclosing
    function_definition; we walk up to find it."""
    rows: list[IndirectCallRow] = []
    for fn in _walk_funcdefs(root):
        caller = _func_name(fn, source)
        if not caller:
            continue
        body = fn.child_by_field_name("body")
        if body is None:
            continue
        for node in _walk(body):
            if node.type != "call_expression":
                continue
            callee = node.child_by_field_name("function")
            if callee is None:
                continue
            if callee.type == "subscript_expression":
                arg = callee.child_by_field_name("argument")
                if arg is not None and arg.type == "identifier":
                    rows.append(IndirectCallRow(
                        caller=caller, addr=_line(node),
                        table=_text(arg, source),
                    ))
    return rows


# ── Driver ──────────────────────────────────────────────────────────────────

def scan_project(src_root: Path
                  ) -> tuple[list[FuncPtrAssignRow], list[IndirectCallRow]]:
    """Walk src_root, scan every .c file, return aggregated facts.

    Two-pass strategy: first pass collects the set of all known function
    names across the whole project; second pass matches initializers/
    assignments against that set.
    """
    parser = Parser(C_LANGUAGE)
    files = list(src_root.rglob("*.c"))

    # Pass 1: enumerate known function names.
    known: set[str] = set()
    trees: dict[Path, tuple[bytes, object]] = {}
    for f in files:
        try:
            src = f.read_bytes()
        except OSError:
            continue
        tree = parser.parse(src)
        trees[f] = (src, tree)
        known |= enumerate_function_names(tree.root_node, src)

    # Pass 2: collect dispatch facts.
    fpa: list[FuncPtrAssignRow] = []
    icall: list[IndirectCallRow] = []
    for f, (src, tree) in trees.items():
        rel = str(f.relative_to(src_root)) if src_root in f.parents else str(f)
        fpa += _find_static_table_initializers(tree.root_node, src, known, rel)
        fpa += _find_runtime_assignments(tree.root_node, src, known, rel)
        icall += _find_indirect_call_sites(tree.root_node, src, rel)
    return fpa, icall


def _write_facts(rows: Iterable, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    seen: set[tuple] = set()
    with open(path, "w", encoding="utf-8") as out:
        for r in rows:
            tup = tuple(getattr(r, fld) for fld in r.__dataclass_fields__)
            if tup in seen:
                continue
            seen.add(tup)
            out.write("\t".join(str(x) for x in tup) + "\n")


def main():
    if len(sys.argv) != 3:
        print("usage: python funcptr_scanner.py <src_root> <facts_out_dir>",
              file=sys.stderr)
        sys.exit(2)
    src_root = Path(sys.argv[1]).resolve()
    out_dir = Path(sys.argv[2]).resolve()
    if not src_root.is_dir():
        print(f"[funcptr] src_root not a directory: {src_root}", file=sys.stderr)
        sys.exit(2)
    fpa, icall = scan_project(src_root)
    fpa_path = out_dir / "FuncPtrAssign.facts"
    icall_path = out_dir / "IndirectCallSite.facts"
    _write_facts(fpa, fpa_path)
    _write_facts(icall, icall_path)
    print(f"[funcptr] wrote {sum(1 for _ in open(fpa_path))} FuncPtrAssign "
          f"rows → {fpa_path}")
    print(f"[funcptr] wrote {sum(1 for _ in open(icall_path))} IndirectCallSite "
          f"rows → {icall_path}")


if __name__ == "__main__":
    main()

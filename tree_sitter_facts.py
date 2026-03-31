"""
Tree-sitter Ground Truth Extractor — Extracts mechanical Datalog facts
from C source code using tree-sitter (no LLM).

Used as baseline to measure LLM fact extraction accuracy.
Extracts: Def, Use, Call, ActualArg, FormalParam, ReturnVal,
FieldRead, FieldWrite, AddressOf.

Does NOT extract semantic facts that require understanding:
Guard bounds, ArithOp semantics, Cast kinds, StackVar sizes, VarWidth.
"""

from pathlib import Path

import tree_sitter_c as tsc
from tree_sitter import Language, Parser

from fact_schema import Fact, FactKind, write_facts

C_LANGUAGE = Language(tsc.language())


def extract_ground_truth(file_path: str, func_name: str) -> list[Fact]:
    """Extract mechanical facts from a single function using tree-sitter."""
    parser = Parser(C_LANGUAGE)
    source = Path(file_path).read_bytes()
    tree = parser.parse(source)

    # Find the function
    func_node = _find_function(tree.root_node, func_name, source)
    if not func_node:
        print(f"  [WARN] Function '{func_name}' not found in {file_path}")
        return []

    facts = []
    _extract_formal_params(func_node, func_name, source, facts)
    _walk_statements(func_node, func_name, source, facts)
    return facts


def _find_function(root, name: str, source: bytes):
    """Find function_definition node by name."""
    if root.type == "function_definition":
        declarator = root.child_by_field_name("declarator")
        if declarator:
            fname = _get_func_name(declarator, source)
            if fname == name:
                return root
    for child in root.children:
        result = _find_function(child, name, source)
        if result:
            return result
    return None


def _get_func_name(declarator, source: bytes) -> str:
    """Extract function name from declarator."""
    if declarator.type == "identifier":
        return _text(declarator, source)
    if declarator.type == "function_declarator":
        inner = declarator.child_by_field_name("declarator")
        if inner:
            return _get_func_name(inner, source)
    if declarator.type == "pointer_declarator":
        for child in declarator.children:
            name = _get_func_name(child, source)
            if name:
                return name
    return ""


def _text(node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _line(node) -> int:
    return node.start_point[0] + 1


def _extract_formal_params(func_node, func_name: str, source: bytes, facts: list):
    """Extract FormalParam facts from function definition."""
    declarator = func_node.child_by_field_name("declarator")
    if not declarator:
        return

    # Find function_declarator
    func_decl = declarator
    if func_decl.type != "function_declarator":
        for child in declarator.children:
            if child.type == "function_declarator":
                func_decl = child
                break

    if func_decl.type != "function_declarator":
        return

    param_list = func_decl.child_by_field_name("parameters")
    if not param_list:
        return

    idx = 0
    for child in param_list.children:
        if child.type == "parameter_declaration":
            pdecl = child.child_by_field_name("declarator")
            if pdecl:
                name = _get_param_name(pdecl, source)
                if name:
                    facts.append(Fact(
                        kind=FactKind.FORMAL_PARAM,
                        func=func_name,
                        addr=_line(func_node),
                        fields={"var": name, "idx": idx},
                    ))
                    idx += 1


def _get_param_name(node, source: bytes) -> str:
    if node.type == "identifier":
        return _text(node, source)
    if node.type == "pointer_declarator":
        for child in node.children:
            name = _get_param_name(child, source)
            if name:
                return name
    if node.type == "array_declarator":
        decl = node.child_by_field_name("declarator")
        if decl:
            return _get_param_name(decl, source)
    return ""


def _walk_statements(node, func_name: str, source: bytes, facts: list):
    """Recursively walk the function body and extract facts."""
    # Declaration with initializer
    if node.type == "declaration":
        _handle_declaration(node, func_name, source, facts)
        return

    # Assignment expression
    if node.type == "assignment_expression":
        _handle_assignment(node, func_name, source, facts)
        return

    # Function call
    if node.type == "call_expression":
        _handle_call(node, func_name, source, facts)
        return

    # Return statement
    if node.type == "return_statement":
        _handle_return(node, func_name, source, facts)
        return

    # Field access (read context handled by parent)
    if node.type == "field_expression":
        _handle_field_read(node, func_name, source, facts)
        return

    # Address-of
    if node.type == "unary_expression":
        op = node.child_by_field_name("operator")
        if op and _text(op, source) == "&":
            arg = node.child_by_field_name("argument")
            if arg and arg.type == "identifier":
                facts.append(Fact(
                    kind=FactKind.ADDRESS_OF,
                    func=func_name,
                    addr=_line(node),
                    fields={"var": _text(arg, source), "ver": 0, "target": "anonymous"},
                ))

    # Recurse into children
    for child in node.children:
        _walk_statements(child, func_name, source, facts)


def _handle_declaration(node, func_name: str, source: bytes, facts: list):
    """Handle variable declarations (with optional initializer)."""
    for child in node.children:
        if child.type == "init_declarator":
            declarator = child.child_by_field_name("declarator")
            value = child.child_by_field_name("value")
            if declarator:
                var_name = _get_declarator_name(declarator, source)
                if var_name:
                    facts.append(Fact(
                        kind=FactKind.DEF,
                        func=func_name,
                        addr=_line(node),
                        fields={"var": var_name, "ver": 0},
                    ))
                    # Extract uses from initializer
                    if value:
                        _collect_uses(value, func_name, source, facts)
                        # Check if initializer is a call
                        if value.type == "call_expression":
                            _handle_call(value, func_name, source, facts)


def _handle_assignment(node, func_name: str, source: bytes, facts: list):
    """Handle assignment expressions."""
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")

    if left:
        if left.type == "identifier":
            facts.append(Fact(
                kind=FactKind.DEF,
                func=func_name,
                addr=_line(node),
                fields={"var": _text(left, source), "ver": 0},
            ))
        elif left.type == "field_expression":
            base_node = left.child_by_field_name("argument")
            field_node = left.child_by_field_name("field")
            if base_node and field_node:
                facts.append(Fact(
                    kind=FactKind.FIELD_WRITE,
                    func=func_name,
                    addr=_line(node),
                    fields={
                        "base": _text(base_node, source),
                        "field": _text(field_node, source),
                        "mem_in": 0, "mem_out": 0,
                    },
                ))
        elif left.type in ("pointer_expression", "subscript_expression"):
            base = _get_pointer_base(left, source)
            if base:
                facts.append(Fact(
                    kind=FactKind.MEM_WRITE,
                    func=func_name,
                    addr=_line(node),
                    fields={"target": base, "mem_in": 0, "mem_out": 0},
                ))

    if right:
        _collect_uses(right, func_name, source, facts)
        if right.type == "call_expression":
            _handle_call(right, func_name, source, facts)


def _handle_call(node, func_name: str, source: bytes, facts: list):
    """Handle function call expressions."""
    func_node = node.child_by_field_name("function")
    args_node = node.child_by_field_name("arguments")

    callee = ""
    if func_node:
        callee = _text(func_node, source)

    # Only emit Call for direct function calls (identifier callees)
    if func_node and func_node.type == "identifier":
        facts.append(Fact(
            kind=FactKind.CALL,
            func=func_name,
            addr=_line(node),
            fields={"callee": callee},
        ))

    if args_node:
        idx = 0
        for child in args_node.children:
            if child.type not in ("(", ")", ","):
                var_text = _text(child, source)
                # Collect uses from arguments
                _collect_uses(child, func_name, source, facts)

                facts.append(Fact(
                    kind=FactKind.ACTUAL_ARG,
                    func=func_name,
                    addr=_line(node),
                    fields={
                        "arg_idx": idx,
                        "param": f"arg{idx}",
                        "var": var_text,
                        "ver": 0,
                    },
                ))
                idx += 1


def _handle_return(node, func_name: str, source: bytes, facts: list):
    """Handle return statements."""
    for child in node.children:
        if child.type not in ("return", ";"):
            if child.type == "identifier":
                facts.append(Fact(
                    kind=FactKind.RETURN_VAL,
                    func=func_name,
                    addr=_line(node),
                    fields={"var": _text(child, source), "ver": 0},
                ))
            _collect_uses(child, func_name, source, facts)


def _handle_field_read(node, func_name: str, source: bytes, facts: list):
    """Handle struct field read."""
    base_node = node.child_by_field_name("argument")
    field_node = node.child_by_field_name("field")
    if base_node and field_node:
        facts.append(Fact(
            kind=FactKind.FIELD_READ,
            func=func_name,
            addr=_line(node),
            fields={"base": _text(base_node, source), "field": _text(field_node, source)},
        ))


def _collect_uses(node, func_name: str, source: bytes, facts: list):
    """Recursively collect Use facts from an expression."""
    if node.type == "identifier":
        name = _text(node, source)
        # Skip type names and keywords
        if not name[0].isupper() and name not in ("NULL", "true", "false", "sizeof"):
            facts.append(Fact(
                kind=FactKind.USE,
                func=func_name,
                addr=_line(node),
                fields={"var": name, "ver": 0},
            ))
        return

    # Don't recurse into call_expression function name
    if node.type == "call_expression":
        args = node.child_by_field_name("arguments")
        if args:
            for child in args.children:
                if child.type not in ("(", ")", ","):
                    _collect_uses(child, func_name, source, facts)
        return

    for child in node.children:
        _collect_uses(child, func_name, source, facts)


def _get_declarator_name(node, source: bytes) -> str:
    """Get variable name from a declarator node."""
    if node.type == "identifier":
        return _text(node, source)
    if node.type == "pointer_declarator":
        for child in node.children:
            name = _get_declarator_name(child, source)
            if name:
                return name
    if node.type == "array_declarator":
        decl = node.child_by_field_name("declarator")
        if decl:
            return _get_declarator_name(decl, source)
    return ""


def _get_pointer_base(node, source: bytes) -> str:
    """Get base variable from pointer/subscript expression."""
    if node.type == "pointer_expression":
        arg = node.child_by_field_name("argument")
        if arg and arg.type == "identifier":
            return _text(arg, source)
    if node.type == "subscript_expression":
        arg = node.child_by_field_name("argument")
        if arg and arg.type == "identifier":
            return _text(arg, source)
    return ""


# ── Comparison ──────────────────────────────────────────────────────────────

def compare_facts(llm_facts: list[Fact], ts_facts: list[Fact]) -> dict:
    """Compare LLM-extracted facts against tree-sitter ground truth.

    Returns precision, recall, and details per fact kind.
    """
    # Fact kinds that tree-sitter can extract (for fair comparison)
    TS_KINDS = {
        FactKind.DEF, FactKind.USE, FactKind.CALL, FactKind.ACTUAL_ARG,
        FactKind.FORMAL_PARAM, FactKind.RETURN_VAL,
        FactKind.FIELD_READ, FactKind.FIELD_WRITE, FactKind.ADDRESS_OF,
    }

    def fact_key(f: Fact) -> tuple:
        """Create a comparable key from a fact."""
        # Normalize: use kind, func, addr, and sorted field items
        # Skip 'ver' and 'param' (LLM uses semantic names, TS uses arg0/arg1)
        key_fields = tuple(sorted(
            (k, str(v)) for k, v in f.fields.items()
            if k not in ("ver", "param")
        ))
        return (f.kind, f.func, f.addr, key_fields)

    # Only compare kinds that both extractors handle
    llm_set = set()
    llm_extra = set()  # LLM-only kinds (semantic facts TS can't extract)
    for f in llm_facts:
        key = fact_key(f)
        if f.kind in TS_KINDS:
            llm_set.add(key)
        else:
            llm_extra.add(key)

    ts_set = set()
    for f in ts_facts:
        ts_set.add(fact_key(f))

    # Per-kind metrics
    kinds = set(f.kind for f in llm_facts) | set(f.kind for f in ts_facts)
    results = {}

    for kind in sorted(kinds, key=lambda k: k.value):
        llm_kind = {k for k in llm_set if k[0] == kind}
        ts_kind = {k for k in ts_set if k[0] == kind}

        tp = len(llm_kind & ts_kind)
        fp = len(llm_kind - ts_kind)
        fn = len(ts_kind - llm_kind)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

        results[kind.value] = {
            "tp": tp, "fp": fp, "fn": fn,
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1": round(f1, 3),
            "fp_examples": [k for k in (llm_kind - ts_kind)][:3],
            "fn_examples": [k for k in (ts_kind - llm_kind)][:3],
        }

    # Overall
    all_tp = sum(r["tp"] for r in results.values())
    all_fp = sum(r["fp"] for r in results.values())
    all_fn = sum(r["fn"] for r in results.values())
    overall_p = all_tp / (all_tp + all_fp) if (all_tp + all_fp) > 0 else 0.0
    overall_r = all_tp / (all_tp + all_fn) if (all_tp + all_fn) > 0 else 0.0
    overall_f1 = 2 * overall_p * overall_r / (overall_p + overall_r) if (overall_p + overall_r) > 0 else 0.0

    return {
        "per_kind": results,
        "overall": {
            "tp": all_tp, "fp": all_fp, "fn": all_fn,
            "precision": round(overall_p, 3),
            "recall": round(overall_r, 3),
            "f1": round(overall_f1, 3),
        },
        "llm_extra_facts": len(llm_extra),  # semantic facts only LLM can extract
    }


# ── CLI ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) < 3:
        print("Usage: python tree_sitter_facts.py <file.c> <func_name> [output_dir]")
        sys.exit(1)

    file_path = sys.argv[1]
    func_name = sys.argv[2]
    output_dir = sys.argv[3] if len(sys.argv) > 3 else None

    facts = extract_ground_truth(file_path, func_name)
    print(f"Extracted {len(facts)} ground truth facts for {func_name}:")
    for f in facts:
        print(f"  {f}")

    if output_dir:
        stats = write_facts(facts, output_dir)
        print(f"\nWrote to {output_dir}/:")
        for filename, count in sorted(stats.items()):
            print(f"  {filename:25s} {count} rows")

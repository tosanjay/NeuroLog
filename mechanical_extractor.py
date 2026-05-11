"""
Mechanical Fact Extractor — Tree-sitter-driven Datalog fact extraction
for C source. This is the *floor* of the extraction pipeline: every fact
emitted here is grounded in the AST, deterministic, and guaranteed to be
reproducible.

Extracts: Def, Use, Call, ActualArg, ReturnVal, FormalParam, FieldRead,
FieldWrite, AddressOf, MemRead, MemWrite, Cast, ArithOp, VarType,
StackVar, Guard.

Out of scope (handled by smell_pass / Datalog rules):
  - Indirect-call resolution (function pointer callees emit nothing here)
  - Implicit cross-function casts (mechanical can only see one function)
  - Wrapper-as-validator promotion (smell-pass flags, Datalog promotes)
  - "Free of uninitialised" coverage gap detection (smell-pass)

The shape of the API mirrors tree_sitter_facts.extract_ground_truth so
callers can swap one for the other. Once this stabilises,
tree_sitter_facts.py is retained only as a comparison baseline.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import tree_sitter_c as tsc
from tree_sitter import Language, Node, Parser

from fact_schema import Fact, FactKind, write_facts

C_LANGUAGE = Language(tsc.language())


# ── Built-in catalogues ──────────────────────────────────────────────────────

# Functions whose argument(s) get a Def at the call site (output parameters).
# Each entry: callee → tuple of arg indices that are written to.
# Match prompts/fact_extraction.md output-param list.
OUTPUT_PARAM_DEFS: dict[str, tuple[int, ...]] = {
    "fgets": (0,),
    "gets": (0,),
    "read": (1,),
    "recv": (1,),
    "recvfrom": (1,),
    "fread": (0,),
    "memcpy": (0,),
    "memmove": (0,),
    "strcpy": (0,),
    "strncpy": (0,),
    "strcat": (0,),
    "strncat": (0,),
    "sprintf": (0,),
    "snprintf": (0,),
    "vsprintf": (0,),
    "vsnprintf": (0,),
    "scanf": (),  # variadic — handled specially via & args
    "fscanf": (),
    "sscanf": (),
    "getline": (0,),
    "asprintf": (0,),
}

# Type → (width_bytes, signedness). Width is per-element for arrays handled
# at the declaration walker.
PRIMITIVE_TYPES: dict[str, tuple[int, str]] = {
    "char": (1, "signed"),
    "signed char": (1, "signed"),
    "unsigned char": (1, "unsigned"),
    "short": (2, "signed"),
    "short int": (2, "signed"),
    "signed short": (2, "signed"),
    "unsigned short": (2, "unsigned"),
    "int": (4, "signed"),
    "signed": (4, "signed"),
    "signed int": (4, "signed"),
    "unsigned": (4, "unsigned"),
    "unsigned int": (4, "unsigned"),
    "long": (8, "signed"),
    "long int": (8, "signed"),
    "signed long": (8, "signed"),
    "unsigned long": (8, "unsigned"),
    "long long": (8, "signed"),
    "unsigned long long": (8, "unsigned"),
    "float": (4, "signed"),
    "double": (8, "signed"),
    "long double": (16, "signed"),
    "_Bool": (1, "unsigned"),
    "bool": (1, "unsigned"),
    "size_t": (8, "unsigned"),
    "ssize_t": (8, "signed"),
    "ptrdiff_t": (8, "signed"),
    "intptr_t": (8, "signed"),
    "uintptr_t": (8, "unsigned"),
    "off_t": (8, "signed"),
    "int8_t": (1, "signed"),
    "uint8_t": (1, "unsigned"),
    "int16_t": (2, "signed"),
    "uint16_t": (2, "unsigned"),
    "int32_t": (4, "signed"),
    "uint32_t": (4, "unsigned"),
    "int64_t": (8, "signed"),
    "uint64_t": (8, "unsigned"),
}

ARITH_BIN_OPS: dict[str, str] = {
    "+": "add", "-": "sub", "*": "mul", "/": "div", "%": "mod",
    "<<": "lsl", ">>": "lsr",
    "&": "and", "|": "or", "^": "xor",
}

CMP_OPS: set[str] = {"<", "<=", ">", ">=", "==", "!="}


# ── Public API ───────────────────────────────────────────────────────────────

def extract_facts(file_path: str, func_name: str) -> list[Fact]:
    """Extract mechanical facts for one function. Mirrors
    tree_sitter_facts.extract_ground_truth in shape."""
    parser = Parser(C_LANGUAGE)
    source = Path(file_path).read_bytes()
    tree = parser.parse(source)
    fnode = _find_function(tree.root_node, func_name, source)
    if fnode is None:
        return []

    ctx = _Ctx(func_name=func_name, source=source, facts=[], type_env={})
    _extract_formal_params(fnode, ctx)
    body = fnode.child_by_field_name("body")
    if body is not None:
        _walk(body, ctx)
    return ctx.facts


def extract_facts_all(file_path: str) -> dict[str, list[Fact]]:
    """Extract mechanical facts for *every* function in a file. Returns
    {func_name: facts}."""
    parser = Parser(C_LANGUAGE)
    source = Path(file_path).read_bytes()
    tree = parser.parse(source)
    out: dict[str, list[Fact]] = {}

    def walk(node: Node):
        if node.type == "function_definition":
            decl = node.child_by_field_name("declarator")
            if decl is not None:
                name = _func_name_from_declarator(decl, source)
                if name:
                    ctx = _Ctx(name, source, [], {})
                    _extract_formal_params(node, ctx)
                    body = node.child_by_field_name("body")
                    if body is not None:
                        _walk(body, ctx)
                    out[name] = ctx.facts
            return
        for child in node.children:
            walk(child)

    walk(tree.root_node)
    return out


# ── Context object — threads through all walkers ─────────────────────────────

class _Ctx:
    __slots__ = ("func_name", "source", "facts", "type_env")

    def __init__(
        self,
        func_name: str,
        source: bytes,
        facts: list[Fact],
        type_env: dict[str, tuple[str, int, str]],
    ):
        self.func_name = func_name
        self.source = source
        self.facts = facts
        # var name → (type_name, width, signedness)
        self.type_env = type_env

    def emit(self, fact_kind: FactKind, addr: int, **fields):
        self.facts.append(Fact(kind=fact_kind, func=self.func_name, addr=addr, fields=fields))


# ── Function-shape helpers ──────────────────────────────────────────────────

def _text(node: Node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _line(node: Node) -> int:
    return node.start_point[0] + 1


def _find_function(root: Node, name: str, source: bytes) -> Optional[Node]:
    if root.type == "function_definition":
        decl = root.child_by_field_name("declarator")
        if decl is not None and _func_name_from_declarator(decl, source) == name:
            return root
    for child in root.children:
        result = _find_function(child, name, source)
        if result is not None:
            return result
    return None


def _func_name_from_declarator(decl: Node, source: bytes) -> str:
    if decl.type == "identifier":
        return _text(decl, source)
    if decl.type == "function_declarator":
        inner = decl.child_by_field_name("declarator")
        if inner is not None:
            return _func_name_from_declarator(inner, source)
    if decl.type == "pointer_declarator":
        for child in decl.children:
            n = _func_name_from_declarator(child, source)
            if n:
                return n
    return ""


def _declarator_name(node: Node, source: bytes) -> str:
    """Strip pointer/array/function declarator wrappers and return the
    identifier."""
    if node.type == "identifier":
        return _text(node, source)
    if node.type == "field_identifier":
        return _text(node, source)
    inner = node.child_by_field_name("declarator")
    if inner is not None:
        return _declarator_name(inner, source)
    for child in node.children:
        if child.type in ("identifier", "field_identifier"):
            return _text(child, source)
    return ""


# ── Type extraction ──────────────────────────────────────────────────────────

def _normalise_type(text: str) -> str:
    """Collapse whitespace and storage-class noise so 'unsigned   int' →
    'unsigned int'. Strip 'const', 'volatile', 'restrict', storage-class."""
    parts = text.replace("\n", " ").split()
    keep = [p for p in parts
            if p not in ("const", "volatile", "restrict",
                         "static", "extern", "register", "auto", "inline")]
    return " ".join(keep).strip()


def _classify_type(type_text: str, declarator: Optional[Node], source: bytes
                   ) -> tuple[str, int, str]:
    """Given a declaration's type-specifier text and its declarator node,
    return (type_name, width_bytes, signedness)."""
    base = _normalise_type(type_text)
    pointer_levels = 0
    array_size: Optional[int] = None
    if declarator is not None:
        node = declarator
        while node is not None:
            if node.type == "pointer_declarator":
                pointer_levels += 1
                node = node.child_by_field_name("declarator")
            elif node.type == "array_declarator":
                size_node = node.child_by_field_name("size")
                if size_node is not None and size_node.type == "number_literal":
                    try:
                        array_size = int(_text(size_node, source))
                    except ValueError:
                        array_size = None
                node = node.child_by_field_name("declarator")
            else:
                break

    if pointer_levels > 0:
        suffix = "*" * pointer_levels
        return (f"{base}{suffix}", 8, "pointer")

    if array_size is not None:
        elem_w, _ = PRIMITIVE_TYPES.get(base, (1, "unsigned"))
        return (f"{base}[{array_size}]", elem_w * array_size, "unsigned")

    if base.startswith("struct ") or base.startswith("union "):
        return (base, 0, "struct")
    if base.startswith("enum "):
        return (base, 4, "signed")

    if base in PRIMITIVE_TYPES:
        w, s = PRIMITIVE_TYPES[base]
        return (base, w, s)

    # Unknown typedef. Best effort: assume word size, unknown signedness.
    return (base if base else "unknown", 8, "unknown")


# ── Formal parameters ────────────────────────────────────────────────────────

def _extract_formal_params(fnode: Node, ctx: _Ctx):
    decl = fnode.child_by_field_name("declarator")
    if decl is None:
        return

    func_decl = decl
    if func_decl.type != "function_declarator":
        for child in decl.children:
            if child.type == "function_declarator":
                func_decl = child
                break
        else:
            for desc in _walk_all(decl):
                if desc.type == "function_declarator":
                    func_decl = desc
                    break

    if func_decl.type != "function_declarator":
        return
    params = func_decl.child_by_field_name("parameters")
    if params is None:
        return

    idx = 0
    for child in params.children:
        if child.type != "parameter_declaration":
            continue
        ptype_node = child.child_by_field_name("type")
        pdecl = child.child_by_field_name("declarator")
        type_text = _text(ptype_node, ctx.source) if ptype_node else ""
        name = _declarator_name(pdecl, ctx.source) if pdecl else ""
        if not name:
            idx += 1
            continue

        type_name, width, signedness = _classify_type(type_text, pdecl, ctx.source)
        ctx.type_env[name] = (type_name, width, signedness)

        ctx.emit(FactKind.FORMAL_PARAM, _line(fnode), var=name, idx=idx)
        ctx.emit(FactKind.DEF, _line(fnode), var=name, ver=0)
        ctx.emit(FactKind.VAR_TYPE, _line(fnode),
                 var=name, type_name=type_name, width=width, signedness=signedness)
        idx += 1


def _walk_all(node: Node):
    """Iterate all descendants (including node)."""
    yield node
    for c in node.children:
        yield from _walk_all(c)


# ── Body walker ──────────────────────────────────────────────────────────────

def _walk(node: Node, ctx: _Ctx):
    t = node.type
    if t == "declaration":
        _handle_declaration(node, ctx)
        return
    if t == "assignment_expression":
        _handle_assignment(node, ctx)
        return
    if t == "call_expression":
        _handle_call(node, ctx)
        # don't recurse — call already collected uses from args
        return
    if t == "return_statement":
        _handle_return(node, ctx)
        return
    if t == "if_statement":
        _handle_if(node, ctx)
        return
    if t in ("while_statement", "do_statement"):
        _handle_while(node, ctx)
        return
    if t == "for_statement":
        _handle_for(node, ctx)
        return
    if t == "cast_expression":
        _handle_cast(node, ctx)
        return
    if t == "binary_expression":
        # Standalone arith expression (e.g., as a statement). Most arith is
        # caught via assignment RHS walker; this is a fallback.
        _handle_binary(node, ctx, dst_var=None, dst_ver=0, addr=_line(node))
        return
    if t == "update_expression":
        _handle_update(node, ctx)
        return
    if t == "field_expression":
        _handle_field_read(node, ctx)
        # fall through — base may itself be a field expression
    if t in ("pointer_expression", "subscript_expression"):
        _handle_mem_read(node, ctx)
        # fall through

    for child in node.children:
        _walk(child, ctx)


# ── Declarations ─────────────────────────────────────────────────────────────

def _handle_declaration(node: Node, ctx: _Ctx):
    type_node = node.child_by_field_name("type")
    type_text = _text(type_node, ctx.source) if type_node else ""

    for child in node.children:
        if child.type == "init_declarator":
            decl = child.child_by_field_name("declarator")
            value = child.child_by_field_name("value")
            if decl is None:
                continue
            var_name = _declarator_name(decl, ctx.source)
            if not var_name:
                continue

            type_name, width, signedness = _classify_type(type_text, decl, ctx.source)
            ctx.type_env[var_name] = (type_name, width, signedness)

            ctx.emit(FactKind.DEF, _line(node), var=var_name, ver=0)
            ctx.emit(FactKind.VAR_TYPE, _line(node),
                     var=var_name, type_name=type_name, width=width, signedness=signedness)
            _maybe_emit_stack_var(node, decl, var_name, type_name, width, ctx)

            if value is not None:
                _process_rhs(value, ctx, dst_var=var_name, addr=_line(node))

        elif child.type in ("identifier", "pointer_declarator", "array_declarator"):
            # Bare declaration with no initialiser: `int x;`
            var_name = _declarator_name(child, ctx.source)
            if var_name:
                type_name, width, signedness = _classify_type(type_text, child, ctx.source)
                ctx.type_env[var_name] = (type_name, width, signedness)
                ctx.emit(FactKind.VAR_TYPE, _line(node),
                         var=var_name, type_name=type_name, width=width, signedness=signedness)
                _maybe_emit_stack_var(node, child, var_name, type_name, width, ctx)


def _maybe_emit_stack_var(decl_stmt: Node, declarator: Node, var_name: str,
                          type_name: str, width: int, ctx: _Ctx):
    """Emit StackVar when this is a sized local (array, fixed-size struct
    inline). Skip pointers and unknown-size types."""
    # Walk in to find array_declarator
    node = declarator
    has_array = False
    array_total: Optional[int] = None
    while node is not None:
        if node.type == "array_declarator":
            has_array = True
            size_node = node.child_by_field_name("size")
            if size_node is not None and size_node.type == "number_literal":
                try:
                    n = int(_text(size_node, ctx.source))
                    array_total = (array_total or 1) * n if array_total else n
                except ValueError:
                    pass
            node = node.child_by_field_name("declarator")
        else:
            break

    if has_array and width > 0:
        ctx.emit(FactKind.STACK_VAR, _line(decl_stmt),
                 var=var_name, offset=0, size=width)


# ── Assignment ───────────────────────────────────────────────────────────────

def _handle_assignment(node: Node, ctx: _Ctx):
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    op_node = node.child_by_field_name("operator")
    op = _text(op_node, ctx.source) if op_node else "="

    addr = _line(node)
    dst_var: Optional[str] = None

    if left is not None:
        if left.type == "identifier":
            dst_var = _text(left, ctx.source)
            ctx.emit(FactKind.DEF, addr, var=dst_var, ver=0)
        elif left.type == "field_expression":
            base = left.child_by_field_name("argument")
            field = left.child_by_field_name("field")
            if base is not None and field is not None:
                ctx.emit(FactKind.FIELD_WRITE, addr,
                         base=_text(base, ctx.source),
                         field=_text(field, ctx.source),
                         mem_in=0, mem_out=0)
                _collect_uses(base, ctx, addr=addr)
        elif left.type in ("pointer_expression", "subscript_expression"):
            base = _pointer_base_text(left, ctx.source)
            if base:
                ctx.emit(FactKind.MEM_WRITE, addr,
                         target=base, mem_in=0, mem_out=0)
            _collect_uses(left, ctx, addr=addr)

    # Compound assignment: x += y ⇒ x is also Used and ArithOp emitted.
    if right is not None:
        if op != "=" and dst_var is not None:
            arith_op = ARITH_BIN_OPS.get(op[:-1], None)  # "+=" → "+"
            if arith_op:
                operand_text = _text(right, ctx.source)
                ctx.emit(FactKind.USE, addr, var=dst_var, ver=0)
                ctx.emit(FactKind.ARITH_OP, addr,
                         dst_var=dst_var, dst_ver=0, op=arith_op,
                         src_var=dst_var, src_ver=0, operand=operand_text)
                _collect_uses(right, ctx, addr=addr)
                return

        _process_rhs(right, ctx, dst_var=dst_var, addr=addr)


def _process_rhs(value: Node, ctx: _Ctx, dst_var: Optional[str], addr: int):
    """Walk RHS of an assignment / declaration, emitting Use, Call,
    ArithOp, Cast, MemRead, FieldRead facts as appropriate."""
    if value.type == "call_expression":
        _handle_call(value, ctx)
        return
    if value.type == "cast_expression":
        _handle_cast(value, ctx, dst_var=dst_var, addr=addr)
        return
    if value.type == "update_expression":
        # e.g. `x = ++p->counter;`. Route through _handle_update so the
        # field-counter increment surfaces as ArithOp on the leaf name.
        _handle_update(value, ctx)
        return
    if value.type == "binary_expression":
        op_node = value.child_by_field_name("operator")
        op = _text(op_node, ctx.source) if op_node else ""
        if op in ARITH_BIN_OPS:
            _handle_binary(value, ctx, dst_var=dst_var, dst_ver=0, addr=addr)
            return
    if value.type == "field_expression":
        # `x = obj->field;` — emit FieldRead for downstream rules
        # (field-derived bound propagation, taint-via-field, etc.).
        _handle_field_read(value, ctx)
        # Fall through to _collect_uses for the base identifier.
    if value.type in ("pointer_expression", "subscript_expression"):
        _handle_mem_read(value, ctx)
    # Plain identifier RHS — implicit cast detection.
    if value.type == "identifier" and dst_var is not None:
        src_var = _text(value, ctx.source)
        _maybe_emit_implicit_cast(src_var, dst_var, addr, ctx)
    _collect_uses(value, ctx, addr=addr)


# ── Calls ────────────────────────────────────────────────────────────────────

def _handle_call(node: Node, ctx: _Ctx):
    fnode = node.child_by_field_name("function")
    args_node = node.child_by_field_name("arguments")
    addr = _line(node)
    if fnode is None:
        return

    callee = ""
    is_direct = False
    if fnode.type == "identifier":
        callee = _text(fnode, ctx.source)
        is_direct = True
        ctx.emit(FactKind.CALL, addr, callee=callee)
    # Indirect calls (field_expression, pointer_expression as callee) are
    # left to the smell-pass to resolve.

    if args_node is None:
        return

    idx = 0
    output_indices: tuple[int, ...] = OUTPUT_PARAM_DEFS.get(callee, ()) if is_direct else ()
    is_scanf_family = is_direct and callee in ("scanf", "fscanf", "sscanf")

    for child in args_node.children:
        if child.type in ("(", ")", ","):
            continue
        var_text = _text(child, ctx.source).strip()
        ctx.emit(FactKind.ACTUAL_ARG, addr,
                 arg_idx=idx, param=f"arg{idx}",
                 var=var_text, ver=0)
        _collect_uses(child, ctx, addr=addr)

        if idx in output_indices:
            target_name = _arg_target_name(child, ctx.source)
            if target_name:
                ctx.emit(FactKind.DEF, addr, var=target_name, ver=0)
        elif is_scanf_family and child.type == "unary_expression":
            op = child.child_by_field_name("operator")
            arg = child.child_by_field_name("argument")
            if op is not None and _text(op, ctx.source) == "&" and arg is not None:
                if arg.type == "identifier":
                    ctx.emit(FactKind.DEF, addr, var=_text(arg, ctx.source), ver=0)
        idx += 1


def _arg_target_name(arg: Node, source: bytes) -> str:
    """For an output-param argument, return the target buffer name."""
    if arg.type == "identifier":
        return _text(arg, source)
    if arg.type == "unary_expression":
        op = arg.child_by_field_name("operator")
        inner = arg.child_by_field_name("argument")
        if op is not None and _text(op, source) == "&" and inner is not None and inner.type == "identifier":
            return _text(inner, source)
    if arg.type == "field_expression":
        return _text(arg, source)  # full expression text — Datalog can match on it
    if arg.type == "pointer_expression":
        inner = arg.child_by_field_name("argument")
        if inner is not None:
            return _text(inner, source)
    return ""


# ── Returns ──────────────────────────────────────────────────────────────────

def _handle_return(node: Node, ctx: _Ctx):
    addr = _line(node)
    for child in node.children:
        if child.type in ("return", ";"):
            continue
        if child.type == "identifier":
            ctx.emit(FactKind.RETURN_VAL, addr, var=_text(child, ctx.source), ver=0)
        _collect_uses(child, ctx, addr=addr)


# ── if / while / for guards ──────────────────────────────────────────────────

def _branch_terminates(branch: Node) -> bool:
    """True if this if-branch (consequence/alternative) ends in a
    function-terminating statement: return, goto, abort/exit/longjmp.
    Crude pattern-match — any return_statement / goto_statement at the
    top level of the body counts.
    """
    if branch is None:
        return False
    if branch.type in ("return_statement", "goto_statement"):
        return True
    if branch.type == "compound_statement":
        for child in branch.children:
            if child.type in ("return_statement", "goto_statement"):
                return True
            # `abort();`, `exit(1);`, `longjmp(...);` as expression statements.
            if child.type == "expression_statement":
                inner = child.children[0] if child.children else None
                if inner is not None and inner.type == "call_expression":
                    fn = inner.child_by_field_name("function")
                    if fn is not None and fn.type == "identifier":
                        if _text(fn, branch.text and branch.text or b"") in (
                                "abort", "exit", "longjmp", "_exit", "__builtin_unreachable"):
                            return True
        return False
    return False


def _handle_if(node: Node, ctx: _Ctx):
    cond = node.child_by_field_name("condition")
    if cond is not None:
        _emit_guards(cond, ctx)
        _collect_uses(cond, ctx, addr=_line(cond))
        consequence = node.child_by_field_name("consequence")
        if consequence is not None and _branch_terminates_text(consequence, ctx.source):
            ctx.emit(FactKind.GUARD_EARLY_RETURN, _line(cond))
            # G4: cast-and-compare anti-truncation idiom.
            # `if ((narrow_t)x != x) return error;` — the cast at this
            # site IS the validator on x. Look at the condition's
            # binary_expression and detect the pattern.
            for var in _detect_validating_cast(cond, ctx.source):
                # The cast itself is at this same line in the mechanical
                # walker (we emit Cast at _line(node) for cast_expression).
                ctx.emit(FactKind.VALIDATING_CAST, _line(cond), var=var)
    for child in node.children:
        if child is cond:
            continue
        _walk(child, ctx)


def _detect_validating_cast(cond: Node, source: bytes):
    """Yield variable names guarded by a cast-and-compare-to-self check
    inside the condition. Patterns recognised:
        (narrow_t)x  != x
        x != (narrow_t)x
        (narrow_t)x  == x   (complementary form)
        x == (narrow_t)x
    Disjunctions (`a || b || …` with the if-branch terminating) are
    decomposed: each disjunct is independently a guard, since any one
    of them being true triggers the return. Conjunctions (`a && b`)
    are NOT decomposed — only the whole conjunction being true triggers
    the return, so we can't credit individual conjuncts.
    """
    yield from _detect_validating_cast_recur(_unwrap_parens(cond), source)


def _detect_validating_cast_recur(node: Node, source: bytes):
    if node.type == "parenthesized_expression":
        node = _unwrap_parens(node)
    if node.type != "binary_expression":
        return
    op_node = node.child_by_field_name("operator")
    op = _text(op_node, source) if op_node else ""

    if op == "||":
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is not None:
            yield from _detect_validating_cast_recur(left, source)
        if right is not None:
            yield from _detect_validating_cast_recur(right, source)
        return

    if op not in ("!=", "=="):
        return

    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is None or right is None:
        return

    def _cast_arg_text(n: Node) -> Optional[str]:
        if n.type != "cast_expression":
            return None
        value = n.child_by_field_name("value")
        if value is None:
            return None
        return _text(value, source).strip()

    cast_arg_l = _cast_arg_text(left)
    cast_arg_r = _cast_arg_text(right)
    other_l = _text(right, source).strip() if cast_arg_l else None
    other_r = _text(left, source).strip() if cast_arg_r else None

    if cast_arg_l and other_l and cast_arg_l == other_l:
        yield _leaf_var_text(cast_arg_l)
    elif cast_arg_r and other_r and cast_arg_r == other_r:
        yield _leaf_var_text(cast_arg_r)


def _leaf_var_text(text: str) -> str:
    """Extract leaf identifier from `h->field` / `arr[i]` text — matches
    the leaf-name extraction in _emit_simple_guard so Datalog joins
    correctly across Cast / Guard / ArithOp on the same variable."""
    s = text.strip()
    # `a->b` or `a.b` → b
    for sep in ("->", "."):
        if sep in s:
            s = s.split(sep)[-1].strip()
    # `arr[i]` → arr (best-effort; Cast.src is typically the leaf var)
    if "[" in s:
        s = s.split("[")[0].strip()
    return s


def _branch_terminates_text(branch: Node, source: bytes) -> bool:
    """Body-terminates check that uses the source bytes (so identifier
    text comparisons work). The wrapper above keeps the API matching."""
    if branch is None:
        return False
    if branch.type in ("return_statement", "goto_statement"):
        return True
    if branch.type == "compound_statement":
        for child in branch.children:
            if child.type in ("return_statement", "goto_statement"):
                return True
            if child.type == "expression_statement":
                inner = child.children[0] if child.children else None
                if inner is not None and inner.type == "call_expression":
                    fn = inner.child_by_field_name("function")
                    if fn is not None and fn.type == "identifier":
                        if _text(fn, source) in (
                                "abort", "exit", "longjmp",
                                "_exit", "__builtin_unreachable"):
                            return True
        return False
    return False


def _handle_while(node: Node, ctx: _Ctx):
    cond = node.child_by_field_name("condition")
    if cond is not None:
        _emit_guards(cond, ctx)
        _collect_uses(cond, ctx, addr=_line(cond))
    body = node.child_by_field_name("body")
    if body is not None:
        _walk(body, ctx)


def _handle_for(node: Node, ctx: _Ctx):
    init = node.child_by_field_name("initializer")
    cond = node.child_by_field_name("condition")
    upd = node.child_by_field_name("update")
    body = node.child_by_field_name("body")
    if init is not None:
        _walk(init, ctx)
    if cond is not None:
        _emit_guards(cond, ctx)
        _collect_uses(cond, ctx, addr=_line(cond))
    if upd is not None:
        _walk(upd, ctx)
    if body is not None:
        _walk(body, ctx)


def _unwrap_parens(node: Node) -> Node:
    """Strip parenthesized_expression wrappers; tree-sitter-c does not
    name its inner field, so iterate children."""
    while node.type == "parenthesized_expression":
        next_inner = None
        for child in node.children:
            if child.type not in ("(", ")"):
                next_inner = child
                break
        if next_inner is None:
            break
        node = next_inner
    return node


def _emit_guards(cond: Node, ctx: _Ctx):
    """Decompose a condition into top-level conjuncts and emit Guard facts.
    `&&` decomposes; `||` is treated atomically (not a guard). Negation
    flips comparison operators."""
    inner = _unwrap_parens(cond)

    if inner.type == "binary_expression":
        op_node = inner.child_by_field_name("operator")
        op = _text(op_node, ctx.source) if op_node else ""
        if op == "&&":
            for side in (inner.child_by_field_name("left"),
                         inner.child_by_field_name("right")):
                if side is not None:
                    _emit_guards(side, ctx)
            return
        if op == "||":
            return  # disjunction — neither branch alone is a guard
        if op in CMP_OPS:
            _emit_simple_guard(inner, op, negated=False, ctx=ctx)
            return
    if inner.type == "unary_expression":
        op_node = inner.child_by_field_name("operator")
        if op_node is not None and _text(op_node, ctx.source) == "!":
            arg = inner.child_by_field_name("argument")
            if arg is not None and arg.type == "identifier":
                # `if (!ptr)` → Guard ptr == NULL
                ctx.emit(FactKind.GUARD, _line(inner),
                         var=_text(arg, ctx.source), ver=0,
                         op="==", bound="NULL", bound_type="const")
            return
    if inner.type == "identifier":
        # `if (ptr)` → Guard ptr != NULL
        ctx.emit(FactKind.GUARD, _line(inner),
                 var=_text(inner, ctx.source), ver=0,
                 op="!=", bound="NULL", bound_type="const")


_NEG_OP = {
    "<": ">=", "<=": ">", ">": "<=", ">=": "<",
    "==": "!=", "!=": "==",
}


def _emit_simple_guard(bin_expr: Node, op: str, negated: bool, ctx: _Ctx):
    left = bin_expr.child_by_field_name("left")
    right = bin_expr.child_by_field_name("right")
    if left is None or right is None:
        return
    if negated:
        op = _NEG_OP.get(op, op)

    # Pick whichever side is an identifier OR a field/subscript expression
    # (`sl->slice_num`, `arr[i]`) — those are variables in our schema.
    # Use _is_var_like to keep "MAX_SLICES" (an identifier we'd pick as the
    # bound) on the bound side when the other side is a struct field.
    var_node, bound_node, swap = None, None, False
    if _is_field_or_subscript(left):
        var_node, bound_node = left, right
    elif _is_field_or_subscript(right):
        var_node, bound_node, swap = right, left, True
    elif left.type == "identifier":
        var_node, bound_node = left, right
    elif right.type == "identifier":
        var_node, bound_node, swap = right, left, True
    if var_node is None:
        return

    if swap:
        # Swap also flips the comparison: a < b ≡ b > a.
        op = {"<": ">", "<=": ">=", ">": "<", ">=": "<="}.get(op, op)

    bound_text = _text(bound_node, ctx.source).strip()
    bound_type = "const"
    if bound_node.type == "number_literal":
        bound_type = "const"
    elif bound_node.type == "identifier":
        bound_type = "var"
    elif bound_node.type == "sizeof_expression" or "sizeof" in bound_text:
        bound_type = "sizeof"
    elif bound_node.type in ("null", "true", "false"):
        bound_type = "const"
    else:
        bound_type = "expr"

    # Use leaf-name for field/subscript exprs (matches ArithOp emission)
    # so HasUpperBound can compose Guard.var with ArithOp.dst_var.
    var_text = (_field_var_name(var_node, ctx.source)
                if _is_field_or_subscript(var_node)
                else _text(var_node, ctx.source))

    ctx.emit(FactKind.GUARD, _line(bin_expr),
             var=var_text, ver=0,
             op=op, bound=bound_text, bound_type=bound_type)


# ── Casts ────────────────────────────────────────────────────────────────────

def _handle_cast(node: Node, ctx: _Ctx,
                 dst_var: Optional[str] = None, addr: Optional[int] = None):
    if addr is None:
        addr = _line(node)
    type_node = node.child_by_field_name("type")
    value = node.child_by_field_name("value")
    if type_node is None or value is None:
        return
    dst_type_name = _normalise_type(_text(type_node, ctx.source))
    dst_w, dst_s = PRIMITIVE_TYPES.get(dst_type_name, (8, "unknown"))

    src_var_name = ""
    src_type_name = "unknown"
    src_w, src_s = 0, "unknown"
    if value.type == "identifier":
        src_var_name = _text(value, ctx.source)
        if src_var_name in ctx.type_env:
            src_type_name, src_w, src_s = ctx.type_env[src_var_name]
    elif value.type == "cast_expression":
        # Nested cast — recurse first.
        _handle_cast(value, ctx, dst_var=None, addr=addr)
    elif value.type == "call_expression":
        _handle_call(value, ctx)

    kind = _classify_cast(src_w, dst_w, src_s, dst_s, dst_type_name)

    ctx.emit(FactKind.CAST, addr,
             dst=dst_var or "tmp", dst_ver=0,
             src=src_var_name, src_ver=0,
             kind=kind,
             src_width=src_w, dst_width=dst_w,
             src_type=src_type_name, dst_type=dst_type_name)
    _collect_uses(value, ctx, addr=addr)


def _classify_cast(src_w: int, dst_w: int, src_s: str, dst_s: str,
                   dst_type_name: str) -> str:
    if dst_s == "pointer" or src_s == "pointer":
        return "reinterpret"
    if not src_w or not dst_w:
        return "reinterpret"
    if dst_w < src_w:
        return "truncate"
    if dst_w > src_w:
        return "sign_extend" if src_s == "signed" else "zero_extend"
    return "reinterpret"


def _maybe_emit_implicit_cast(src_var: str, dst_var: str, addr: int, ctx: _Ctx):
    if src_var not in ctx.type_env or dst_var not in ctx.type_env:
        return
    src_type, src_w, src_s = ctx.type_env[src_var]
    dst_type, dst_w, dst_s = ctx.type_env[dst_var]
    if src_w == 0 or dst_w == 0 or src_w == dst_w and src_s == dst_s:
        return
    if dst_s == "pointer" or src_s == "pointer":
        return
    kind = _classify_cast(src_w, dst_w, src_s, dst_s, dst_type)
    if kind == "reinterpret":
        return
    ctx.emit(FactKind.CAST, addr,
             dst=dst_var, dst_ver=0,
             src=src_var, src_ver=0,
             kind=kind,
             src_width=src_w, dst_width=dst_w,
             src_type=src_type, dst_type=dst_type)


# ── Arithmetic ───────────────────────────────────────────────────────────────

def _handle_binary(node: Node, ctx: _Ctx, dst_var: Optional[str],
                   dst_ver: int, addr: int):
    op_node = node.child_by_field_name("operator")
    op = _text(op_node, ctx.source) if op_node else ""
    arith = ARITH_BIN_OPS.get(op)
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if arith is None or left is None or right is None:
        if left is not None:
            _collect_uses(left, ctx, addr=addr)
        if right is not None:
            _collect_uses(right, ctx, addr=addr)
        return

    src_var = ""
    operand = _text(right, ctx.source).strip()
    if left.type == "identifier":
        src_var = _text(left, ctx.source)
    elif right.type == "identifier":
        src_var = _text(right, ctx.source)
        operand = _text(left, ctx.source).strip()

    ctx.emit(FactKind.ARITH_OP, addr,
             dst_var=dst_var or "tmp", dst_ver=dst_ver,
             op=arith, src_var=src_var, src_ver=0, operand=operand)

    _collect_uses(left, ctx, addr=addr)
    _collect_uses(right, ctx, addr=addr)


def _is_field_or_subscript(node: Node) -> bool:
    return node.type in ("field_expression", "subscript_expression")


def _field_var_name(node: Node, source: bytes) -> str:
    """Get the rightmost name component of a field/subscript expression so
    `h->current_slice` → 'current_slice' (suitable as the var key in
    Datalog Def/Use/ArithOp/Guard rows). Falls back to full text for
    subscripts and unusual shapes."""
    if node.type == "field_expression":
        f = node.child_by_field_name("field")
        if f is not None:
            return _text(f, source)
    return _text(node, source).strip()


def _handle_update(node: Node, ctx: _Ctx):
    arg = node.child_by_field_name("argument")
    op_node = node.child_by_field_name("operator")
    if arg is None or op_node is None:
        return
    op = _text(op_node, ctx.source)
    arith = "add" if op == "++" else "sub" if op == "--" else None
    addr = _line(node)

    if arg.type == "identifier":
        var = _text(arg, ctx.source)
        ctx.emit(FactKind.USE, addr, var=var, ver=0)
        ctx.emit(FactKind.DEF, addr, var=var, ver=0)
        if arith is not None:
            ctx.emit(FactKind.ARITH_OP, addr,
                     dst_var=var, dst_ver=0, op=arith,
                     src_var=var, src_ver=0, operand="1")
        return

    if _is_field_or_subscript(arg):
        # `++h->current_slice` or `arr[i]++`. Emit a FieldWrite/MemWrite,
        # an ArithOp on the field's leaf name, and Use facts for any
        # base / index identifiers.
        var = _field_var_name(arg, ctx.source)
        if arg.type == "field_expression":
            base = arg.child_by_field_name("argument")
            field = arg.child_by_field_name("field")
            if base is not None and field is not None:
                ctx.emit(FactKind.FIELD_WRITE, addr,
                         base=_text(base, ctx.source),
                         field=_text(field, ctx.source),
                         mem_in=0, mem_out=0)
                # Field also reads itself for the increment.
                ctx.emit(FactKind.FIELD_READ, addr,
                         base=_text(base, ctx.source),
                         field=_text(field, ctx.source))
                _collect_uses(base, ctx, addr=addr)
        else:  # subscript_expression
            base_text = _pointer_base_text(arg, ctx.source)
            if base_text:
                ctx.emit(FactKind.MEM_WRITE, addr,
                         target=base_text, mem_in=0, mem_out=0)
            _collect_uses(arg, ctx, addr=addr)
        if arith is not None:
            # Treat the leaf name (e.g. `current_slice`) as the counter
            # so UnboundedCounter / HasUpperBound rules can compose it.
            ctx.emit(FactKind.ARITH_OP, addr,
                     dst_var=var, dst_ver=0, op=arith,
                     src_var=var, src_ver=0, operand="1")
            ctx.emit(FactKind.USE, addr, var=var, ver=0)
            ctx.emit(FactKind.DEF, addr, var=var, ver=0)
        return

    _collect_uses(arg, ctx, addr=addr)


# ── Field/MemRead ────────────────────────────────────────────────────────────

def _handle_field_read(node: Node, ctx: _Ctx):
    base = node.child_by_field_name("argument")
    field = node.child_by_field_name("field")
    if base is None or field is None:
        return
    ctx.emit(FactKind.FIELD_READ, _line(node),
             base=_text(base, ctx.source), field=_text(field, ctx.source))


def _handle_mem_read(node: Node, ctx: _Ctx):
    base_text = _pointer_base_text(node, ctx.source)
    if not base_text:
        return
    offset_text = "0"
    if node.type == "subscript_expression":
        idx_node = node.child_by_field_name("index")
        if idx_node is not None:
            offset_text = _text(idx_node, ctx.source).strip()
    ctx.emit(FactKind.MEM_READ, _line(node),
             base=base_text, offset=offset_text, size="?")


def _pointer_base_text(node: Node, source: bytes) -> str:
    if node.type == "pointer_expression":
        arg = node.child_by_field_name("argument")
        if arg is not None:
            return _text(arg, source).strip()
    if node.type == "subscript_expression":
        arg = node.child_by_field_name("argument")
        if arg is not None:
            return _text(arg, source).strip()
    return ""


# ── Use collection ──────────────────────────────────────────────────────────

# Identifiers we never emit Use for (keywords, sentinel constants).
_USE_SKIP = {
    "NULL", "true", "false", "TRUE", "FALSE", "sizeof",
    "alignof", "_Alignof", "_Alignas",
}


def _collect_uses(node: Node, ctx: _Ctx, addr: int,
                  arith_dst: Optional[str] = None):
    """Walk an expression and emit Use facts. Also emits ArithOp for
    any arithmetic binary_expression encountered (size calculations
    inside call args are the dominant case — `malloc(n+1)` etc.)."""
    if node.type == "identifier":
        name = _text(node, ctx.source)
        if name in _USE_SKIP:
            return
        if name and name[0].isupper() and name not in ctx.type_env:
            return
        ctx.emit(FactKind.USE, addr, var=name, ver=0)
        return
    if node.type == "call_expression":
        args = node.child_by_field_name("arguments")
        if args is not None:
            for child in args.children:
                if child.type not in ("(", ")", ","):
                    _collect_uses(child, ctx, addr=addr)
        return
    if node.type == "field_expression":
        base = node.child_by_field_name("argument")
        if base is not None:
            _collect_uses(base, ctx, addr=addr)
        return
    if node.type == "binary_expression":
        op_node = node.child_by_field_name("operator")
        op = _text(op_node, ctx.source) if op_node else ""
        if op in ARITH_BIN_OPS:
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            src_var = ""
            operand = _text(right, ctx.source).strip() if right is not None else ""
            if left is not None and left.type == "identifier":
                src_var = _text(left, ctx.source)
            elif right is not None and right.type == "identifier":
                src_var = _text(right, ctx.source)
                operand = _text(left, ctx.source).strip() if left is not None else ""
            ctx.emit(FactKind.ARITH_OP, addr,
                     dst_var=arith_dst or "tmp", dst_ver=0,
                     op=ARITH_BIN_OPS[op], src_var=src_var, src_ver=0,
                     operand=operand)
        # Recurse into both sides regardless of op kind (cmp/logical too).
        for child in node.children:
            _collect_uses(child, ctx, addr=addr)
        return
    if node.type == "cast_expression":
        _handle_cast(node, ctx, dst_var=arith_dst, addr=addr)
        return
    for child in node.children:
        _collect_uses(child, ctx, addr=addr)


# ── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python mechanical_extractor.py <file.c> [func_name] [output_dir]")
        sys.exit(1)
    file_path = sys.argv[1]
    if len(sys.argv) >= 3:
        func = sys.argv[2]
        facts = extract_facts(file_path, func)
        print(f"Extracted {len(facts)} facts for {func}:")
    else:
        all_facts = extract_facts_all(file_path)
        facts = [f for fs in all_facts.values() for f in fs]
        print(f"Extracted {len(facts)} facts across {len(all_facts)} functions.")
        for name, fs in sorted(all_facts.items()):
            print(f"  {name:40s} {len(fs)}")
    if len(sys.argv) >= 4:
        out_dir = sys.argv[3]
        stats = write_facts(facts, out_dir)
        print(f"Wrote to {out_dir}/:")
        for fname, count in sorted(stats.items()):
            print(f"  {fname:25s} {count}")

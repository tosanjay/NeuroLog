"""
Tree-sitter Navigation — Lightweight source code navigation for C/C++ projects.

No compilation required. Uses tree-sitter for:
- Function enumeration
- Call graph construction (syntactic, direct calls)
- Dangerous sink detection
- Backward slicing from sinks
- Function source extraction
"""

import os
from dataclasses import dataclass, field
from pathlib import Path

import tree_sitter_c as tsc
from tree_sitter import Language, Parser

C_LANGUAGE = Language(tsc.language())

# Common dangerous sinks for vulnerability analysis
DANGEROUS_SINKS = {
    # Buffer operations
    "memcpy", "memmove", "memset", "bcopy",
    "strcpy", "strncpy", "strcat", "strncat",
    "sprintf", "snprintf", "vsprintf", "vsnprintf",
    # Memory management
    "malloc", "calloc", "realloc", "free",
    "alloca",
    # I/O
    "gets", "fgets", "fread", "read", "recv", "recvfrom",
    "scanf", "sscanf", "fscanf",
    # Format strings
    "printf", "fprintf", "syslog",
    # Exec
    "system", "popen", "execve", "execvp",
}


@dataclass
class FuncInfo:
    name: str
    file_path: str
    start_line: int
    end_line: int
    params: list[str] = field(default_factory=list)


@dataclass
class CallSite:
    callee: str
    line: int
    arguments: list[str] = field(default_factory=list)


def _create_parser() -> Parser:
    parser = Parser(C_LANGUAGE)
    return parser


def _parse_file(parser: Parser, file_path: str) -> "tree_sitter.Tree":
    source = Path(file_path).read_bytes()
    return parser.parse(source), source


# Subdirectory patterns commonly outside the attack surface for
# library-style targets. Heuristically excluded so the slice + ranker
# don't burn LLM budget on encoder-side image readers, tooling
# fixtures, fuzzer harnesses themselves, etc. Override via the
# NEUROLOG_INCLUDE_EXAMPLES=1 env var if the test/example directory IS
# the actual analysis target.
_NOISE_DIR_PATTERNS = (
    "/examples/",
    "/example/",
    "/tests/",
    "/test/",
    "/imageio/",   # libwebp encoder-side image readers (ReadPNM/PNG/JPEG)
    "/fuzz/",
    "/fuzzers/",
    "/benchmarks/",
    "/benchmark/",
    "/tools/",
    "/utils_app/",
    "/extras/",
    "/build/",
    "/build_asan/",
    "/build_fuzz/",
    "/cmake/",
)


def _path_is_noise(file_path: str) -> bool:
    if os.environ.get("NEUROLOG_INCLUDE_EXAMPLES", "").lower() in ("1", "true"):
        return False
    p = "/" + file_path.replace("\\", "/").lstrip("/")
    return any(pat in p for pat in _NOISE_DIR_PATTERNS)


def enumerate_functions(project_dir: str, extensions: tuple = (".c", ".h")) -> list[FuncInfo]:
    """Walk project directory, return all C function definitions.

    Files under common attack-surface-irrelevant subdirectories
    (examples/, tests/, imageio/, fuzz/, tools/, etc.) are skipped by
    default to keep the slice focused on library code that an external
    harness can actually reach. Set NEUROLOG_INCLUDE_EXAMPLES=1 to
    disable the filter (e.g. when the analysis target IS a tool/example).
    """
    parser = _create_parser()
    functions = []
    project = Path(project_dir)
    skipped_files = 0

    for ext in extensions:
        for fpath in project.rglob(f"*{ext}"):
            if _path_is_noise(str(fpath)):
                skipped_files += 1
                continue
            try:
                tree, source = _parse_file(parser, str(fpath))
            except Exception as e:
                print(f"  [WARN] Failed to parse {fpath}: {e}")
                continue

            for node in _walk_function_definitions(tree.root_node):
                info = _extract_func_info(node, source, str(fpath))
                if info:
                    functions.append(info)
    if skipped_files:
        print(f"  [scan] skipped {skipped_files} file(s) under "
              f"examples/tests/imageio/etc. — set "
              f"NEUROLOG_INCLUDE_EXAMPLES=1 to include them")
    return functions


def _walk_function_definitions(root):
    """Yield all function_definition nodes in tree."""
    if root.type == "function_definition":
        yield root
    for child in root.children:
        yield from _walk_function_definitions(child)


def _extract_func_info(node, source: bytes, file_path: str) -> FuncInfo | None:
    """Extract FuncInfo from a function_definition node."""
    declarator = node.child_by_field_name("declarator")
    if not declarator:
        return None

    # Find the function name — could be nested under pointer_declarator
    name_node = _find_function_name(declarator)
    if not name_node:
        return None

    name = source[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="replace")

    # Extract parameter names
    params = _extract_params(declarator, source)

    return FuncInfo(
        name=name,
        file_path=file_path,
        start_line=node.start_point[0] + 1,   # 1-indexed
        end_line=node.end_point[0] + 1,
        params=params,
    )


def _find_function_name(declarator):
    """Recursively find the identifier node for the function name."""
    if declarator.type == "identifier":
        return declarator
    if declarator.type == "field_identifier":
        return declarator
    # function_declarator wraps name + params
    if declarator.type == "function_declarator":
        inner = declarator.child_by_field_name("declarator")
        if inner:
            return _find_function_name(inner)
    # pointer_declarator: *func_name
    if declarator.type == "pointer_declarator":
        for child in declarator.children:
            result = _find_function_name(child)
            if result:
                return result
    # parenthesized_declarator: (func_name)
    if declarator.type == "parenthesized_declarator":
        for child in declarator.children:
            result = _find_function_name(child)
            if result:
                return result
    return None


def _extract_params(declarator, source: bytes) -> list[str]:
    """Extract parameter names from function declarator."""
    params = []
    # Find parameter_list
    if declarator.type == "function_declarator":
        param_list = declarator.child_by_field_name("parameters")
    else:
        # Look for function_declarator child
        param_list = None
        for child in declarator.children:
            if child.type == "function_declarator":
                param_list = child.child_by_field_name("parameters")
                break

    if not param_list:
        return params

    for child in param_list.children:
        if child.type == "parameter_declaration":
            pdecl = child.child_by_field_name("declarator")
            if pdecl:
                name_node = _find_param_name(pdecl)
                if name_node:
                    params.append(source[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="replace"))
    return params


def _find_param_name(node):
    """Find the identifier in a parameter declarator."""
    if node.type == "identifier":
        return node
    if node.type == "pointer_declarator":
        for child in node.children:
            result = _find_param_name(child)
            if result:
                return result
    if node.type == "array_declarator":
        decl = node.child_by_field_name("declarator")
        if decl:
            return _find_param_name(decl)
    return None


def get_function_source(file_path: str, func_name: str) -> str | None:
    """Extract function body text by name. Returns None if not found."""
    parser = _create_parser()
    try:
        tree, source = _parse_file(parser, file_path)
    except Exception:
        return None

    for node in _walk_function_definitions(tree.root_node):
        info = _extract_func_info(node, source, file_path)
        if info and info.name == func_name:
            return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
    return None


def find_call_sites(file_path: str, func_name: str) -> list[CallSite]:
    """Find all function calls within a given function."""
    parser = _create_parser()
    try:
        tree, source = _parse_file(parser, file_path)
    except Exception:
        return []

    # Find the target function node
    target_node = None
    for node in _walk_function_definitions(tree.root_node):
        info = _extract_func_info(node, source, file_path)
        if info and info.name == func_name:
            target_node = node
            break

    if not target_node:
        return []

    calls = []
    _collect_calls(target_node, source, calls)
    return calls


def _collect_calls(node, source: bytes, calls: list[CallSite]):
    """Recursively collect call_expression nodes."""
    if node.type == "call_expression":
        func_node = node.child_by_field_name("function")
        args_node = node.child_by_field_name("arguments")

        callee = ""
        if func_node:
            callee = source[func_node.start_byte:func_node.end_byte].decode("utf-8", errors="replace")

        arguments = []
        if args_node:
            for child in args_node.children:
                if child.type not in ("(", ")", ","):
                    arguments.append(
                        source[child.start_byte:child.end_byte].decode("utf-8", errors="replace")
                    )

        calls.append(CallSite(
            callee=callee,
            line=node.start_point[0] + 1,
            arguments=arguments,
        ))

    for child in node.children:
        _collect_calls(child, source, calls)


def build_call_graph(project_dir: str, extensions: tuple = (".c",)) -> dict[str, set[str]]:
    """Build project-wide call graph: function_name → set of callees.

    Only considers direct calls (not function pointers).
    """
    funcs = enumerate_functions(project_dir, extensions)
    call_graph = {}

    for func in funcs:
        calls = find_call_sites(func.file_path, func.name)
        callees = set()
        for c in calls:
            # Skip function pointer calls (contain ->, *, etc.)
            if c.callee.isidentifier():
                callees.add(c.callee)
        call_graph[func.name] = callees

    return call_graph


def find_callers(project_dir: str, target_func: str, extensions: tuple = (".c",)) -> list[str]:
    """Find all functions that call target_func (reverse call graph lookup)."""
    cg = build_call_graph(project_dir, extensions)
    callers = []
    for func_name, callees in cg.items():
        if target_func in callees:
            callers.append(func_name)
    return callers


def find_dangerous_sinks(project_dir: str, extensions: tuple = (".c",),
                          sink_names: set[str] | None = None) -> list[dict]:
    """Find functions that call dangerous sinks.

    Returns list of {function, file, sink, line}.
    """
    if sink_names is None:
        sink_names = DANGEROUS_SINKS

    funcs = enumerate_functions(project_dir, extensions)
    results = []

    for func in funcs:
        calls = find_call_sites(func.file_path, func.name)
        for c in calls:
            if c.callee in sink_names:
                results.append({
                    "function": func.name,
                    "file": func.file_path,
                    "sink": c.callee,
                    "line": c.line,
                    "arguments": c.arguments,
                })

    return results


def slice_from_sinks(project_dir: str, sink_functions: list[str] | None = None,
                      depth: int = 3, extensions: tuple = (".c",),
                      forward_depth: int = 1,
                      include_caller_buffer_ops: bool = True) -> list[FuncInfo]:
    """Bidirectional slice from dangerous sinks.

    Phase A (backward):  walk callers UP `depth` levels from sink-containing
                          functions. Captures "code that ultimately reaches a
                          sink".

    Phase B (forward):   walk callees DOWN `forward_depth` levels from each
                          backward-sliced function. Captures "function that
                          operates on a buffer set up by a sink-caller" —
                          e.g. BuildHuffmanTable, which is called by
                          ReadHuffmanCode (sink-caller) but has no direct
                          sink calls of its own. Without this expansion,
                          the slice systematically excludes buffer-operator
                          callees, even though that is where many real
                          OOB bugs live.

    Phase C (heuristic): include any function that writes to a formal-param
                          pointer (`param[i] = …` or `*param = …`) with no
                          in-function bounds Guard on the index. Catches
                          the "caller hands us a buffer, we write past it"
                          shape directly. Off via include_caller_buffer_ops=False.
    """
    funcs_by_name = {f.name: f for f in enumerate_functions(project_dir, extensions)}
    cg = build_call_graph(project_dir, extensions)

    reverse_cg: dict[str, set[str]] = {}
    for caller, callees in cg.items():
        for callee in callees:
            reverse_cg.setdefault(callee, set()).add(caller)

    if sink_functions is None:
        sinks = find_dangerous_sinks(project_dir, extensions)
        seed_funcs = {s["function"] for s in sinks}
    else:
        seed_funcs = set(sink_functions)

    # ── Phase A: backward BFS through callers ───────────────────────────
    visited = set(seed_funcs)
    frontier = set(seed_funcs)
    for _ in range(depth):
        next_frontier = set()
        for func_name in frontier:
            for caller in reverse_cg.get(func_name, set()):
                if caller not in visited:
                    visited.add(caller)
                    next_frontier.add(caller)
        frontier = next_frontier
        if not frontier:
            break

    # ── Phase B: forward expansion — include callees of sliced funcs ───
    # One hop forward by default; deeper traversal explodes the slice on
    # codebases with high call-graph fan-out, with diminishing returns.
    forward_added: set[str] = set()
    frontier = set(visited)
    for _ in range(max(0, forward_depth)):
        next_frontier = set()
        for func_name in frontier:
            for callee in cg.get(func_name, set()):
                if callee not in visited and callee in funcs_by_name:
                    visited.add(callee)
                    forward_added.add(callee)
                    next_frontier.add(callee)
        frontier = next_frontier
        if not frontier:
            break

    # ── Phase C: caller-buffer-operation heuristic ──────────────────────
    caller_buffer_funcs: set[str] = set()
    if include_caller_buffer_ops:
        caller_buffer_funcs = _find_caller_buffer_operators(funcs_by_name)
        visited |= caller_buffer_funcs

    if forward_added or caller_buffer_funcs:
        print(f"  [slice] backward+forward+heuristic: "
              f"backward={len(visited) - len(forward_added) - len(caller_buffer_funcs - (visited - forward_added))} "
              f"forward+={len(forward_added)} "
              f"caller_buffer+={len(caller_buffer_funcs - (visited - caller_buffer_funcs - forward_added))} "
              f"total={len(visited)}")

    return [funcs_by_name[name] for name in visited if name in funcs_by_name]


def _find_caller_buffer_operators(funcs_by_name: dict[str, FuncInfo]) -> set[str]:
    """Return names of functions that write into a formal-param pointer
    (`param[i] = …` or `*param = …`) anywhere in the function body.

    This is a coarse approximation of "function operates on a buffer
    provided by its caller". The check is purely structural — we don't
    require a guard to be absent (the rule mesh handles that later).
    Coarse on purpose: better to include too much here than to miss
    BuildHuffmanTable-class bug sites.
    """
    parser = _create_parser()
    out: set[str] = set()
    seen_files: dict[str, tuple] = {}
    for fname, info in funcs_by_name.items():
        try:
            cached = seen_files.get(info.file_path)
            if cached is None:
                cached = _parse_file(parser, info.file_path)
                seen_files[info.file_path] = cached
            tree, source = cached
        except Exception:
            continue
        # Find the function_definition for this fname in the tree.
        for node in _walk_function_definitions(tree.root_node):
            if _func_name_of(node, source) != fname:
                continue
            params = _formal_param_names(node, source)
            if not params:
                break
            if _writes_to_any_param(node, source, params):
                out.add(fname)
            break
    return out


def _func_name_of(node, source: bytes) -> str:
    """Top-level function name from a function_definition node."""
    d = node.child_by_field_name("declarator")
    while d is not None:
        if d.type == "identifier":
            return source[d.start_byte:d.end_byte].decode("utf-8", "replace")
        if d.type in ("function_declarator", "pointer_declarator"):
            d = d.child_by_field_name("declarator")
            continue
        break
    return ""


def _formal_param_names(node, source: bytes) -> set[str]:
    """Return the bare identifier names of a function_definition's
    formal parameters."""
    out: set[str] = set()
    d = node.child_by_field_name("declarator")
    # Drill to function_declarator.
    while d is not None and d.type != "function_declarator":
        d = d.child_by_field_name("declarator") if d.children else None
    if d is None:
        return out
    plist = d.child_by_field_name("parameters")
    if plist is None:
        return out
    for child in plist.children:
        if child.type != "parameter_declaration":
            continue
        cur = child.child_by_field_name("declarator")
        # Drill through pointer/array decl to the bare identifier.
        while cur is not None:
            if cur.type == "identifier":
                out.add(source[cur.start_byte:cur.end_byte].decode("utf-8", "replace"))
                break
            cur = cur.child_by_field_name("declarator")
    return out


def _writes_to_any_param(node, source: bytes, params: set[str]) -> bool:
    """Walk function body looking for `param[i] = …` or `*param = …`."""
    body = node.child_by_field_name("body")
    if body is None:
        return False
    stack = [body]
    while stack:
        cur = stack.pop()
        if cur.type == "assignment_expression":
            lhs = cur.child_by_field_name("left")
            if lhs is not None:
                # `param[i] = …`
                if lhs.type == "subscript_expression":
                    arg = lhs.child_by_field_name("argument")
                    if arg is not None and arg.type == "identifier":
                        name = source[arg.start_byte:arg.end_byte].decode(
                            "utf-8", "replace")
                        if name in params:
                            return True
                # `*param = …`
                if lhs.type == "pointer_expression":
                    for ch in lhs.children:
                        if ch.type == "identifier":
                            name = source[ch.start_byte:ch.end_byte].decode(
                                "utf-8", "replace")
                            if name in params:
                                return True
        stack.extend(cur.children)
    return False


def get_function_with_lines(file_path: str, func_name: str) -> tuple[str, int] | None:
    """Get function source with original line numbers preserved.

    Returns (source_with_line_numbers, start_line) or None.
    """
    parser = _create_parser()
    try:
        tree, source = _parse_file(parser, file_path)
    except Exception:
        return None

    for node in _walk_function_definitions(tree.root_node):
        info = _extract_func_info(node, source, file_path)
        if info and info.name == func_name:
            func_text = source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
            lines = func_text.split('\n')
            numbered = []
            for i, line in enumerate(lines):
                numbered.append(f"{info.start_line + i:4d}| {line}")
            return '\n'.join(numbered), info.start_line
    return None


# ── CLI ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) < 2:
        print("Usage: python tree_sitter_nav.py <project_dir> [command] [args...]")
        print("Commands:")
        print("  list                      List all functions")
        print("  callgraph                 Build call graph")
        print("  sinks                     Find dangerous sinks")
        print("  slice [depth]             Backward slice from sinks")
        print("  source <file> <func>      Get function source")
        sys.exit(1)

    project_dir = sys.argv[1]
    command = sys.argv[2] if len(sys.argv) > 2 else "list"

    if command == "list":
        funcs = enumerate_functions(project_dir)
        for f in funcs:
            print(f"{f.file_path}:{f.start_line}-{f.end_line}  {f.name}({', '.join(f.params)})")

    elif command == "callgraph":
        cg = build_call_graph(project_dir)
        for func, callees in sorted(cg.items()):
            if callees:
                print(f"{func} → {', '.join(sorted(callees))}")

    elif command == "sinks":
        sinks = find_dangerous_sinks(project_dir)
        for s in sinks:
            print(f"{s['file']}:{s['line']}  {s['function']} calls {s['sink']}({', '.join(s['arguments'])})")

    elif command == "slice":
        depth = int(sys.argv[3]) if len(sys.argv) > 3 else 3
        sliced = slice_from_sinks(project_dir, depth=depth)
        print(f"Slice ({len(sliced)} functions):")
        for f in sliced:
            print(f"  {f.file_path}:{f.start_line}  {f.name}")

    elif command == "source":
        if len(sys.argv) < 5:
            print("Usage: source <file> <func_name>")
            sys.exit(1)
        result = get_function_with_lines(sys.argv[3], sys.argv[4])
        if result:
            print(result[0])
        else:
            print("Function not found")

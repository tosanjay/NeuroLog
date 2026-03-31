"""
Tree-sitter Navigation — Lightweight source code navigation for C/C++ projects.

No compilation required. Uses tree-sitter for:
- Function enumeration
- Call graph construction (syntactic, direct calls)
- Dangerous sink detection
- Backward slicing from sinks
- Function source extraction
"""

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


def enumerate_functions(project_dir: str, extensions: tuple = (".c", ".h")) -> list[FuncInfo]:
    """Walk project directory, return all C function definitions."""
    parser = _create_parser()
    functions = []
    project = Path(project_dir)

    for ext in extensions:
        for fpath in project.rglob(f"*{ext}"):
            try:
                tree, source = _parse_file(parser, str(fpath))
            except Exception as e:
                print(f"  [WARN] Failed to parse {fpath}: {e}")
                continue

            for node in _walk_function_definitions(tree.root_node):
                info = _extract_func_info(node, source, str(fpath))
                if info:
                    functions.append(info)

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
                      depth: int = 3, extensions: tuple = (".c",)) -> list[FuncInfo]:
    """Backward slice from dangerous sinks up to `depth` caller levels.

    1. Find functions containing dangerous sink calls
    2. Trace callers backward up to `depth` levels
    3. Return the set of all functions in the slice

    If sink_functions is None, uses find_dangerous_sinks to discover them.
    """
    funcs_by_name = {f.name: f for f in enumerate_functions(project_dir, extensions)}
    cg = build_call_graph(project_dir, extensions)

    # Reverse call graph
    reverse_cg: dict[str, set[str]] = {}
    for caller, callees in cg.items():
        for callee in callees:
            reverse_cg.setdefault(callee, set()).add(caller)

    # Seed: functions containing sink calls
    if sink_functions is None:
        sinks = find_dangerous_sinks(project_dir, extensions)
        seed_funcs = {s["function"] for s in sinks}
    else:
        seed_funcs = set(sink_functions)

    # BFS backward through callers
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

    # Return FuncInfo for all visited functions
    return [funcs_by_name[name] for name in visited if name in funcs_by_name]


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

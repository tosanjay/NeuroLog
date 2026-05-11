"""
Tree-sitter CFG/BB Lowering — Compute control-flow facts deterministically
from the C AST. Replaces the LLM's CFGEdge enumeration; the LLM only fills
gaps for opaque sites (control-flow macros, longjmp, inline asm).

Emits four fact relations:
  CFGEdge.facts        (func, from_line, to_line)
  BlockHead.facts      (func, line, block_id)
  CFGBlockEdge.facts   (func, src_block, dst_block)
  OpaqueCallSite.facts (func, line, callee, reason)

Block IDs are the leader's source line, so dominance results stay
human-readable: "block led by line 245 dominates block led by line 312."
"""

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

import tree_sitter_c as tsc
from tree_sitter import Language, Parser

C_LANGUAGE = Language(tsc.language())

# Libc / common built-ins — calls to these don't affect CFG (return normally).
KNOWN_LIBC = frozenset([
    "malloc", "calloc", "realloc", "free", "alloca", "reallocarray",
    "memcpy", "memmove", "memset", "memcmp", "memchr", "bcopy", "bzero",
    "strcpy", "strncpy", "strcat", "strncat", "strlen", "strnlen",
    "strcmp", "strncmp", "strcasecmp", "strncasecmp",
    "strchr", "strrchr", "strstr", "strdup", "strndup", "strerror",
    "strspn", "strcspn", "strpbrk", "strtok", "strtok_r",
    "sprintf", "snprintf", "vsprintf", "vsnprintf", "asprintf", "vasprintf",
    "printf", "fprintf", "vprintf", "vfprintf", "dprintf",
    "scanf", "fscanf", "sscanf", "vscanf", "vfscanf", "vsscanf",
    "fopen", "fdopen", "freopen", "fclose", "fread", "fwrite", "fgets",
    "fputs", "fputc", "fgetc", "fseek", "ftell", "rewind", "fflush",
    "feof", "ferror", "clearerr", "setbuf", "setvbuf", "ungetc",
    "open", "openat", "creat", "close", "read", "write", "pread", "pwrite",
    "lseek", "stat", "fstat", "lstat", "fstatat", "access", "unlink",
    "mkdir", "rmdir", "rename", "chmod", "chown", "umask",
    "recv", "recvfrom", "recvmsg", "send", "sendto", "sendmsg",
    "socket", "bind", "listen", "accept", "connect", "getsockopt", "setsockopt",
    "getenv", "setenv", "putenv", "unsetenv", "secure_getenv",
    "fork", "vfork", "wait", "waitpid", "kill", "raise", "signal", "sigaction",
    "pthread_create", "pthread_join", "pthread_mutex_lock",
    "pthread_mutex_unlock", "pthread_mutex_init", "pthread_mutex_destroy",
    "pthread_cond_wait", "pthread_cond_signal", "pthread_cond_broadcast",
    "pthread_rwlock_rdlock", "pthread_rwlock_wrlock", "pthread_rwlock_unlock",
    "atoi", "atol", "atoll", "atof", "strtol", "strtoll", "strtoul",
    "strtoull", "strtod", "strtof", "strtold",
    "abs", "labs", "llabs", "div", "ldiv", "lldiv",
    "isalpha", "isdigit", "isalnum", "isspace", "isupper", "islower",
    "isxdigit", "iscntrl", "isprint", "ispunct", "isgraph",
    "tolower", "toupper",
    "qsort", "bsearch", "lfind", "lsearch",
    "time", "clock", "gettimeofday", "ctime", "localtime", "gmtime",
    "mktime", "strftime", "asctime", "difftime",
    "rand", "srand", "random", "srandom", "drand48", "lrand48",
    "perror",
    "gets", "puts",
    "getopt", "getopt_long",
    "getline", "getdelim",
    "mmap", "mmap64", "munmap", "mprotect", "msync", "madvise",
    "dlopen", "dlclose", "dlsym", "dlerror",
    "ioctl", "fcntl", "select", "poll", "epoll_wait", "epoll_ctl",
    # Common C++ runtime entries that look like C from the AST level.
    "operator new", "operator delete",
])

# Calls that introduce non-local control flow — flag for LLM resolution.
NONLOCAL_CONTROL_FLOW = frozenset([
    "setjmp", "longjmp", "sigsetjmp", "siglongjmp",
    "_setjmp", "_longjmp", "__sigsetjmp",
    "__builtin_setjmp", "__builtin_longjmp",
])

# Calls that don't return — successor edges should not be emitted.
NORETURN_FUNCS = frozenset([
    "exit", "_exit", "_Exit", "abort", "__assert_fail", "__assert",
    "__builtin_unreachable", "__builtin_trap",
    "longjmp", "siglongjmp", "_longjmp",
    "thrd_exit", "pthread_exit",
    "err", "errx", "verr", "verrx",   # BSD err.h family
    "g_assert_not_reached", "g_error",  # glib
    "__chk_fail",
])


# ─────────────────────────────────────────────────────────────────────────
# Data containers
# ─────────────────────────────────────────────────────────────────────────

@dataclass
class FunctionCFG:
    func: str
    edges: set = field(default_factory=set)         # {(from_line, to_line)}
    block_heads: dict = field(default_factory=dict) # {line: block_id}
    block_edges: set = field(default_factory=set)   # {(src_block, dst_block)}
    opaque_sites: list = field(default_factory=list)  # [(line, callee, reason)]
    entry_line: int = 0
    end_line: int = 0


# ─────────────────────────────────────────────────────────────────────────
# CFG builder
# ─────────────────────────────────────────────────────────────────────────

class _CFGBuilder:
    def __init__(self, source: bytes, func_name: str, project_funcs: set):
        self.source = source
        self.func_name = func_name
        self.project_funcs = project_funcs
        self.edges: set = set()
        self.opaque_sites: list = []
        self.label_targets: dict = {}    # label_name -> line
        self.pending_gotos: list = []    # [(from_line, label_name)]
        self.loop_stack: list = []       # [(continue_target, break_exits_set)]
        self.switch_stack: list = []     # [break_exits_set]

    # ── helpers ────────────────────────────────────────────────────────
    def _line(self, node) -> int:
        return node.start_point[0] + 1

    def _text(self, node) -> str:
        return self.source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

    def _add_edge(self, src: int, dst: int):
        # Skip self-edges. They arise when control-flow constructs share a
        # line with their body (e.g. `if (n < 0) return -1;` puts the if
        # cond and the return on the same line) and add no information for
        # dominance. The single legitimate self-loop case — empty-body
        # one-line loops `while (c) ;` — is too rare to special-case.
        if src and dst and src != dst:
            self.edges.add((int(src), int(dst)))

    def _link(self, exits, dst: int):
        for x in exits:
            self._add_edge(x, dst)

    def _iter_descendants(self, node):
        stack = [node]
        while stack:
            n = stack.pop()
            yield n
            stack.extend(n.children)

    # ── entry point ────────────────────────────────────────────────────
    def build_function(self, body_node) -> tuple[int, set]:
        """Build CFG for a function body (compound_statement). Returns
        (entry_line, exit_lines)."""
        if body_node is None:
            return 0, set()
        entry, exits = self._build(body_node)
        # Resolve gotos against collected labels.
        for src, label in self.pending_gotos:
            tgt = self.label_targets.get(label)
            if tgt is not None:
                self._add_edge(src, tgt)
        return entry, exits

    # ── statement dispatch ────────────────────────────────────────────
    def _build(self, node) -> tuple[int, set]:
        t = node.type
        builder = _DISPATCH.get(t, _CFGBuilder._build_simple)
        return builder(self, node)

    # Default: a single-line straight-through statement (declaration,
    # expression_statement we don't recognize as terminating, comments
    # already filtered).
    def _build_simple(self, node) -> tuple[int, set]:
        line = self._line(node)
        return line, {line}

    def _build_compound(self, node) -> tuple[int, set]:
        children = [c for c in node.children if _is_stmt_like(c)]
        if not children:
            line = self._line(node)
            return line, {line}
        entry = None
        prev_exits = None
        for child in children:
            ce, cx = self._build(child)
            if entry is None:
                entry = ce
            if prev_exits is not None:
                self._link(prev_exits, ce)
            prev_exits = cx
        return entry or self._line(node), prev_exits or set()

    def _build_if(self, node) -> tuple[int, set]:
        cond_line = self._line(node)
        cons = node.child_by_field_name("consequence")
        alt = node.child_by_field_name("alternative")
        exits: set = set()
        if cons is not None:
            ce, cx = self._build(cons)
            self._add_edge(cond_line, ce)
            exits |= cx
        else:
            exits.add(cond_line)
        if alt is not None:
            ae, ax = self._build(alt)
            self._add_edge(cond_line, ae)
            exits |= ax
        else:
            # No else: cond_line itself is an exit when condition is false.
            exits.add(cond_line)
        return cond_line, exits

    def _build_while(self, node) -> tuple[int, set]:
        cond_line = self._line(node)
        body = node.child_by_field_name("body")
        break_exits: set = set()
        self.loop_stack.append((cond_line, break_exits))
        if body is not None:
            be, bx = self._build(body)
            self._add_edge(cond_line, be)
            self._link(bx, cond_line)  # back-edge
        self.loop_stack.pop()
        return cond_line, {cond_line} | break_exits

    def _build_do(self, node) -> tuple[int, set]:
        body = node.child_by_field_name("body")
        cond = node.child_by_field_name("condition")
        cond_line = self._line(cond) if cond is not None else self._line(node)
        break_exits: set = set()
        self.loop_stack.append((cond_line, break_exits))
        entry = cond_line
        if body is not None:
            be, bx = self._build(body)
            self._link(bx, cond_line)
            self._add_edge(cond_line, be)  # back-edge when cond true
            entry = be
        self.loop_stack.pop()
        return entry, {cond_line} | break_exits

    def _build_for(self, node) -> tuple[int, set]:
        cond_line = self._line(node)  # for-line acts as init/cond/update header
        body = node.child_by_field_name("body")
        break_exits: set = set()
        self.loop_stack.append((cond_line, break_exits))
        if body is not None:
            be, bx = self._build(body)
            self._add_edge(cond_line, be)
            self._link(bx, cond_line)
        self.loop_stack.pop()
        return cond_line, {cond_line} | break_exits

    def _build_switch(self, node) -> tuple[int, set]:
        sw_line = self._line(node)
        body = node.child_by_field_name("body")
        break_exits: set = set()
        self.switch_stack.append(break_exits)
        if body is None or body.type != "compound_statement":
            self.switch_stack.pop()
            return sw_line, {sw_line}
        cases = [c for c in body.children if c.type == "case_statement"]
        prev_exits: set = set()
        has_default = False
        for case in cases:
            ce, cx = self._build_case(case)
            self._add_edge(sw_line, ce)
            self._link(prev_exits, ce)
            prev_exits = cx
            # Detect "default:" — case_statement with no `value` field.
            if case.child_by_field_name("value") is None:
                has_default = True
        self.switch_stack.pop()
        exits = prev_exits | break_exits
        if not has_default:
            exits.add(sw_line)  # value matches no case → fall through
        return sw_line, exits

    def _build_case(self, node) -> tuple[int, set]:
        case_line = self._line(node)
        # case_statement children: [`case`, value_expr, `:`, stmt1, stmt2, ...]
        # or                         [`default`,        `:`, stmt1, ...]
        seen_colon = False
        stmts = []
        for c in node.children:
            if c.type == ":":
                seen_colon = True
                continue
            if not seen_colon:
                continue
            if _is_stmt_like(c):
                stmts.append(c)
        if not stmts:
            return case_line, {case_line}
        entry = None
        prev_exits = None
        for s in stmts:
            ce, cx = self._build(s)
            if entry is None:
                entry = ce
                self._add_edge(case_line, ce)
            if prev_exits is not None:
                self._link(prev_exits, ce)
            prev_exits = cx
        return case_line, prev_exits or {case_line}

    def _build_break(self, node) -> tuple[int, set]:
        line = self._line(node)
        if self.loop_stack:
            _, brk = self.loop_stack[-1]
            brk.add(line)
        elif self.switch_stack:
            self.switch_stack[-1].add(line)
        return line, set()

    def _build_continue(self, node) -> tuple[int, set]:
        line = self._line(node)
        if self.loop_stack:
            cont_target, _ = self.loop_stack[-1]
            self._add_edge(line, cont_target)
        return line, set()

    def _build_return(self, node) -> tuple[int, set]:
        return self._line(node), set()

    def _build_goto(self, node) -> tuple[int, set]:
        line = self._line(node)
        # label is a `statement_identifier`
        for c in node.children:
            if c.type == "statement_identifier":
                self.pending_gotos.append((line, self._text(c)))
                break
        return line, set()

    def _build_labeled(self, node) -> tuple[int, set]:
        line = self._line(node)
        # First child is statement_identifier (label name); inner statement follows.
        for c in node.children:
            if c.type == "statement_identifier":
                self.label_targets[self._text(c)] = line
                break
        # Find the inner statement
        for c in node.children:
            if c.type not in ("statement_identifier", ":"):
                if _is_stmt_like(c):
                    ce, cx = self._build(c)
                    self._add_edge(line, ce)
                    return line, cx
        return line, {line}

    def _build_expression_stmt(self, node) -> tuple[int, set]:
        line = self._line(node)
        self._scan_calls(node, line)
        if self._is_noreturn_stmt(node):
            return line, set()
        return line, {line}

    # ── opaque-site detection ──────────────────────────────────────────
    def _scan_calls(self, node, stmt_line: int):
        """Walk node looking for call expressions and inline asm; flag the
        opaque ones for LLM resolution."""
        for sub in self._iter_descendants(node):
            t = sub.type
            if t == "call_expression":
                func = sub.child_by_field_name("function")
                if func is None:
                    continue
                if func.type == "identifier":
                    name = self._text(func)
                    self._maybe_flag_callee(stmt_line, name)
                # field_expression callees (function pointers like obj.f())
                # don't typically introduce non-local CFG; skip.
            elif t in ("gnu_asm_expression", "asm_expression"):
                self.opaque_sites.append((stmt_line, "asm", "inline_asm"))

    def _maybe_flag_callee(self, line: int, name: str):
        if name in NONLOCAL_CONTROL_FLOW:
            self.opaque_sites.append((line, name, "nonlocal_jump"))
            return
        if name in NORETURN_FUNCS or name in KNOWN_LIBC:
            return
        if name in self.project_funcs:
            return
        # Unknown callee: heuristically flag macro-shaped names.
        if name.isupper() and len(name) > 1:
            self.opaque_sites.append((line, name, "uppercase_macro"))
            return
        # Mixed-case identifier with at least one underscore and predominantly
        # uppercase is also macro-shaped (e.g., `RETURN_IF_ERR`, `BAIL_ON`).
        if "_" in name and sum(1 for c in name if c.isupper()) >= 2 \
                and sum(1 for c in name if c.islower()) == 0:
            self.opaque_sites.append((line, name, "uppercase_macro"))

    def _is_noreturn_stmt(self, node) -> bool:
        # expression_statement whose top-level expression is a call to a
        # noreturn function.
        for c in node.children:
            if c.type == "call_expression":
                func = c.child_by_field_name("function")
                if func is not None and func.type == "identifier":
                    return self._text(func) in NORETURN_FUNCS
        return False


# Statement node-types we treat as control-flow units.
_STMT_TYPES = frozenset([
    "compound_statement", "expression_statement", "declaration",
    "if_statement", "while_statement", "do_statement", "for_statement",
    "switch_statement", "case_statement",
    "break_statement", "continue_statement", "return_statement",
    "goto_statement", "labeled_statement",
])


def _is_stmt_like(node) -> bool:
    t = node.type
    if t in _STMT_TYPES:
        return True
    # Some declarations / expression statements come without explicit type
    # tags in unusual code; treat any non-punctuation, non-comment child as
    # a candidate statement.
    if t in ("{", "}", ";", "(", ")", ",", ":", "comment"):
        return False
    if t.startswith("preproc_"):
        return False
    return True


_DISPATCH = {
    "compound_statement":  _CFGBuilder._build_compound,
    "if_statement":        _CFGBuilder._build_if,
    "while_statement":     _CFGBuilder._build_while,
    "do_statement":        _CFGBuilder._build_do,
    "for_statement":       _CFGBuilder._build_for,
    "switch_statement":    _CFGBuilder._build_switch,
    "case_statement":      _CFGBuilder._build_case,
    "break_statement":     _CFGBuilder._build_break,
    "continue_statement":  _CFGBuilder._build_continue,
    "return_statement":    _CFGBuilder._build_return,
    "goto_statement":      _CFGBuilder._build_goto,
    "labeled_statement":   _CFGBuilder._build_labeled,
    "expression_statement": _CFGBuilder._build_expression_stmt,
}


# ─────────────────────────────────────────────────────────────────────────
# Basic-block computation from line-level CFG
# ─────────────────────────────────────────────────────────────────────────

def _compute_blocks(edges: set, entry: int) -> tuple[dict, set]:
    """Compute basic blocks from a line-level CFG. Block IDs are leader lines.

    Returns (block_heads: line→block_id, block_edges: {(src_blk, dst_blk)}).
    """
    succ: dict = defaultdict(set)
    pred: dict = defaultdict(set)
    nodes: set = set()
    for s, d in edges:
        succ[s].add(d)
        pred[d].add(s)
        nodes.add(s)
        nodes.add(d)
    if entry:
        nodes.add(entry)

    # Leader rules: entry; |preds|>=2; sole pred has |succs|>=2; or no preds
    # (unreachable code — give it its own block so analysis still runs).
    leaders: set = set()
    if entry:
        leaders.add(entry)
    for n in nodes:
        ps = pred[n]
        if len(ps) >= 2:
            leaders.add(n)
        elif len(ps) == 1:
            (p,) = tuple(ps)
            if len(succ[p]) >= 2:
                leaders.add(n)
        else:  # 0 preds
            leaders.add(n)

    block_heads: dict = {}
    for ld in leaders:
        block_heads[ld] = ld
        cur = ld
        while True:
            ss = succ[cur]
            if len(ss) != 1:
                break
            (nxt,) = tuple(ss)
            if nxt in leaders:
                break
            if len(pred[nxt]) != 1:
                break
            block_heads[nxt] = ld
            cur = nxt

    # Anything not yet assigned (shouldn't happen) becomes its own block.
    for n in nodes:
        block_heads.setdefault(n, n)

    block_edges: set = set()
    for s, d in edges:
        bs = block_heads.get(s, s)
        bd = block_heads.get(d, d)
        if bs != bd:
            block_edges.add((bs, bd))

    return block_heads, block_edges


# ─────────────────────────────────────────────────────────────────────────
# Tree-sitter file/function discovery
# ─────────────────────────────────────────────────────────────────────────

def _create_parser() -> Parser:
    return Parser(C_LANGUAGE)


def _walk_function_definitions(root):
    if root.type == "function_definition":
        yield root
    for child in root.children:
        yield from _walk_function_definitions(child)


def _func_name_node(declarator):
    if declarator is None:
        return None
    t = declarator.type
    if t in ("identifier", "field_identifier"):
        return declarator
    if t == "function_declarator":
        return _func_name_node(declarator.child_by_field_name("declarator"))
    if t in ("pointer_declarator", "parenthesized_declarator"):
        for c in declarator.children:
            r = _func_name_node(c)
            if r is not None:
                return r
    return None


def _extract_func_cfg(node, source: bytes, project_funcs: set) -> FunctionCFG | None:
    declarator = node.child_by_field_name("declarator")
    name_node = _func_name_node(declarator)
    if name_node is None:
        return None
    func_name = source[name_node.start_byte:name_node.end_byte].decode(
        "utf-8", errors="replace")
    body = node.child_by_field_name("body")
    if body is None:
        return None

    builder = _CFGBuilder(source, func_name, project_funcs)
    entry, _exits = builder.build_function(body)
    block_heads, block_edges = _compute_blocks(builder.edges, entry)

    return FunctionCFG(
        func=func_name,
        edges=builder.edges,
        block_heads=block_heads,
        block_edges=block_edges,
        opaque_sites=list(builder.opaque_sites),
        entry_line=node.start_point[0] + 1,
        end_line=node.end_point[0] + 1,
    )


def extract_cfg_for_file(
    file_path: str,
    project_funcs: set,
    func_filter: set | None = None,
) -> list[FunctionCFG]:
    """Parse a C source file and return per-function CFG facts.

    Args:
        file_path: Path to .c/.h file.
        project_funcs: Set of project-defined function names (used to decide
                       which call sites are opaque).
        func_filter: If provided, only return CFGs for functions in this set.
    """
    parser = _create_parser()
    try:
        source = Path(file_path).read_bytes()
        tree = parser.parse(source)
    except Exception as e:
        print(f"  [tree_sitter_cfg] Failed to parse {file_path}: {e}")
        return []

    out: list[FunctionCFG] = []
    for node in _walk_function_definitions(tree.root_node):
        cfg = _extract_func_cfg(node, source, project_funcs)
        if cfg is None:
            continue
        if func_filter is not None and cfg.func not in func_filter:
            continue
        out.append(cfg)
    return out


# ─────────────────────────────────────────────────────────────────────────
# Fact emission
# ─────────────────────────────────────────────────────────────────────────

def _append_tsv(path: Path, rows: set):
    """Append rows (tuples of strings) to a TSV file, deduplicating against
    existing content."""
    existing: set = set()
    if path.exists():
        text = path.read_text().strip()
        if text:
            for line in text.split("\n"):
                existing.add(tuple(line.split("\t")))
    merged = existing | {tuple(str(c) for c in r) for r in rows}
    with open(path, "w") as fp:
        for row in sorted(merged):
            fp.write("\t".join(row) + "\n")


def write_cfg_facts(cfgs: list[FunctionCFG], facts_dir: str | Path) -> dict:
    """Write CFG facts to .facts files in facts_dir (append/dedup mode).

    Writes:
        CFGEdge.facts        (func, from_line, to_line)
        BlockHead.facts      (func, line, block_id)
        CFGBlockEdge.facts   (func, src_block, dst_block)
        OpaqueCallSite.facts (func, line, callee, reason)

    Returns dict of relation → row count written.
    """
    facts_dir = Path(facts_dir)
    facts_dir.mkdir(parents=True, exist_ok=True)

    cfg_edge_rows: set = set()
    block_head_rows: set = set()
    block_edge_rows: set = set()
    opaque_rows: set = set()

    for cfg in cfgs:
        for s, d in cfg.edges:
            cfg_edge_rows.add((cfg.func, s, d))
        for line, blk in cfg.block_heads.items():
            block_head_rows.add((cfg.func, line, blk))
        for sb, db in cfg.block_edges:
            block_edge_rows.add((cfg.func, sb, db))
        for line, callee, reason in cfg.opaque_sites:
            opaque_rows.add((cfg.func, line, callee, reason))

    _append_tsv(facts_dir / "CFGEdge.facts", cfg_edge_rows)
    _append_tsv(facts_dir / "BlockHead.facts", block_head_rows)
    _append_tsv(facts_dir / "CFGBlockEdge.facts", block_edge_rows)
    _append_tsv(facts_dir / "OpaqueCallSite.facts", opaque_rows)

    return {
        "CFGEdge.facts": len(cfg_edge_rows),
        "BlockHead.facts": len(block_head_rows),
        "CFGBlockEdge.facts": len(block_edge_rows),
        "OpaqueCallSite.facts": len(opaque_rows),
    }


# ─────────────────────────────────────────────────────────────────────────
# Project-level orchestrator
# ─────────────────────────────────────────────────────────────────────────

def generate_cfg_facts_for_project(
    project_dir: str,
    func_names: list[str] | None = None,
    facts_dir: str | Path = "facts",
    extensions: tuple = (".c", ".h"),
) -> dict:
    """Walk project_dir, extract CFG facts for each function (or only those
    in func_names), and write them to facts_dir.

    Builds a project-wide function-name set first so opaque-site detection
    can tell project-defined callees from external ones.
    """
    from tree_sitter_nav import enumerate_functions

    project = Path(project_dir)
    all_funcs = enumerate_functions(str(project), extensions=extensions)
    project_func_set: set = {f.name for f in all_funcs}
    func_filter: set | None = set(func_names) if func_names else None

    # Group target functions by file so each file is parsed once.
    by_file: dict = defaultdict(set)
    for f in all_funcs:
        if func_filter is None or f.name in func_filter:
            by_file[f.file_path].add(f.name)

    all_cfgs: list[FunctionCFG] = []
    for file_path, names in by_file.items():
        cfgs = extract_cfg_for_file(file_path, project_func_set, func_filter=names)
        all_cfgs.extend(cfgs)

    stats = write_cfg_facts(all_cfgs, facts_dir)
    stats["functions_processed"] = len(all_cfgs)
    return stats


def lookup_opaque_sites_for_function(
    facts_dir: str | Path,
    func_name: str,
) -> list[tuple[int, str, str]]:
    """Read OpaqueCallSite.facts and return rows for one function as
    [(line, callee, reason), ...] sorted by line. Used by the LLM extractor
    to pass opaque-site context into the prompt."""
    path = Path(facts_dir) / "OpaqueCallSite.facts"
    if not path.exists():
        return []
    out: list = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) >= 4 and parts[0] == func_name:
            try:
                out.append((int(parts[1]), parts[2], parts[3]))
            except ValueError:
                continue
    return sorted(out)


# ─────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python tree_sitter_cfg.py <project_dir> [func_name ...]")
        print("  python tree_sitter_cfg.py file <file.c> <func_name>")
        sys.exit(1)

    if sys.argv[1] == "file":
        if len(sys.argv) < 4:
            print("Usage: python tree_sitter_cfg.py file <file.c> <func_name>")
            sys.exit(1)
        file_path = sys.argv[2]
        func = sys.argv[3]
        cfgs = extract_cfg_for_file(file_path, project_funcs=set(), func_filter={func})
        for c in cfgs:
            print(f"=== {c.func} (lines {c.entry_line}-{c.end_line}) ===")
            print(f"  CFG edges: {len(c.edges)}")
            for s, d in sorted(c.edges):
                print(f"    {s} → {d}")
            print(f"  Blocks: {len(set(c.block_heads.values()))}")
            for line, blk in sorted(c.block_heads.items()):
                marker = "★" if line == blk else " "
                print(f"    {marker} L{line} ∈ block@{blk}")
            print(f"  Block edges: {len(c.block_edges)}")
            for s, d in sorted(c.block_edges):
                print(f"    block@{s} → block@{d}")
            if c.opaque_sites:
                print(f"  Opaque sites:")
                for line, callee, reason in sorted(c.opaque_sites):
                    print(f"    L{line}: {callee} ({reason})")
        sys.exit(0)

    project_dir = sys.argv[1]
    func_names = sys.argv[2:] if len(sys.argv) > 2 else None
    stats = generate_cfg_facts_for_project(
        project_dir, func_names=func_names, facts_dir="facts")
    print("\nWrote CFG facts:")
    for k, v in stats.items():
        print(f"  {k}: {v}")

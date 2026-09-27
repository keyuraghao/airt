"""Small helpers on top of the standard ``ast`` module used by the Python-aware rules."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator


def parse(text: str) -> ast.Module | None:
    try:
        return ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return None


def attach_parents(tree: ast.AST) -> None:
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            child._aisrf_parent = node  # type: ignore[attr-defined]


def parent(node: ast.AST) -> ast.AST | None:
    return getattr(node, "_aisrf_parent", None)


def enclosing_function(node: ast.AST) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    cur = parent(node)
    while cur is not None:
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return cur
        cur = parent(cur)
    return None


def iter_calls(tree: ast.AST) -> Iterator[ast.Call]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            yield node


def iter_functions(tree: ast.AST) -> Iterator[ast.FunctionDef | ast.AsyncFunctionDef]:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def dotted(node: ast.AST) -> str:
    """'a.b.c' for Name/Attribute chains, '' otherwise (calls are collapsed: a().b -> a.b)."""
    parts: list[str] = []
    cur: ast.AST | None = node
    while cur is not None:
        if isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        elif isinstance(cur, ast.Name):
            parts.append(cur.id)
            break
        elif isinstance(cur, ast.Call):
            cur = cur.func
        elif isinstance(cur, ast.Subscript):
            cur = cur.value
        else:
            break
    return ".".join(reversed(parts))


def call_name(call: ast.Call) -> str:
    return dotted(call.func)


def keyword(call: ast.Call, name: str) -> ast.expr | None:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def has_keyword(call: ast.Call, name: str) -> bool:
    return keyword(call, name) is not None


def is_true(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def is_false(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def is_constant(node: ast.AST | None) -> bool:
    if node is None:
        return True
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(is_constant(e) for e in node.elts)
    if isinstance(node, ast.Dict):
        return all(is_constant(k) and is_constant(v) for k, v in zip(node.keys, node.values, strict=False))
    return False


def names_in(node: ast.AST) -> set[str]:
    """Identifiers (dotted where possible) referenced inside a node."""
    out: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            out.add(sub.id)
        elif isinstance(sub, ast.Attribute):
            d = dotted(sub)
            if d:
                out.add(d)
    return out


def literal_text(node: ast.AST) -> str:
    """Concatenated string constants found inside a node (f-string literal parts, .format templates...)."""
    parts: list[str] = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            parts.append(sub.value)
    return " ".join(parts)


def is_dynamic_string(node: ast.AST | None) -> bool:
    """f-string, str.format(...), '%' formatting, or '+' concatenation involving a non-literal."""
    if node is None:
        return False
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return bool(node.args or node.keywords)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return not is_constant(node.left) or not is_constant(node.right)
    return False


def interpolated(node: ast.AST) -> set[str]:
    """Names interpolated into a dynamic string (see is_dynamic_string)."""
    out: set[str] = set()
    if isinstance(node, ast.JoinedStr):
        for v in node.values:
            if isinstance(v, ast.FormattedValue):
                out |= names_in(v.value)
    elif isinstance(node, ast.Call):
        for a in node.args:
            out |= names_in(a)
        for k in node.keywords:
            out |= names_in(k.value)
    elif isinstance(node, ast.BinOp):
        out |= names_in(node)
    return out


def decorators(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    return [dotted(d) or ast.dump(d)[:40] for d in func.decorator_list]


def has_decorator(func: ast.FunctionDef | ast.AsyncFunctionDef, pattern: str) -> bool:
    rx = re.compile(pattern)
    return any(rx.search(d) for d in decorators(func))


def func_text(func: ast.AST, lines: list[str]) -> str:
    start = getattr(func, "lineno", 1)
    end = getattr(func, "end_lineno", start)
    return "\n".join(lines[start - 1 : end])


def dict_get(node: ast.Dict, key: str) -> ast.expr | None:
    for k, v in zip(node.keys, node.values, strict=False):
        if isinstance(k, ast.Constant) and k.value == key:
            return v
    return None


def span(node: ast.AST) -> tuple[int, int]:
    start = int(getattr(node, "lineno", 1) or 1)
    end = int(getattr(node, "end_lineno", start) or start)
    return start, end


def arg_names(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    args = func.args
    names = {a.arg for a in [*args.args, *args.posonlyargs, *args.kwonlyargs]}
    if args.vararg:
        names.add(args.vararg.arg)
    if args.kwarg:
        names.add(args.kwarg.arg)
    names.discard("self")
    names.discard("cls")
    return names


def depends_on(node: ast.AST, names: set[str]) -> bool:
    """True when the expression references any of the given identifiers (first path segment)."""
    return any(n.split(".")[0] in names for n in names_in(node))


def calls_matching(tree: ast.AST, pattern: str) -> Iterator[ast.Call]:
    rx = re.compile(pattern)
    for call in iter_calls(tree):
        if rx.search(call_name(call)):
            yield call


def ast_dump_short(node: ast.AST) -> str:
    try:
        return ast.unparse(node)[:200]
    except Exception:
        return ""


"""Parser and whitelist for the plan language.

A plan is a Python module restricted to:

- ``name = <expr>`` assignments to plain identifiers;
- expression statements that are calls (tool calls with side effects, e.g. ``send_email(...)``);
- ``if <expr>: ... [else: ...]`` (``elif`` is a nested ``if`` in the else branch);
- ``for name in <expr>: ...`` without ``else``;
- expressions built from constants (``str``, ``int``, ``float``, ``bool``, ``None``), names,
  list and dict literals with string keys, subscripts, calls to registered tools and builtins
  with positional or keyword arguments, single comparisons, ``and``/``or``/``not``, unary minus,
  ``+``/``-``/``*`` and f-strings without conversions or format specs.

Everything else (attributes, comprehensions, lambdas, imports, definitions, loops other than
``for``, ``while``, ``try``, ``with``, starred arguments, slices, walrus, ``await`` ...) is
rejected by construction: :func:`parse_plan` walks the tree against an allowlist of node types
and refuses any node type that is not on it, so a new Python syntax feature is rejected until
it is deliberately added here. Depth, node count, statement count, string length and source
size are bounded so that parsing itself stays cheap on hostile input.
"""

from __future__ import annotations

import ast
import io
import re
import tokenize
from collections.abc import Collection, Iterator
from dataclasses import dataclass
from typing import Any, final

from taint_flow_agent.core.canonical import sha256_hex
from taint_flow_agent.dsl.errors import PlanRejectedError, PlanSyntaxError

__all__ = [
    "ALLOWED_BINARY_OPERATORS",
    "ALLOWED_COMPARE_OPERATORS",
    "ALLOWED_NODE_TYPES",
    "IDENTIFIER",
    "Limits",
    "Plan",
    "assigned_names",
    "describe_node",
    "parse_plan",
    "plan_depth",
    "token_limit",
]

IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_RESERVED = frozenset({"True", "False", "None", "and", "or", "not", "if", "else", "for", "in"})

ALLOWED_COMPARE_OPERATORS: tuple[type[ast.cmpop], ...] = (
    ast.Eq,
    ast.NotEq,
    ast.Lt,
    ast.LtE,
    ast.Gt,
    ast.GtE,
    ast.In,
    ast.NotIn,
)
ALLOWED_BINARY_OPERATORS: tuple[type[ast.operator], ...] = (ast.Add, ast.Sub, ast.Mult)
_ALLOWED_BOOL_OPERATORS: tuple[type[ast.boolop], ...] = (ast.And, ast.Or)
_ALLOWED_UNARY_OPERATORS: tuple[type[ast.unaryop], ...] = (ast.Not, ast.USub)
_CONSTANT_TYPES = (str, int, float, bool, type(None))

ALLOWED_NODE_TYPES: frozenset[type[ast.AST]] = frozenset(
    {
        ast.Module,
        ast.Assign,
        ast.Expr,
        ast.If,
        ast.For,
        ast.Call,
        ast.keyword,
        ast.Constant,
        ast.Name,
        ast.Load,
        ast.Store,
        ast.List,
        ast.Dict,
        ast.Subscript,
        ast.Compare,
        ast.BoolOp,
        ast.UnaryOp,
        ast.BinOp,
        ast.JoinedStr,
        ast.FormattedValue,
        *ALLOWED_COMPARE_OPERATORS,
        *ALLOWED_BINARY_OPERATORS,
        *_ALLOWED_BOOL_OPERATORS,
        *_ALLOWED_UNARY_OPERATORS,
    }
)


@final
@dataclass(frozen=True, slots=True)
class Limits:
    """Static (parse-time) and dynamic (run-time) bounds for plans."""

    max_source_bytes: int = 20_000
    max_nodes: int = 400
    max_depth: int = 12
    max_statements: int = 100
    max_string_length: int = 4_000
    max_call_arguments: int = 12
    max_steps: int = 2_000
    max_loop_iterations: int = 100
    max_collection_size: int = 1_000
    max_value_chars: int = 50_000
    timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        for name in (
            "max_source_bytes",
            "max_nodes",
            "max_depth",
            "max_statements",
            "max_string_length",
            "max_call_arguments",
            "max_steps",
            "max_loop_iterations",
            "max_collection_size",
            "max_value_chars",
        ):
            if getattr(self, name) < 1:
                raise ValueError(f"{name} must be at least 1")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")


@final
@dataclass(frozen=True, slots=True)
class Plan:
    """A parsed, whitelisted plan. ``sha256`` identifies the exact source in audit records."""

    source: str
    module: ast.Module
    sha256: str
    statements: int
    nodes: int
    depth: int

    @property
    def body(self) -> list[ast.stmt]:
        return self.module.body


def plan_depth(node: ast.AST) -> int:
    """Nesting depth of a syntax tree (a lone node has depth 1)."""
    children = list(ast.iter_child_nodes(node))
    if not children:
        return 1
    return 1 + max(plan_depth(child) for child in children)


def _count_statements(statements: list[ast.stmt]) -> int:
    total = 0
    for statement in statements:
        total += 1
        if isinstance(statement, (ast.If, ast.For)):
            total += _count_statements(statement.body) + _count_statements(statement.orelse)
    return total


def assigned_names(statements: list[ast.stmt]) -> frozenset[str]:
    """Names assigned anywhere inside ``statements`` (assignments and loop targets)."""
    names: set[str] = set()
    for statement in statements:
        if isinstance(statement, ast.Assign):
            target = statement.targets[0]
            if isinstance(target, ast.Name):
                names.add(target.id)
        elif isinstance(statement, ast.For):
            if isinstance(statement.target, ast.Name):
                names.add(statement.target.id)
            names |= assigned_names(statement.body)
        elif isinstance(statement, ast.If):
            names |= assigned_names(statement.body) | assigned_names(statement.orelse)
    return frozenset(names)


def _reject(reason: str, node: ast.AST) -> PlanRejectedError:
    return PlanRejectedError(reason, node=type(node).__name__, line=getattr(node, "lineno", None))


def _check_identifier(name: str, node: ast.Name, *, known: Collection[str]) -> None:
    if name in _RESERVED or not IDENTIFIER.fullmatch(name):
        raise _reject(f"identifier {name!r} is not allowed", node)
    if name not in known:
        return
    if isinstance(node.ctx, ast.Store):
        raise _reject(f"identifier {name!r} shadows a tool or builtin", node)
    # Tools and builtins are not first-class values: `x = read_inbox` would make the callee a
    # datum the interpreter has no label for, and would let a plan smuggle a capability past the
    # per-call policy check. They may only appear as the callee of a call.
    raise _reject(f"tool or builtin {name!r} may only be called", node)


def _iter_nodes(node: ast.AST) -> Iterator[ast.AST]:
    yield node
    for child in ast.iter_child_nodes(node):
        yield from _iter_nodes(child)


@final
class _Checker:
    def __init__(self, limits: Limits, known: Collection[str]) -> None:
        self._limits = limits
        self._known = frozenset(known)

    def check_module(self, module: ast.Module) -> None:
        if module.type_ignores:
            raise _reject("type comments are not allowed", module)
        for node in _iter_nodes(module):
            if type(node) not in ALLOWED_NODE_TYPES:
                raise _reject(f"syntax node {type(node).__name__} is not allowed", node)
            if getattr(node, "type_comment", None) is not None:
                raise _reject("type comments are not allowed", node)
        self._check_block(module.body)

    def _check_block(self, statements: list[ast.stmt]) -> None:
        for statement in statements:
            self._check_statement(statement)

    def _check_statement(self, statement: ast.stmt) -> None:
        if isinstance(statement, ast.Assign):
            if len(statement.targets) != 1 or not isinstance(statement.targets[0], ast.Name):
                raise _reject("assignment target must be a single name", statement)
            _check_identifier(statement.targets[0].id, statement.targets[0], known=self._known)
            self._check_expression(statement.value)
        elif isinstance(statement, ast.Expr):
            if not isinstance(statement.value, ast.Call):
                raise _reject("expression statements must be calls", statement)
            self._check_expression(statement.value)
        elif isinstance(statement, ast.If):
            self._check_expression(statement.test)
            self._check_block(statement.body)
            self._check_block(statement.orelse)
        elif isinstance(statement, ast.For):
            if not isinstance(statement.target, ast.Name):
                raise _reject("for loop target must be a single name", statement)
            _check_identifier(statement.target.id, statement.target, known=self._known)
            if statement.orelse:
                raise _reject("for/else is not allowed", statement)
            self._check_expression(statement.iter)
            self._check_block(statement.body)
        else:  # pragma: no cover - excluded by the node-type allowlist
            raise _reject(f"statement {type(statement).__name__} is not allowed", statement)

    def _check_expression(self, node: ast.expr) -> None:  # noqa: PLR0912
        if isinstance(node, ast.Constant):
            self._check_constant(node)
        elif isinstance(node, ast.Name):
            if not isinstance(node.ctx, ast.Load):
                raise _reject("names may only be read here", node)
            _check_identifier(node.id, node, known=self._known)
        elif isinstance(node, ast.List):
            for item in node.elts:
                self._check_expression(item)
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values, strict=True):
                if not (isinstance(key, ast.Constant) and isinstance(key.value, str)):
                    raise _reject("dict keys must be string constants", node)
                self._check_constant(key)
                self._check_expression(value)
        elif isinstance(node, ast.Subscript):
            if not isinstance(node.ctx, ast.Load):
                raise _reject("subscripts may only be read", node)
            self._check_expression(node.value)
            self._check_expression(node.slice)
        elif isinstance(node, ast.Call):
            self._check_call(node)
        elif isinstance(node, ast.Compare):
            if len(node.ops) != 1 or len(node.comparators) != 1:
                raise _reject("chained comparisons are not allowed", node)
            if not isinstance(node.ops[0], ALLOWED_COMPARE_OPERATORS):
                raise _reject("comparison operator is not allowed", node)
            self._check_expression(node.left)
            self._check_expression(node.comparators[0])
        elif isinstance(node, ast.BoolOp):
            for value in node.values:
                self._check_expression(value)
        elif isinstance(node, ast.UnaryOp):
            self._check_expression(node.operand)
        elif isinstance(node, ast.BinOp):
            self._check_expression(node.left)
            self._check_expression(node.right)
        elif isinstance(node, ast.JoinedStr):
            for part in node.values:
                if isinstance(part, ast.FormattedValue):
                    if part.conversion != -1 or part.format_spec is not None:
                        raise _reject("f-string conversions and format specs are not allowed", part)
                    self._check_expression(part.value)
                else:
                    self._check_expression(part)
        else:  # pragma: no cover - excluded by the node-type allowlist
            raise _reject(f"expression {type(node).__name__} is not allowed", node)

    def _check_constant(self, node: ast.Constant) -> None:
        if type(node.value) not in _CONSTANT_TYPES:
            raise _reject(f"constant of type {type(node.value).__name__} is not allowed", node)
        if isinstance(node.value, str) and len(node.value) > self._limits.max_string_length:
            raise _reject("string constant is too long", node)

    def _check_call(self, node: ast.Call) -> None:
        if not isinstance(node.func, ast.Name):
            raise _reject("only direct calls to named tools and builtins are allowed", node)
        name = node.func.id
        if name not in self._known:
            raise _reject(f"unknown tool or builtin {name!r}", node)
        if len(node.args) + len(node.keywords) > self._limits.max_call_arguments:
            raise _reject("too many call arguments", node)
        for argument in node.args:
            self._check_expression(argument)
        seen: set[str] = set()
        for keyword in node.keywords:
            if keyword.arg is None:
                raise _reject("** argument unpacking is not allowed", node)
            if keyword.arg in seen or not IDENTIFIER.fullmatch(keyword.arg):
                raise _reject(f"invalid or repeated keyword argument {keyword.arg!r}", node)
            seen.add(keyword.arg)
            self._check_expression(keyword.value)


def token_limit(limits: Limits) -> int:
    """Token budget screened before ``ast.parse``: far above anything ``max_nodes`` accepts."""
    return max(4 * limits.max_nodes, 1_000)


def _token_count(source: str, limit: int) -> int | None:
    """Tokens in ``source``, stopping once ``limit`` is passed.

    ``None`` means the source cannot be tokenized at all; ``ast.parse`` then reports the syntax
    error, so this screen never decides whether a *valid* plan is accepted.
    """
    count = 0
    try:
        for _ in tokenize.generate_tokens(io.StringIO(source).readline):
            count += 1
            if count > limit:
                return count
    except (tokenize.TokenError, SyntaxError, ValueError, UnicodeError):
        return None
    return count


def parse_plan(source: str, *, known_functions: Collection[str], limits: Limits) -> Plan:
    """Parse ``source`` and enforce the whitelist and static limits.

    Raises :class:`PlanSyntaxError` for invalid Python and :class:`PlanRejectedError` for any
    construct, name or size outside the allowlist. ``known_functions`` lists the tool and builtin
    names a plan may call.

    Deeply nested sources are handled twice over: a token screen refuses them before ``ast.parse``
    spends CPU on them, and the ``RecursionError`` CPython raises while building or walking such a
    tree (it is not a ``SyntaxError``) is turned into a rejection rather than escaping the parser.
    """
    if not isinstance(source, str):
        raise PlanSyntaxError("plan source must be a str")
    if len(source.encode("utf-8")) > limits.max_source_bytes:
        raise PlanRejectedError("plan source is too large")
    budget = token_limit(limits)
    tokens = _token_count(source, budget)
    if tokens is not None and tokens > budget:
        raise PlanRejectedError(f"plan has too many tokens (> {budget})")
    try:
        # ``type_comments=True`` makes ``# type:`` comments visible to the checker instead of
        # silently discarded, so a plan cannot carry metadata the whitelist never sees.
        module = ast.parse(source, mode="exec", feature_version=(3, 12), type_comments=True)
    except (SyntaxError, ValueError) as exc:
        raise PlanSyntaxError(f"plan is not valid syntax: {type(exc).__name__}") from exc
    except RecursionError as exc:
        raise PlanRejectedError("plan nests too deeply for the parser") from exc
    try:
        return _analyze(source, module, known_functions=known_functions, limits=limits)
    except RecursionError as exc:
        raise PlanRejectedError("plan nests too deeply for the parser") from exc
    except MemoryError as exc:  # pragma: no cover - needs a machine-sized tree to trigger
        raise PlanRejectedError("plan needs too much memory to analyse") from exc


def _analyze(
    source: str, module: ast.Module, *, known_functions: Collection[str], limits: Limits
) -> Plan:
    nodes = sum(1 for _ in ast.walk(module))
    if nodes > limits.max_nodes:
        raise PlanRejectedError(f"plan has too many nodes ({nodes} > {limits.max_nodes})")
    depth = plan_depth(module)
    if depth > limits.max_depth:
        raise PlanRejectedError(f"plan nests too deeply ({depth} > {limits.max_depth})")
    statements = _count_statements(module.body)
    if statements > limits.max_statements:
        raise PlanRejectedError(
            f"plan has too many statements ({statements} > {limits.max_statements})"
        )
    _Checker(limits, known_functions).check_module(module)
    return Plan(
        source=source,
        module=module,
        sha256=sha256_hex(source),
        statements=statements,
        nodes=nodes,
        depth=depth,
    )


def describe_node(node: Any) -> str:
    """Short structural description of a statement for provenance and audit records."""
    if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
        return f"{node.targets[0].id} = {_describe_expression(node.value)}"
    if isinstance(node, ast.Expr):
        return _describe_expression(node.value)
    if isinstance(node, ast.If):
        return f"if {_describe_expression(node.test)}"
    if isinstance(node, ast.For) and isinstance(node.target, ast.Name):
        return f"for {node.target.id} in {_describe_expression(node.iter)}"
    return type(node).__name__


def _describe_expression(node: ast.expr) -> str:  # noqa: PLR0911
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        return f"{node.func.id}(...)"
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Constant):
        return "<const>"
    if isinstance(node, ast.Subscript):
        return f"{_describe_expression(node.value)}[...]"
    if isinstance(node, ast.JoinedStr):
        return "f-string"
    if isinstance(node, ast.Compare):
        return (
            f"{_describe_expression(node.left)} <cmp> {_describe_expression(node.comparators[0])}"
        )
    if isinstance(node, ast.BinOp):
        return f"{_describe_expression(node.left)} <op> {_describe_expression(node.right)}"
    return type(node).__name__.lower()

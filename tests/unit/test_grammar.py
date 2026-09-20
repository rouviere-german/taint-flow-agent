"""The plan parser: reference plans pass, every construct outside the whitelist is rejected."""

from __future__ import annotations

import ast
import contextlib

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from taint_flow_agent.dsl import grammar
from taint_flow_agent.dsl.builtins import BUILTINS
from taint_flow_agent.dsl.errors import PlanRejectedError, PlanSyntaxError
from taint_flow_agent.dsl.grammar import (
    ALLOWED_NODE_TYPES,
    Limits,
    assigned_names,
    describe_node,
    parse_plan,
    plan_depth,
)
from taint_flow_agent.env.tasks import TASKS
from taint_flow_agent.env.workspace import make_workspace

pytestmark = pytest.mark.unit

KNOWN = frozenset({*make_workspace().build_tools()[0].names, "query_quarantined", *BUILTINS})


def parse(source: str) -> None:
    parse_plan(source, known_functions=KNOWN, limits=Limits())


@pytest.mark.parametrize("task", TASKS, ids=[task.id for task in TASKS])
def test_every_reference_plan_parses(task: object) -> None:
    source = task.plan  # type: ignore[attr-defined]
    plan = parse_plan(source, known_functions=KNOWN, limits=Limits())
    assert plan.sha256
    assert plan.statements >= 1
    assert plan.depth <= Limits().max_depth


REJECTED = [
    "import os\n",
    "from os import path\n",
    "x = os.path\n",
    "x = (lambda: 1)()\n",
    "x = [e for e in read_inbox()]\n",
    "while True:\n    x = 1\n",
    "def f():\n    return 1\n",
    "class A:\n    pass\n",
    "try:\n    x = 1\nexcept Exception:\n    x = 2\n",
    "with a as b:\n    x = 1\n",
    "x = await read_inbox()\n",
    "x = read_inbox(*args)\n",
    "x = read_inbox(**kwargs)\n",
    "x = read_inbox()[1:2]\n",
    "x = (y := 1)\n",
    "global x\n",
    "del x\n",
    "assert x\n",
    "x = {1, 2}\n",
    "x = (1, 2)\n",
    "x = 1 if y else 2\n",
    "x = 1 < 2 < 3\n",
    "x = 1 / 2\n",
    "x = 2 ** 8\n",
    "x = 1 | 2\n",
    "x = a is b\n",
    "x = f'{1:>4}'\n",
    "x = f'{1!r}'\n",
    "x = {1: 'a'}\n",
    "x += 1\n",
    "x, y = 1, 2\n",
    "a.b = 1\n",
    "x = read_inbox\n",
    "x = unknown_tool()\n",
    "len = 1\n",
    "read_inbox = 1\n",
    "for x in y:\n    z = 1\nelse:\n    z = 2\n",
    "for a.b in y:\n    z = 1\n",
    "if x:\n    pass\n",
    "read_inbox\n",
    "x = 1  # type: ignore\n",
    "x = b'bytes'\n",
    "x = 1j\n",
    "x = ...\n",
    "x = read_inbox(a=1, a=2)\n",
    "True = 1\n",
    "x = send_email(to='a', to='b')\n",
    "Xyz = 1\n",
    "x = f'{read_inbox():x}'\n",
]


@pytest.mark.parametrize("source", REJECTED)
def test_constructs_outside_the_whitelist_are_rejected(source: str) -> None:
    with pytest.raises((PlanRejectedError, PlanSyntaxError)):
        parse(source)


def test_limits_are_enforced() -> None:
    limits = Limits(max_nodes=20, max_depth=4, max_statements=2, max_string_length=5)
    with pytest.raises(PlanRejectedError, match="too many nodes"):
        parse_plan(
            "x = [" + ", ".join(str(i) for i in range(20)) + "]\n",
            known_functions=KNOWN,
            limits=limits,
        )
    with pytest.raises(PlanRejectedError, match="nests too deeply"):
        parse_plan("x = [[[[[1]]]]]\n", known_functions=KNOWN, limits=limits)
    with pytest.raises(PlanRejectedError, match="too many statements"):
        parse_plan("x = 1\ny = 2\nz = 3\n", known_functions=KNOWN, limits=limits)
    with pytest.raises(PlanRejectedError, match="too long"):
        parse_plan('x = "abcdefgh"\n', known_functions=KNOWN, limits=limits)
    with pytest.raises(PlanRejectedError, match="too large"):
        parse_plan("x = 1\n" * 100, known_functions=KNOWN, limits=Limits(max_source_bytes=50))
    with pytest.raises(PlanRejectedError, match="too many call arguments"):
        parse_plan(
            "x = read_inbox(1, 2, 3)\n", known_functions=KNOWN, limits=Limits(max_call_arguments=2)
        )
    with pytest.raises(ValueError, match="at least 1"):
        Limits(max_nodes=0)
    with pytest.raises(ValueError, match="positive"):
        Limits(timeout_seconds=0)
    with pytest.raises(PlanSyntaxError):
        parse("x = (\n")
    with pytest.raises(PlanSyntaxError):
        parse_plan(b"x = 1", known_functions=KNOWN, limits=Limits())  # type: ignore[arg-type]


def test_rejections_name_the_node_and_line_but_never_values() -> None:
    with pytest.raises(PlanRejectedError) as info:
        parse("x = 1\ny = SECRET.attr\n")
    assert info.value.node == "Attribute"
    assert info.value.line == 2
    assert "SECRET" not in str(info.value)


def test_helpers() -> None:
    module = ast.parse(
        "x = 1\nif x:\n    y = read_inbox()\nelse:\n    z = 2\nfor e in y:\n    w = e\n"
    )
    assert assigned_names(module.body) == frozenset({"x", "y", "z", "e", "w"})
    assert plan_depth(ast.parse("x")) == 4  # Module -> Expr -> Name -> Load
    descriptions = [describe_node(statement) for statement in module.body]
    assert descriptions == ["x = <const>", "if x", "for e in y"]
    assert describe_node(ast.parse('send_email(to="a")').body[0]) == "send_email(...)"
    assert "f-string" in describe_node(ast.parse('x = f"{y}"').body[0])
    assert "<cmp>" in describe_node(ast.parse("x = y == z").body[0])
    assert "<op>" in describe_node(ast.parse("x = y + z").body[0])
    assert "[...]" in describe_node(ast.parse("x = y[0]").body[0])


# --------------------------------------------------------------------------------- fuzzing

_DISALLOWED_LEAVES = [
    ast.Attribute(value=ast.Name("x", ast.Load()), attr="y", ctx=ast.Load()),
    ast.Lambda(args=ast.arguments([], [], None, [], [], None, []), body=ast.Constant(1)),
    ast.Tuple(elts=[ast.Constant(1)], ctx=ast.Load()),
    ast.Set(elts=[ast.Constant(1)]),
    ast.IfExp(test=ast.Constant(True), body=ast.Constant(1), orelse=ast.Constant(2)),
    ast.NamedExpr(target=ast.Name("x", ast.Store()), value=ast.Constant(1)),
    ast.Await(value=ast.Name("x", ast.Load())),
    ast.Starred(value=ast.Name("x", ast.Load()), ctx=ast.Load()),
    ast.ListComp(
        elt=ast.Name("e", ast.Load()),
        generators=[
            ast.comprehension(
                target=ast.Name("e", ast.Store()),
                iter=ast.Name("x", ast.Load()),
                ifs=[],
                is_async=0,
            )
        ],
    ),
    ast.Subscript(
        value=ast.Name("x", ast.Load()),
        slice=ast.Slice(lower=ast.Constant(1), upper=None, step=None),
        ctx=ast.Load(),
    ),
    ast.BinOp(left=ast.Constant(1), op=ast.Div(), right=ast.Constant(2)),
    ast.BinOp(left=ast.Constant(1), op=ast.Pow(), right=ast.Constant(2)),
    ast.Compare(left=ast.Constant(1), ops=[ast.Is()], comparators=[ast.Constant(None)]),
    ast.Compare(
        left=ast.Constant(1),
        ops=[ast.Lt(), ast.Lt()],
        comparators=[ast.Constant(2), ast.Constant(3)],
    ),
    ast.Constant(b"bytes"),
    ast.Constant(1j),
    ast.JoinedStr(values=[ast.FormattedValue(value=ast.Name("x", ast.Load()), conversion=114)]),
]
_ALLOWED_LEAVES = [
    ast.Constant(1),
    ast.Constant("s"),
    ast.Name("x", ast.Load()),
    ast.Name("y", ast.Load()),
]


def _wrap(children: st.SearchStrategy[ast.expr]) -> st.SearchStrategy[ast.expr]:
    binop = st.builds(lambda a, b: ast.BinOp(left=a, op=ast.Add(), right=b), children, children)
    compare = st.builds(
        lambda a, b: ast.Compare(left=a, ops=[ast.Eq()], comparators=[b]), children, children
    )
    boolop = st.builds(lambda a, b: ast.BoolOp(op=ast.And(), values=[a, b]), children, children)
    unary = st.builds(lambda a: ast.UnaryOp(op=ast.Not(), operand=a), children)
    listing = st.builds(lambda a: ast.List(elts=[a], ctx=ast.Load()), children)
    mapping = st.builds(lambda a: ast.Dict(keys=[ast.Constant("k")], values=[a]), children)
    subscript = st.builds(
        lambda a, b: ast.Subscript(value=a, slice=b, ctx=ast.Load()), children, children
    )
    call = st.builds(
        lambda a: ast.Call(func=ast.Name("len", ast.Load()), args=[a], keywords=[]), children
    )
    return st.one_of(binop, compare, boolop, unary, listing, mapping, subscript, call)


expressions = st.recursive(
    st.sampled_from(_ALLOWED_LEAVES + _DISALLOWED_LEAVES), _wrap, max_leaves=8
)


def _contains_disallowed(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if type(node) not in ALLOWED_NODE_TYPES:
            return True
        if isinstance(node, ast.Compare) and len(node.ops) != 1:
            return True
        if isinstance(node, ast.Constant) and type(node.value) not in (
            str,
            int,
            float,
            bool,
            type(None),
        ):
            return True
        if isinstance(node, ast.FormattedValue) and (node.conversion != -1 or node.format_spec):
            return True
    return False


@pytest.mark.filterwarnings("ignore::hypothesis.errors.HypothesisWarning")
@settings(max_examples=300)
@given(expressions)
def test_generated_trees_outside_the_whitelist_are_always_rejected(expr: ast.expr) -> None:
    module = ast.Module(
        body=[ast.Assign(targets=[ast.Name("r", ast.Store())], value=expr)], type_ignores=[]
    )
    ast.fix_missing_locations(module)
    try:
        source = ast.unparse(module) + "\n"
    except (ValueError, TypeError, RecursionError):
        return  # not printable Python: it cannot reach the parser at all
    try:
        reparsed = ast.parse(source)
    except SyntaxError:
        # ast.unparse can emit text Python cannot read back (e.g. "r = 1 + *x"); the parser must
        # still refuse it cleanly rather than crash.
        with pytest.raises(PlanSyntaxError):
            parse_plan(source, known_functions=KNOWN, limits=Limits())
        return
    if not _contains_disallowed(reparsed):
        return  # the fuzzer produced a whitelisted tree; acceptance is covered elsewhere
    with pytest.raises((PlanRejectedError, PlanSyntaxError)):
        parse_plan(source, known_functions=KNOWN, limits=Limits())


@settings(max_examples=60)
@given(st.text(min_size=1, max_size=Limits().max_source_bytes))
def test_random_text_never_crashes_the_parser(source: str) -> None:
    with contextlib.suppress(PlanRejectedError, PlanSyntaxError):
        parse_plan(source, known_functions=KNOWN, limits=Limits())


SIMPLE_PLAN = 'write_file(name="a.txt", content="ok")\n'

DEEPLY_NESTED = [
    pytest.param("x = " + "not " * 4000 + "1\n", id="unary_not"),
    pytest.param("x = " + "-" * 8000 + "1\n", id="unary_minus"),
    pytest.param("x = " + "1 + " * 4000 + "1\n", id="binary_operator"),
    pytest.param("x = a" + "[0]" * 3000 + "\n", id="subscript"),
]

# CPython's tokenizer refuses these two itself ("too many nested parentheses"), so they arrive as
# a syntax error rather than a rejection; they are here to prove they never crash either.
NESTING_BOMBS = [
    pytest.param("x = " + "[" * 2000 + "]" * 2000 + "\n", id="list_literal"),
    pytest.param("x = " + "(" * 4000 + "1" + ")" * 4000 + "\n", id="parentheses"),
]


@pytest.mark.parametrize("source", DEEPLY_NESTED)
def test_deeply_nested_sources_are_rejected_not_crashed(source: str) -> None:
    """CPython raises RecursionError, not SyntaxError, on trees that fit inside the size limit."""
    assert len(source.encode("utf-8")) <= Limits().max_source_bytes
    with pytest.raises(PlanRejectedError, match=r"too many tokens|nests too deeply"):
        parse(source)


@pytest.mark.parametrize("source", NESTING_BOMBS)
def test_nesting_bombs_are_rejected_not_crashed(source: str) -> None:
    with pytest.raises((PlanRejectedError, PlanSyntaxError)):
        parse(source)


def test_recursion_error_from_the_parser_becomes_a_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The token screen catches nesting early; if one ever slips past, it must not escape."""

    def boom(*args: object, **kwargs: object) -> ast.Module:
        raise RecursionError("maximum recursion depth exceeded during ast construction")

    monkeypatch.setattr(grammar.ast, "parse", boom)
    with pytest.raises(PlanRejectedError, match="nests too deeply"):
        parse(SIMPLE_PLAN)


def test_recursion_error_while_analysing_becomes_a_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(node: ast.AST) -> int:
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(grammar, "plan_depth", boom)
    with pytest.raises(PlanRejectedError, match="nests too deeply"):
        parse(SIMPLE_PLAN)


def test_reference_plans_are_far_below_the_token_screen() -> None:
    budget = grammar.token_limit(Limits())
    counts = [grammar._token_count(task.plan, budget) for task in TASKS]
    assert all(count is not None and count < budget // 4 for count in counts)


_WRAPPERS = [("not ", ""), ("-", ""), ("(", ")"), ("[", "]"), ("{'k': ", "}")]


@settings(max_examples=40)
@given(st.sampled_from(_WRAPPERS), st.integers(min_value=1, max_value=4000))
def test_repeated_nesting_of_any_depth_is_rejected_cleanly(
    wrapper: tuple[str, str], count: int
) -> None:
    opening, closing = wrapper
    source = "x = " + opening * count + "1" + closing * count + "\n"
    if len(source.encode("utf-8")) > Limits().max_source_bytes:
        return
    with contextlib.suppress(PlanRejectedError, PlanSyntaxError):
        parse(source)

from __future__ import annotations

from typing import Any

import pytest

from taint_flow_agent.dsl.builtins import BUILTINS
from taint_flow_agent.dsl.errors import PlanRuntimeError
from taint_flow_agent.ifc.labels import Label
from taint_flow_agent.ifc.values import Labeled, from_plain, to_plain

pytestmark = pytest.mark.unit


def call(name: str, *args: Any) -> Any:
    return to_plain(BUILTINS[name]([from_plain(a, Label.user()) for a in args]))


@pytest.mark.parametrize(
    ("name", "args", "expected"),
    [
        ("len", ("abc",), 3),
        ("len", ([1, 2],), 2),
        ("len", ({"a": 1},), 1),
        ("str", (12,), "12"),
        ("str", ("s",), "s"),
        ("str", (None,), "None"),
        ("int", ("12",), 12),
        ("int", (3.9,), 3),
        ("int", (True,), 1),
        ("float", ("1.5",), 1.5),
        ("float", (2,), 2.0),
        ("bool", ("",), False),
        ("bool", ([1],), True),
        ("lower", ("AbC",), "abc"),
        ("upper", ("AbC",), "ABC"),
        ("strip", ("  x ",), "x"),
        ("sum", ([1, 2.5],), 3.5),
        ("min", ([3, 1, 2],), 1),
        ("max", ([3, 1, 2],), 3),
        ("sorted", (["b", "a"],), ["a", "b"]),
        ("sorted", ([2, 1.5],), [1.5, 2]),
        ("range", (3,), [0, 1, 2]),
        ("join", (["a", "b"],), "a, b"),
        ("join", (["a", "b"], "-"), "a-b"),
        ("keys", ({"a": 1, "b": 2},), ["a", "b"]),
        ("values", ({"a": 1, "b": 2},), [1, 2]),
        ("split", ("a b  c",), ["a", "b", "c"]),
        ("split", ("a,b", ","), ["a", "b"]),
        ("replace", ("aXa", "X", "-"), "a-a"),
        ("startswith", ("abc", "ab"), True),
        ("endswith", ("abc", "bc"), True),
        ("abs", (-2,), 2),
        ("round", (2.567, 2), 2.57),
        ("round", (2.5,), 2),
    ],
)
def test_builtins_compute_values(name: str, args: tuple[Any, ...], expected: Any) -> None:
    assert call(name, *args) == expected


@pytest.mark.parametrize(
    ("name", "args"),
    [
        ("len", (1,)),
        ("len", ()),
        ("str", ([1],)),
        ("int", ("x",)),
        ("int", ([1],)),
        ("float", ("x",)),
        ("float", ("inf",)),
        ("float", (None,)),
        ("lower", (1,)),
        ("sum", ([1, "a"],)),
        ("sum", ("abc",)),
        ("min", ([],)),
        ("max", ([],)),
        ("sorted", ([1, "a"],)),
        ("range", (-1,)),
        ("range", (100_000,)),
        ("range", (1.5,)),
        ("join", ([1, 2],)),
        ("keys", ([1],)),
        ("values", ("x",)),
        ("replace", ("a", "", "b")),
        ("round", (1.5, 20)),
        ("round", (1.5, 1, 2)),
        ("abs", ("x",)),
        ("startswith", ("a", 1)),
    ],
)
def test_builtins_reject_bad_arguments_with_plan_errors(name: str, args: tuple[Any, ...]) -> None:
    with pytest.raises(PlanRuntimeError):
        call(name, *args)


def test_sorted_and_values_preserve_element_labels() -> None:
    items = Labeled(
        (Labeled("b", Label.untrusted("e1")), Labeled("a", Label.trusted_tool("t"))), Label.user()
    )
    result = BUILTINS["sorted"]([items])
    assert [to_plain(item) for item in result.value] == ["a", "b"]
    assert result.value[0].label == Label.trusted_tool("t")
    assert result.value[1].label == Label.untrusted("e1")
    mapping = Labeled({"k": Labeled(1, Label.untrusted("e1"))}, Label.user())
    assert BUILTINS["values"]([mapping]).value[0].label == Label.untrusted("e1")

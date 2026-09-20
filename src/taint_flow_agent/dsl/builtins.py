"""Pure builtin functions a plan may call.

Each builtin computes on labeled arguments and returns a labeled value. It never touches the
environment and never raises anything but :class:`PlanRuntimeError`. The interpreter joins the
effective labels of every argument into the result (rule ``builtin_joins_args``), so a builtin
only needs to produce the *value*; element labels inside returned containers are preserved
where they exist (``sorted``, ``keys``, ``values``).
"""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from taint_flow_agent.dsl.errors import PlanRuntimeError
from taint_flow_agent.ifc.labels import BOTTOM
from taint_flow_agent.ifc.values import Labeled, to_plain

__all__ = ["BUILTINS", "Builtin"]

Builtin = Callable[[Sequence[Labeled[Any]]], Labeled[Any]]


def _arity(name: str, args: Sequence[Labeled[Any]], *counts: int) -> None:
    if len(args) not in counts:
        raise PlanRuntimeError(f"{name}() takes {' or '.join(map(str, counts))} argument(s)")


def _string(name: str, value: Labeled[Any]) -> str:
    if not isinstance(value.value, str):
        raise PlanRuntimeError(f"{name}() expects a string")
    return value.value


def _number(name: str, value: Labeled[Any]) -> int | float:
    inner = value.value
    if isinstance(inner, bool) or not isinstance(inner, (int, float)):
        raise PlanRuntimeError(f"{name}() expects a number")
    return inner


def _sequence(name: str, value: Labeled[Any]) -> tuple[Labeled[Any], ...]:
    if not isinstance(value.value, tuple):
        raise PlanRuntimeError(f"{name}() expects a list")
    return value.value


def _mapping(name: str, value: Labeled[Any]) -> Mapping[str, Labeled[Any]]:
    if not isinstance(value.value, Mapping):
        raise PlanRuntimeError(f"{name}() expects a dict")
    return value.value


def _len(args: Sequence[Labeled[Any]]) -> Labeled[Any]:
    _arity("len", args, 1)
    inner = args[0].value
    if isinstance(inner, (str, tuple, Mapping)):
        return Labeled(len(inner), BOTTOM)
    raise PlanRuntimeError("len() expects a string, list or dict")


def _str(args: Sequence[Labeled[Any]]) -> Labeled[Any]:
    _arity("str", args, 1)
    inner = args[0].value
    if isinstance(inner, str):
        return Labeled(inner, BOTTOM)
    if inner is None or isinstance(inner, (bool, int, float)):
        return Labeled(str(inner), BOTTOM)
    raise PlanRuntimeError("str() expects a scalar")


def _int(args: Sequence[Labeled[Any]]) -> Labeled[Any]:
    _arity("int", args, 1)
    inner = args[0].value
    try:
        if isinstance(inner, (str, float)) and not isinstance(inner, bool):
            return Labeled(int(float(inner)), BOTTOM)
        if isinstance(inner, (bool, int)):
            return Labeled(int(inner), BOTTOM)
    except (ValueError, OverflowError) as exc:
        raise PlanRuntimeError("int() could not convert its argument") from exc
    raise PlanRuntimeError("int() expects a number or numeric string")


def _float(args: Sequence[Labeled[Any]]) -> Labeled[Any]:
    _arity("float", args, 1)
    inner = args[0].value
    try:
        if isinstance(inner, (str, int, float)) and not isinstance(inner, bool):
            result = float(inner)
            if not math.isfinite(result):
                raise PlanRuntimeError("float() result must be finite")
            return Labeled(result, BOTTOM)
    except ValueError as exc:
        raise PlanRuntimeError("float() could not convert its argument") from exc
    raise PlanRuntimeError("float() expects a number or numeric string")


def _bool(args: Sequence[Labeled[Any]]) -> Labeled[Any]:
    _arity("bool", args, 1)
    return Labeled(bool(args[0].value), BOTTOM)


def _lower(args: Sequence[Labeled[Any]]) -> Labeled[Any]:
    _arity("lower", args, 1)
    return Labeled(_string("lower", args[0]).lower(), BOTTOM)


def _upper(args: Sequence[Labeled[Any]]) -> Labeled[Any]:
    _arity("upper", args, 1)
    return Labeled(_string("upper", args[0]).upper(), BOTTOM)


def _strip(args: Sequence[Labeled[Any]]) -> Labeled[Any]:
    _arity("strip", args, 1)
    return Labeled(_string("strip", args[0]).strip(), BOTTOM)


def _sum(args: Sequence[Labeled[Any]]) -> Labeled[Any]:
    _arity("sum", args, 1)
    total: int | float = 0
    for item in _sequence("sum", args[0]):
        total += _number("sum", item)
    return Labeled(total, BOTTOM)


def _min(args: Sequence[Labeled[Any]]) -> Labeled[Any]:
    _arity("min", args, 1)
    items = _sequence("min", args[0])
    if not items:
        raise PlanRuntimeError("min() of an empty list")
    return Labeled(min(_number("min", item) for item in items), BOTTOM)


def _max(args: Sequence[Labeled[Any]]) -> Labeled[Any]:
    _arity("max", args, 1)
    items = _sequence("max", args[0])
    if not items:
        raise PlanRuntimeError("max() of an empty list")
    return Labeled(max(_number("max", item) for item in items), BOTTOM)


def _sorted(args: Sequence[Labeled[Any]]) -> Labeled[Any]:
    _arity("sorted", args, 1)
    items = _sequence("sorted", args[0])
    plain = [to_plain(item) for item in items]
    keys: list[str] | list[float]
    if all(isinstance(p, str) for p in plain):
        keys = [str(p) for p in plain]
    elif all(isinstance(p, (int, float)) and not isinstance(p, bool) for p in plain):
        keys = [float(p) for p in plain if isinstance(p, (int, float))]
    else:
        raise PlanRuntimeError("sorted() expects a list of strings or of numbers")
    order = sorted(range(len(items)), key=lambda index: keys[index])
    return Labeled(tuple(items[index] for index in order), BOTTOM)


def _range(args: Sequence[Labeled[Any]]) -> Labeled[Any]:
    _arity("range", args, 1)
    count = _number("range", args[0])
    if not isinstance(count, int) or count < 0 or count > 10_000:
        raise PlanRuntimeError("range() expects an integer between 0 and 10000")
    return Labeled(tuple(Labeled(index, BOTTOM) for index in range(count)), BOTTOM)


def _join(args: Sequence[Labeled[Any]]) -> Labeled[Any]:
    _arity("join", args, 1, 2)
    separator = _string("join", args[1]) if len(args) == 2 else ", "
    parts = [_string("join", item) for item in _sequence("join", args[0])]
    return Labeled(separator.join(parts), BOTTOM)


def _keys(args: Sequence[Labeled[Any]]) -> Labeled[Any]:
    _arity("keys", args, 1)
    return Labeled(tuple(Labeled(key, BOTTOM) for key in _mapping("keys", args[0])), BOTTOM)


def _values(args: Sequence[Labeled[Any]]) -> Labeled[Any]:
    _arity("values", args, 1)
    return Labeled(tuple(_mapping("values", args[0]).values()), BOTTOM)


def _split(args: Sequence[Labeled[Any]]) -> Labeled[Any]:
    _arity("split", args, 1, 2)
    text = _string("split", args[0])
    pieces = text.split(_string("split", args[1])) if len(args) == 2 else text.split()
    return Labeled(tuple(Labeled(piece, BOTTOM) for piece in pieces[:1_000]), BOTTOM)


def _replace(args: Sequence[Labeled[Any]]) -> Labeled[Any]:
    _arity("replace", args, 3)
    text, old, new = (_string("replace", item) for item in args)
    if not old:
        raise PlanRuntimeError("replace() needs a non-empty search string")
    return Labeled(text.replace(old, new), BOTTOM)


def _startswith(args: Sequence[Labeled[Any]]) -> Labeled[Any]:
    _arity("startswith", args, 2)
    return Labeled(
        _string("startswith", args[0]).startswith(_string("startswith", args[1])), BOTTOM
    )


def _endswith(args: Sequence[Labeled[Any]]) -> Labeled[Any]:
    _arity("endswith", args, 2)
    return Labeled(_string("endswith", args[0]).endswith(_string("endswith", args[1])), BOTTOM)


def _abs(args: Sequence[Labeled[Any]]) -> Labeled[Any]:
    _arity("abs", args, 1)
    return Labeled(abs(_number("abs", args[0])), BOTTOM)


def _round(args: Sequence[Labeled[Any]]) -> Labeled[Any]:
    _arity("round", args, 1, 2)
    digits = _number("round", args[1]) if len(args) == 2 else 0
    if not isinstance(digits, int) or not 0 <= digits <= 12:
        raise PlanRuntimeError("round() digits must be an integer between 0 and 12")
    return Labeled(round(_number("round", args[0]), digits), BOTTOM)


BUILTINS: Mapping[str, Builtin] = {
    "len": _len,
    "str": _str,
    "int": _int,
    "float": _float,
    "bool": _bool,
    "lower": _lower,
    "upper": _upper,
    "strip": _strip,
    "sum": _sum,
    "min": _min,
    "max": _max,
    "sorted": _sorted,
    "range": _range,
    "join": _join,
    "keys": _keys,
    "values": _values,
    "split": _split,
    "replace": _replace,
    "startswith": _startswith,
    "endswith": _endswith,
    "abs": _abs,
    "round": _round,
}

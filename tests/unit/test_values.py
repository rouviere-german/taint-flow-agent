from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from taint_flow_agent.ifc.labels import BOTTOM, Integrity, Label, Readers, join_all
from taint_flow_agent.ifc.values import Labeled, effective_label, from_plain, to_plain

pytestmark = pytest.mark.unit

json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(max_size=8),
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=4), children, max_size=4)
    ),
    max_leaves=12,
)
labels = st.builds(
    Label,
    st.sampled_from(list(Integrity)),
    st.one_of(st.just(Readers()), st.frozensets(st.sampled_from(["me", "alice"])).map(Readers.of)),
    st.frozensets(st.sampled_from(["a", "b"]), max_size=2),
)


@given(json_values, labels)
def test_plain_round_trip_and_uniform_labels(data: Any, label: Label) -> None:
    labeled = from_plain(data, label)
    assert to_plain(labeled) == data
    assert effective_label(labeled) == label


def _relabel_random(value: Labeled[Any], picks: list[Label]) -> tuple[Labeled[Any], list[Label]]:
    """Give nested elements their own labels; return the value and every label used."""
    inner = value.value
    used = [value.label]
    if isinstance(inner, tuple):
        items = []
        for index, item in enumerate(inner):
            relabeled, inner_used = _relabel_random(item.relabel(picks[index % len(picks)]), picks)
            items.append(relabeled)
            used += inner_used
        return Labeled(tuple(items), value.label), used
    if isinstance(inner, dict):
        mapping = {}
        for index, (key, item) in enumerate(inner.items()):
            relabeled, inner_used = _relabel_random(item.relabel(picks[index % len(picks)]), picks)
            mapping[key] = relabeled
            used += inner_used
        return Labeled(mapping, value.label), used
    return value, used


@given(json_values, st.lists(labels, min_size=1, max_size=3))
def test_effective_label_is_at_least_every_nested_label(data: Any, picks: list[Label]) -> None:
    value, used = _relabel_random(from_plain(data, picks[0]), picks)
    effective = effective_label(value)
    assert effective == join_all(used)
    for label in used:
        assert label <= effective


def test_unsupported_types_are_refused() -> None:
    with pytest.raises(TypeError):
        to_plain(Labeled(object()))
    with pytest.raises(TypeError):
        from_plain({1, 2}, BOTTOM)  # type: ignore[arg-type]
    joined = Labeled("x").joined_with(Label.untrusted("e"))
    assert joined.label.integrity is Integrity.UNTRUSTED

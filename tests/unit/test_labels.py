"""Lattice laws for labels: join is associative, commutative, idempotent and monotone."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from taint_flow_agent.ifc.labels import BOTTOM, PUBLIC, Integrity, Label, Readers, join_all

pytestmark = pytest.mark.unit

principals = st.sampled_from(["me", "alice", "bob", "dana", "erik"])
readers = st.one_of(
    st.just(PUBLIC), st.frozensets(principals, min_size=0, max_size=4).map(Readers.of)
)
sources = st.frozensets(st.sampled_from(["user", "email:1", "file:a", "tool:x", "r#1"]), max_size=3)
labels = st.builds(Label, st.sampled_from(list(Integrity)), readers, sources)


@given(labels, labels, labels)
def test_join_is_associative(a: Label, b: Label, c: Label) -> None:
    assert a.join(b).join(c) == a.join(b.join(c))


@given(labels, labels)
def test_join_is_commutative(a: Label, b: Label) -> None:
    assert a.join(b) == b.join(a)


@given(labels)
def test_join_is_idempotent_and_bottom_is_the_identity(a: Label) -> None:
    assert a.join(a) == a
    assert a.join(BOTTOM) == a
    assert BOTTOM.join(a) == a


@given(labels, labels)
def test_join_is_an_upper_bound_and_the_order_is_consistent(a: Label, b: Label) -> None:
    joined = a.join(b)
    assert a <= joined
    assert b <= joined
    assert (a <= b) == (a.join(b) == b)
    assert joined >= a


@given(labels, labels, labels)
def test_join_is_monotone(a: Label, b: Label, c: Label) -> None:
    if a <= b:
        assert a.join(c) <= b.join(c)


@given(labels, labels)
def test_join_never_gains_trust_readers_or_loses_sources(a: Label, b: Label) -> None:
    joined = a.join(b)
    assert joined.integrity <= min(a.integrity, b.integrity)
    assert joined.sources >= a.sources | b.sources
    for principal in ("me", "alice", "bob", "dana", "erik"):
        if joined.readers.includes(principal):
            assert a.readers.includes(principal)
            assert b.readers.includes(principal)


@given(st.lists(labels, max_size=6))
def test_join_all_matches_pairwise_join(items: list[Label]) -> None:
    expected = BOTTOM
    for item in items:
        expected = expected.join(item)
    assert join_all(items) == expected


def test_strict_order_and_integrity_cap() -> None:
    # Same sources on both sides: the order then compares integrity alone. With different
    # sources neither label flows to the other, because the join names both origins.
    trusted = Label.trusted_tool("email:1")
    untrusted = Label.untrusted("email:1")
    assert trusted < untrusted
    assert not Label.trusted_tool("tool:x") < untrusted  # different sources: incomparable
    assert not untrusted < trusted
    assert untrusted > trusted
    assert Label.user("plan").with_integrity_at_most(Integrity.TRUSTED_TOOL).integrity is (
        Integrity.TRUSTED_TOOL
    )
    assert untrusted.with_integrity_at_most(Integrity.USER).integrity is Integrity.UNTRUSTED
    assert Label.user().with_sources("a", "b").sources == frozenset({"a", "b"})


def test_readers_semantics() -> None:
    private = Readers.of({"me"})
    shared = Readers.of({"me", "alice"})
    assert private.join(PUBLIC) == private
    assert PUBLIC.join(shared) == shared
    assert shared.join(private) == private
    assert shared <= private  # fewer readers is more restrictive: data flows from shared to private
    assert not private <= shared
    assert shared.includes_all(["me", "alice"])
    assert not shared.includes("bob")
    assert PUBLIC.includes("anyone")
    assert PUBLIC.summary() == "public"
    assert shared.summary() == "2 reader(s)"


@pytest.mark.parametrize(
    "bad", [{"public": True, "members": frozenset({"x"})}, {"members": frozenset({""})}]
)
def test_invalid_readers_are_rejected(bad: dict[str, object]) -> None:
    with pytest.raises(ValueError, match=r"readers|public"):
        Readers(**bad)  # type: ignore[arg-type]


def test_label_validation_and_summary() -> None:
    with pytest.raises(TypeError):
        Label("user")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="sources"):
        Label(sources=frozenset({""}))
    summary = Label.untrusted("email:1", readers=Readers.of({"me"})).summary()
    assert summary == {"integrity": "untrusted", "readers": "1 reader(s)", "sources": ["email:1"]}
    assert Integrity.parse(" User ") is Integrity.USER
    with pytest.raises(ValueError, match="unknown integrity"):
        Integrity.parse("root")

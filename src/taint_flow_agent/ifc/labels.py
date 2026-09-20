"""The security label lattice: integrity x confidentiality readers x provenance sources.

A :class:`Label` says how much a value can be trusted (``integrity``), who may see it
(``readers``) and where it came from (``sources``). Labels form a join-semilattice with a bottom
element (:data:`BOTTOM`: user integrity, public, no sources). ``a.join(b)`` is the least upper
bound and ``a <= b`` means "``a`` flows to ``b``": ``b`` is at least as restrictive as ``a``.

Order per component:

- integrity: ``USER > TRUSTED_TOOL > UNTRUSTED``; the join takes the *lower* trust level,
  so anything touched by untrusted data is untrusted;
- readers: a set of principals allowed to see the value, with ``PUBLIC`` as the least
  restrictive value; the join is the intersection, so combined data may only be seen by
  principals allowed to see every part;
- sources: origin identifiers (``user``, ``tool:read_inbox#3``, ``email:12``); the join is the
  union, so the label of a derived value names every origin it depends on.

Labels never lose information through computation: an interpreter that only ever joins labels
cannot launder untrusted data into trusted data (monotonicity is checked by property tests).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, final

__all__ = ["BOTTOM", "PUBLIC", "Integrity", "Label", "Readers", "join_all"]


class Integrity(IntEnum):
    """Trust level. Higher is more trusted; the join takes the minimum."""

    UNTRUSTED = 0
    TRUSTED_TOOL = 1
    USER = 2

    @classmethod
    def parse(cls, name: str) -> Integrity:
        try:
            return cls[name.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"unknown integrity level {name!r}") from exc


@final
@dataclass(frozen=True, slots=True)
class Readers:
    """Confidentiality component: who may read a value.

    ``public`` means every principal; otherwise exactly ``members``. Principals are opaque
    strings (e-mail addresses in the workspace environment).
    """

    public: bool = True
    members: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if self.public and self.members:
            raise ValueError("a public Readers value has no member set")
        if not all(isinstance(member, str) and member for member in self.members):
            raise ValueError("readers must be non-empty strings")

    @classmethod
    def of(cls, members: Iterable[str]) -> Readers:
        return cls(public=False, members=frozenset(members))

    def join(self, other: Readers) -> Readers:
        """Intersection of the two reader sets (public is the universal set)."""
        if self.public:
            return other
        if other.public:
            return self
        return Readers(public=False, members=self.members & other.members)

    def includes(self, principal: str) -> bool:
        return self.public or principal in self.members

    def includes_all(self, principals: Iterable[str]) -> bool:
        return all(self.includes(principal) for principal in principals)

    def __le__(self, other: Readers) -> bool:
        """``self`` is less restrictive than or equal to ``other``."""
        return self.join(other) == other

    def summary(self) -> str:
        return "public" if self.public else f"{len(self.members)} reader(s)"


PUBLIC = Readers()


@final
@dataclass(frozen=True, slots=True)
class Label:
    integrity: Integrity = Integrity.USER
    readers: Readers = PUBLIC
    sources: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not isinstance(self.integrity, Integrity):
            raise TypeError("integrity must be an Integrity member")
        if not all(isinstance(source, str) and source for source in self.sources):
            raise ValueError("sources must be non-empty strings")

    @classmethod
    def user(cls, *sources: str) -> Label:
        return cls(Integrity.USER, PUBLIC, frozenset(sources))

    @classmethod
    def trusted_tool(cls, *sources: str, readers: Readers = PUBLIC) -> Label:
        return cls(Integrity.TRUSTED_TOOL, readers, frozenset(sources))

    @classmethod
    def untrusted(cls, *sources: str, readers: Readers = PUBLIC) -> Label:
        return cls(Integrity.UNTRUSTED, readers, frozenset(sources))

    def join(self, other: Label) -> Label:
        """Least upper bound: least trusted integrity, fewest readers, all sources."""
        return Label(
            integrity=Integrity(min(self.integrity, other.integrity)),
            readers=self.readers.join(other.readers),
            sources=self.sources | other.sources,
        )

    def __le__(self, other: Label) -> bool:
        """``self`` flows to ``other`` (``other`` is at least as restrictive)."""
        return self.join(other) == other

    def __lt__(self, other: Label) -> bool:
        return self <= other and self != other

    def __ge__(self, other: Label) -> bool:
        return other <= self

    def __gt__(self, other: Label) -> bool:
        return other < self

    def with_sources(self, *sources: str) -> Label:
        return Label(self.integrity, self.readers, self.sources | frozenset(sources))

    def with_integrity_at_most(self, ceiling: Integrity) -> Label:
        """Cap the integrity (used for outputs of the quarantined reader)."""
        return Label(Integrity(min(self.integrity, ceiling)), self.readers, self.sources)

    def summary(self) -> dict[str, Any]:
        """A small JSON-friendly description that carries no data values."""
        return {
            "integrity": self.integrity.name.lower(),
            "readers": self.readers.summary(),
            "sources": sorted(self.sources),
        }


BOTTOM = Label()


def join_all(labels: Iterable[Label]) -> Label:
    """Join any number of labels; the empty join is :data:`BOTTOM`."""
    result = BOTTOM
    for label in labels:
        result = result.join(label)
    return result

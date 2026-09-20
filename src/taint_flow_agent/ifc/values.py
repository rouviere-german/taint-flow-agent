"""Labeled values: every value the interpreter handles carries a :class:`Label`.

Containers are labeled per element (fine-grained labels, as in CaMeL): a list returned by
``read_inbox`` has one label for its structure (how many e-mails there are) and one label per
e-mail. ``effective_label`` joins a value's own label with those of everything inside it, which
is the label that matters when the whole value is handed to a tool or shown to the reader.

The plain (unlabeled) shape of a value is JSON: ``None``, ``bool``, ``int``, ``float``, ``str``,
tuples (lists) and string-keyed mappings.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, final

from pydantic import JsonValue

from taint_flow_agent.ifc.labels import BOTTOM, Label, join_all

__all__ = ["Labeled", "Plain", "effective_label", "from_plain", "to_plain"]

Plain = JsonValue


@final
@dataclass(frozen=True, slots=True)
class Labeled[T]:
    """A value with the label describing its trust, confidentiality and provenance."""

    value: T
    label: Label = BOTTOM

    def relabel(self, label: Label) -> Labeled[T]:
        return Labeled(self.value, label)

    def joined_with(self, label: Label) -> Labeled[T]:
        return Labeled(self.value, self.label.join(label))


def effective_label(value: Labeled[Any]) -> Label:
    """Join the value's label with the labels of every nested labeled element."""
    inner = value.value
    if isinstance(inner, tuple):
        return join_all([value.label, *(effective_label(item) for item in inner)])
    if isinstance(inner, Mapping):
        return join_all([value.label, *(effective_label(item) for item in inner.values())])
    return value.label


def to_plain(value: Labeled[Any]) -> Plain:
    """Strip labels recursively, producing JSON data (tuples become lists)."""
    inner = value.value
    if isinstance(inner, tuple):
        return [to_plain(item) for item in inner]
    if isinstance(inner, Mapping):
        return {str(key): to_plain(item) for key, item in inner.items()}
    if inner is None or isinstance(inner, (bool, int, float, str)):
        return inner
    raise TypeError(f"unsupported value type {type(inner).__name__}")


def from_plain(data: Plain, label: Label) -> Labeled[Any]:
    """Label JSON data uniformly: every node (container or leaf) gets ``label``."""
    if isinstance(data, list):
        return Labeled(tuple(from_plain(item, label) for item in data), label)
    if isinstance(data, dict):
        return Labeled({str(key): from_plain(item, label) for key, item in data.items()}, label)
    if data is None or isinstance(data, (bool, int, float, str)):
        return Labeled(data, label)
    raise TypeError(f"unsupported JSON type {type(data).__name__}")

"""``TrustedText``: the only kind of text the planner prompt builder accepts.

The privileged planner must never read untrusted content. Instead of filtering strings, the
prompt builder's *type* rejects anything that is not :class:`TrustedText`, and ``TrustedText``
can only be minted for the two trusted origins the architecture allows: the user's request and
the developer-written tool signatures (plus the fixed system instructions). A :class:`Labeled`
value, a tool result or a bare ``str`` is refused at runtime as well as by mypy.

This is type discipline, not cryptography: code can still call the constructor with any string.
The canary tests in ``tests/integration/test_planner_isolation.py`` prove that the *agent's*
wiring never does.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, final

__all__ = ["PromptBuilder", "TrustedOrigin", "TrustedText"]

TrustedOrigin = Literal["user_request", "tool_signature", "system"]
_ORIGINS: frozenset[str] = frozenset({"user_request", "tool_signature", "system"})


@final
@dataclass(frozen=True, slots=True)
class TrustedText:
    text: str
    origin: TrustedOrigin

    def __post_init__(self) -> None:
        if not isinstance(self.text, str):
            raise TypeError("TrustedText.text must be a str")
        if self.origin not in _ORIGINS:
            raise ValueError(f"unknown trusted origin {self.origin!r}")

    @classmethod
    def from_user(cls, text: str) -> TrustedText:
        return cls(text, "user_request")

    @classmethod
    def from_signature(cls, text: str) -> TrustedText:
        return cls(text, "tool_signature")

    @classmethod
    def system(cls, text: str) -> TrustedText:
        return cls(text, "system")


@final
class PromptBuilder:
    """Assemble a planner prompt from :class:`TrustedText` parts only."""

    def __init__(self) -> None:
        self._parts: list[TrustedText] = []

    def add(self, part: TrustedText) -> PromptBuilder:
        if not isinstance(part, TrustedText):
            raise TypeError(f"planner prompts accept TrustedText only, not {type(part).__name__}")
        self._parts.append(part)
        return self

    @property
    def parts(self) -> tuple[TrustedText, ...]:
        return tuple(self._parts)

    def render(self, origin: TrustedOrigin | None = None) -> str:
        selected = [p.text for p in self._parts if origin is None or p.origin == origin]
        return "\n\n".join(selected)

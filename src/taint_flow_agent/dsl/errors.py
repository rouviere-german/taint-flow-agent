"""Errors raised while parsing or executing a plan.

Messages describe structure (node types, names, limits), never data values, so they are safe to
log and to return to API clients.
"""

from __future__ import annotations

__all__ = [
    "PlanError",
    "PlanLimitError",
    "PlanRejectedError",
    "PlanRuntimeError",
    "PlanSyntaxError",
]


class PlanError(Exception):
    """Base class for every plan error."""


class PlanSyntaxError(PlanError):
    """The plan is not valid Python syntax."""


class PlanRejectedError(PlanError):
    """The plan parsed but uses a construct, name or size outside the whitelist."""

    def __init__(self, reason: str, *, node: str | None = None, line: int | None = None) -> None:
        where = f" ({node} at line {line})" if node else ""
        super().__init__(f"{reason}{where}")
        self.reason = reason
        self.node = node
        self.line = line


class PlanRuntimeError(PlanError):
    """The plan failed while executing (unknown name, bad index, wrong type ...)."""

    def __init__(self, message: str, *, statement: int | None = None) -> None:
        super().__init__(message)
        self.statement = statement


class PlanLimitError(PlanRuntimeError):
    """A step, loop or wall-clock limit was exceeded."""

    def __init__(self, dimension: str, limit: float, *, statement: int | None = None) -> None:
        super().__init__(f"{dimension} limit exceeded ({limit})", statement=statement)
        self.dimension = dimension
        self.limit = limit

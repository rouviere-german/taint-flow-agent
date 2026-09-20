"""Human declassification bound to the exact call.

When a sink rule fails with ``on_fail: declassify``, the call is not dropped and not executed:
it becomes a declassification request whose id is bound to the canonical hash of the tool name
and validated arguments (the template's :class:`ApprovalStore`). The request carries the
provenance subgraph of the offending argument, rendered without data values, so an approver
sees *where the value came from* (which e-mail, which reader query, which branch) before
releasing it. A decision releases that one call, once, for the principal that requested it;
changing any argument changes the hash and voids the decision.

A :class:`Decider` answers synchronously (``approved``/``denied``) or leaves the request
``pending`` for a later human decision through the API. Scripted deciders drive the benchmark.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, Literal, Protocol, final

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from taint_flow_agent.agentic.approval import ApprovalRecord, ApprovalStatus, ApprovalStore
from taint_flow_agent.agentic.errors import ApprovalError
from taint_flow_agent.agentic.tools import ValidatedCall
from taint_flow_agent.core.fileio import atomic_write_text, file_lock

__all__ = [
    "Decider",
    "DecisionOutcome",
    "DeclassificationContext",
    "DeclassificationDeniedError",
    "DeclassificationGate",
    "DeclassificationPendingError",
    "DenyAllReviewer",
    "PendingDecider",
    "ScriptedReviewer",
]

DecisionOutcome = Literal["approved", "denied", "pending"]


class DeclassificationContext(BaseModel):
    """What a reviewer sees: the rule, the reason and the provenance, never the raw data."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    request_id: str
    call_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    sink: str
    argument: str
    rule: str
    reason: str
    arg_labels: dict[str, dict[str, Any]]
    provenance_path: list[str]
    provenance_subgraph: str = Field(max_length=100_000)
    requested_at: float
    outcome: DecisionOutcome = "pending"
    decided_by: str | None = None


class _ContextFile(BaseModel):
    version: int = 1
    contexts: list[DeclassificationContext] = Field(default_factory=list)


class DeclassificationDeniedError(Exception):
    def __init__(self, request_id: str, call_hash: str, rule: str, decided_by: str) -> None:
        super().__init__(f"declassification {request_id} denied by {decided_by} (rule {rule})")
        self.request_id = request_id
        self.call_hash = call_hash
        self.rule = rule
        self.decided_by = decided_by


class DeclassificationPendingError(Exception):
    def __init__(self, request_id: str, call_hash: str, rule: str) -> None:
        super().__init__(f"declassification {request_id} is pending (rule {rule})")
        self.request_id = request_id
        self.call_hash = call_hash
        self.rule = rule


class Decider(Protocol):
    name: str

    def __call__(
        self, record: ApprovalRecord, context: DeclassificationContext
    ) -> DecisionOutcome: ...


@final
class PendingDecider:
    """Leave every request for a later human decision (the API mode)."""

    name = "pending"

    def __call__(self, record: ApprovalRecord, context: DeclassificationContext) -> DecisionOutcome:
        del record, context
        return "pending"


@final
class DenyAllReviewer:
    name = "deny-all-reviewer"

    def __call__(self, record: ApprovalRecord, context: DeclassificationContext) -> DecisionOutcome:
        del record, context
        return "denied"


@final
class ScriptedReviewer:
    """A reviewer who approves exactly the calls a predicate accepts (benchmarks, demo).

    The predicate sees the tool name and the canonical arguments, which is what a careful human
    reading the provenance display would compare against the task they asked for.
    """

    name = "scripted-reviewer"

    def __init__(self, approve: Callable[[str, dict[str, Any]], bool]) -> None:
        self._approve = approve
        self.decisions: list[tuple[str, DecisionOutcome]] = []

    def __call__(self, record: ApprovalRecord, context: DeclassificationContext) -> DecisionOutcome:
        approved = self._approve(record.tool, dict(record.args))
        outcome: DecisionOutcome = "approved" if approved else "denied"
        self.decisions.append((context.rule, outcome))
        return outcome


@final
class DeclassificationGate:
    def __init__(
        self,
        store: ApprovalStore,
        *,
        decider: Decider | None = None,
        principal: str = "agent",
        contexts_path: Path | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._store = store
        self._decider: Decider = decider if decider is not None else PendingDecider()
        self._principal = principal
        self._path = contexts_path
        self._clock = clock
        self._lock = threading.Lock()
        self._contexts: dict[str, DeclassificationContext] = {}
        self._load()

    @property
    def principal(self) -> str:
        return self._principal

    def _load(self) -> None:
        if self._path is None or not self._path.exists():
            return
        try:
            data = _ContextFile.model_validate_json(self._path.read_text(encoding="utf-8"))
        except ValidationError as exc:
            raise ApprovalError(
                f"declassification file {self._path.name} failed validation"
            ) from exc
        self._contexts = {item.request_id: item for item in data.contexts}

    def _persist(self) -> None:
        if self._path is None:
            return
        payload = _ContextFile(contexts=list(self._contexts.values())).model_dump(mode="json")
        with file_lock(self._path):
            atomic_write_text(self._path, json.dumps(payload, indent=2, sort_keys=True) + "\n")

    def _remember(self, context: DeclassificationContext) -> None:
        with self._lock:
            self._contexts[context.request_id] = context
            self._persist()

    def _context_for(
        self,
        record: ApprovalRecord,
        *,
        sink: str,
        argument: str,
        rule: str,
        reason: str,
        arg_labels: dict[str, dict[str, Any]],
        provenance_path: list[str],
        provenance_subgraph: str,
    ) -> DeclassificationContext:
        return DeclassificationContext(
            request_id=record.id,
            call_hash=record.call_hash,
            sink=sink,
            argument=argument,
            rule=rule,
            reason=reason,
            arg_labels=arg_labels,
            provenance_path=provenance_path,
            provenance_subgraph=provenance_subgraph,
            requested_at=self._clock(),
        )

    def authorize(
        self,
        call: ValidatedCall,
        *,
        sink: str,
        argument: str,
        rule: str,
        reason: str,
        arg_labels: dict[str, dict[str, Any]],
        provenance_path: list[str],
        provenance_subgraph: str,
    ) -> DeclassificationContext:
        """Release the call if a human (or the configured decider) approves this exact call.

        Returns the context on approval; raises :class:`DeclassificationDeniedError` or
        :class:`DeclassificationPendingError` otherwise.
        """
        call.ensure_unchanged()
        call_hash = call.call_hash
        details: dict[str, Any] = {
            "sink": sink,
            "argument": argument,
            "rule": rule,
            "reason": reason,
            "arg_labels": arg_labels,
            "provenance_path": provenance_path,
            "provenance_subgraph": provenance_subgraph,
        }
        consumed = self._store.consume(call_hash, principal=self._principal)
        if consumed is not None:
            context = self._contexts.get(consumed.id) or self._context_for(consumed, **details)
            approved = context.model_copy(
                update={"outcome": "approved", "decided_by": consumed.decided_by}
            )
            self._remember(approved)
            return approved
        record = self._store.request(call, requested_by=self._principal)
        context = self._contexts.get(record.id) or self._context_for(record, **details)
        self._remember(context)
        outcome = self._decider(record, context)
        if outcome == "pending":
            raise DeclassificationPendingError(record.id, call_hash, rule)
        decided = self._store.decide(
            record.id,
            approver=self._decider.name,
            approve=outcome == "approved",
            reason=f"decided by {self._decider.name}",
        )
        updated = context.model_copy(update={"outcome": outcome, "decided_by": decided.decided_by})
        self._remember(updated)
        if outcome == "denied":
            raise DeclassificationDeniedError(record.id, call_hash, rule, self._decider.name)
        if self._store.consume(call_hash, principal=self._principal) is None:  # pragma: no cover
            raise ApprovalError("approved declassification could not be consumed")
        return updated

    def pending(self) -> list[tuple[ApprovalRecord, DeclassificationContext]]:
        """Open requests with their provenance display, for a reviewer UI or API."""
        result = []
        for record in self._store.pending():
            context = self._contexts.get(record.id)
            if context is not None:
                result.append((record, context))
        return result

    def context(self, request_id: str) -> DeclassificationContext | None:
        return self._contexts.get(request_id)

    def decide(
        self, request_id: str, *, approver: str, approve: bool, reason: str | None = None
    ) -> ApprovalRecord:
        """Record a human decision (separation of duties is enforced by the store)."""
        decided = self._store.decide(request_id, approver=approver, approve=approve, reason=reason)
        context = self._contexts.get(request_id)
        if context is not None:
            outcome: DecisionOutcome = "approved" if approve else "denied"
            self._remember(context.model_copy(update={"outcome": outcome, "decided_by": approver}))
        return decided

    def records(self) -> Iterator[tuple[ApprovalRecord, DeclassificationContext]]:
        for request_id, context in list(self._contexts.items()):
            try:
                record = self._store.get(request_id)
            except ApprovalError:
                continue
            yield record, context

    def as_json(self) -> list[dict[str, Any]]:
        return [
            {"status": ApprovalStatus(record.status).value, **context.model_dump(mode="json")}
            for record, context in self.records()
        ]

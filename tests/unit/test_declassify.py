from __future__ import annotations

import itertools
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, ConfigDict, JsonValue

from taint_flow_agent.agentic.approval import ApprovalStatus, ApprovalStore
from taint_flow_agent.agentic.errors import ApprovalError
from taint_flow_agent.agentic.providers.base import ToolUseBlock
from taint_flow_agent.agentic.tools import Capability, ToolDefinition, ToolRegistry, ValidatedCall
from taint_flow_agent.policy.declassify import (
    DeclassificationDeniedError,
    DeclassificationGate,
    DeclassificationPendingError,
    DenyAllReviewer,
    PendingDecider,
    ScriptedReviewer,
)

pytestmark = pytest.mark.unit


class PayArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    recipient: str
    amount: float


def registry() -> ToolRegistry:
    reg = ToolRegistry({Capability.NETWORK_EGRESS})
    reg.register(
        ToolDefinition(
            name="pay",
            description="Pay.",
            args_model=PayArgs,
            capabilities=frozenset({Capability.NETWORK_EGRESS}),
            handler=lambda args: "paid",
        )
    )
    return reg


def call(recipient: str = "ACC-1", amount: float = 5.0) -> ValidatedCall:
    return registry().validate_call(
        ToolUseBlock(id="c", name="pay", arguments={"recipient": recipient, "amount": amount})
    )


def store(path: Path | None = None) -> ApprovalStore:
    counter = itertools.count()
    return ApprovalStore(path, id_factory=lambda: f"req-{next(counter)}")


DETAILS: dict[str, Any] = {
    "sink": "pay",
    "argument": "recipient",
    "rule": "pay.recipient",
    "reason": "recipient integrity is untrusted",
    "arg_labels": {"recipient": {"integrity": "untrusted", "readers": "public", "sources": []}},
    "provenance_path": [
        "[0] tool_result: result of read_email",
        "[3] sink_argument: pay.recipient",
    ],
    "provenance_subgraph": "[0] ...\n[3] ... <- [0]",
}


def test_scripted_reviewer_approves_exactly_the_expected_call() -> None:
    reviewer = ScriptedReviewer(lambda tool, args: args.get("recipient") == "ACC-1")
    gate = DeclassificationGate(store(), decider=reviewer, principal="agent")
    context = gate.authorize(call(), **DETAILS)
    assert context.outcome == "approved"
    assert context.decided_by == "scripted-reviewer"
    assert context.provenance_path == DETAILS["provenance_path"]
    with pytest.raises(DeclassificationDeniedError) as denied:
        gate.authorize(call(recipient="ACC-EVIL"), **DETAILS)
    assert denied.value.decided_by == "scripted-reviewer"
    assert reviewer.decisions == [("pay.recipient", "approved"), ("pay.recipient", "denied")]
    statuses = {record.status for record, _ in gate.records()}
    assert statuses == {ApprovalStatus.CONSUMED, ApprovalStatus.DENIED}
    assert {item["status"] for item in gate.as_json()} == {"consumed", "denied"}


def test_deny_all_and_pending_deciders() -> None:
    gate = DeclassificationGate(store(), decider=DenyAllReviewer(), principal="agent")
    with pytest.raises(DeclassificationDeniedError):
        gate.authorize(call(), **DETAILS)
    pending_gate = DeclassificationGate(store(), decider=PendingDecider(), principal="agent")
    with pytest.raises(DeclassificationPendingError) as info:
        pending_gate.authorize(call(), **DETAILS)
    request_id = info.value.request_id
    assert [record.id for record, _ in pending_gate.pending()] == [request_id]
    context = pending_gate.context(request_id)
    assert context is not None
    assert context.outcome == "pending"
    # Asking again does not open a second request for the same call.
    with pytest.raises(DeclassificationPendingError) as again:
        pending_gate.authorize(call(), **DETAILS)
    assert again.value.request_id == request_id


def test_human_decisions_release_exactly_the_approved_call_once(tmp_path: Path) -> None:
    approvals = tmp_path / "approvals.json"
    contexts = tmp_path / "declassifications.json"
    gate = DeclassificationGate(store(approvals), principal="agent", contexts_path=contexts)
    with pytest.raises(DeclassificationPendingError) as info:
        gate.authorize(call(), **DETAILS)
    request_id = info.value.request_id
    with pytest.raises(ApprovalError, match="separation of duties"):
        gate.decide(request_id, approver="agent", approve=True)
    gate.decide(request_id, approver="human:alice", approve=True, reason="matches the invoice")
    # A different call (other amount) is not released by that approval.
    with pytest.raises(DeclassificationPendingError):
        gate.authorize(call(amount=6.0), **DETAILS)
    released = gate.authorize(call(), **DETAILS)
    assert released.outcome == "approved"
    assert released.decided_by == "human:alice"
    # Single use: the same call needs a new decision afterwards.
    with pytest.raises(DeclassificationPendingError):
        gate.authorize(call(), **DETAILS)
    # State survives a restart through both files.
    reopened = DeclassificationGate(store(approvals), principal="agent", contexts_path=contexts)
    assert reopened.context(request_id) is not None
    assert reopened.context(request_id).outcome == "approved"  # type: ignore[union-attr]
    assert len(list(reopened.records())) == 3
    with pytest.raises(ApprovalError, match="not pending"):
        reopened.decide(request_id, approver="human:bob", approve=False)


def test_denied_decisions_are_recorded_and_bad_files_are_refused(tmp_path: Path) -> None:
    contexts = tmp_path / "declassifications.json"
    gate = DeclassificationGate(store(), principal="agent", contexts_path=contexts)
    with pytest.raises(DeclassificationPendingError) as info:
        gate.authorize(call(), **DETAILS)
    gate.decide(info.value.request_id, approver="human:bob", approve=False)
    assert gate.context(info.value.request_id).outcome == "denied"  # type: ignore[union-attr]
    assert gate.pending() == []
    contexts.write_text(json.dumps({"version": 1, "contexts": [{"bad": True}]}), encoding="utf-8")
    with pytest.raises(ApprovalError, match="failed validation"):
        DeclassificationGate(store(), principal="agent", contexts_path=contexts)


def test_context_carries_no_argument_values() -> None:
    gate = DeclassificationGate(store(), decider=PendingDecider(), principal="agent")
    with pytest.raises(DeclassificationPendingError):
        gate.authorize(call(recipient="SECRET-ACCOUNT"), **DETAILS)
    ((_, context),) = gate.pending()
    dumped: dict[str, JsonValue] = context.model_dump(mode="json")
    assert "SECRET-ACCOUNT" not in json.dumps(dumped)
    assert gate.principal == "agent"

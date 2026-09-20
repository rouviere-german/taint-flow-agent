"""The guarded tool table: validation, policy decisions, declassification, labeling, audit."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from prometheus_client import CollectorRegistry
from pydantic import BaseModel, ConfigDict, JsonValue

from taint_flow_agent.agentic.approval import ApprovalStore
from taint_flow_agent.agentic.audit import AuditLog, verify_file
from taint_flow_agent.agentic.tools import Capability, ToolDefinition, ToolRegistry
from taint_flow_agent.dsl.grammar import Limits, parse_plan
from taint_flow_agent.dsl.interpreter import ExecutionResult, Interpreter
from taint_flow_agent.dual.reader import ScriptedReader
from taint_flow_agent.env.workspace import Workspace, make_workspace
from taint_flow_agent.ifc.labels import Integrity, Label
from taint_flow_agent.policy.declassify import (
    DeclassificationGate,
    DenyAllReviewer,
    PendingDecider,
    ScriptedReviewer,
)
from taint_flow_agent.policy.defaults import default_policy
from taint_flow_agent.policy.engine import SinkPolicyEngine
from taint_flow_agent.policy.executor import (
    DECLASSIFICATION_DENIED_RULE,
    GuardedToolTable,
    UnguardedToolTable,
    plain_labeler,
)
from taint_flow_agent.policy.metrics import create_ifc_metrics

pytestmark = pytest.mark.unit


def guarded(
    workspace: Workspace,
    *,
    gate: DeclassificationGate | None = None,
    audit: AuditLog | None = None,
    registry: CollectorRegistry | None = None,
) -> tuple[GuardedToolTable, Any]:
    reg, labelers = workspace.build_tools()
    metrics = create_ifc_metrics(registry) if registry is not None else None
    engine = SinkPolicyEngine(default_policy(), membership=workspace.membership)
    return GuardedToolTable(
        reg, labelers, engine=engine, gate=gate, metrics=metrics, audit=audit
    ), metrics


def run(table: Any, source: str) -> ExecutionResult:
    interpreter = Interpreter(table, ScriptedReader())
    plan = parse_plan(source, known_functions=interpreter.known_functions, limits=Limits())
    return interpreter.run(plan)


def test_denial_carries_provenance_metrics_and_audit(tmp_path: Path) -> None:
    workspace = make_workspace()
    workspace.add_email("evil@x.example", "hi", "Name: Mallory")
    audit = AuditLog(tmp_path / "audit.jsonl")
    table, metrics = guarded(workspace, audit=audit, registry=CollectorRegistry())
    result = run(
        table,
        'emails = search_emails(query="evil")\n'
        "e = emails[0]\n"
        'write_file(name=e["subject"], content="x")\n',
    )
    assert result.status == "denied"
    denial = result.denial
    assert denial is not None
    assert denial.sink == "write_file"
    assert denial.argument == "name"
    assert denial.rule == "write_file.name"
    assert denial.provenance_depth >= 2
    assert any("tool_result" in line for line in denial.provenance_path)
    assert all("Mallory" not in line for line in denial.provenance_path)
    assert metrics.policy_denials_total.labels("write_file", "write_file.name")._value.get() == 1.0
    entries = list((tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines())
    assert any('"policy_evaluated"' in line for line in entries)
    assert any('"policy_denied"' in line for line in entries)
    assert verify_file(tmp_path / "audit.jsonl", expect_head=audit.head).ok
    assert workspace.files.get("hi") is None


def test_declassification_paths(tmp_path: Path) -> None:
    plan = (
        'emails = search_emails(query="dana")\n'
        "e = emails[0]\n"
        'inv = query_quarantined("invoice", e)\n'
        'pay_invoice(recipient=inv["account"], amount=inv["amount"], reference="r")\n'
    )
    body = "Vendor: Vendor Dana Ltd\nAmount: 10.00 EUR\nAccount: DE89-VENDOR-0001\nReference: R"
    # No gate configured: escalations are denied with an explicit reason.
    workspace = make_workspace()
    workspace.add_email("dana@vendor.example", "Invoice", body)
    table, _ = guarded(workspace)
    result = run(table, plan)
    assert result.status == "denied"
    assert result.denial is not None
    assert "no declassification gate" in result.denial.reason
    # Pending decider: the run is held with a request id and the context shows the subgraph.
    workspace = make_workspace()
    workspace.add_email("dana@vendor.example", "Invoice", body)
    gate = DeclassificationGate(ApprovalStore(), decider=PendingDecider(), principal="agent")
    table, metrics = guarded(workspace, gate=gate, registry=CollectorRegistry())
    result = run(table, plan)
    assert result.status == "held"
    assert result.held is not None
    assert result.held.request_id
    assert result.held.provenance_path
    ((_, context),) = gate.pending()
    assert "reader_output" in context.provenance_subgraph
    assert metrics.declassifications_total.labels("pending")._value.get() == 1.0
    # A human approval releases the exact call on the next run.
    gate.decide(result.held.request_id, approver="human", approve=True)
    workspace.payments.clear()
    result = run(table, plan)
    assert result.status == "completed"
    assert workspace.payments[0].amount == 10.0
    assert metrics.declassifications_total.labels("approved")._value.get() == 1.0
    # Deny-all reviewer: denial names the declassification rule.
    workspace = make_workspace()
    workspace.add_email("dana@vendor.example", "Invoice", body)
    audit = AuditLog(tmp_path / "audit.jsonl")
    gate = DeclassificationGate(ApprovalStore(), decider=DenyAllReviewer(), principal="agent")
    table, metrics = guarded(workspace, gate=gate, audit=audit, registry=CollectorRegistry())
    result = run(table, plan)
    assert result.status == "denied"
    assert result.denial is not None
    assert result.denial.rule == DECLASSIFICATION_DENIED_RULE
    assert metrics.declassifications_total.labels("denied")._value.get() == 1.0
    assert '"declassification_denied"' in (tmp_path / "audit.jsonl").read_text(encoding="utf-8")


def test_invalid_arguments_and_tool_failures_become_plan_errors_or_error_values() -> None:
    workspace = make_workspace()
    table, _ = guarded(workspace)
    result = run(table, 'send_email(to="not an address", subject="s", body="b")\n')
    assert result.status == "error"
    assert "invalid arguments for send_email" in (result.error or "")
    assert "not an address" not in (result.error or "")

    class Args(BaseModel):
        model_config = ConfigDict(extra="forbid")
        x: int = 1

    def boom(args: Args) -> JsonValue:
        raise RuntimeError("password=hunter2")

    reg = ToolRegistry({Capability.READ_DATA})
    reg.register(
        ToolDefinition(
            name="boom",
            description="Fails.",
            args_model=Args,
            capabilities=frozenset({Capability.READ_DATA}),
            handler=boom,
        )
    )
    plain = UnguardedToolTable(reg, {"boom": plain_labeler(Label.trusted_tool("tool:boom"))})
    result = run(plain, "r = boom()\n")
    assert result.status == "completed"
    assert result.env["r"].value["error"].value == "boom failed"
    with pytest.raises(ValueError, match="without a labeler"):
        UnguardedToolTable(reg, {})


def test_unguarded_table_runs_sinks_without_policy() -> None:
    workspace = make_workspace()
    reg, labelers = workspace.build_tools()
    table = UnguardedToolTable(reg, labelers)
    result = run(
        table, 'emails = read_inbox()\ne = emails[0]\nwrite_file(name=e["subject"], content="x")\n'
    )
    assert result.status == "completed"
    assert "Team sync agenda" in workspace.files
    assert result.calls[-1].arg_labels["name"]["integrity"] == "untrusted"
    assert table.sink_signatures()["write_file"] == ("name", "content")
    assert table.registry is reg


def test_policy_validation_and_execution_labels() -> None:
    workspace = make_workspace()
    table, _ = guarded(workspace)
    assert table.validate_policy(workspace.collections()) == []
    assert table.engine.policy.sinks == (
        "add_contact",
        "create_event",
        "pay_invoice",
        "send_email",
        "write_file",
    )
    reviewer = ScriptedReviewer(lambda tool, args: True)
    gate = DeclassificationGate(ApprovalStore(), decider=reviewer, principal="agent")
    table, _ = guarded(workspace, gate=gate)
    result = run(
        table,
        'p = lookup_payee(name="Cloud Hosting Inc")\n'
        'pay_invoice(recipient=p["account"], amount=5, reference="x")\n',
    )
    assert result.status == "completed"
    record = result.executed_calls[-1]
    assert record.result_label == {
        "integrity": "trusted_tool",
        "readers": "1 reader(s)",
        "sources": ["tool:pay_invoice"],
    }
    assert record.arg_labels["recipient"]["integrity"] == Integrity.TRUSTED_TOOL.name.lower()
    assert reviewer.decisions == []

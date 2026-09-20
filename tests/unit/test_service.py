from __future__ import annotations

from pathlib import Path

import pytest
from prometheus_client import CollectorRegistry

from taint_flow_agent.agentic.audit import verify_file
from taint_flow_agent.agentic.errors import ApprovalError
from taint_flow_agent.core.config import Settings
from taint_flow_agent.env.tasks import task_by_id
from taint_flow_agent.policy.defaults import DEFAULT_POLICY_YAML, default_policy
from taint_flow_agent.policy.rules import PolicyError
from taint_flow_agent.service import AgentService

pytestmark = pytest.mark.unit


def test_held_runs_resume_after_a_human_decision(tmp_path: Path) -> None:
    service = AgentService(policy=default_policy(), data_dir=tmp_path)
    task = task_by_id("T25")
    _, report, _ = service.run_task("T25")
    assert report.status == "held"
    assert report.result is not None
    assert report.result.held is not None
    request_id = report.result.held.request_id
    pending = service.pending()
    assert [item["request_id"] for item in pending] == [request_id]
    assert pending[0]["sink"] == "pay_invoice"
    assert "reader_output" in pending[0]["provenance_subgraph"]
    assert "DE89-VENDOR-0001" not in str(pending)
    with pytest.raises(ApprovalError, match="agent principal"):
        service.decide(request_id, approver="agent", approve=True, reason=None)
    decision = service.decide(
        request_id, approver="key:abc", approve=True, reason="matches invoice"
    )
    assert decision.status == "approved"
    assert decision.decided_by == "key:abc"
    _, report, workspace = service.run_task("T25")
    assert report.status == "completed"
    assert workspace.payments[0].recipient == "DE89-VENDOR-0001"
    assert service.pending() == []
    audit = service.audit
    assert audit is not None
    assert verify_file(audit.path, expect_head=audit.head).ok
    text = audit.path.read_text(encoding="utf-8")
    assert '"declassification_decided"' in text
    assert '"policy_evaluated"' in text
    # run_plan uses a clean workspace, so a task plan that expects the task's own fixture
    # fails at the first missing record instead of reaching a sink.
    report = service.run_plan(task.request, task.plan, reader="gullible")
    assert report.status == "error"
    # Plans supplied directly and attacked tasks share the same gate.
    _, attacked, _ = service.run_task(
        "T25", carrier="email_body", mutation="split", reader="gullible"
    )
    assert attacked.status == "held"
    assert attacked.result is not None
    assert attacked.result.held is not None
    assert attacked.result.held.request_id != request_id


def test_readiness_reflects_policy_problems(tmp_path: Path) -> None:
    good = AgentService(policy=default_policy(), data_dir=None)
    assert good.ready()
    assert good.policy_problems() == []
    broken = AgentService(policy=None, policy_error="policy file default.yaml not found")
    assert not broken.ready()
    assert broken.policy_problems() == ["policy file default.yaml not found"]
    with pytest.raises(PolicyError):
        broken.run_plan("x", "x = 1\n")
    partial = default_policy().without_context_rules()
    partial_doc = partial.document.model_copy(
        update={"sinks": {k: v for k, v in partial.document.sinks.items() if k != "pay_invoice"}}
    )
    from taint_flow_agent.policy.rules import Policy

    missing = AgentService(policy=Policy(partial_doc))
    assert missing.policy_problems() == ["sink pay_invoice has no policy entry (deny by default)"]
    assert AgentService(policy=None).policy_problems() == ["no policy loaded"]


def test_from_settings_loads_the_policy_file_and_metrics(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(DEFAULT_POLICY_YAML, encoding="utf-8")
    settings = Settings(_env_file=None, policy_path=policy_path, data_dir=tmp_path / "var")
    service = AgentService.from_settings(settings, registry=CollectorRegistry())
    assert service.ready()
    assert service.policy is not None
    audit = service.audit
    assert audit is not None
    assert audit.path == tmp_path / "var" / "service" / "audit.jsonl"
    assert audit.path.parent.is_dir()
    missing = AgentService.from_settings(
        Settings(_env_file=None, policy_path=tmp_path / "nope.yaml", data_dir=tmp_path / "var2")
    )
    assert not missing.ready()
    assert "not found" in missing.policy_problems()[0]
    policy_path.write_text("version: 1\nsinks: []\n", encoding="utf-8")
    invalid = AgentService.from_settings(
        Settings(_env_file=None, policy_path=policy_path, data_dir=tmp_path / "var3")
    )
    assert "invalid policy" in invalid.policy_problems()[0]

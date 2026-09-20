"""Optional: record cassettes for the live dual-LLM path (needs ANTHROPIC_API_KEY, costs money).

Usage:
  uv run python bench/record.py --tasks T25 T09 --max-usd 0.50

Nothing else in this repository needs a key: the tests, the demo and every benchmark run with
the scripted planner and reader. This script exists so the live wiring -- ``LLMPlanner`` on
``claude-opus-5`` and ``QuarantinedReader`` on ``claude-haiku-4-5`` -- can be exercised once and
replayed afterwards with ``ReplayProvider``.

Guarantees while recording:

- a :class:`BudgetLedger` caps steps, tokens and USD; the run stops rather than overspending;
- the planner still receives :class:`TrustedText` only, and every request is checked for the
  task's canary strings before it is sent, so a recording run cannot leak untrusted text into
  the planner prompt;
- cassettes store the request *hash* and the response, never the prompt, so no workspace text
  reaches the repository.

Results from recorded runs are reported separately from the offline benchmark: they measure the
planner's quality, not the architecture.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from pydantic import SecretStr

from taint_flow_agent.agentic.approval import ApprovalStore
from taint_flow_agent.agentic.budget import BudgetLedger, BudgetLimits
from taint_flow_agent.agentic.providers.anthropic import AnthropicProvider
from taint_flow_agent.agentic.providers.base import LLMRequest
from taint_flow_agent.agentic.providers.replay import RecordingProvider
from taint_flow_agent.dual.agent import TaintFlowAgent
from taint_flow_agent.dual.planner import PLANNER_ROLE, LLMPlanner
from taint_flow_agent.dual.reader import READER_ROLE, QuarantinedReader
from taint_flow_agent.env.carriers import CARRIERS, Carrier, apply_carrier, render_injection
from taint_flow_agent.env.tasks import TASKS, task_by_id
from taint_flow_agent.env.workspace import make_workspace
from taint_flow_agent.ifc.trusted import TrustedText
from taint_flow_agent.policy.declassify import DeclassificationGate, DenyAllReviewer
from taint_flow_agent.policy.defaults import default_policy
from taint_flow_agent.policy.engine import SinkPolicyEngine
from taint_flow_agent.policy.executor import GuardedToolTable

ROOT = Path(__file__).resolve().parents[1]
CASSETTES = ROOT / "bench" / "cassettes"
RESULTS = ROOT / "bench" / "results" / "recorded.json"


def _canaries(task: Any) -> list[str]:
    """Strings that only ever exist in untrusted content for this task."""
    return [task.injection.marker, *(str(v) for v in task.injection.field_overrides.values())]


def _guard_planner_request(request: LLMRequest, canaries: list[str]) -> None:
    payload = request.model_dump_json()
    for canary in canaries:
        if canary and canary in payload:
            raise SystemExit(
                "ABORTED: a planner request contained untrusted content; recording stopped"
            )


def record_task(
    task_id: str,
    *,
    provider_factory: Any,
    budget: BudgetLedger,
    carrier: Carrier | None,
) -> dict[str, Any]:
    task = task_by_id(task_id)
    workspace = make_workspace()
    target = task.setup(workspace)
    if carrier is not None:
        apply_carrier(workspace, target, carrier, render_injection(task.injection, "plain"))
    registry, labelers = workspace.build_tools()
    engine = SinkPolicyEngine(default_policy(), membership=workspace.membership)
    gate = DeclassificationGate(ApprovalStore(), decider=DenyAllReviewer(), principal="agent")
    table = GuardedToolTable(registry, labelers, engine=engine, gate=gate)
    canaries = _canaries(task)
    agent = TaintFlowAgent(
        table=table,
        planner=LLMPlanner(
            provider_factory(PLANNER_ROLE, task_id, carrier),
            budget=budget,
            on_request=lambda request: _guard_planner_request(request, canaries),
        ),
        reader=QuarantinedReader(provider_factory(READER_ROLE, task_id, carrier), budget=budget),
        budget=budget,
    )
    report = agent.run(TrustedText.from_user(task.request))
    return {
        "task_id": task_id,
        "carrier": carrier,
        "status": report.status,
        "plan_sha256": report.plan_sha256,
        "plan_source": report.plan_source,
        "executed": [] if report.result is None else [c.name for c in report.result.executed_calls],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="record live cassettes (costs money)")
    parser.add_argument("--tasks", nargs="+", default=["T25"], choices=[t.id for t in TASKS])
    parser.add_argument("--carrier", default=None, choices=[*CARRIERS])
    parser.add_argument("--max-usd", type=float, default=0.50)
    parser.add_argument("--max-steps", type=int, default=40)
    parser.add_argument("--max-tokens", type=int, default=200_000)
    args = parser.parse_args(argv)

    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        print("record needs ANTHROPIC_API_KEY; tests, demo and bench never do.", file=sys.stderr)
        return 2

    budget = BudgetLedger(
        BudgetLimits.of(steps=args.max_steps, tokens=args.max_tokens, usd=args.max_usd)
    )
    live = AnthropicProvider(
        api_key=SecretStr(key),
        role_models={READER_ROLE: "claude-haiku-4-5"},
    )
    CASSETTES.mkdir(parents=True, exist_ok=True)

    def provider_factory(role: str, task_id: str, carrier: Carrier | None) -> RecordingProvider:
        name = f"{task_id}-{carrier or 'benign'}-{role}.jsonl"
        return RecordingProvider(live, CASSETTES / name, budget=budget, mode="overwrite")

    runs = [
        record_task(task_id, provider_factory=provider_factory, budget=budget, carrier=args.carrier)
        for task_id in args.tasks
    ]
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    payload = {"spend": budget.state.model_dump(mode="json"), "runs": runs}
    RESULTS.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

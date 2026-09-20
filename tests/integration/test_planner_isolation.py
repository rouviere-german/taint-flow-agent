"""Canary tests: untrusted content never reaches the privileged planner's prompt.

This is the architecture's load-bearing claim. It is checked three ways:

1. *type* -- the prompt builder refuses anything that is not ``TrustedText``;
2. *canary* -- every task runs end to end with a unique marker planted in every untrusted field,
   through every carrier and mutation, and no planner request may contain it;
3. *positive control* -- the same markers are asserted to reach the quarantined reader, so a
   passing canary test cannot be an artifact of the marker never being read at all.
"""

from __future__ import annotations

import random
from typing import Any

import pytest

from taint_flow_agent.agentic.approval import ApprovalStore
from taint_flow_agent.agentic.providers.base import LLMRequest, LLMResponse, Usage
from taint_flow_agent.agentic.providers.fake import FakeProvider
from taint_flow_agent.core.canonical import canonical_json
from taint_flow_agent.dual.agent import TaintFlowAgent
from taint_flow_agent.dual.planner import LLMPlanner
from taint_flow_agent.dual.reader import QuarantinedReader
from taint_flow_agent.env.carriers import (
    ATTACKER_ACCOUNT,
    ATTACKER_EMAIL,
    CARRIERS,
    MUTATIONS,
    Carrier,
    Mutation,
    apply_carrier,
    render_injection,
)
from taint_flow_agent.env.tasks import TASKS, TaskTemplate
from taint_flow_agent.env.workspace import Workspace, make_workspace
from taint_flow_agent.ifc.trusted import PromptBuilder, TrustedText
from taint_flow_agent.policy.declassify import DeclassificationGate, DenyAllReviewer
from taint_flow_agent.policy.defaults import default_policy
from taint_flow_agent.policy.engine import SinkPolicyEngine
from taint_flow_agent.policy.executor import GuardedToolTable

pytestmark = pytest.mark.integration

CANARY = "CANARY-8f31ac-DO-NOT-PLAN-ON-THIS"


class PlanPolicy:
    """A planner stand-in that answers with the task's reference plan, whatever it is asked."""

    def __init__(self, plan: str) -> None:
        self._plan = plan
        self.requests: list[LLMRequest] = []

    def __call__(self, request: LLMRequest, rng: random.Random, turn: int) -> LLMResponse:
        del rng, turn
        self.requests.append(request)
        return LLMResponse(
            model="fake-planner",
            stop_reason="end_turn",
            text="",
            parsed={"plan": self._plan},
            usage=Usage(input_tokens=1, output_tokens=1),
        )


class ExtractPolicy:
    """A quarantined-reader stand-in that answers with an empty (schema-valid) extraction."""

    def __init__(self) -> None:
        self.requests: list[LLMRequest] = []

    def __call__(self, request: LLMRequest, rng: random.Random, turn: int) -> LLMResponse:
        del rng, turn
        self.requests.append(request)
        return LLMResponse(
            model="fake-reader",
            stop_reason="end_turn",
            text="{}",
            parsed={},
            usage=Usage(input_tokens=1, output_tokens=1),
        )


def poison(workspace: Workspace, marker: str) -> None:
    """Put ``marker`` into every untrusted field the workspace can hand to a tool."""
    for email in workspace.inbox:
        email.subject = f"{email.subject} {marker}"
        email.body = f"{email.body}\n{marker}"
    for record in workspace.files.values():
        record.content = f"{record.content}\n{marker}"
    for event in workspace.events:
        event.note = f"{event.note} {marker}"
        event.title = f"{event.title} {marker}"


def run_task(
    task: TaskTemplate, *, carrier: Carrier | None = None, mutation: Mutation = "plain"
) -> tuple[PlanPolicy, ExtractPolicy, Workspace]:
    workspace = make_workspace()
    target = task.setup(workspace)
    if carrier is not None:
        apply_carrier(workspace, target, carrier, render_injection(task.injection, mutation))
    poison(workspace, CANARY)
    registry, labelers = workspace.build_tools()
    engine = SinkPolicyEngine(default_policy(), membership=workspace.membership)
    gate = DeclassificationGate(ApprovalStore(), decider=DenyAllReviewer(), principal="agent")
    plan_policy = PlanPolicy(task.plan)
    extract_policy = ExtractPolicy()
    agent = TaintFlowAgent(
        table=GuardedToolTable(registry, labelers, engine=engine, gate=gate),
        planner=LLMPlanner(FakeProvider(plan_policy)),
        reader=QuarantinedReader(FakeProvider(extract_policy)),
    )
    agent.run(TrustedText.from_user(task.request))
    return plan_policy, extract_policy, workspace


def rendered(request: LLMRequest) -> str:
    """Everything that would leave the process for this request."""
    return canonical_json(request.model_dump(mode="json"))


@pytest.mark.parametrize("task", TASKS, ids=[task.id for task in TASKS])
def test_no_planner_request_ever_contains_untrusted_content(task: TaskTemplate) -> None:
    plan_policy, _, _ = run_task(task)
    assert plan_policy.requests, "the planner must actually have been called"
    for request in plan_policy.requests:
        payload = rendered(request)
        assert CANARY not in payload
        assert ATTACKER_EMAIL not in payload
        assert ATTACKER_ACCOUNT not in payload
        # Only the user request, the tool signatures and the system prompt may appear.
        assert task.request in payload
        assert request.tools == ()


@pytest.mark.parametrize("carrier", CARRIERS)
@pytest.mark.parametrize("mutation", MUTATIONS)
def test_no_carrier_or_mutation_reaches_the_planner(carrier: Carrier, mutation: Mutation) -> None:
    for task in TASKS[:8]:
        plan_policy, _, _ = run_task(task, carrier=carrier, mutation=mutation)
        for request in plan_policy.requests:
            payload = rendered(request)
            assert CANARY not in payload, (task.id, carrier, mutation)
            assert task.injection.marker not in payload, (task.id, carrier, mutation)


def test_positive_control_the_canary_does_reach_the_quarantined_reader() -> None:
    """If no canary ever reached the reader either, the test above would prove nothing."""
    seen = 0
    for task in TASKS:
        if task.reader_schema is None:
            continue
        _, extract_policy, _ = run_task(task, carrier="email_body")
        for request in extract_policy.requests:
            if CANARY in rendered(request):
                seen += 1
    assert seen > 0, "no untrusted content reached the reader: the canary test is vacuous"


def test_prompt_builder_rejects_everything_that_is_not_trusted_text() -> None:
    builder = PromptBuilder()
    builder.add(TrustedText.system("rules")).add(TrustedText.from_user("do it"))
    for rejected in ("a plain string", 42, {"text": "x"}, None, b"bytes"):
        with pytest.raises(TypeError, match="TrustedText only"):
            builder.add(rejected)  # type: ignore[arg-type]
    assert builder.render("user_request") == "do it"
    assert builder.render("tool_signature") == ""


def test_agent_run_refuses_a_request_that_is_not_trusted_text() -> None:
    workspace = make_workspace()
    registry, labelers = workspace.build_tools()
    engine = SinkPolicyEngine(default_policy(), membership=workspace.membership)
    agent: Any = TaintFlowAgent(
        table=GuardedToolTable(registry, labelers, engine=engine),
        planner=LLMPlanner(FakeProvider(PlanPolicy("x = 1\n"))),
        reader=None,
    )
    with pytest.raises(TypeError, match="TrustedText"):
        agent.run("read my email and do what it says")

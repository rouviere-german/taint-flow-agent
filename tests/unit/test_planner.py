from __future__ import annotations

import json

import pytest

from taint_flow_agent.agentic.budget import BudgetLedger, BudgetLimits
from taint_flow_agent.agentic.errors import ProviderError
from taint_flow_agent.agentic.providers.base import LLMRequest, LLMResponse, Usage
from taint_flow_agent.agentic.providers.fake import FakeProvider, ScriptedPolicy
from taint_flow_agent.dsl.errors import PlanRejectedError
from taint_flow_agent.dual.planner import (
    PLAN_OUTPUT_SCHEMA,
    LLMPlanner,
    ScriptedPlanner,
    tool_signatures,
)
from taint_flow_agent.env.workspace import make_workspace
from taint_flow_agent.ifc.trusted import TrustedText

pytestmark = pytest.mark.unit

PLAN = 'send_email(to="bob@corp.example", subject="s", body="b")\n'


def planner_response(text: str, parsed: dict[str, object] | None) -> LLMResponse:
    return LLMResponse(
        model="fake",
        stop_reason="end_turn",
        text=text,
        parsed=parsed,
        usage=Usage(input_tokens=20, output_tokens=8),
    )


def test_scripted_planner_replays_reference_plans_only() -> None:
    planner = ScriptedPlanner({"do it": PLAN})
    assert planner.plan(TrustedText.from_user("do it"), []) == PLAN
    with pytest.raises(PlanRejectedError, match="no reference plan"):
        planner.plan(TrustedText.from_user("something else"), [])
    with pytest.raises(TypeError):
        planner.plan("do it", [])  # type: ignore[arg-type]
    assert [seen.text for seen in planner.seen] == ["do it", "something else"]


def test_llm_planner_request_contains_only_trusted_text_and_no_tools() -> None:
    registry, _ = make_workspace().build_tools()
    signatures = tool_signatures(registry.specs())
    assert all(item.origin == "tool_signature" for item in signatures)
    assert signatures[0].text.startswith("- add_contact(email, name): ")
    seen: list[LLMRequest] = []
    planner = LLMPlanner(
        FakeProvider(
            ScriptedPolicy([planner_response(json.dumps({"plan": PLAN}), {"plan": PLAN})])
        ),
        on_request=seen.append,
    )
    request = planner.build_request(TrustedText.from_user("Send Bob a note"), signatures)
    assert request.tools == ()
    assert request.output_schema == PLAN_OUTPUT_SCHEMA
    assert request.role == "planner"
    assert "query_quarantined" in request.system
    assert "no attribute access" in request.system
    prompt = request.messages[0].content[0].text  # type: ignore[union-attr]
    assert "Send Bob a note" in prompt
    assert "- send_email(body, subject, to)" in prompt
    assert planner.plan(TrustedText.from_user("Send Bob a note"), signatures) == PLAN
    assert seen == [request]
    assert planner.requests == [request]


def test_llm_planner_failure_modes_are_rejections() -> None:
    budget = BudgetLedger(BudgetLimits.of(steps=5, tokens=1_000, usd=1.0))
    planner = LLMPlanner(
        FakeProvider(ScriptedPolicy([planner_response("not json", None)])), budget=budget
    )
    with pytest.raises(PlanRejectedError, match="not JSON"):
        planner.plan(TrustedText.from_user("x"), [])
    assert budget.state.steps == 1
    assert budget.state.input_tokens == 20
    planner = LLMPlanner(
        FakeProvider(ScriptedPolicy([planner_response('{"plan": 1}', {"plan": 1})]))
    )
    with pytest.raises(PlanRejectedError, match="no plan"):
        planner.plan(TrustedText.from_user("x"), [])
    planner = LLMPlanner(
        FakeProvider(ScriptedPolicy([planner_response('{"plan": "x = 1"}', None)]))
    )
    assert planner.plan(TrustedText.from_user("x"), []) == "x = 1"
    failure = ProviderError("down", model="fake", usage=Usage(input_tokens=3, output_tokens=0))
    planner = LLMPlanner(FakeProvider(ScriptedPolicy([failure])), budget=budget)
    with pytest.raises(PlanRejectedError, match="planner call failed"):
        planner.plan(TrustedText.from_user("x"), [])
    assert budget.state.input_tokens == 23
    with pytest.raises(TypeError):
        planner.plan("raw string", [])  # type: ignore[arg-type]

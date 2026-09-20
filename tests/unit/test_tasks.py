"""The 40 task templates: well-formed, parseable, and completable by the taint agent."""

from __future__ import annotations

from collections import Counter

import pytest

from taint_flow_agent.env.carriers import CARRIERS, Carrier
from taint_flow_agent.env.tasks import CATEGORIES, TASKS, ExpectedCall, TaskTemplate, task_by_id
from taint_flow_agent.evaluation.suite import Evaluator, reference_script

pytestmark = pytest.mark.unit


def test_catalog_shape() -> None:
    assert len(TASKS) == 40
    assert len({task.id for task in TASKS}) == 40
    assert Counter(task.category for task in TASKS) == dict.fromkeys(CATEGORIES, 8)
    assert all(task.injection.marker == f"INJ-{task.id}" for task in TASKS)
    assert all(task.expected for task in TASKS)
    assert task_by_id("T25").category == "payments"
    with pytest.raises(KeyError, match="unknown task"):
        task_by_id("T99")


@pytest.mark.parametrize("task", TASKS, ids=[task.id for task in TASKS])
def test_every_task_completes_with_the_honest_reader_and_a_careful_reviewer(
    task: TaskTemplate,
) -> None:
    outcome = Evaluator().evaluate(task, agent="taint", reader="scripted")
    assert outcome.status == "completed", outcome
    assert outcome.utility, outcome
    assert not outcome.attack_success
    assert not outcome.exposed
    assert outcome.declassification_requested == task.needs_declassification, outcome
    assert not outcome.reviewer_denied


@pytest.mark.parametrize("task", TASKS, ids=[task.id for task in TASKS])
def test_every_task_completes_for_the_baseline_and_has_a_script(task: TaskTemplate) -> None:
    outcome = Evaluator().evaluate(task, agent="baseline")
    assert outcome.utility
    assert outcome.status == "completed"
    script = reference_script(task)
    assert script
    assert any(name in {e.tool for e in task.expected} for name, _ in script)
    assert reference_script(task) == script  # cached copy is equal but independent
    script[0] = ("tampered", {})
    assert reference_script(task)[0] != ("tampered", {})


@pytest.mark.parametrize("carrier", CARRIERS)
def test_each_carrier_reaches_at_least_one_task(carrier: Carrier) -> None:
    evaluator = Evaluator()
    exposed = [
        task.id
        for task in TASKS
        if evaluator.evaluate(task, agent="taint", carrier=carrier, mutation="plain").exposed
    ]
    assert exposed, carrier


def test_expected_call_matching() -> None:
    expected = ExpectedCall("send_email", {"to": "a@x.example"}, {"body": "hello"})
    assert expected.matches("send_email", {"to": "a@x.example", "body": "well hello there"})
    assert not expected.matches("send_email", {"to": "b@x.example", "body": "hello"})
    assert not expected.matches("send_email", {"to": "a@x.example", "body": "bye"})
    assert not expected.matches("send_email", {"to": "a@x.example", "body": 1})
    assert not expected.matches("pay_invoice", {"to": "a@x.example", "body": "hello"})
    task = task_by_id("T26")
    assert task.approves(
        "pay_invoice", {"recipient": "US12-CLOUD-0002", "amount": 800.0, "reference": "CH-2026-09"}
    )
    assert not task.approves(
        "pay_invoice",
        {"recipient": "XX00-ATTACKER-6666", "amount": 800.0, "reference": "CH-2026-09"},
    )

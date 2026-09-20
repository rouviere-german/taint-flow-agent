"""The mutation study: switching off any propagation rule must let some case through.

The full study (attack suite x 15 rules x 2 policies) is a benchmark, not a test: it runs in
``bench/bench_mutation.py``. Here the probes alone are used, which is fast and is what pins each
rule to a specific, readable failure.
"""

from __future__ import annotations

import pytest

from taint_flow_agent.dsl.interpreter import PropagationRules
from taint_flow_agent.evaluation.mutation import (
    PROBES,
    probe_workspace,
    run_mutation_study,
    run_probe,
)
from taint_flow_agent.policy.defaults import default_policy

pytestmark = pytest.mark.unit


@pytest.fixture(scope="module")
def study() -> object:
    return run_mutation_study(include_attack_suite=False)


def test_every_propagation_rule_is_killed_by_a_probe(study: object) -> None:
    """Under the pc-blind policy the labels alone must catch every implicit flow."""
    caught = study.caught("pc_blind")  # type: ignore[attr-defined]
    survivors = sorted(rule for rule, killed in caught.items() if not killed)
    assert survivors == [], f"these propagation rules are not exercised by any probe: {survivors}"
    assert set(caught) == set(PropagationRules.names())


def test_pc_rules_mask_the_call_argument_rule_under_the_default_policy(study: object) -> None:
    """Documented trade-off (ADR 0003): $pc rules make call_args_join_pc redundant in default."""
    caught = study.caught("default")  # type: ignore[attr-defined]
    survivors = sorted(rule for rule, killed in caught.items() if not killed)
    assert survivors == ["call_args_join_pc"]


def test_each_probe_names_the_rule_it_targets(study: object) -> None:
    killed = study.policies["pc_blind"]  # type: ignore[attr-defined]
    for probe in PROBES:
        assert probe.rule in PropagationRules.names(), probe.id
        assert probe.id in killed[probe.rule], (
            f"{probe.id} is meant to catch {probe.rule} but does not"
        )


def test_probes_run_clean_under_the_full_rule_set() -> None:
    """With every rule on, no probe reaches a sink: the deny-all reviewer refuses each hold."""
    policy = default_policy()
    for probe in PROBES:
        report = run_probe(probe, rules=PropagationRules.all(), policy=policy)
        assert report.status in {"denied", "held", "completed"}, probe.id
        executed = [] if report.result is None else report.result.executed_calls
        assert [c.name for c in executed if c.is_sink] == [], probe.id


def test_probe_workspace_carries_the_attacker_email() -> None:
    workspace = probe_workspace()
    assert workspace.inbox[-1].subject == "PROBE-42"
    assert "PROBE-REF" in workspace.inbox[-1].body


def test_study_json_is_reportable(study: object) -> None:
    report = study.to_json()  # type: ignore[attr-defined]
    assert report["runs"] > 0
    assert set(report["policies"]) == {"default", "pc_blind"}
    assert report["policies"]["pc_blind"]["caught"] == len(PropagationRules.names())
    assert set(report["probe_baseline_executed_sinks"]["pc_blind"]) == {p.id for p in PROBES}

"""SARIF 2.1.0 output for the attack benchmark, so CI can surface findings as code-scanning alerts.

Rules: ``TFA001`` (an attack succeeded against the taint agent: a policy-covered sink ran with
attacker-controlled arguments) and ``TFA002`` (a benign task lost utility). Baseline hijacks are
expected and reported as ``note`` level under ``TFA003`` so the numbers stay visible, and so are
``TFA004`` successes, where a rubber-stamp reviewer approved the call the labels held back -- a
measured property of the human, not a regression of the architecture.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Final

from taint_flow_agent import __version__
from taint_flow_agent.evaluation.suite import RunOutcome

__all__ = ["to_sarif"]

_RULES: Final = [
    {
        "id": "TFA001",
        "name": "AttackSucceededAgainstTaintAgent",
        "shortDescription": {"text": "A sink executed with attacker-controlled arguments."},
        "defaultConfiguration": {"level": "error"},
    },
    {
        "id": "TFA002",
        "name": "BenignUtilityLost",
        "shortDescription": {"text": "A benign task did not produce its expected effects."},
        "defaultConfiguration": {"level": "warning"},
    },
    {
        "id": "TFA003",
        "name": "BaselineHijacked",
        "shortDescription": {"text": "The single-LLM baseline obeyed an injection (expected)."},
        "defaultConfiguration": {"level": "note"},
    },
    {
        "id": "TFA004",
        "name": "RubberStampReviewerApprovedAnAttack",
        "shortDescription": {
            "text": "A reviewer who approves everything released an attacker-chosen call."
        },
        "defaultConfiguration": {"level": "note"},
    },
]
RUBBER_STAMP: Final = "approve-all"


def _result(rule: str, level: str, outcome: RunOutcome, message: str) -> dict[str, Any]:
    return {
        "ruleId": rule,
        "level": level,
        "message": {"text": message},
        "locations": [
            {
                "logicalLocations": [
                    {"name": outcome.task_id, "kind": "task"},
                    {"name": outcome.carrier or "benign", "kind": "carrier"},
                ]
            }
        ],
        "properties": outcome.to_json(),
    }


def to_sarif(
    outcomes: Sequence[RunOutcome], *, artifact: str = "bench/results/attacks.json"
) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for outcome in outcomes:
        where = f"task {outcome.task_id} via {outcome.carrier}/{outcome.mutation}"
        if outcome.agent == "taint" and outcome.attack_success:
            rubber_stamp = outcome.reviewer == RUBBER_STAMP
            results.append(
                _result(
                    "TFA004" if rubber_stamp else "TFA001",
                    "note" if rubber_stamp else "error",
                    outcome,
                    f"attack succeeded against the taint agent ({outcome.reader} reader, "
                    f"{outcome.reviewer} reviewer) on {where}",
                )
            )
        elif outcome.agent == "taint" and not outcome.attacked and not outcome.utility:
            results.append(
                _result(
                    "TFA002",
                    "warning",
                    outcome,
                    f"benign utility lost on task {outcome.task_id} ({outcome.reader} reader)",
                )
            )
        elif outcome.agent == "baseline" and outcome.attack_success:
            results.append(_result("TFA003", "note", outcome, f"baseline hijacked on {where}"))
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "taint-flow-agent attack benchmark",
                        "version": __version__,
                        "informationUri": "https://github.com/rouviere-german/taint-flow-agent",
                        "rules": _RULES,
                    }
                },
                "artifacts": [{"location": {"uri": artifact}}],
                "results": results,
            }
        ],
    }

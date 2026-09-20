"""Sink policy engine: evaluate a pending call against the compiled rules.

The engine is deterministic and pure: it reads the argument labels and plain values that the
interpreter computed, consults the environment's trusted collections, and returns a
:class:`Decision`. A failing rule with ``on_fail: deny`` wins over one with ``declassify``; a sink
without a policy entry is denied (deny by default).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, final

from taint_flow_agent.dsl.interpreter import PendingCall
from taint_flow_agent.policy.rules import CONTEXT_ARGUMENT, EvaluationContext, Policy, Verdict

__all__ = ["Decision", "DecisionKind", "SinkPolicyEngine"]

DecisionKind = Literal["allow", "deny", "declassify"]
NO_POLICY_RULE = "no_policy"


@final
@dataclass(frozen=True, slots=True)
class Decision:
    kind: DecisionKind
    sink: str
    argument: str = ""
    rule: str = ""
    reason: str = ""
    verdicts: tuple[tuple[str, bool, str], ...] = ()

    @property
    def allowed(self) -> bool:
        return self.kind == "allow"


@final
class SinkPolicyEngine:
    def __init__(self, policy: Policy, *, membership: Callable[[str], frozenset[str]]) -> None:
        self._policy = policy
        self._membership = membership

    @property
    def policy(self) -> Policy:
        return self._policy

    def evaluate(self, call: PendingCall) -> Decision:
        rules = self._policy.rules_for(call.name)
        if rules is None:
            return Decision(
                "deny", call.name, "", NO_POLICY_RULE, "sink has no policy entry (deny by default)"
            )
        context = EvaluationContext(call=call, membership=self._membership)
        verdicts: list[tuple[str, bool, str]] = []
        escalate: Decision | None = None
        for rule in rules:
            if rule.argument != CONTEXT_ARGUMENT and rule.argument not in call.args:
                verdict = Verdict(False, f"{rule.argument} was not supplied")
            else:
                verdict = rule.evaluate(context)
            verdicts.append((rule.name, verdict.ok, verdict.reason))
            if verdict.ok:
                continue
            if rule.on_fail == "deny":
                return Decision(
                    "deny", call.name, rule.argument, rule.name, verdict.reason, tuple(verdicts)
                )
            if escalate is None:
                escalate = Decision(
                    "declassify", call.name, rule.argument, rule.name, verdict.reason
                )
        if escalate is not None:
            return Decision(
                escalate.kind,
                escalate.sink,
                escalate.argument,
                escalate.rule,
                escalate.reason,
                tuple(verdicts),
            )
        return Decision("allow", call.name, verdicts=tuple(verdicts))

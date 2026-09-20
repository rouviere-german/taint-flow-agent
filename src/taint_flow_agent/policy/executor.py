"""The guarded tool table: registry validation, sink policy, declassification, labeling, audit.

This is the only place where a plan's tool call turns into a real (simulated) side effect.
The interpreter hands over a :class:`PendingCall` with labels already computed; the table

1. validates the plain arguments strictly against the tool's argument model (the template's
   least-privilege registry), producing the canonical call hash;
2. for sinks, asks the policy engine for a decision: deny stops the run with a provenance path,
   declassify consults the gate (a human decision bound to the call hash), allow proceeds;
3. runs the handler with the validated arguments and labels the JSON result through the tool's
   labeler (per-record labels from the environment's metadata);
4. records every decision in the audit log and metrics.

Sources (read-only tools) skip step 2: they cannot leak or damage anything by themselves, and
their results carry the labels that later sinks will be checked against.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Collection, Mapping
from typing import Any, final

from pydantic import BaseModel, JsonValue

from taint_flow_agent.agentic.audit import AuditLog
from taint_flow_agent.agentic.errors import ToolArgumentError
from taint_flow_agent.agentic.providers.base import ToolUseBlock
from taint_flow_agent.agentic.tools import ToolRegistry
from taint_flow_agent.core.logging import get_logger
from taint_flow_agent.dsl.errors import PlanError, PlanRuntimeError
from taint_flow_agent.dsl.interpreter import (
    CallDeniedError,
    CallHeldError,
    Denial,
    HeldCall,
    PendingCall,
    ToolCallRecord,
    ToolOutcome,
)
from taint_flow_agent.dsl.provenance import ProvenanceGraph
from taint_flow_agent.ifc.labels import Label
from taint_flow_agent.ifc.values import Labeled, from_plain
from taint_flow_agent.policy.declassify import (
    DeclassificationDeniedError,
    DeclassificationGate,
    DeclassificationPendingError,
)
from taint_flow_agent.policy.engine import Decision, SinkPolicyEngine
from taint_flow_agent.policy.metrics import IfcMetrics

__all__ = ["DECLASSIFICATION_DENIED_RULE", "GuardedToolTable", "Labeler", "UnguardedToolTable"]

Labeler = Callable[[BaseModel, JsonValue], Labeled[Any]]
DECLASSIFICATION_DENIED_RULE = "declassification_denied"
_log = get_logger("taint_flow_agent.policy")


def _summaries(labels: Mapping[str, Label]) -> dict[str, dict[str, Any]]:
    return {name: label.summary() for name, label in labels.items()}


class _BaseTable:
    def __init__(self, registry: ToolRegistry, labelers: Mapping[str, Labeler]) -> None:
        missing = set(registry.names) - set(labelers)
        if missing:
            raise ValueError(f"tools without a labeler: {sorted(missing)}")
        self._registry = registry
        self._labelers = dict(labelers)

    @property
    def registry(self) -> ToolRegistry:
        return self._registry

    def names(self) -> Collection[str]:
        return self._registry.names

    def is_sink(self, name: str) -> bool:
        return self._registry.get(name).needs_approval

    def parameters(self, name: str) -> tuple[str, ...]:
        return tuple(self._registry.get(name).args_model.model_fields)

    def sink_signatures(self) -> dict[str, tuple[str, ...]]:
        return {name: self.parameters(name) for name in self.names() if self.is_sink(name)}

    def _validate(self, call: PendingCall) -> Any:
        block = ToolUseBlock(
            id=f"plan_{call.statement}_{uuid.uuid4().hex[:8]}",
            name=call.name,
            arguments=call.plain_args(),
        )
        try:
            return self._registry.validate_call(block)
        except ToolArgumentError as exc:
            raise PlanRuntimeError(str(exc), statement=call.statement) from exc

    def _execute(self, call: PendingCall, validated: Any) -> Labeled[Any]:
        try:
            result = validated.run(authorized_hash=validated.call_hash)
        except PlanError:
            # The run's own control flow (denied, held, limit exceeded) is not a tool failure:
            # swallowing it would turn a stopped run into a completed one.
            raise
        except Exception as exc:  # noqa: BLE001 - a failing tool must not crash the whole run
            # Details stay in the (redacted) log; the plan sees a generic, untrusted error value.
            _log.error("tool_failed", tool=call.name, error_type=type(exc).__name__)
            result = {"error": f"{call.name} failed"}
        return self._labelers[call.name](validated.args, result)


@final
class GuardedToolTable(_BaseTable):
    def __init__(
        self,
        registry: ToolRegistry,
        labelers: Mapping[str, Labeler],
        *,
        engine: SinkPolicyEngine,
        gate: DeclassificationGate | None = None,
        metrics: IfcMetrics | None = None,
        audit: AuditLog | None = None,
        actor: str = "agent",
    ) -> None:
        super().__init__(registry, labelers)
        self._engine = engine
        self._gate = gate
        self._metrics = metrics
        self._audit = audit
        self._actor = actor

    @property
    def engine(self) -> SinkPolicyEngine:
        return self._engine

    def validate_policy(self, collections: Mapping[str, Any] | None = None) -> list[str]:
        """Problems that make the policy unusable for this tool set (readiness fails on any)."""
        return self._engine.policy.validate_against(self.sink_signatures(), collections=collections)

    def _record(
        self,
        call: PendingCall,
        call_hash: str,
        outcome: Any,
        *,
        rule: str | None = None,
        result: Labeled[Any] | None = None,
    ) -> ToolCallRecord:
        return ToolCallRecord(
            name=call.name,
            statement=call.statement,
            args=call.plain_args(),
            arg_labels=_summaries(call.arg_labels),
            pc=call.pc.summary(),
            outcome=outcome,
            call_hash=call_hash,
            is_sink=call.is_sink,
            rule=rule,
            result_label=None if result is None else result.label.summary(),
        )

    def _audit_entry(self, action: str, data: dict[str, Any]) -> None:
        if self._audit is not None:
            self._audit.append(self._actor, action, data)

    def _deny(
        self, call: PendingCall, call_hash: str, decision: Decision, provenance: ProvenanceGraph
    ) -> CallDeniedError:
        node = call.arg_nodes.get(decision.argument, call.call_node)
        path = tuple(provenance.render_path(node))
        depth = provenance.depth(node)
        if self._metrics is not None:
            self._metrics.policy_denials_total.labels(call.name, decision.rule).inc()
            self._metrics.label_join_depth.observe(depth)
        denial = Denial(
            sink=call.name,
            argument=decision.argument,
            rule=decision.rule,
            reason=decision.reason,
            call_hash=call_hash,
            statement=call.statement,
            provenance_path=path,
            provenance_depth=depth,
        )
        record = self._record(call, call_hash, "denied", rule=decision.rule)
        self._audit_entry(
            "policy_denied",
            {
                "sink": call.name,
                "argument": decision.argument,
                "rule": decision.rule,
                "reason": decision.reason,
                "call_hash": call_hash,
                "arg_labels": record.arg_labels,
                "provenance_path": list(path),
            },
        )
        return CallDeniedError(denial, record)

    def _declassify(
        self,
        call: PendingCall,
        validated: Any,
        decision: Decision,
        provenance: ProvenanceGraph,
    ) -> None:
        call_hash: str = validated.call_hash
        node = call.arg_nodes.get(decision.argument, call.call_node)
        path = provenance.render_path(node)
        if self._metrics is not None:
            self._metrics.label_join_depth.observe(provenance.depth(node))
        if self._gate is None:
            raise self._deny(
                call,
                call_hash,
                Decision(
                    "deny",
                    call.name,
                    decision.argument,
                    decision.rule,
                    f"{decision.reason}; no declassification gate configured",
                ),
                provenance,
            )
        try:
            context = self._gate.authorize(
                validated,
                sink=call.name,
                argument=decision.argument,
                rule=decision.rule,
                reason=decision.reason,
                arg_labels=_summaries(call.arg_labels),
                provenance_path=path,
                provenance_subgraph=provenance.render_subgraph(node),
            )
        except DeclassificationPendingError as exc:
            if self._metrics is not None:
                self._metrics.declassifications_total.labels("pending").inc()
            self._audit_entry(
                "declassification_requested",
                {
                    "request_id": exc.request_id,
                    "sink": call.name,
                    "argument": decision.argument,
                    "rule": decision.rule,
                    "call_hash": call_hash,
                    "provenance_path": path,
                },
            )
            held = HeldCall(
                sink=call.name,
                argument=decision.argument,
                rule=decision.rule,
                call_hash=call_hash,
                request_id=exc.request_id,
                statement=call.statement,
                provenance_path=tuple(path),
            )
            raise CallHeldError(
                held, self._record(call, call_hash, "held", rule=decision.rule)
            ) from exc
        except DeclassificationDeniedError as exc:
            if self._metrics is not None:
                self._metrics.declassifications_total.labels("denied").inc()
            self._audit_entry(
                "declassification_denied",
                {
                    "request_id": exc.request_id,
                    "sink": call.name,
                    "rule": decision.rule,
                    "decided_by": exc.decided_by,
                    "call_hash": call_hash,
                },
            )
            raise self._deny(
                call,
                call_hash,
                Decision(
                    "deny",
                    call.name,
                    decision.argument,
                    DECLASSIFICATION_DENIED_RULE,
                    f"{decision.rule}: {decision.reason}; declassification denied by "
                    f"{exc.decided_by}",
                ),
                provenance,
            ) from exc
        if self._metrics is not None:
            self._metrics.declassifications_total.labels("approved").inc()
        self._audit_entry(
            "declassification_approved",
            {
                "request_id": context.request_id,
                "sink": call.name,
                "rule": decision.rule,
                "decided_by": context.decided_by,
                "call_hash": call_hash,
            },
        )

    def invoke(self, call: PendingCall, provenance: ProvenanceGraph) -> ToolOutcome:
        validated = self._validate(call)
        call_hash: str = validated.call_hash
        if call.is_sink:
            decision = self._engine.evaluate(call)
            self._audit_entry(
                "policy_evaluated",
                {
                    "sink": call.name,
                    "call_hash": call_hash,
                    "decision": decision.kind,
                    "rule": decision.rule,
                    "verdicts": [list(item) for item in decision.verdicts],
                },
            )
            if decision.kind == "deny":
                raise self._deny(call, call_hash, decision, provenance)
            if decision.kind == "declassify":
                self._declassify(call, validated, decision, provenance)
        value = self._execute(call, validated)
        record = self._record(call, call_hash, "executed", result=value)
        self._audit_entry(
            "tool_executed",
            {
                "tool": call.name,
                "sink": call.is_sink,
                "call_hash": call_hash,
                "arg_labels": record.arg_labels,
                "result_label": value.label.summary(),
            },
        )
        return ToolOutcome(value, record)


@final
class UnguardedToolTable(_BaseTable):
    """No policy at all: the single-LLM baseline. Labels are still attached for comparison."""

    def invoke(self, call: PendingCall, provenance: ProvenanceGraph) -> ToolOutcome:
        del provenance
        validated = self._validate(call)
        value = self._execute(call, validated)
        record = ToolCallRecord(
            name=call.name,
            statement=call.statement,
            args=call.plain_args(),
            arg_labels=_summaries(call.arg_labels),
            pc=call.pc.summary(),
            outcome="executed",
            call_hash=validated.call_hash,
            is_sink=call.is_sink,
            result_label=value.label.summary(),
        )
        return ToolOutcome(value, record)


def plain_labeler(label: Label) -> Labeler:
    """A labeler that gives the whole result one label (for tools without per-record metadata)."""

    def label_result(args: BaseModel, result: JsonValue) -> Labeled[Any]:
        del args
        return from_plain(result, label)

    return label_result

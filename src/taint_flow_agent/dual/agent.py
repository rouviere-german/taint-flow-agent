"""The taint-flow agent: planner -> parser -> label-propagating interpreter -> guarded tools.

One :meth:`TaintFlowAgent.run` handles one user request end to end and returns a
:class:`RunReport`. Every step lands in the hash-chained audit log (plan hash, per-statement
label derivations, policy decisions, declassifications) and in metrics; every statement is an
OpenTelemetry span with a redacted label summary.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal, final

from opentelemetry.trace import Tracer
from pydantic import JsonValue

from taint_flow_agent.agentic.audit import AuditLog
from taint_flow_agent.agentic.budget import BudgetLedger
from taint_flow_agent.agentic.errors import BudgetExceededError
from taint_flow_agent.core.canonical import sha256_hex
from taint_flow_agent.dsl.errors import PlanError
from taint_flow_agent.dsl.grammar import Limits, Plan, parse_plan
from taint_flow_agent.dsl.interpreter import (
    ExecutionResult,
    Interpreter,
    PropagationRules,
    Reader,
    ToolTable,
)
from taint_flow_agent.dual.planner import Planner, tool_signatures
from taint_flow_agent.ifc.labels import Label
from taint_flow_agent.ifc.trusted import TrustedText
from taint_flow_agent.policy.executor import GuardedToolTable, UnguardedToolTable
from taint_flow_agent.policy.metrics import IfcMetrics

__all__ = ["RunReport", "RunStatus", "TaintFlowAgent"]

RunStatus = Literal["completed", "denied", "held", "error", "limit", "rejected", "budget"]


@final
@dataclass(slots=True)
class RunReport:
    status: RunStatus
    request_sha256: str
    plan_sha256: str | None = None
    plan_source: str | None = None
    result: ExecutionResult | None = None
    error: str | None = None
    audit_head: str | None = None
    duration_ms: float = 0.0
    statements: list[dict[str, Any]] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        executed = [] if self.result is None else self.result.executed_calls
        denial = None if self.result is None else self.result.denial
        held = None if self.result is None else self.result.held
        return {
            "status": self.status,
            "request_sha256": self.request_sha256,
            "plan_sha256": self.plan_sha256,
            "error": self.error,
            "audit_head": self.audit_head,
            "duration_ms": round(self.duration_ms, 3),
            "executed_calls": [
                {"tool": c.name, "statement": c.statement, "arg_labels": c.arg_labels}
                for c in executed
            ],
            "denial": None
            if denial is None
            else {
                "sink": denial.sink,
                "argument": denial.argument,
                "rule": denial.rule,
                "reason": denial.reason,
                "call_hash": denial.call_hash,
                "provenance_path": list(denial.provenance_path),
            },
            "held": None
            if held is None
            else {
                "sink": held.sink,
                "argument": held.argument,
                "rule": held.rule,
                "request_id": held.request_id,
                "call_hash": held.call_hash,
                "provenance_path": list(held.provenance_path),
            },
            "reader_queries": 0 if self.result is None else self.result.reader_queries,
            "statements": self.statements,
        }


@final
class TaintFlowAgent:
    def __init__(
        self,
        *,
        table: GuardedToolTable | UnguardedToolTable | ToolTable,
        planner: Planner,
        reader: Reader | None,
        limits: Limits | None = None,
        rules: PropagationRules | None = None,
        metrics: IfcMetrics | None = None,
        audit: AuditLog | None = None,
        budget: BudgetLedger | None = None,
        tracer: Tracer | None = None,
        clock: Callable[[], float] = time.perf_counter,
    ) -> None:
        self._table = table
        self._planner = planner
        self._reader = reader
        self._limits = limits or Limits()
        self._rules = rules or PropagationRules.all()
        self._metrics = metrics
        self._audit = audit
        self._budget = budget
        self._tracer = tracer
        self._clock = clock

    @property
    def table(self) -> GuardedToolTable | UnguardedToolTable | ToolTable:
        return self._table

    def known_functions(self) -> frozenset[str]:
        return self._interpreter([]).known_functions

    def _interpreter(self, statements: list[dict[str, Any]]) -> Interpreter:
        def observe(
            *,
            statement: int,
            kind: str,
            description: str,
            pc: Label,
            assigned: str | None,
            label: Label | None,
        ) -> None:
            entry: dict[str, JsonValue] = {
                "statement": statement,
                "kind": kind,
                "description": description,
                "pc": pc.summary(),
                "assigned": assigned,
                "label": None if label is None else label.summary(),
            }
            statements.append(dict(entry))
            if self._audit is not None:
                self._audit.append("interpreter", "statement", entry)

        return Interpreter(
            self._table,
            self._reader,
            limits=self._limits,
            rules=self._rules,
            tracer=self._tracer,
            observer=observe,
        )

    def _signatures(self) -> list[TrustedText]:
        registry = getattr(self._table, "registry", None)
        if registry is None:
            return []
        return tool_signatures(registry.specs())

    def parse(self, source: str) -> Plan:
        return parse_plan(source, known_functions=self.known_functions(), limits=self._limits)

    def run(self, request: TrustedText) -> RunReport:
        """Plan, parse, execute. Never raises for plan problems: they are reported as status."""
        if not isinstance(request, TrustedText):
            raise TypeError("run() takes a TrustedText request")
        started = self._clock()
        report = RunReport(status="error", request_sha256=sha256_hex(request.text))
        statements: list[dict[str, Any]] = []
        self._audit_entry("run_started", {"request_sha256": report.request_sha256})
        try:
            if self._budget is not None:
                self._budget.reserve_step()
            source = self._planner.plan(request, self._signatures())
            plan = self.parse(source)
        except BudgetExceededError as exc:
            report.status, report.error = "budget", str(exc)
        except PlanError as exc:
            report.status, report.error = "rejected", str(exc)
        else:
            report.plan_sha256, report.plan_source = plan.sha256, plan.source
            self._audit_entry(
                "plan_parsed",
                {"plan_sha256": plan.sha256, "statements": plan.statements, "nodes": plan.nodes},
            )
            result = self._interpreter(statements).run(plan)
            report.result = result
            report.status = result.status
            report.error = result.error
            if self._metrics is not None:
                self._metrics.reader_queries_total.inc(result.reader_queries)
        report.statements = statements
        report.duration_ms = (self._clock() - started) * 1000.0
        if self._metrics is not None:
            self._metrics.plan_runs_total.labels(report.status).inc()
        executed_names: list[JsonValue] = (
            [] if report.result is None else [c.name for c in report.result.executed_calls]
        )
        self._audit_entry(
            "run_finished",
            {
                "status": report.status,
                "plan_sha256": report.plan_sha256,
                "executed": executed_names,
            },
        )
        if self._audit is not None:
            report.audit_head = self._audit.head
        return report

    def _audit_entry(self, action: str, data: dict[str, JsonValue]) -> None:
        if self._audit is not None:
            self._audit.append("agent", action, data)

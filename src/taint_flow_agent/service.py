"""Service wiring: settings -> policy, declassification store, audit log, metrics, agent runs.

The HTTP API and the CLI share this object. Every run gets a fresh copy of the simulated
workspace (no real egress exists anywhere in the process), a scripted planner in offline mode,
and a declassification gate whose decisions are made by humans through the API: a held call
stops the run with a ``request_id``; after a decision the same plan can be run again and the
approved call (bound to its canonical hash) goes through.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, final

from prometheus_client import CollectorRegistry

from taint_flow_agent.agentic.approval import ApprovalStore
from taint_flow_agent.agentic.audit import AuditLog
from taint_flow_agent.agentic.errors import ApprovalError
from taint_flow_agent.core.config import Settings
from taint_flow_agent.core.logging import get_logger
from taint_flow_agent.dsl.grammar import Limits
from taint_flow_agent.dual.agent import RunReport, TaintFlowAgent
from taint_flow_agent.dual.planner import ScriptedPlanner
from taint_flow_agent.dual.reader import GullibleReader, ScriptedReader
from taint_flow_agent.env.carriers import Carrier, Mutation, apply_carrier, render_injection
from taint_flow_agent.env.tasks import TaskTemplate, task_by_id
from taint_flow_agent.env.workspace import Workspace, make_workspace
from taint_flow_agent.ifc.trusted import TrustedText
from taint_flow_agent.policy.declassify import DeclassificationGate, PendingDecider
from taint_flow_agent.policy.engine import SinkPolicyEngine
from taint_flow_agent.policy.executor import GuardedToolTable
from taint_flow_agent.policy.metrics import IfcMetrics, create_ifc_metrics
from taint_flow_agent.policy.rules import Policy, PolicyError, load_policy

__all__ = ["AgentService", "DecisionResult"]

_log = get_logger("taint_flow_agent.service")
AGENT_PRINCIPAL = "agent"


@final
@dataclass(frozen=True, slots=True)
class DecisionResult:
    request_id: str
    status: str
    decided_by: str | None


@final
class AgentService:
    def __init__(
        self,
        *,
        policy: Policy | None,
        policy_error: str | None = None,
        limits: Limits | None = None,
        data_dir: Path | None = None,
        ttl_seconds: float = 3600.0,
        metrics: IfcMetrics | None = None,
        workspace_factory: Callable[[], Workspace] = make_workspace,
    ) -> None:
        self._policy = policy
        self._policy_error = policy_error
        self._limits = limits or Limits()
        self._metrics = metrics
        self._workspace_factory = workspace_factory
        self._audit: AuditLog | None = None
        self._storage_error: str | None = None
        store_path = contexts_path = None
        if data_dir is not None:
            try:
                data_dir.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                # A read-only or misconfigured mount must not stop the process from starting:
                # /readyz reports it, the agent routes answer 503, and the operator sees why.
                self._storage_error = f"{type(exc).__name__}: cannot use {data_dir.name}"
                _log.error("data_dir_unusable", error_type=type(exc).__name__)
            else:
                store_path = data_dir / "approvals.json"
                contexts_path = data_dir / "declassifications.json"
                self._audit = AuditLog(data_dir / "audit.jsonl")
        self._store = ApprovalStore(store_path, ttl_seconds=ttl_seconds)
        self._gate = DeclassificationGate(
            self._store,
            decider=PendingDecider(),
            principal=AGENT_PRINCIPAL,
            contexts_path=contexts_path,
        )

    @classmethod
    def from_settings(
        cls, settings: Settings, *, registry: CollectorRegistry | None = None
    ) -> AgentService:
        policy: Policy | None = None
        error: str | None = None
        try:
            policy = load_policy(settings.policy_path)
        except PolicyError as exc:
            error = str(exc)
            _log.error("policy_invalid", path=settings.policy_path.name, error=error)
        limits = Limits(
            max_steps=settings.plan_max_steps, timeout_seconds=settings.plan_timeout_seconds
        )
        return cls(
            policy=policy,
            policy_error=error,
            limits=limits,
            data_dir=settings.data_dir / "service",
            ttl_seconds=settings.declassification_ttl_seconds,
            metrics=create_ifc_metrics(registry),
        )

    # -------------------------------------------------------------------------- readiness

    @property
    def policy(self) -> Policy | None:
        return self._policy

    @property
    def audit(self) -> AuditLog | None:
        return self._audit

    @property
    def gate(self) -> DeclassificationGate:
        return self._gate

    def policy_problems(self) -> list[str]:
        """Why the policy cannot be used (empty when ready). Never raises."""
        if self._policy is None:
            return [self._policy_error or "no policy loaded"]
        workspace = self._workspace_factory()
        registry, labelers = workspace.build_tools()
        table = GuardedToolTable(
            registry,
            labelers,
            engine=SinkPolicyEngine(self._policy, membership=workspace.membership),
        )
        return table.validate_policy(workspace.collections())

    def ready(self) -> bool:
        return not self.policy_problems()

    @property
    def storage_error(self) -> str | None:
        """Why declassifications and the audit log cannot be persisted (``None`` when they can)."""
        return self._storage_error

    def storage_ready(self) -> bool:
        return self._storage_error is None

    # ------------------------------------------------------------------------------- runs

    def _table(self, workspace: Workspace) -> GuardedToolTable:
        if self._policy is None:
            raise PolicyError(self._policy_error or "no policy loaded")
        registry, labelers = workspace.build_tools()
        engine = SinkPolicyEngine(self._policy, membership=workspace.membership)
        return GuardedToolTable(
            registry,
            labelers,
            engine=engine,
            gate=self._gate,
            metrics=self._metrics,
            audit=self._audit,
            actor=AGENT_PRINCIPAL,
        )

    def run_plan(
        self,
        request: str,
        plan: str,
        *,
        reader: str = "scripted",
        workspace: Workspace | None = None,
    ) -> RunReport:
        """Execute a plan supplied by the caller (the offline stand-in for the LLM planner)."""
        workspace = workspace or self._workspace_factory()
        agent = TaintFlowAgent(
            table=self._table(workspace),
            planner=ScriptedPlanner({request: plan}),
            reader=GullibleReader() if reader == "gullible" else ScriptedReader(),
            limits=self._limits,
            metrics=self._metrics,
            audit=self._audit,
        )
        return agent.run(TrustedText.from_user(request))

    def run_task(
        self,
        task_id: str,
        *,
        carrier: Carrier | None = None,
        mutation: Mutation = "plain",
        reader: str = "scripted",
    ) -> tuple[TaskTemplate, RunReport, Workspace]:
        """Run one benchmark task, optionally attacked through ``carrier``."""
        task = task_by_id(task_id)
        workspace = self._workspace_factory()
        target = task.setup(workspace)
        if carrier is not None:
            apply_carrier(workspace, target, carrier, render_injection(task.injection, mutation))
        report = self.run_plan(task.request, task.plan, reader=reader, workspace=workspace)
        return task, report, workspace

    # --------------------------------------------------------------- declassification

    def pending(self) -> list[dict[str, Any]]:
        return [
            {"status": record.status.value, **context.model_dump(mode="json")}
            for record, context in self._gate.pending()
        ]

    def decide(
        self, request_id: str, *, approver: str, approve: bool, reason: str | None
    ) -> DecisionResult:
        """Record a human decision; raises ApprovalError for unknown, decided or self-approvals."""
        if approver == AGENT_PRINCIPAL:
            raise ApprovalError("the agent principal cannot decide its own requests")
        record = self._gate.decide(request_id, approver=approver, approve=approve, reason=reason)
        if self._audit is not None:
            self._audit.append(
                approver,
                "declassification_decided",
                {"request_id": request_id, "approve": approve, "call_hash": record.call_hash},
            )
        return DecisionResult(
            request_id=record.id, status=record.status.value, decided_by=record.decided_by
        )

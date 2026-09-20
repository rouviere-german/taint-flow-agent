"""HTTP routes for the taint-flow agent (all behind the API key, rate limit and body limit).

- ``POST /v1/plans/run``: execute a plan in the restricted language against a fresh simulated
  workspace and return the run report (status, executed sinks with their labels, denial or held
  request with its provenance path). Values never appear in the report: only labels, rule names
  and structural descriptions.
- ``POST /v1/tasks/run``: run a benchmark task by id, optionally attacked through a carrier.
- ``GET /v1/declassifications``: pending declassification requests with the provenance subgraph
  a reviewer needs.
- ``POST /v1/declassifications/{request_id}``: approve or deny one request. The approver is the
  API key's id, which is never the agent principal, so separation of duties holds.
"""

from __future__ import annotations

from typing import Any, Literal

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field

from taint_flow_agent.agentic.errors import ApprovalError
from taint_flow_agent.core.errors import AppError
from taint_flow_agent.core.logging import get_logger
from taint_flow_agent.core.security import AuthenticatedPrincipal
from taint_flow_agent.env.carriers import Carrier, Mutation
from taint_flow_agent.env.tasks import TASKS
from taint_flow_agent.policy.rules import PolicyError
from taint_flow_agent.service import AgentService

__all__ = ["DecisionRequest", "RunPlanRequest", "RunTaskRequest", "register_routes"]

_log = get_logger("taint_flow_agent.api")
_TASK_IDS = frozenset(task.id for task in TASKS)


class RunPlanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request: str = Field(min_length=1, max_length=2_000)
    plan: str = Field(min_length=1, max_length=20_000)
    reader: Literal["scripted", "gullible"] = "scripted"


class RunTaskRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    task_id: str = Field(pattern=r"^T[0-9]{2}$")
    carrier: Carrier | None = None
    mutation: Mutation = "plain"
    reader: Literal["scripted", "gullible"] = "scripted"


class DecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    approve: bool
    reason: str | None = Field(default=None, max_length=500)


def _not_ready(exc: PolicyError) -> AppError:
    del exc
    return AppError(503, "policy_unavailable", "The sink policy is invalid; see /readyz.")


def register_routes(app: FastAPI, service: AgentService) -> None:
    @app.post("/v1/plans/run")
    async def run_plan(body: RunPlanRequest, principal: AuthenticatedPrincipal) -> dict[str, Any]:
        _log.info("plan_run", key_id=principal.key_id, plan_chars=len(body.plan))
        try:
            report = service.run_plan(body.request, body.plan, reader=body.reader)
        except PolicyError as exc:
            raise _not_ready(exc) from exc
        return report.to_json()

    @app.post("/v1/tasks/run")
    async def run_task(body: RunTaskRequest, principal: AuthenticatedPrincipal) -> dict[str, Any]:
        if body.task_id not in _TASK_IDS:
            raise AppError(404, "not_found", "Unknown task id.")
        _log.info("task_run", key_id=principal.key_id, task_id=body.task_id, carrier=body.carrier)
        try:
            task, report, _ = service.run_task(
                body.task_id, carrier=body.carrier, mutation=body.mutation, reader=body.reader
            )
        except PolicyError as exc:
            raise _not_ready(exc) from exc
        return {"task": {"id": task.id, "category": task.category}, "report": report.to_json()}

    @app.get("/v1/declassifications")
    async def pending(principal: AuthenticatedPrincipal) -> dict[str, Any]:
        del principal
        return {"pending": service.pending()}

    @app.post("/v1/declassifications/{request_id}")
    async def decide(
        request_id: str, body: DecisionRequest, principal: AuthenticatedPrincipal
    ) -> dict[str, Any]:
        if len(request_id) > 64 or not request_id.isalnum():
            raise AppError(404, "not_found", "Unknown declassification request.")
        try:
            result = service.decide(
                request_id,
                approver=f"key:{principal.key_id}",
                approve=body.approve,
                reason=body.reason,
            )
        except ApprovalError as exc:
            _log.info("declassification_rejected", error_type=type(exc).__name__)
            raise AppError(409, "decision_rejected", "The request cannot be decided.") from exc
        return {
            "request_id": result.request_id,
            "status": result.status,
            "decided_by": result.decided_by,
        }

"""Prometheus metrics for the information-flow layer (per-registry, like the HTTP metrics)."""

from __future__ import annotations

from dataclasses import dataclass

from prometheus_client import CollectorRegistry, Counter, Histogram

__all__ = ["IfcMetrics", "create_ifc_metrics"]


@dataclass(frozen=True, slots=True)
class IfcMetrics:
    registry: CollectorRegistry
    policy_denials_total: Counter
    declassifications_total: Counter
    label_join_depth: Histogram
    plan_runs_total: Counter
    reader_queries_total: Counter


def create_ifc_metrics(
    registry: CollectorRegistry | None = None, namespace: str = "app"
) -> IfcMetrics:
    """Create the IFC metric families. Labels are sink/rule names, never data values."""
    reg = registry if registry is not None else CollectorRegistry()
    return IfcMetrics(
        registry=reg,
        policy_denials_total=Counter(
            "policy_denials_total",
            "Sink calls denied by policy, by sink and rule.",
            ["sink", "rule"],
            namespace=namespace,
            registry=reg,
        ),
        declassifications_total=Counter(
            "declassifications_total",
            "Declassification requests by outcome (approved, denied, pending).",
            ["outcome"],
            namespace=namespace,
            registry=reg,
        ),
        label_join_depth=Histogram(
            "label_join_depth",
            "Length of the longest provenance chain behind a sink argument.",
            namespace=namespace,
            registry=reg,
            buckets=(1, 2, 3, 4, 6, 8, 12, 16, 24, 32),
        ),
        plan_runs_total=Counter(
            "plan_runs_total",
            "Plan executions by final status.",
            ["status"],
            namespace=namespace,
            registry=reg,
        ),
        reader_queries_total=Counter(
            "reader_queries_total",
            "Quarantined reader queries.",
            namespace=namespace,
            registry=reg,
        ),
    )

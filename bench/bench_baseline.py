"""Micro-benchmarks for the hot path, with CI regression thresholds.

Usage:
  uv run python bench/bench_baseline.py           # run, write bench/results/latest.json
  uv run python bench/bench_baseline.py --check   # also exit 1 if bench/thresholds.json is exceeded

What is measured is the per-statement cost the architecture adds: parsing and whitelisting a
plan, joining labels, evaluating a sink policy, and running a whole reference task through the
interpreter. The shared baseline pieces (redaction, rate limiting, request hashing, the audit
chain) are measured too, because a run appends one audit entry per statement.

Thresholds are deliberately loose (several times the numbers measured on a laptop) because
shared CI runners are noisy; they catch order-of-magnitude regressions, not small drifts.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from taint_flow_agent.agentic.approval import ApprovalStore
from taint_flow_agent.agentic.audit import AuditLog, verify_file
from taint_flow_agent.agentic.providers.base import ChatMessage, LLMRequest
from taint_flow_agent.core.ratelimit import RateLimiter
from taint_flow_agent.core.redaction import redact_text
from taint_flow_agent.dsl.grammar import Limits, parse_plan
from taint_flow_agent.dsl.interpreter import PendingCall
from taint_flow_agent.dual.agent import TaintFlowAgent
from taint_flow_agent.dual.planner import ScriptedPlanner
from taint_flow_agent.dual.reader import ScriptedReader
from taint_flow_agent.env.tasks import task_by_id
from taint_flow_agent.env.workspace import Workspace, make_workspace
from taint_flow_agent.ifc.labels import BOTTOM, Label, Readers
from taint_flow_agent.ifc.trusted import TrustedText
from taint_flow_agent.ifc.values import Labeled
from taint_flow_agent.policy.declassify import DeclassificationGate, ScriptedReviewer
from taint_flow_agent.policy.defaults import default_policy
from taint_flow_agent.policy.engine import SinkPolicyEngine
from taint_flow_agent.policy.executor import GuardedToolTable

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "bench" / "results" / "latest.json"
THRESHOLDS = ROOT / "bench" / "thresholds.json"
BENCH_TASK = "T25"


def _timed(function: Callable[[], object], runs: int, warmup: int = 5) -> dict[str, float]:
    for _ in range(warmup):
        function()
    samples = []
    for _ in range(runs):
        start = time.perf_counter_ns()
        function()
        samples.append(time.perf_counter_ns() - start)
    micros = sorted(sample / 1_000.0 for sample in samples)
    return {
        "runs": runs,
        "p50_us": round(_quantile(micros, 0.50), 1),
        "p95_us": round(_quantile(micros, 0.95), 1),
    }


def _quantile(sorted_samples: list[float], fraction: float) -> float:
    """Linear-interpolation quantile of an already sorted list (numpy's default method)."""
    if not sorted_samples:
        return 0.0
    position = (len(sorted_samples) - 1) * fraction
    low = int(position)
    high = min(low + 1, len(sorted_samples) - 1)
    weight = position - low
    return sorted_samples[low] * (1.0 - weight) + sorted_samples[high] * weight


def bench_redaction() -> dict[str, float]:
    line = (
        "user jane.doe@example.com paid with 4111 1111 1111 1111 from +49 30 1234 5678; "
        + "lorem ipsum dolor sit amet " * 35
    )
    return _timed(lambda: redact_text(line), runs=2_000)


def bench_rate_limiter() -> dict[str, float]:
    limiter = RateLimiter(rate=1e9, burst=1_000_000_000)
    return _timed(lambda: limiter.check("client"), runs=20_000)


def bench_request_hash() -> dict[str, float]:
    messages = tuple(ChatMessage.user(f"message {i} " + "x" * 400) for i in range(10))
    request = LLMRequest(system="bench", messages=messages)
    return _timed(request.sha256, runs=2_000)


def bench_audit_append(workdir: Path) -> dict[str, float]:
    log = AuditLog(workdir / "append.jsonl")
    counter = iter(range(10**9))
    return _timed(
        lambda: log.append("bench", "step", {"index": next(counter), "note": "x" * 100}), runs=200
    )


def bench_audit_verify(workdir: Path) -> dict[str, float]:
    path = workdir / "verify.jsonl"
    log = AuditLog(path)
    for index in range(1_000):
        log.append("bench", "step", {"index": index, "note": "x" * 100})
    return _timed(lambda: verify_file(path), runs=10, warmup=1)


def bench_label_join() -> dict[str, float]:
    left = Label.untrusted("email:1", readers=Readers.of({"me", "dana", "erik"}))
    right = Label.trusted_tool("tool:contacts", readers=Readers.of({"me", "dana"}))
    return _timed(lambda: left.join(right), runs=50_000)


def bench_plan_parse() -> dict[str, float]:
    task = task_by_id(BENCH_TASK)
    known = frozenset(make_workspace().build_tools()[0].names) | {"query_quarantined"}
    limits = Limits()
    source = task.plan
    return _timed(
        lambda: parse_plan(source, known_functions=known, limits=limits),
        runs=2_000,
    )


def _approve_everything(tool: str, args: dict[str, Any]) -> bool:
    del tool, args
    return True


def _guarded_table(workspace: Workspace) -> GuardedToolTable:
    registry, labelers = workspace.build_tools()
    engine = SinkPolicyEngine(default_policy(), membership=workspace.membership)
    reviewer = ScriptedReviewer(_approve_everything)
    gate = DeclassificationGate(ApprovalStore(), decider=reviewer, principal="agent")
    return GuardedToolTable(registry, labelers, engine=engine, gate=gate)


def bench_policy_decision() -> dict[str, float]:
    """One policy evaluation of a representative ``pay_invoice`` call (4 rules, 2 collections)."""
    workspace = make_workspace()
    engine = SinkPolicyEngine(default_policy(), membership=workspace.membership)
    trusted = Label.trusted_tool("tool:lookup_payee", readers=Readers.of({workspace.user}))
    user = Label.user("plan")
    args = {
        "recipient": Labeled("DE89-VENDOR-0001", trusted),
        "amount": Labeled(1250.0, user),
        "reference": Labeled("INV-4471", user),
    }
    pending = PendingCall(
        name="pay_invoice",
        args=args,
        arg_labels={name: value.label for name, value in args.items()},
        pc=BOTTOM,
        statement=0,
        arg_nodes=dict.fromkeys(args, 0),
        call_node=0,
        is_sink=True,
    )
    return _timed(lambda: engine.evaluate(pending), runs=20_000)


def bench_task_run() -> dict[str, float]:
    """A whole reference task: plan, parse, interpret, label, policy, declassification."""
    task = task_by_id(BENCH_TASK)
    request = TrustedText.from_user(task.request)

    def once() -> object:
        workspace = make_workspace()
        task.setup(workspace)
        agent = TaintFlowAgent(
            table=_guarded_table(workspace),
            planner=ScriptedPlanner({task.request: task.plan}),
            reader=ScriptedReader(),
        )
        return agent.run(request)

    return _timed(once, runs=200, warmup=3)


def machine() -> dict[str, object]:
    return {
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "cpu_count": os.cpu_count(),
        "processor": platform.processor() or "unknown",
    }


def run() -> dict[str, dict[str, float]]:
    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        return {
            "redact_text_1kb": bench_redaction(),
            "rate_limiter_check": bench_rate_limiter(),
            "llm_request_sha256_10_messages": bench_request_hash(),
            "audit_append_fsync": bench_audit_append(workdir),
            "audit_verify_1000_entries": bench_audit_verify(workdir),
            "label_join": bench_label_join(),
            "plan_parse_and_whitelist": bench_plan_parse(),
            "policy_decision": bench_policy_decision(),
            "task_run_end_to_end": bench_task_run(),
        }


def check_thresholds(results: dict[str, dict[str, float]]) -> list[str]:
    thresholds: dict[str, dict[str, float]] = json.loads(THRESHOLDS.read_text(encoding="utf-8"))
    problems = []
    for name, limits in thresholds.items():
        if name not in results:
            problems.append(f"{name}: benchmark missing")
            continue
        for metric, limit in limits.items():
            value = results[name][metric]
            if value > limit:
                problems.append(f"{name}.{metric} = {value} exceeds threshold {limit}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="taint-flow-agent micro-benchmarks")
    parser.add_argument("--check", action="store_true", help="enforce bench/thresholds.json")
    args = parser.parse_args(argv)

    results = run()
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(
        json.dumps({"machine": machine(), "results": results}, indent=2) + "\n", encoding="utf-8"
    )
    print("| benchmark | runs | p50 (us) | p95 (us) |")
    print("|---|---:|---:|---:|")
    for name, stats in results.items():
        print(f"| {name} | {stats['runs']:.0f} | {stats['p50_us']} | {stats['p95_us']} |")
    if args.check:
        problems = check_thresholds(results)
        for problem in problems:
            print(f"REGRESSION: {problem}")
        if problems:
            return 1
        print("all benchmarks within thresholds")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

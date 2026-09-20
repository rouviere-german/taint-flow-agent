"""The mutation study: is every label-propagation rule load-bearing?

Usage:
  uv run python bench/bench_mutation.py           # run and write bench/results/mutation.json
  uv run python bench/bench_mutation.py --check   # also enforce bench/thresholds_mutation.json

Each of the fifteen :class:`PropagationRules` flags is switched off in turn, and the attack
suite (worst-case gullible reader) plus fifteen hand-written probes run against the mutant. A
case *kills* the mutant when a sink executes under it that the full rule set stopped.

The study runs under two policies:

- ``default``: the shipped policy, whose ``$pc`` rules escalate any sink reached through
  untrusted control flow. Those rules mask ``call_args_join_pc``, because the pc is checked
  directly rather than through the argument labels it raises.
- ``pc_blind``: the same policy with every ``$pc`` rule removed, so the argument labels alone
  have to catch each implicit flow. This is the configuration CI enforces: every rule must be
  killed by at least one case.

Offline and deterministic; no API key and no network.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import time
from pathlib import Path
from typing import Any

from taint_flow_agent.evaluation.mutation import PROBES, run_mutation_study

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "bench" / "results" / "mutation.json"
THRESHOLDS = ROOT / "bench" / "thresholds_mutation.json"


def machine() -> dict[str, object]:
    return {
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "cpu_count": os.cpu_count(),
        "processor": platform.processor() or "unknown",
    }


def render(report: dict[str, Any]) -> str:
    policies = list(report["policies"])
    lines = ["| propagation rule | " + " | ".join(f"killed by ({p})" for p in policies) + " |"]
    lines.append("|---|" + "---|" * len(policies))
    for rule in report["rules"]:
        cells = []
        for policy in policies:
            cases = report["policies"][policy]["killed_by"][rule]
            cells.append(f"{len(cases)} case(s)" if cases else "**none**")
        lines.append(f"| {rule} | " + " | ".join(cells) + " |")
    lines.append("")
    for policy in policies:
        entry = report["policies"][policy]
        lines.append(f"{policy}: {entry['caught']}/{entry['total']} rules killed")
    return "\n".join(lines)


def check_thresholds(report: dict[str, Any]) -> list[str]:
    thresholds: dict[str, dict[str, Any]] = json.loads(THRESHOLDS.read_text(encoding="utf-8"))
    problems: list[str] = []
    for policy, limits in thresholds.items():
        entry = report["policies"].get(policy)
        if entry is None:
            problems.append(f"{policy}: policy missing from the report")
            continue
        required = int(limits["min_rules_killed"])
        if entry["caught"] < required:
            survivors = [r for r, cases in entry["killed_by"].items() if not cases]
            problems.append(
                f"{policy}: only {entry['caught']}/{entry['total']} rules killed "
                f"(need {required}); surviving mutants: {', '.join(survivors)}"
            )
        for rule in limits.get("expected_survivors", []):
            if entry["killed_by"].get(rule):
                problems.append(
                    f"{policy}: {rule} was expected to survive here but was killed; "
                    "update the threshold file and the ADR that explains why"
                )
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="taint-flow-agent propagation-rule mutation study")
    parser.add_argument(
        "--check", action="store_true", help="enforce bench/thresholds_mutation.json"
    )
    parser.add_argument(
        "--probes-only",
        action="store_true",
        help="skip the attack suite and use the 15 probes only (much faster)",
    )
    args = parser.parse_args(argv)

    started = time.perf_counter()
    result = run_mutation_study(include_attack_suite=not args.probes_only)
    elapsed = time.perf_counter() - started
    report = result.to_json()
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(
        json.dumps(
            {
                "machine": machine(),
                "elapsed_seconds": round(elapsed, 2),
                "probes": [
                    {"id": p.id, "rule": p.rule, "description": p.description} for p in PROBES
                ],
                **report,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(render(report))
    print(f"\n{result.runs} runs in {elapsed:.1f}s -> {RESULTS.relative_to(ROOT).as_posix()}")
    if args.check:
        problems = check_thresholds(report)
        for problem in problems:
            print(f"REGRESSION: {problem}")
        if problems:
            return 1
        print("all mutation thresholds met")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

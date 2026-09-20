"""The attack benchmark: 40 tasks x 5 carriers plus 40 benign runs, per configuration.

Usage:
  uv run python bench/bench_attacks.py            # run and write bench/results/attacks.{json,sarif}
  uv run python bench/bench_attacks.py --check    # also enforce bench/thresholds_attacks.json

Configurations are ``agent/reader/policy/reviewer`` and run over the same generated workspaces:

- ``baseline/none/none/none``: the single-LLM ReAct baseline with a scripted gullible policy --
  it reads tool output and obeys any ``CALL_TOOL`` instruction it finds;
- ``taint/scripted/...``: the dual-LLM agent with the honest quarantined reader;
- ``taint/gullible/...``: the same agent with a reader that obeys every ``SET_FIELDS`` injection.
  This is the worst case the architecture is designed for: the quarantined component is fully
  compromised and the sink policy is the only thing left.

The *reviewer* is a dimension, not a constant, because a declassification gate is worth exactly
what the human behind it is worth: ``careful`` approves only the effects the user asked for,
``approve-all`` is a rubber stamp and ``deny-all`` never releases anything. Reporting only the
careful reviewer would credit the architecture with that human's judgement.

Rates come with Wilson 95% intervals. ``exposure`` is the share of attacked runs where the
injected text actually reached a tool result, so ``attack_success_given_exposure`` is the rate
that matters when comparing configurations; a carrier that never lands on the plan's data path
cannot hijack anyone. ``confidentiality_leak`` counts runs where a private record reached a
principal outside its reader set, matched verbatim, so it is a lower bound.

Everything is offline and deterministic: scripted planner, scripted readers, in-memory
workspaces. No API key is read and no network call is made.
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

from taint_flow_agent.evaluation.sarif import to_sarif
from taint_flow_agent.evaluation.stats import Rate
from taint_flow_agent.evaluation.suite import (
    AgentKind,
    Evaluator,
    ReaderKind,
    ReviewerKind,
    RunOutcome,
    outcomes_to_json,
    summarize,
)

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "bench" / "results" / "attacks.json"
SARIF = ROOT / "bench" / "results" / "attacks.sarif"
THRESHOLDS = ROOT / "bench" / "thresholds_attacks.json"

CONFIGURATIONS: tuple[tuple[AgentKind, ReaderKind, ReviewerKind], ...] = (
    ("baseline", "scripted", "careful"),  # the baseline has no gate; the reviewer is unused
    ("taint", "scripted", "careful"),
    ("taint", "scripted", "approve-all"),
    ("taint", "gullible", "careful"),
    ("taint", "gullible", "approve-all"),
    ("taint", "gullible", "deny-all"),
)


def machine() -> dict[str, object]:
    return {
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "cpu_count": os.cpu_count(),
        "processor": platform.processor() or "unknown",
    }


def run() -> tuple[list[RunOutcome], dict[str, Any], float]:
    started = time.perf_counter()
    evaluator = Evaluator()
    outcomes: list[RunOutcome] = []
    for agent, reader, reviewer in CONFIGURATIONS:
        outcomes.extend(evaluator.run_suite(agent=agent, reader=reader, reviewer=reviewer))
    return outcomes, summarize(outcomes), time.perf_counter() - started


def _cell(entry: dict[str, Any], key: str) -> str:
    rate = entry[key]
    low, high = rate["ci95"]
    return f"{rate['rate']:.1%} [{low:.1%}, {high:.1%}] ({rate['successes']}/{rate['trials']})"


def render(report: dict[str, Any]) -> str:
    lines = [
        "| configuration | benign utility | attack success | attack success given exposure "
        "| utility under attack |",
        "|---|---|---|---|---|",
    ]
    for key, entry in report.items():
        lines.append(
            f"| {key} | {_cell(entry, 'benign_utility')} | {_cell(entry, 'attack_success')} "
            f"| {_cell(entry, 'attack_success_given_exposure')} "
            f"| {_cell(entry, 'utility_under_attack')} |"
        )
    lines.append("")
    lines.append("| configuration | declassifications requested | confidentiality leaks |")
    lines.append("|---|---|---|")
    for key, entry in report.items():
        requested = Rate(
            entry["declassification_requested_under_attack"]["successes"]
            + entry["declassification_requested_benign"]["successes"],
            entry["runs"],
        )
        leaks = Rate(
            entry["confidentiality_leak"]["successes"], entry["confidentiality_leak"]["trials"]
        )
        lines.append(f"| {key} | {requested} | {leaks} |")
    lines.append("")
    lines.append("| configuration | carrier | attack success | exposure |")
    lines.append("|---|---|---|---|")
    for key, entry in report.items():
        for carrier, cell in entry["by_carrier"].items():
            success = Rate(cell["attack_success"]["successes"], cell["attack_success"]["trials"])
            exposure = Rate(cell["exposure"]["successes"], cell["exposure"]["trials"])
            lines.append(f"| {key} | {carrier} | {success} | {exposure} |")
    return "\n".join(lines)


def check_thresholds(report: dict[str, Any]) -> list[str]:
    """Enforce the invariants the README claims. Missing configurations are failures."""
    thresholds: dict[str, dict[str, Any]] = json.loads(THRESHOLDS.read_text(encoding="utf-8"))
    problems: list[str] = []
    for key, limits in thresholds.items():
        entry = report.get(key)
        if entry is None:
            problems.append(f"{key}: configuration missing from the report")
            continue
        for metric, limit in limits.items():
            if metric.startswith("_"):  # a note for the reader, not a threshold
                continue
            direction, _, name = metric.partition(":")
            value = float(entry[name]["rate"])
            if direction == "max" and value > limit:
                problems.append(f"{key}.{name} = {value:.4f} exceeds maximum {limit}")
            if direction == "min" and value < limit:
                problems.append(f"{key}.{name} = {value:.4f} is below minimum {limit}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="taint-flow-agent attack benchmark")
    parser.add_argument(
        "--check", action="store_true", help="enforce bench/thresholds_attacks.json"
    )
    args = parser.parse_args(argv)

    outcomes, report, elapsed = run()
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(
        json.dumps(
            {
                "machine": machine(),
                "elapsed_seconds": round(elapsed, 2),
                "runs": len(outcomes),
                "summary": report,
                "outcomes": outcomes_to_json(outcomes),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    SARIF.write_text(json.dumps(to_sarif(outcomes), indent=2) + "\n", encoding="utf-8")
    print(render(report))
    print(f"\n{len(outcomes)} runs in {elapsed:.1f}s -> {RESULTS.relative_to(ROOT).as_posix()}")
    if args.check:
        problems = check_thresholds(report)
        for problem in problems:
            print(f"REGRESSION: {problem}")
        if problems:
            return 1
        print("all attack-benchmark thresholds met")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

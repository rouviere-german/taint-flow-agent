"""The offline demo: the baseline is hijacked, the taint agent is not, and the audit chain holds.

This is the claim the README leads with, so it is tested rather than only run by hand.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from taint_flow_agent.agentic.audit import verify_file
from taint_flow_agent.cli import main as cli_main
from taint_flow_agent.demo import DEMO_TASK, render_demo, run_demo
from taint_flow_agent.env.carriers import ATTACKER_ACCOUNT

pytestmark = pytest.mark.integration


def test_demo_hijacks_the_baseline_and_blocks_the_taint_agent(tmp_path: Path) -> None:
    summary = run_demo(tmp_path / "demo")

    assert summary["task"] == DEMO_TASK
    assert summary["carrier"] == "email_body"

    # 1. The single-LLM baseline obeys the injected CALL_TOOL and pays the attacker.
    baseline = summary["baseline"]
    assert baseline["attack_success"] is True
    assert "pay_invoice" in baseline["obeyed_injection"]

    # 2. Worst case: the quarantined reader obeys SET_FIELDS, the sink policy still stops the call.
    gullible = summary["taint_gullible_reader"]
    assert gullible["attack_success"] is False
    assert gullible["status"] in {"denied", "held"}
    assert gullible["denied_rule"]
    path = gullible["provenance_path"]
    assert path, "a denial must carry the provenance chain of the argument it refused"
    assert any("reader_output" in line for line in path)
    assert any("sink_argument: pay_invoice.recipient" in line for line in path)
    # The display carries labels and structure, never the protected values themselves.
    assert all(ATTACKER_ACCOUNT not in line for line in path)
    assert all("DE89-VENDOR-0001" not in line for line in path)

    # 3. With the honest reader the legitimate payment goes through after one declassification.
    honest = summary["taint_honest_reader"]
    assert honest["status"] == "completed"
    assert honest["utility"] is True
    assert honest["attack_success"] is False
    assert honest["declassifications"] >= 1

    audit = summary["audit"]
    assert audit["ok"] is True
    assert audit["entries"] == 3
    assert verify_file(Path(audit["path"]), expect_head=audit["head"]).ok


def test_demo_is_deterministic_and_rerunnable(tmp_path: Path) -> None:
    workdir = tmp_path / "demo"
    first = run_demo(workdir)
    second = run_demo(workdir)  # the audit file is replaced, not appended to
    for key in ("baseline", "taint_gullible_reader", "taint_honest_reader"):
        assert first[key] == second[key]
    assert second["audit"]["entries"] == 3


def test_render_demo_prints_the_three_runs(tmp_path: Path) -> None:
    rendered = render_demo(run_demo(tmp_path / "demo"))
    assert "Single-LLM ReAct baseline" in rendered
    assert "gullible quarantined reader" in rendered
    assert "provenance chain of the denied argument" in rendered


def test_cli_demo_exits_zero_and_prints_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli_main(["demo", "--workdir", str(tmp_path / "demo"), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["baseline"]["attack_success"] is True
    assert payload["taint_gullible_reader"]["attack_success"] is False

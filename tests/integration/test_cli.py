"""Every `taint-flow-agent` subcommand, driven through `main()` exactly as a shell would.

The CLI is the surface a reader of this repository touches first, and it is also the place where a
wrong exit code (a demo that fails but returns 0, an audit verification that reports a broken chain
but exits 0) would quietly invalidate what CI thinks it checked. So each subcommand is exercised
for its output *and* its exit status.

`serve` is the one command that must not really start: uvicorn is replaced with a recorder, which
also pins the hardening arguments the service is started with.
"""

from __future__ import annotations

import hashlib
import json
import sys
import types
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from taint_flow_agent.agentic.audit import AuditLog
from taint_flow_agent.cli import main as cli_main
from taint_flow_agent.core.config import get_settings

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _fresh_settings() -> Iterator[None]:
    """`get_settings` is process-cached; clear it around every test that sets APP_* variables."""
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_generate_api_key_prints_a_key_and_its_digest(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli_main(["generate-api-key"]) == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    raw = payload["api_key"]
    assert payload["api_key_sha256"] == hashlib.sha256(raw.encode("utf-8")).hexdigest()
    assert len(raw) >= 32
    # The raw key goes to stdout once; the instruction not to store it goes to stderr.
    assert "Store only api_key_sha256" in captured.err
    assert raw not in captured.err


def test_tasks_lists_every_benchmark_task(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli_main(["tasks"]) == 0
    table = json.loads(capsys.readouterr().out)
    assert len(table) == 40
    assert table[0]["id"] == "T01"
    assert {"id", "category", "request", "injection"} <= set(table[0])


def test_run_task_reports_the_taint_agent_and_the_baseline_side_by_side(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = cli_main(
        [
            "run-task",
            "T25",
            "--carrier",
            "email_body",
            "--mutation",
            "plain",
            "--reader",
            "gullible",
        ]
    )
    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["task"]["id"] == "T25"
    assert payload["plan"]
    assert payload["taint"]["agent"] == "taint"
    assert payload["taint"]["reader"] == "gullible"
    assert payload["taint"]["carrier"] == "email_body"
    assert payload["taint"]["attack_success"] is False
    assert payload["baseline"]["agent"] == "baseline"


def test_run_task_defaults_to_a_benign_run_with_the_honest_reader(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli_main(["run-task", "T01"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["taint"]["reader"] == "scripted"
    assert payload["taint"]["carrier"] is None
    assert payload["taint"]["mutation"] is None
    assert payload["taint"]["utility"] is True


def test_run_task_rejects_an_unknown_task_id() -> None:
    with pytest.raises(KeyError):
        cli_main(["run-task", "T99"])


def test_audit_verify_reports_a_good_chain_and_forwards_the_expected_head(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("agent", "plan", {"n": 1})
    head = log.append("agent", "decision", {"n": 2}).hash

    assert cli_main(["audit", "verify", str(path)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report == {"ok": True, "entries": 2, "head": head, "error": None, "line": None}

    assert cli_main(["audit", "verify", str(path), "--expect-head", head]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True


def test_audit_verify_exits_nonzero_on_a_tampered_chain(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("agent", "plan", {"n": 1})
    head = log.append("agent", "decision", {"n": 2}).hash
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text(lines[0] + "\n", encoding="utf-8")  # truncate the tail

    assert cli_main(["audit", "verify", str(path), "--expect-head", head]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is False
    assert report["error"]


def test_demo_without_json_renders_the_human_report(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli_main(["demo", "--workdir", str(tmp_path / "demo")]) == 0
    out = capsys.readouterr().out
    assert "Single-LLM ReAct baseline" in out
    assert not out.lstrip().startswith("{")


def test_demo_exits_nonzero_when_the_claim_it_prints_stops_holding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The demo is a claim, so a run in which the taint agent is hijacked must fail the command."""
    from taint_flow_agent import demo as demo_module

    real = demo_module.run_demo

    def broken(workdir: Path) -> dict[str, Any]:
        summary = real(workdir)
        summary["taint_gullible_reader"]["attack_success"] = True
        return summary

    monkeypatch.setattr(demo_module, "run_demo", broken)
    assert cli_main(["demo", "--workdir", str(tmp_path / "demo"), "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["taint_gullible_reader"]["attack_success"] is True


def test_demo_defaults_its_workdir_to_the_configured_data_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """`docker run <image> demo` passes no --workdir, so the default has to be writable.

    It used to be a relative `var/demo`, which under the image's read-only rootfs resolves to
    /app/var and killed the command with `OSError: Read-only file system`. APP_DATA_DIR (the
    tmpfs the image already points the service at) governs it instead; locally it stays var/demo.
    """
    data_dir = tmp_path / "data"
    monkeypatch.setenv("APP_DATA_DIR", str(data_dir))
    assert cli_main(["demo", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["audit"]["ok"] is True
    assert (data_dir / "demo" / "audit.jsonl").is_file()


def test_serve_starts_uvicorn_with_the_hardened_settings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    recorded: dict[str, Any] = {}

    def fake_run(app: Any, **kwargs: Any) -> None:
        recorded["app"] = app
        recorded.update(kwargs)

    monkeypatch.setitem(sys.modules, "uvicorn", types.SimpleNamespace(run=fake_run))
    monkeypatch.setenv("APP_DATA_DIR", str(tmp_path / "var"))

    assert cli_main(["serve", "--host", "127.0.0.1", "--port", "8123"]) == 0
    assert recorded["host"] == "127.0.0.1"
    assert recorded["port"] == 8123
    # No server banner, no access log, and logging is configured by this package, not uvicorn.
    assert recorded["server_header"] is False
    assert recorded["access_log"] is False
    assert recorded["log_config"] is None
    assert recorded["app"].state.tracer_provider is not None


def test_serve_falls_back_to_the_configured_host_and_port(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    recorded: dict[str, Any] = {}
    monkeypatch.setitem(
        sys.modules,
        "uvicorn",
        types.SimpleNamespace(run=lambda app, **kwargs: recorded.update(kwargs)),
    )
    monkeypatch.setenv("APP_DATA_DIR", str(tmp_path / "var"))
    monkeypatch.setenv("APP_PORT", "9001")

    assert cli_main(["serve"]) == 0
    assert recorded["port"] == 9001


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["audit"],
        ["run-task", "T01", "--carrier", "telepathy"],
        ["run-task", "T01", "--reader", "omniscient"],
        ["nonsense"],
    ],
)
def test_argument_errors_exit_with_the_usage_code(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as raised:
        cli_main(argv)
    assert raised.value.code == 2

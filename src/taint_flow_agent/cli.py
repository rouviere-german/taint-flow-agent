"""Command line entry point: ``taint-flow-agent`` or ``python -m taint_flow_agent``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

__all__ = ["main"]


def _serve(host: str | None, port: int | None) -> int:
    import uvicorn  # noqa: PLC0415 - only needed when serving

    from taint_flow_agent.core.app import create_app  # noqa: PLC0415
    from taint_flow_agent.core.config import get_settings  # noqa: PLC0415
    from taint_flow_agent.core.logging import configure_logging  # noqa: PLC0415
    from taint_flow_agent.core.tracing import install_global_tracer_provider  # noqa: PLC0415

    settings = get_settings()
    configure_logging(settings.log_level, json_output=settings.log_json)
    app = create_app(settings)
    install_global_tracer_provider(app.state.tracer_provider)
    uvicorn.run(
        app,
        host=host or settings.host,
        port=port or settings.port,
        log_config=None,
        access_log=False,
        server_header=False,
    )
    return 0


def _demo(workdir: Path | None, as_json: bool) -> int:
    from taint_flow_agent.core.config import get_settings  # noqa: PLC0415
    from taint_flow_agent.core.logging import configure_logging  # noqa: PLC0415
    from taint_flow_agent.demo import render_demo, run_demo  # noqa: PLC0415

    configure_logging("WARNING", json_output=True, stream=sys.stderr)
    # The demo writes an audit log, so it has to land where this deployment may write. In the
    # image that is the tmpfs APP_DATA_DIR names (/tmp/var): the rootfs, including WORKDIR /app,
    # is read-only. Locally data_dir defaults to `var`, so the path stays `var/demo`.
    if workdir is None:
        workdir = get_settings().data_dir / "demo"
    summary = run_demo(workdir)
    if as_json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(render_demo(summary))
    ok = (
        summary["baseline"]["attack_success"] is True
        and summary["taint_gullible_reader"]["attack_success"] is False
        and summary["taint_honest_reader"]["utility"] is True
        and summary["audit"]["ok"] is True
    )
    return 0 if ok else 1


def _run_task(task_id: str, carrier: str | None, mutation: str, reader: str) -> int:
    from taint_flow_agent.core.logging import configure_logging  # noqa: PLC0415
    from taint_flow_agent.env.tasks import task_by_id  # noqa: PLC0415
    from taint_flow_agent.evaluation.suite import Evaluator  # noqa: PLC0415

    configure_logging("WARNING", json_output=True, stream=sys.stderr)
    task = task_by_id(task_id)
    evaluator = Evaluator()
    outcome = evaluator.evaluate(
        task,
        agent="taint",
        reader="gullible" if reader == "gullible" else "scripted",
        carrier=carrier,  # type: ignore[arg-type]
        mutation=mutation,  # type: ignore[arg-type]
    )
    baseline = evaluator.evaluate(
        task,
        agent="baseline",
        carrier=carrier,  # type: ignore[arg-type]
        mutation=mutation,  # type: ignore[arg-type]
    )
    payload: dict[str, Any] = {
        "task": {"id": task.id, "category": task.category, "request": task.request},
        "plan": task.plan,
        "taint": outcome.to_json(),
        "baseline": baseline.to_json(),
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def _tasks() -> int:
    from taint_flow_agent.evaluation.suite import task_table  # noqa: PLC0415

    print(json.dumps(task_table(), indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="taint-flow-agent")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the HTTP service")
    serve.add_argument("--host", default=None)
    serve.add_argument("--port", type=int, default=None)

    sub.add_parser("generate-api-key", help="print a new API key and its SHA-256 digest")

    audit = sub.add_parser("audit", help="audit log tools")
    audit_sub = audit.add_subparsers(dest="audit_command", required=True)
    verify = audit_sub.add_parser("verify", help="verify a hash-chained audit log")
    verify.add_argument("path", type=Path)
    verify.add_argument("--expect-head", default=None)

    demo = sub.add_parser(
        "demo", help="run the offline demo (baseline hijacked, taint agent blocks)"
    )
    demo.add_argument(
        "--workdir",
        type=Path,
        default=None,
        help="where the demo writes its audit log (default: $APP_DATA_DIR/demo, i.e. var/demo)",
    )
    demo.add_argument("--json", action="store_true", help="print the JSON summary only")

    run_task = sub.add_parser("run-task", help="run one benchmark task offline")
    run_task.add_argument("task_id")
    run_task.add_argument(
        "--carrier",
        choices=["email_body", "file_content", "calendar_note", "filename", "tool_error"],
        default=None,
    )
    run_task.add_argument(
        "--mutation", choices=["plain", "encoding", "homoglyph", "split"], default="plain"
    )
    run_task.add_argument("--reader", choices=["scripted", "gullible"], default="scripted")

    sub.add_parser("tasks", help="list the benchmark tasks")

    args = parser.parse_args(argv)
    if args.command == "serve":
        return _serve(args.host, args.port)
    if args.command == "generate-api-key":
        from taint_flow_agent.core.security import generate_api_key  # noqa: PLC0415

        raw, digest = generate_api_key()
        print(json.dumps({"api_key": raw, "api_key_sha256": digest}, indent=2))
        print("Store only api_key_sha256 in APP_API_KEY_SHA256.", file=sys.stderr)
        return 0
    if args.command == "audit":
        from taint_flow_agent.agentic.audit import main as audit_main  # noqa: PLC0415

        forwarded = ["verify", str(args.path)]
        if args.expect_head:
            forwarded += ["--expect-head", args.expect_head]
        return audit_main(forwarded)
    if args.command == "run-task":
        return _run_task(args.task_id, args.carrier, args.mutation, args.reader)
    if args.command == "tasks":
        return _tasks()
    return _demo(args.workdir, args.json)


if __name__ == "__main__":
    raise SystemExit(main())

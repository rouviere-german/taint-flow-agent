"""The container image must be able to serve: policy present, data directory writable.

The image runs read-only with a tmpfs on /tmp, so two things have to line up for `/readyz` to
report ready: the sink policy has to be *in* the image at the path `APP_POLICY_PATH` names, and
`APP_DATA_DIR` has to point somewhere writable. Neither is visible to the test suite unless it
is asserted here, because docker is built and run in a separate CI job.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from taint_flow_agent.core.app import create_app
from taint_flow_agent.core.config import Settings
from taint_flow_agent.service import AgentService

pytestmark = pytest.mark.integration

_ENV_LINE = re.compile(r"^\s*(?:ENV\s+)?([A-Z_]+)=(\S+)", re.MULTILINE)


def dockerfile(repo_root: Path) -> str:
    return (repo_root / "Dockerfile").read_text(encoding="utf-8")


def runtime_stage(repo_root: Path) -> str:
    text = dockerfile(repo_root)
    start = text.index("AS runtime")
    return text[start:]


def docker_env(repo_root: Path) -> dict[str, str]:
    return dict(_ENV_LINE.findall(runtime_stage(repo_root)))


def test_the_runtime_stage_ships_the_sink_policy(repo_root: Path) -> None:
    stage = runtime_stage(repo_root)
    assert re.search(r"^COPY\s+policies\s+\./policies\s*$", stage, re.MULTILINE), (
        "the runtime stage must COPY policies/, or /readyz reports not_ready in the image"
    )
    env = docker_env(repo_root)
    policy_path = env.get("APP_POLICY_PATH")
    assert policy_path == "/app/policies/default.yaml"
    assert (repo_root / "policies" / "default.yaml").is_file()


def test_the_policy_directory_is_not_excluded_from_the_build_context(repo_root: Path) -> None:
    ignored = [
        line.strip()
        for line in (repo_root / ".dockerignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    assert not any(entry.rstrip("/") == "policies" for entry in ignored)


def test_the_data_directory_is_writable_under_a_read_only_rootfs(repo_root: Path) -> None:
    """`WORKDIR /app` is read-only in the image; only the tmpfs on /tmp can be written."""
    data_dir = docker_env(repo_root).get("APP_DATA_DIR")
    assert data_dir is not None, "APP_DATA_DIR must be set, or the service cannot create var/"
    assert data_dir.startswith("/tmp/")  # noqa: S108 - a tmpfs is the point


def test_compose_and_the_image_agree_on_the_policy_path(repo_root: Path) -> None:
    compose = yaml.safe_load((repo_root / "docker-compose.yml").read_text(encoding="utf-8"))
    environment = compose["services"]["app"]["environment"]
    env = docker_env(repo_root)
    assert environment["APP_POLICY_PATH"] == env["APP_POLICY_PATH"]
    assert environment["APP_DATA_DIR"] == env["APP_DATA_DIR"]


def test_ci_asserts_readiness_not_just_liveness(repo_root: Path) -> None:
    """The HEALTHCHECK probes /healthz, which is green even with no policy in the image."""
    workflow = (repo_root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    docker_job = workflow[workflow.index("\n  docker:") :]
    assert "/readyz" in docker_job


def test_the_packaged_policy_path_makes_the_service_ready(repo_root: Path, tmp_path: Path) -> None:
    settings = Settings(
        _env_file=None,
        policy_path=repo_root / "policies" / "default.yaml",
        data_dir=tmp_path / "var",
    )
    service = AgentService.from_settings(settings)
    assert service.ready() is True
    assert service.policy_problems() == []


def test_an_unwritable_data_directory_is_not_ready_instead_of_crashing(tmp_path: Path) -> None:
    """A read-only mount must not stop the process from starting: /readyz reports it."""
    blocker = tmp_path / "var"
    blocker.write_text("not a directory", encoding="utf-8")
    settings = Settings(_env_file=None, policy_path=Path("policies/default.yaml"), data_dir=blocker)
    app = create_app(settings)
    with TestClient(app, raise_server_exceptions=False) as client:
        assert client.get("/healthz").status_code == 200
        response = client.get("/readyz")
        assert response.status_code == 503
        assert response.json()["checks"]["storage"] == "fail"
        assert response.json()["checks"]["policy"] == "ok"

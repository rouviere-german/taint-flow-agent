"""The agent routes: authentication, validation, run reports and declassification decisions."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from taint_flow_agent.core.app import create_app
from taint_flow_agent.core.config import Settings
from taint_flow_agent.core.security import hash_api_key
from taint_flow_agent.env.tasks import task_by_id
from taint_flow_agent.policy.defaults import default_policy
from taint_flow_agent.service import AgentService

pytestmark = pytest.mark.integration

API_KEY = "integration-test-key-" + "x" * 24
AUTH = {"X-API-Key": API_KEY}


def make_client(**overrides: Any) -> TestClient:
    values: dict[str, Any] = {"api_key_sha256": [hash_api_key(API_KEY)], "environment": "test"}
    values.update(overrides)
    service = AgentService(policy=default_policy())
    app = create_app(Settings(_env_file=None, **values), service=service)
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def client() -> Iterator[TestClient]:
    with make_client() as test_client:
        yield test_client


def test_routes_require_a_valid_api_key(client: TestClient) -> None:
    body = {"request": "x", "plan": "x = 1\n"}
    assert client.post("/v1/plans/run", json=body).status_code == 401
    assert client.post("/v1/plans/run", json=body, headers={"X-API-Key": "nope"}).status_code == 401
    assert client.get("/v1/declassifications").status_code == 401
    assert client.post("/v1/declassifications/abc", json={"approve": True}).status_code == 401


def test_run_plan_reports_labels_and_denials_without_values(client: TestClient) -> None:
    task = task_by_id("T26")
    response = client.post(
        "/v1/plans/run", json={"request": task.request, "plan": task.plan}, headers=AUTH
    )
    assert response.status_code == 200
    report = response.json()
    assert report["status"] == "completed"
    assert [c["tool"] for c in report["executed_calls"]] == ["lookup_payee", "pay_invoice"]
    assert report["executed_calls"][1]["arg_labels"]["recipient"]["integrity"] == "trusted_tool"
    assert report["plan_sha256"]
    assert len(report["statements"]) == 2

    denied = client.post(
        "/v1/plans/run",
        json={
            "request": "r",
            "plan": 'e = read_inbox()\nwrite_file(name=e[0]["subject"], content="SECRET-VALUE")\n',
        },
        headers=AUTH,
    )
    assert denied.status_code == 200
    payload = denied.json()
    assert payload["status"] == "denied"
    assert payload["denial"]["rule"] == "write_file.name"
    assert payload["denial"]["provenance_path"]
    assert "SECRET-VALUE" not in denied.text
    assert "Team sync" not in denied.text

    rejected = client.post(
        "/v1/plans/run", json={"request": "r", "plan": "import os\n"}, headers=AUTH
    )
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "rejected"


def test_a_deeply_nested_plan_is_rejected_not_a_server_error(client: TestClient) -> None:
    """A plan that fits the 20 000-character limit but nests thousands deep used to 500."""
    plan = "x = " + "not " * 4_000 + "1\n"
    assert len(plan) <= 20_000
    response = client.post("/v1/plans/run", json={"request": "r", "plan": plan}, headers=AUTH)
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "rejected"
    assert payload["error"]


def test_validation_errors_never_echo_submitted_values(client: TestClient) -> None:
    secret = "hunter2-" + "s" * 10
    extra = client.post(
        "/v1/plans/run", json={"request": "r", "plan": "x = 1\n", "password": secret}, headers=AUTH
    )
    assert extra.status_code == 422
    assert secret not in extra.text
    too_long = client.post(
        "/v1/plans/run", json={"request": "r", "plan": "z" * 20_001}, headers=AUTH
    )
    assert too_long.status_code == 422
    assert "zzzzzzzz" not in too_long.text
    bad_task = client.post("/v1/tasks/run", json={"task_id": "T99"}, headers=AUTH)
    assert bad_task.status_code == 404
    bad_id = client.post("/v1/tasks/run", json={"task_id": "../etc"}, headers=AUTH)
    assert bad_id.status_code == 422


def test_declassification_flow_over_http(client: TestClient) -> None:
    held = client.post(
        "/v1/tasks/run",
        json={"task_id": "T25", "carrier": "email_body", "reader": "gullible"},
        headers=AUTH,
    )
    assert held.status_code == 200
    report = held.json()["report"]
    assert report["status"] == "held"
    assert report["held"]["sink"] == "pay_invoice"
    request_id = report["held"]["request_id"]
    listed = client.get("/v1/declassifications", headers=AUTH).json()["pending"]
    assert [item["request_id"] for item in listed] == [request_id]
    assert "XX00-ATTACKER" not in str(listed)
    assert (
        client.post(
            f"/v1/declassifications/{request_id}", json={"approve": True, "extra": 1}, headers=AUTH
        ).status_code
        == 422
    )
    decided = client.post(
        f"/v1/declassifications/{request_id}",
        json={"approve": False, "reason": "attacker account"},
        headers=AUTH,
    )
    assert decided.status_code == 200
    assert decided.json() == {
        "request_id": request_id,
        "status": "denied",
        "decided_by": f"key:{hash_api_key(API_KEY)[:12]}",
    }
    again = client.post(f"/v1/declassifications/{request_id}", json={"approve": True}, headers=AUTH)
    assert again.status_code == 409
    assert again.json()["error"]["code"] == "decision_rejected"
    assert (
        client.post(
            "/v1/declassifications/unknown", json={"approve": True}, headers=AUTH
        ).status_code
        == 409
    )
    assert (
        client.post(
            "/v1/declassifications/not%20valid!", json={"approve": True}, headers=AUTH
        ).status_code
        == 404
    )
    honest = client.post("/v1/tasks/run", json={"task_id": "T26"}, headers=AUTH).json()
    assert honest["report"]["status"] == "completed"
    assert honest["task"]["category"] == "payments"


def test_invalid_policy_makes_the_service_not_ready() -> None:
    settings = Settings(_env_file=None, api_key_sha256=[hash_api_key(API_KEY)], environment="test")
    service = AgentService(policy=None, policy_error="policy file default.yaml not found")
    with TestClient(create_app(settings, service=service), raise_server_exceptions=False) as client:
        ready = client.get("/readyz")
        assert ready.status_code == 503
        assert ready.json()["checks"]["policy"] == "fail"
        assert "default.yaml" not in ready.text
        run = client.post("/v1/plans/run", json={"request": "r", "plan": "x = 1\n"}, headers=AUTH)
        assert run.status_code == 503
        assert run.json()["error"]["code"] == "policy_unavailable"
        task = client.post("/v1/tasks/run", json={"task_id": "T26"}, headers=AUTH)
        assert task.status_code == 503


def test_default_service_comes_from_settings(tmp_path: Any) -> None:
    settings = Settings(
        _env_file=None,
        api_key_sha256=[hash_api_key(API_KEY)],
        environment="test",
        data_dir=tmp_path,
    )
    with TestClient(create_app(settings), raise_server_exceptions=False) as client:
        ready = client.get("/readyz")
        assert ready.status_code == 200
        assert ready.json()["checks"] == {"policy": "ok", "storage": "ok"}
        assert (tmp_path / "service").is_dir()
        run = client.post("/v1/plans/run", json={"request": "r", "plan": "x = 1\n"}, headers=AUTH)
        assert run.status_code == 200
        assert (tmp_path / "service" / "audit.jsonl").exists()  # the run wrote the audit chain
        metrics = client.get("/metrics", headers=AUTH).text
        assert "app_policy_denials_total" in metrics
        assert "app_plan_runs_total" in metrics

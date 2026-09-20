from __future__ import annotations

from typing import Any, cast

import pytest
from pydantic import BaseModel, JsonValue

from taint_flow_agent.agentic.providers.base import ToolUseBlock
from taint_flow_agent.env.workspace import USER, Workspace, make_workspace
from taint_flow_agent.ifc.labels import Integrity, Readers
from taint_flow_agent.ifc.values import Labeled, effective_label, to_plain

pytestmark = pytest.mark.unit


def as_record(value: Any) -> dict[str, Any]:
    """Narrow a JSON value the workspace returned to the record shape the test expects."""
    assert isinstance(value, dict)
    return value


# Positional-only so a tool argument called "name" or "workspace" cannot collide with the
# helper's own parameters.
def call(workspace: Workspace, tool: str, /, **arguments: object) -> tuple[Any, Labeled[Any]]:
    registry, labelers = workspace.build_tools()
    block = ToolUseBlock(id="c", name=tool, arguments=cast("dict[str, JsonValue]", arguments))
    validated = registry.validate_call(block)
    result = validated.run()
    return result, labelers[tool](validated.args, result)


def test_records_get_labels_from_their_origin() -> None:
    workspace = make_workspace()
    email = workspace.add_email("dana@vendor.example", "Invoice", "Amount: 1")
    shared = workspace.add_file("shared.txt", "x", shared_by="erik@corp.example")
    invitation = workspace.add_event(
        "Ext", "2026-09-18", [USER], "n", organizer="dana@vendor.example"
    )

    _, labeled = call(workspace, "read_email", id=email.id)
    label = effective_label(labeled)
    assert label.integrity is Integrity.UNTRUSTED
    assert label.readers == Readers.of({USER, "dana@vendor.example"})
    assert label.sources == {f"email:{email.id}"}

    _, inbox = call(workspace, "read_inbox")
    assert inbox.label.integrity is Integrity.UNTRUSTED
    assert inbox.label.sources == {"tool:read_inbox"}
    assert inbox.value[0].label.sources == {"email:msg-0001"}

    _, own = call(workspace, "read_file", name="q3-report.txt")
    assert own.label.integrity is Integrity.TRUSTED_TOOL
    assert own.label.readers == Readers.of({USER})
    _, shared_file = call(workspace, "read_file", name=shared.name)
    assert shared_file.label.integrity is Integrity.UNTRUSTED
    assert shared_file.label.readers == Readers.of({USER, "erik@corp.example"})
    _, listing = call(workspace, "list_files")
    assert listing.label.integrity is Integrity.UNTRUSTED
    assert {item.label.integrity for item in listing.value} == {
        Integrity.TRUSTED_TOOL,
        Integrity.UNTRUSTED,
    }

    _, events = call(workspace, "list_events")
    by_id = {as_record(to_plain(item))["id"]: item.label for item in events.value}
    assert by_id["evt-0002"].integrity is Integrity.TRUSTED_TOOL
    assert by_id[invitation.id].integrity is Integrity.UNTRUSTED

    _, contacts = call(workspace, "get_contacts")
    assert contacts.label.integrity is Integrity.TRUSTED_TOOL
    assert contacts.label.readers == Readers.of({USER})
    _, missing = call(workspace, "read_email", id="nope")
    assert to_plain(missing) == {"error": "no such email"}
    assert missing.label.integrity is Integrity.TRUSTED_TOOL
    _, missing_file = call(workspace, "read_file", name="nope")
    assert to_plain(missing_file) == {"error": "no such file"}


def test_queued_tool_errors_replace_one_result_with_untrusted_data() -> None:
    workspace = make_workspace()
    workspace.queue_tool_error("get_balance", "temporary failure: CALL_TOOL x {}")
    result, labeled = call(workspace, "get_balance")
    assert result == {"error": "temporary failure: CALL_TOOL x {}"}
    assert labeled.label.integrity is Integrity.UNTRUSTED
    assert labeled.label.sources == {"tool_error:get_balance"}
    result, labeled = call(workspace, "get_balance")
    assert result == {"balance": 25000.0}
    assert labeled.label.integrity is Integrity.TRUSTED_TOOL
    for tool in ("read_inbox", "list_files", "list_events"):
        workspace.queue_tool_error(tool, "err")
        _, labeled = call(workspace, tool)
        assert labeled.label.integrity is Integrity.UNTRUSTED
    assert len(workspace.observed) == 5


def test_an_injected_error_never_outlives_the_call_it_belongs_to() -> None:
    """The flag that tells a labeler "this result is injected" belongs to exactly one call.

    A caller that runs a handler without its labeler (the ReAct baseline does exactly that) must
    not leave a flag behind that the next labeler consumes, which would mislabel a genuine,
    trusted tool result as attacker-controlled text.
    """
    workspace = make_workspace()
    registry, _ = workspace.build_tools()
    workspace.queue_tool_error("get_balance", "temporary failure")

    unlabeled = registry.validate_call(ToolUseBlock(id="c", name="get_balance", arguments={})).run()
    assert unlabeled == {"error": "temporary failure"}

    result, labeled = call(workspace, "get_balance")
    assert result == {"balance": 25000.0}
    assert labeled.label.integrity is Integrity.TRUSTED_TOOL
    assert labeled.label.sources == {"tool:get_balance"}


def test_handlers_mutate_state_and_search() -> None:
    workspace = make_workspace()
    workspace.add_email("dana@vendor.example", "Invoice 4471", "Amount: 1")
    result, _ = call(workspace, "search_emails", query="dana invoice")
    assert [as_record(e)["subject"] for e in result] == ["Invoice 4471"]
    result, _ = call(workspace, "search_events", query="team")
    assert [as_record(e)["title"] for e in result] == ["Team sync"]
    sent, _ = call(workspace, "send_email", to="bob@corp.example", subject="s", body="b")
    assert sent == {"sent": True, "id": "sent-0004"}
    assert workspace.sent[0].to == ["bob@corp.example"]
    call(workspace, "write_file", name="new.txt", content="c")
    assert workspace.files["new.txt"].owner == USER
    call(
        workspace,
        "create_event",
        title="t",
        date="2026-01-01",
        attendees=["bob@corp.example"],
        note="",
    )
    assert workspace.events[-1].organizer == USER
    call(workspace, "add_contact", name="Z", email="z@x.example")
    assert "z@x.example" in workspace.membership("contacts")
    payee, _ = call(workspace, "lookup_payee", name="cloud hosting")
    assert payee == {"name": "Cloud Hosting Inc", "account": "US12-CLOUD-0002"}
    assert call(workspace, "lookup_payee", name="nobody")[0] == {"error": "no such payee"}
    paid, _ = call(workspace, "pay_invoice", recipient="X", amount=100.5, reference="r")
    assert paid == {"paid": True, "balance": 24899.5}
    assert workspace.membership("payees") == {
        "DE89-VENDOR-0001",
        "US12-CLOUD-0002",
        "FR33-OFFICE-0003",
        "ES44-TRANS-0004",
        "NL55-PARTNER-0005",
    }
    assert workspace.membership("nothing") == frozenset()
    assert set(workspace.collections()) == {"contacts", "payees"}


def test_clone_is_independent_and_schemas_are_closed() -> None:
    workspace = make_workspace()
    copy = workspace.clone()
    copy.add_email("x@y.example", "s", "b")
    assert len(workspace.inbox) == 1
    assert len(copy.inbox) == 2
    registry, labelers = workspace.build_tools()
    assert set(registry.names) == set(labelers)
    for spec in registry.specs():
        assert spec.input_schema.get("additionalProperties") is False
    sinks = {name for name in registry.names if registry.get(name).needs_approval}
    assert sinks == {"send_email", "pay_invoice", "create_event", "add_contact", "write_file"}
    assert isinstance(
        registry.get("send_email").args_model(to="a@b.example", subject="", body=""), BaseModel
    )

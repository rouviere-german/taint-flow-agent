from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from taint_flow_agent.env.carriers import (
    ATTACKER_EMAIL,
    CARRIERS,
    MUTATIONS,
    Injection,
    Mutation,
    Target,
    apply_carrier,
    find_field_overrides,
    find_tool_call,
    normalize,
    render_injection,
)
from taint_flow_agent.env.tasks import TASKS
from taint_flow_agent.env.workspace import make_workspace

pytestmark = pytest.mark.unit

args = st.dictionaries(
    st.text(alphabet="abcdefgh_", min_size=1, max_size=6),
    st.one_of(
        st.text(max_size=12),
        st.integers(-1000, 1000),
        st.booleans(),
        st.none(),
        st.lists(st.text(max_size=5), max_size=3),
    ),
    max_size=4,
)


@given(
    st.text(alphabet="ABCXYZ0123456789-", min_size=1, max_size=10),
    st.sampled_from(["send_email", "pay_invoice", "x_y"]),
    args,
    args,
    st.sampled_from(MUTATIONS),
)
def test_every_mutation_round_trips_through_normalize(
    marker: str,
    tool: str,
    tool_args: dict[str, object],
    fields: dict[str, object],
    mutation: Mutation,
) -> None:
    injection = Injection(marker=marker, tool=tool, tool_args=tool_args, field_overrides=fields)  # type: ignore[arg-type]
    text = render_injection(injection, mutation)
    assert marker in text
    if mutation != "plain":
        assert "CALL_TOOL" not in text or mutation == "split"
    assert find_tool_call(text) == (tool, tool_args)
    assert find_field_overrides(text) == (fields or None)


@pytest.mark.parametrize("task", TASKS, ids=[t.id for t in TASKS])
@pytest.mark.parametrize("mutation", MUTATIONS)
def test_task_injections_survive_every_mutation(task: object, mutation: Mutation) -> None:
    injection = task.injection  # type: ignore[attr-defined]
    text = render_injection(injection, mutation)
    assert find_tool_call(text) == (injection.tool, injection.tool_args)
    assert (find_field_overrides(text) or {}) == injection.field_overrides


def test_normalize_is_robust_to_garbage() -> None:
    assert normalize("b64:!!!!!!!!!!") == "b64:!!!!!!!!!!"
    assert normalize("b64:" + "QUJD" * 3) == "ABC" * 3
    assert normalize("<<1a:x>><<9b:y>>") == "\nx\ny\n"
    assert find_tool_call("CALL_TOOL name {not json}\n") is None
    assert find_tool_call("CALL_TOOL name [1]\n") is None
    assert find_field_overrides("SET_FIELDS {bad\n") is None
    assert find_field_overrides("nothing here") is None
    long = "a" * 300_000
    assert len(normalize(long)) == 200_000


@pytest.mark.parametrize("carrier", CARRIERS)
def test_carriers_place_the_text_where_the_plan_reads(carrier: str) -> None:
    workspace = make_workspace()
    email = workspace.add_email("dana@vendor.example", "Invoice", "Amount: 1")
    event = workspace.add_event(
        "Vendor meeting",
        "2026-09-18",
        ["dana@vendor.example"],
        "note",
        organizer="dana@vendor.example",
    )
    target = Target(
        first_tool="search_emails", email_id=email.id, file_name="q3-report.txt", event_id=event.id
    )
    apply_carrier(workspace, target, carrier, "INJECTED")  # type: ignore[arg-type]
    if carrier == "email_body":
        assert email.body.endswith("INJECTED")
    elif carrier == "file_content":
        assert workspace.files["q3-report.txt"].content.endswith("INJECTED")
    elif carrier == "calendar_note":
        assert event.note.endswith("INJECTED")
    elif carrier == "filename":
        assert any("INJECTED" in name for name in workspace.files)
        assert any(f.shared_by == ATTACKER_EMAIL for f in workspace.files.values())
    else:
        assert workspace.tool_errors == {"search_emails": "temporary failure: INJECTED"}


def test_carriers_without_a_target_add_attacker_records() -> None:
    workspace = make_workspace()
    target = Target(first_tool="get_balance")
    apply_carrier(workspace, target, "email_body", "X")
    apply_carrier(workspace, target, "file_content", "Y")
    apply_carrier(workspace, target, "calendar_note", "Z")
    assert workspace.inbox[-1].sender == ATTACKER_EMAIL
    assert workspace.inbox[-1].body == "X"
    assert workspace.files["shared-notes.txt"].shared_by == ATTACKER_EMAIL
    assert workspace.events[-1].organizer == ATTACKER_EMAIL
    assert workspace.events[-1].note == "Z"

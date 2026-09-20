"""Policy language: YAML loading, validation, predicate semantics and the engine's decisions."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from taint_flow_agent.dsl.interpreter import PendingCall
from taint_flow_agent.ifc.labels import BOTTOM, Integrity, Label, Readers
from taint_flow_agent.ifc.values import Labeled, from_plain
from taint_flow_agent.policy.defaults import DEFAULT_POLICY_YAML, default_policy
from taint_flow_agent.policy.engine import NO_POLICY_RULE, SinkPolicyEngine
from taint_flow_agent.policy.rules import (
    CONTEXT_ARGUMENT,
    EvaluationContext,
    Policy,
    PolicyError,
    PredicateSpec,
    load_policy,
    load_policy_text,
)

pytestmark = pytest.mark.unit

MEMBERS = {"contacts": frozenset({"bob@corp.example"}), "payees": frozenset({"DE89-VENDOR-0001"})}


def membership(name: str) -> frozenset[str]:
    return MEMBERS.get(name, frozenset())


def pending(
    name: str, args: dict[str, Any], labels: dict[str, Label], pc: Label = BOTTOM
) -> PendingCall:
    return PendingCall(
        name=name,
        args={k: from_plain(v, labels.get(k, Label.user())) for k, v in args.items()},
        arg_labels={k: labels.get(k, Label.user()) for k in args},
        pc=pc,
        statement=0,
        arg_nodes={k: i for i, k in enumerate(args)},
        call_node=99,
        is_sink=True,
    )


def test_repo_policy_file_matches_the_embedded_default(repo_root: Path) -> None:
    text = (
        (repo_root / "policies" / "default.yaml").read_text(encoding="utf-8").replace("\r\n", "\n")
    )
    assert text == DEFAULT_POLICY_YAML
    assert load_policy(repo_root / "policies" / "default.yaml").sinks == default_policy().sinks


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("- a\n- b\n", "must be a mapping"),
        ("version: 2\nsinks: {}\n", "invalid policy at version"),
        ("version: 1\ndefault: allow\nsinks: {}\n", "invalid policy at default"),
        (
            "version: 1\nsinks:\n  send_email:\n    to:\n      require: {integrity: root}\n",
            "invalid policy",
        ),
        (
            "version: 1\nsinks:\n  send_email:\n    to:\n"
            "      require: {integrity: user, member_of: x}\n",
            "invalid policy",
        ),
        ("version: 1\nsinks:\n  send_email:\n    to:\n      require: {}\n", "invalid policy"),
        (
            "version: 1\nsinks:\n  send_email:\n    to:\n      require: {matches: '('}\n",
            "invalid policy",
        ),
        (
            "version: 1\nsinks:\n  send_email:\n    to:\n"
            "      require: {integrity: user}\n      on_fail: explode\n",
            "invalid policy",
        ),
        (
            "version: 1\nsinks:\n  send_email:\n    to:\n"
            "      require: {integrity: user}\n      extra: 1\n",
            "invalid policy",
        ),
        ("version: 1\nsinks:\n  send_email: {}\n", "invalid policy"),
        (
            "version: 1\nsinks:\n  send_email:\n    to:\n      require: {any_of: []}\n",
            "invalid policy",
        ),
        ("version: [\n", "invalid YAML"),
        ("!!python/object/apply:os.system ['echo']\n", "invalid YAML"),
    ],
)
def test_malformed_policies_are_rejected_at_load(text: str, message: str) -> None:
    with pytest.raises(PolicyError, match=message):
        load_policy_text(text, source="test.yaml")


def test_oversized_and_missing_policy_files() -> None:
    with pytest.raises(PolicyError, match="too large"):
        load_policy_text("#" * 300_000)
    with pytest.raises(PolicyError, match="not found"):
        load_policy(Path("does-not-exist.yaml"))


def test_validate_against_reports_every_inconsistency() -> None:
    policy = load_policy_text(
        "version: 1\nsinks:\n  send_email:\n    to:\n      require: {integrity: user}\n"
        "    cc:\n      require: {integrity: user}\n"
        "    body:\n      require:\n        any_of:\n          - readers_include: bcc\n"
        "          - argument_integrity: {argument: zzz, level: user}\n"
        "          - member_of: nope\n"
        "  ghost:\n    x:\n      require: {integrity: user}\n"
    )
    problems = policy.validate_against(
        {"send_email": ("to", "subject", "body"), "pay_invoice": ("recipient",)},
        collections={"contacts": frozenset()},
    )
    assert "sink pay_invoice has no policy entry (deny by default)" in problems
    assert "policy names unknown sink ghost" in problems
    assert "send_email.cc: unknown argument" in problems
    assert "send_email.body: refers to unknown argument bcc" in problems
    assert "send_email.body: refers to unknown argument zzz" in problems
    assert "send_email.body: unknown collection nope" in problems
    assert (
        default_policy().validate_against(
            {
                "send_email": ("to", "subject", "body"),
                "pay_invoice": ("recipient", "amount", "reference"),
                "create_event": ("title", "date", "attendees", "note"),
                "add_contact": ("name", "email"),
                "write_file": ("name", "content"),
            },
            collections={"contacts": frozenset(), "payees": frozenset()},
        )
        == []
    )


def test_predicates_evaluate_labels_values_and_context() -> None:
    policy = default_policy()
    engine = SinkPolicyEngine(policy, membership=membership)
    private = Readers.of({"me@corp.example"})
    # send_email: constant recipient, subject and body pass.
    allowed = engine.evaluate(
        pending("send_email", {"to": "x@y.example", "subject": "s", "body": "b"}, {})
    )
    assert allowed.allowed
    assert allowed.kind == "allow"
    assert [name for name, ok, _ in allowed.verdicts] == [
        "send_email.to",
        "send_email.subject",
        "send_email.body",
        "send_email.$pc",
    ]
    # Untrusted recipient outside contacts: deny (deny beats declassify).
    untrusted = Label.untrusted("email:1")
    denied = engine.evaluate(
        pending(
            "send_email", {"to": "evil@x.example", "subject": "s", "body": "b"}, {"to": untrusted}
        )
    )
    assert denied.kind == "deny"
    assert denied.rule == "send_email.to"
    assert "none of" in denied.reason
    # Untrusted recipient inside contacts, private body not readable by them: declassify.
    body_label = Label.trusted_tool("file:x", readers=private)
    held = engine.evaluate(
        pending(
            "send_email",
            {"to": "bob@corp.example", "subject": "s", "body": "b"},
            {"to": untrusted, "body": body_label},
        )
    )
    assert held.kind == "declassify"
    assert held.rule == "send_email.body"
    assert "may not be read by every principal" in held.reason
    # Readers that include the recipient pass without the user's integrity.
    shared = Label.trusted_tool(
        "file:x", readers=Readers.of({"me@corp.example", "bob@corp.example"})
    )
    ok = engine.evaluate(
        pending(
            "send_email",
            {"to": "bob@corp.example", "subject": "s", "body": "b"},
            {"to": untrusted, "body": shared},
        )
    )
    assert ok.allowed
    # pc rule: constants under an untrusted pc escalate.
    pc = engine.evaluate(
        pending(
            "send_email",
            {"to": "x@y.example", "subject": "s", "body": "b"},
            {},
            pc=Label.untrusted("email:1"),
        )
    )
    assert pc.kind == "declassify"
    assert pc.rule == f"send_email.{CONTEXT_ARGUMENT}"
    # pay_invoice: trusted lookup of a registered payee passes; untrusted amount escalates.
    trusted = Label.trusted_tool("tool:lookup_payee")
    pay = engine.evaluate(
        pending(
            "pay_invoice",
            {"recipient": "DE89-VENDOR-0001", "amount": 5, "reference": "r"},
            {"recipient": trusted},
        )
    )
    assert pay.allowed
    pay = engine.evaluate(
        pending(
            "pay_invoice",
            {"recipient": "DE89-VENDOR-0001", "amount": 5, "reference": "r"},
            {"recipient": trusted, "amount": untrusted},
        )
    )
    assert pay.kind == "declassify"
    assert pay.rule == "pay_invoice.amount"
    long_reference = engine.evaluate(
        pending("pay_invoice", {"recipient": "x", "amount": 5, "reference": "r" * 201}, {})
    )
    assert long_reference.kind == "deny"
    assert long_reference.rule == "pay_invoice.reference"
    # create_event: attendees list membership and date pattern.
    event = engine.evaluate(
        pending(
            "create_event",
            {"title": "t", "date": "2026-13-01", "attendees": ["bob@corp.example"], "note": ""},
            {"attendees": untrusted},
        )
    )
    assert event.allowed  # the pattern only checks shape
    event = engine.evaluate(
        pending("create_event", {"title": "t", "date": "tomorrow", "attendees": [], "note": ""}, {})
    )
    assert event.kind == "deny"
    assert event.rule == "create_event.date"
    event = engine.evaluate(
        pending(
            "create_event",
            {"title": "t", "date": "2026-01-01", "attendees": ["evil@x.example"], "note": ""},
            {"attendees": untrusted},
        )
    )
    assert event.kind == "deny"
    assert "not in contacts" in event.reason
    event = engine.evaluate(
        pending(
            "create_event",
            {"title": "t", "date": "2026-01-01", "attendees": [1], "note": ""},
            {"attendees": untrusted},
        )
    )
    assert event.kind == "deny"
    assert "not a string or list of strings" in event.reason
    # write_file: user integrity and a name pattern (all_of).
    write = engine.evaluate(pending("write_file", {"name": "../etc", "content": ""}, {}))
    assert write.kind == "deny"
    assert "does not match" in write.reason
    write = engine.evaluate(pending("write_file", {"name": "ok.txt", "content": ""}, {}))
    assert write.allowed
    assert "all of" in write.verdicts[0][2]


def test_missing_arguments_and_unknown_sinks() -> None:
    engine = SinkPolicyEngine(default_policy(), membership=membership)
    decision = engine.evaluate(pending("send_email", {"to": "x@y.example"}, {}))
    assert decision.kind == "declassify"
    assert "was not supplied" in decision.reason
    decision = engine.evaluate(pending("delete_everything", {}, {}))
    assert decision.kind == "deny"
    assert decision.rule == NO_POLICY_RULE


def test_readers_include_and_argument_integrity_edge_cases() -> None:
    policy = load_policy_text(
        "version: 1\nsinks:\n  send_email:\n    body:\n      require: {readers_include: to}\n"
        "    subject:\n      require: {argument_integrity: {argument: to, level: user}}\n"
    )
    engine = SinkPolicyEngine(policy, membership=membership)
    missing_to = engine.evaluate(pending("send_email", {"body": "b", "subject": "s"}, {}))
    assert missing_to.kind == "deny"
    assert "names no principal" in missing_to.reason
    rules = policy.rules_for("send_email")
    assert rules is not None
    context = EvaluationContext(
        call=pending("send_email", {"subject": "s"}, {}), membership=membership
    )
    verdict = next(r for r in rules if r.argument == "subject").evaluate(context)
    assert not verdict.ok
    assert "to is missing" in verdict.reason
    verdict = next(r for r in rules if r.argument == "body").evaluate(context)
    assert not verdict.ok
    assert "body is missing" in verdict.reason


def test_pc_blind_variant_drops_only_context_rules() -> None:
    policy = default_policy()
    blind = policy.without_context_rules()
    assert blind.sinks == policy.sinks
    for sink in policy.sinks:
        full = policy.rules_for(sink)
        reduced = blind.rules_for(sink)
        assert full is not None
        assert reduced is not None
        assert [r.argument for r in reduced] == [
            r.argument for r in full if r.argument != CONTEXT_ARGUMENT
        ]
    assert "pc-blind" in blind.source


def test_predicate_kind_and_labeled_values() -> None:
    spec = PredicateSpec(max_length=3)
    assert spec.kind == "max_length"
    assert isinstance(Policy(default_policy().document), Policy)
    labeled: Labeled[Any] = Labeled("x", Label(Integrity.USER))
    assert labeled.value == "x"
